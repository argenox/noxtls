/* Real NoxV port and production CCM dispatcher, independent public vectors. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "encryption/aes/noxtls_aes.h"
#include "encryption/aes/noxtls_aes_ccm.h"
#include "encryption/aes/noxtls_aes_accel.h"
#include "noxv_ccm_vectors.h"

#if NOXTLS_FEATURE_NOXV_HW_ACCEL != 1 || \
    NOXTLS_FEATURE_NOXV_CCM_ACCEL != CCM_TEST_GATE_ON
#error "The CCM fixture must exercise the selected mocked accelerator profile"
#endif

static uint32_t regs[0x40/4];
static unsigned checks, errors, model_faults, starts, key_writes, mmio, status_reads;
static unsigned irq_depth, irq_entries, timeout_at, reject_at, force_busy;
static const uint8_t *guard_output;
static uint8_t guard_bytes[32];
static unsigned guard_length;
#define CHECK(c,m) do { ++checks; if(!(c)) { ++errors; fprintf(stderr,"FAIL %s:%d %s\n",__FILE__,__LINE__,m); } } while(0)
static uint32_t pack(const uint8_t *p) { return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3]; }
static void unpack(uint32_t w,uint8_t *p) { p[0]=(uint8_t)(w>>24);p[1]=(uint8_t)(w>>16);p[2]=(uint8_t)(w>>8);p[3]=(uint8_t)w; }
static void reset_model(void)
{
    memset(regs,0,sizeof(regs));regs[1]=2u; /* Previous DONE must not be reused. */
    model_faults=starts=key_writes=mmio=status_reads=irq_depth=irq_entries=timeout_at=reject_at=force_busy=0u;
    guard_output=NULL;guard_length=0u;
}
uintptr_t noxtls_noxv_aes_irq_save(void)
{
    if(irq_depth!=0u) ++model_faults;
    ++irq_depth;++irq_entries;return 8u;
}
void noxtls_noxv_aes_irq_restore(uintptr_t state)
{
    if(irq_depth!=1u || state!=8u) ++model_faults;
    --irq_depth;
}
uint32_t noxtls_noxv_aes_mmio_read(uint32_t off)
{
    ++mmio;if(irq_depth!=1u || off>=sizeof(regs) || (off&3u)) {++model_faults;return 0u;}
    if(off==4u) {++status_reads;if(force_busy) return 1u;}
    return regs[off/4u];
}
void noxtls_noxv_aes_mmio_write(uint32_t off,uint32_t value)
{
    unsigned i;uint8_t key[16],input[16];
    ++mmio;if(irq_depth!=1u || off>=sizeof(regs) || (off&3u)) {++model_faults;return;}
    if(off>=8u && off<24u) ++key_writes;
    regs[off/4u]=value;
    if(off!=0u) return;
    if(value&4u) regs[1]=0u;
    if(!(value&2u)) return;
    ++starts;regs[1]=0u;
    if(guard_output && memcmp(guard_output,guard_bytes,guard_length)!=0) ++model_faults;
    if(timeout_at==starts) return;
    if(reject_at==starts) {regs[1]=18u;return;} /* Denied START plus stale DONE. */
    for(i=0u;i<4u;++i) {unpack(regs[2u+i],key+4u*i);unpack(regs[6u+i],input+4u*i);}
    for(i=0u;i<sizeof(aes_vectors)/sizeof(aes_vectors[0]);++i) {
        if(memcmp(key,aes_vectors[i].key,16u)==0 && memcmp(input,aes_vectors[i].input,16u)==0) {
            unsigned j;for(j=0u;j<4u;++j) regs[10u+j]=pack(aes_vectors[i].output+4u*j);
            regs[1]=2u;return;
        }
    }
    ++model_faults;
}
static int all_byte(const uint8_t *p,unsigned n,uint8_t v) {unsigned i;for(i=0;i<n;++i) if(p[i]!=v) return 0;return 1;}
static void check_vectors(void)
{
    unsigned v;
    for(v=0u;v<sizeof(ccm_vectors)/sizeof(ccm_vectors[0]);++v) {
        const ccm_vector_t *x=&ccm_vectors[v];
        uint8_t out[35],tag[6],bad[4],buf[35];noxtls_return_t rc;unsigned i;
        memset(out,0xa5,sizeof(out));memset(tag,0xa5,sizeof(tag));reset_model();
        rc=noxtls_aes_ccm_encrypt(x->key,NOXTLS_AES_128_BIT,x->nonce,13u,&x->aad,1u,x->plain,x->length,out+1u,tag+1u,4u);
        CHECK(rc==NOXTLS_RETURN_SUCCESS,"public CCM encryption");
        CHECK(memcmp(out+1u,x->cipher,x->length)==0 && memcmp(tag+1u,x->tag,4u)==0,"independent ciphertext/MIC");
        CHECK(out[0]==0xa5 && out[x->length+1u]==0xa5 && tag[0]==0xa5 && tag[5]==0xa5,"encrypt canaries");
        CHECK(model_faults==0u && irq_depth==0u,"balanced encrypted MMIO transaction");
#if CCM_TEST_GATE_ON
        if(x->length<=16u) CHECK(key_writes==4u && irq_entries==1u,"one loaded key and owner across CCM blocks");
        else CHECK(key_writes>4u && irq_entries>1u,"17+-byte public fallback remains usable");
#else
        CHECK(key_writes>4u && irq_entries>1u,"default-off public CCM uses generic composition");
#endif
        if(x->length==16u) {
            memset(buf,0xa5,sizeof(buf));memcpy(buf+1u,x->nonce,13u);reset_model();
            rc=noxtls_aes_ccm_encrypt(x->key,NOXTLS_AES_128_BIT,buf+1u,13u,&x->aad,1u,x->plain,x->length,buf+1u,tag+1u,4u);
            CHECK(rc==NOXTLS_RETURN_SUCCESS && memcmp(buf+1u,x->cipher,x->length)==0,"counter template survives nonce/output alias");
        }
        /* In-place encryption and decryption must keep counter/nonce ownership. */
        memset(buf,0xa5,sizeof(buf));memcpy(buf+1u,x->plain,x->length);reset_model();
        rc=noxtls_aes_ccm_encrypt(x->key,NOXTLS_AES_128_BIT,x->nonce,13u,&x->aad,1u,buf+1u,x->length,buf+1u,tag+1u,4u);
        CHECK(rc==NOXTLS_RETURN_SUCCESS && memcmp(buf+1u,x->cipher,x->length)==0,"in-place ciphertext");
        reset_model();
#if CCM_TEST_GATE_ON
        if(x->length<=16u) {guard_output=buf+1u;guard_length=x->length;memcpy(guard_bytes,buf+1u,x->length);}
#endif
        rc=noxtls_aes_ccm_decrypt(x->key,NOXTLS_AES_128_BIT,x->nonce,13u,&x->aad,1u,buf+1u,x->length,x->tag,4u,buf+1u);
        CHECK(rc==NOXTLS_RETURN_SUCCESS && memcmp(buf+1u,x->plain,x->length)==0,"in-place authenticated plaintext");
        CHECK(model_faults==0u && irq_depth==0u && buf[0]==0xa5 && buf[x->length+1u]==0xa5,"no early publication or out-of-bounds write");
        for(i=0u;i<4u;++i) {
            memcpy(bad,x->tag,4u);bad[i]^=0x80u;memset(out,0xa5,sizeof(out));reset_model();
#if CCM_TEST_GATE_ON
            if(x->length<=16u) {guard_output=out+1u;guard_length=x->length;memcpy(guard_bytes,out+1u,x->length);}
#endif
            rc=noxtls_aes_ccm_decrypt(x->key,NOXTLS_AES_128_BIT,x->nonce,13u,&x->aad,1u,x->cipher,x->length,bad,4u,out+1u);
            CHECK(rc==NOXTLS_RETURN_BAD_DATA && all_byte(out+1u,x->length,0u),"each wrong MIC byte denies and erases output");
            CHECK(model_faults==0u && irq_depth==0u && out[0]==0xa5 && out[x->length+1u]==0xa5,"MIC denial preserves bounds and ownership");
        }
    }
}
static void check_admission(void)
{
    const ccm_vector_t *x=&ccm_vectors[2];uint8_t out[35],tag[6];noxtls_return_t rc;
    unsigned n;
    for(n=0u;n<4u;++n) {
        reset_model();memset(out,0xa5,sizeof(out));memset(tag,0xa5,sizeof(tag));
        rc=noxtls_aes_ccm_encrypt_accel_port(x->key,NOXTLS_AES_128_BIT,x->nonce,n==0u?12u:13u,&x->aad,n==1u?0u:1u,x->plain,n==2u?17u:x->length,out,tag,n==3u?8u:4u);
        CHECK(rc==NOXTLS_RETURN_NOT_SUPPORTED && mmio==0u && all_byte(out,sizeof(out),0xa5) && all_byte(tag,sizeof(tag),0xa5),"unsupported geometry has no output/MMIO side effects");
    }
#if CCM_TEST_GATE_ON
    reset_model();rc=noxtls_aes_ccm_encrypt_accel_port(NULL,NOXTLS_AES_128_BIT,x->nonce,13u,&x->aad,1u,x->plain,x->length,out,tag,4u);
    CHECK(rc==NOXTLS_RETURN_NULL && mmio==0u,"null input fails before hardware");
    reset_model();force_busy=1u;memset(out,0xa5,sizeof(out));memset(tag,0xa5,sizeof(tag));
    rc=noxtls_aes_ccm_encrypt_accel_port(x->key,NOXTLS_AES_128_BIT,x->nonce,13u,&x->aad,1u,x->plain,x->length,out+1u,tag+1u,4u);
    CHECK(rc==NOXTLS_RETURN_TIMEOUT && starts==0u && key_writes==0u && status_reads==8u && irq_depth==0u,"busy engine has bounded fail-closed admission");
    CHECK(all_byte(out+1u,x->length,0u) && all_byte(tag+1u,4u,0u),"busy denial erases outputs");
    reset_model();reject_at=2u;memset(out,0xa5,sizeof(out));memset(tag,0xa5,sizeof(tag));
    rc=noxtls_aes_ccm_encrypt(x->key,NOXTLS_AES_128_BIT,x->nonce,13u,&x->aad,1u,x->plain,x->length,out+1u,tag+1u,4u);
    CHECK(rc==NOXTLS_RETURN_FAILED && all_byte(out+1u,x->length,0u) && all_byte(tag+1u,4u,0u),"rejected START never consumes stale DONE");
    CHECK(model_faults==0u && irq_depth==0u && starts==2u,"AAR arbitration failure restores owner without fallback");
    /* Longest admitted vector exercises every possible terminal block failure. */
    x=&ccm_vectors[4];
    for(n=1u;n<=5u;++n) {
        reset_model();timeout_at=n;memset(out,0xa5,sizeof(out));memset(tag,0xa5,sizeof(tag));
        rc=noxtls_aes_ccm_encrypt(x->key,NOXTLS_AES_128_BIT,x->nonce,13u,&x->aad,1u,x->plain,x->length,out+1u,tag+1u,4u);
        CHECK(rc==NOXTLS_RETURN_TIMEOUT && all_byte(out+1u,x->length,0u) && all_byte(tag+1u,4u,0u),"each encrypt block timeout propagates and erases partial results");
        CHECK(model_faults==0u && irq_depth==0u && starts==n,"no fallback after hardware error");
        reset_model();timeout_at=n;memset(out,0xa5,sizeof(out));guard_output=out+1u;guard_length=x->length;memcpy(guard_bytes,out+1u,x->length);
        rc=noxtls_aes_ccm_decrypt(x->key,NOXTLS_AES_128_BIT,x->nonce,13u,&x->aad,1u,x->cipher,x->length,x->tag,4u,out+1u);
        CHECK(rc==NOXTLS_RETURN_TIMEOUT && all_byte(out+1u,x->length,0u),"each decrypt block timeout denies partial plaintext");
        CHECK(model_faults==0u && irq_depth==0u && starts==n,"decrypt timeout restores exclusive owner");
    }
#else
    reset_model();memset(out,0xa5,sizeof(out));rc=noxtls_aes_ccm_encrypt_accel_port(x->key,NOXTLS_AES_128_BIT,x->nonce,13u,&x->aad,1u,x->plain,x->length,out,tag,4u);
    CHECK(rc==NOXTLS_RETURN_NOT_SUPPORTED && mmio==0u && all_byte(out,sizeof(out),0xa5),"unselected port never touches hardware or output");
#endif
}
int main(void)
{
    check_vectors();check_admission();
    printf("NoxV CCM gate=%d checks=%u failed=%u\n",CCM_TEST_GATE_ON,checks,errors);
    return errors?1:0;
}
