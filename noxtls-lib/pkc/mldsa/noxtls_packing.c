#include "noxtls_mldsa_internal_common.h"
#include "noxtls_packing.h"
#include "noxtls_poly.h"
#include "noxtls_polyvec.h"

static int noxtls_mld_unpack_hints(noxtls_mld_polyveck *h,
                            const uint8_t packed_hints[MLDSA_POLYVECH_PACKEDBYTES])
{
    unsigned int poly_idx;
    unsigned int hint_cursor;
    unsigned int hint_bound;

    noxtls_mld_memset(h, 0, sizeof(noxtls_mld_polyveck));

    hint_cursor = 0u;
    for(poly_idx = 0u; poly_idx < MLDSA_K; ++poly_idx) {
        unsigned int j;
        uint8_t prev_index;
        hint_bound = packed_hints[MLDSA_OMEGA + poly_idx];

        if(hint_bound < hint_cursor || hint_bound > MLDSA_OMEGA) {
            return 1;
        }

        prev_index = 0u;
        for(j = hint_cursor; j < hint_bound; ++j) {
            uint8_t coeff_index = packed_hints[j];
            if(j > hint_cursor && coeff_index <= prev_index) {
                return 1;
            }
            h->vec[poly_idx].coeffs[coeff_index] = 1;
            prev_index = coeff_index;
        }
        hint_cursor = hint_bound;
    }

    for(poly_idx = hint_cursor; poly_idx < MLDSA_OMEGA; ++poly_idx) {
        if(packed_hints[poly_idx] != 0u) {
            return 1;
        }
    }

    return 0;
}

MLD_INTERNAL_API
void noxtls_mld_pack_pk(uint8_t pk[MLDSA_CRYPTO_PUBLICKEYBYTES],
                 const uint8_t rho[MLDSA_SEEDBYTES],
                 const noxtls_mld_polyveck *t1)
{
    unsigned int i;

    noxtls_mld_memcpy(pk, rho, MLDSA_SEEDBYTES);
    for(i = 0u; i < MLDSA_K; ++i) {
        noxtls_mld_polyt1_pack(pk + MLDSA_SEEDBYTES + i * MLDSA_POLYT1_PACKEDBYTES,
                        &t1->vec[i]);
    }
}

MLD_INTERNAL_API
void noxtls_mld_unpack_pk(uint8_t rho[MLDSA_SEEDBYTES],
                   noxtls_mld_polyveck *t1,
                   const uint8_t pk[MLDSA_CRYPTO_PUBLICKEYBYTES])
{
    unsigned int i;

    noxtls_mld_memcpy(rho, pk, MLDSA_SEEDBYTES);
    for(i = 0u; i < MLDSA_K; ++i) {
        noxtls_mld_polyt1_unpack(&t1->vec[i],
                          pk + MLDSA_SEEDBYTES + i * MLDSA_POLYT1_PACKEDBYTES);
    }
}

MLD_INTERNAL_API
void noxtls_mld_pack_sk(uint8_t sk[MLDSA_CRYPTO_SECRETKEYBYTES],
                 const uint8_t rho[MLDSA_SEEDBYTES],
                 const uint8_t tr[MLDSA_TRBYTES],
                 const uint8_t key[MLDSA_SEEDBYTES],
                 const noxtls_mld_polyveck *t0,
                 const noxtls_mld_polyvecl *s1,
                 const noxtls_mld_polyveck *s2)
{
    noxtls_mld_memcpy(sk, rho, MLDSA_SEEDBYTES);
    sk += MLDSA_SEEDBYTES;

    noxtls_mld_memcpy(sk, key, MLDSA_SEEDBYTES);
    sk += MLDSA_SEEDBYTES;

    noxtls_mld_memcpy(sk, tr, MLDSA_TRBYTES);
    sk += MLDSA_TRBYTES;

    noxtls_mld_polyvecl_pack_eta(sk, s1);
    sk += MLDSA_L * MLDSA_POLYETA_PACKEDBYTES;

    noxtls_mld_polyveck_pack_eta(sk, s2);
    sk += MLDSA_K * MLDSA_POLYETA_PACKEDBYTES;

    noxtls_mld_polyveck_pack_t0(sk, t0);
}

MLD_INTERNAL_API
void noxtls_mld_unpack_sk(uint8_t rho[MLDSA_SEEDBYTES],
                   uint8_t tr[MLDSA_TRBYTES],
                   uint8_t key[MLDSA_SEEDBYTES],
                   noxtls_mld_polyveck *t0,
                   noxtls_mld_polyvecl *s1,
                   noxtls_mld_polyveck *s2,
                   const uint8_t sk[MLDSA_CRYPTO_SECRETKEYBYTES])
{
    noxtls_mld_memcpy(rho, sk, MLDSA_SEEDBYTES);
    sk += MLDSA_SEEDBYTES;

    noxtls_mld_memcpy(key, sk, MLDSA_SEEDBYTES);
    sk += MLDSA_SEEDBYTES;

    noxtls_mld_memcpy(tr, sk, MLDSA_TRBYTES);
    sk += MLDSA_TRBYTES;

    noxtls_mld_polyvecl_unpack_eta(s1, sk);
    sk += MLDSA_L * MLDSA_POLYETA_PACKEDBYTES;

    noxtls_mld_polyveck_unpack_eta(s2, sk);
    sk += MLDSA_K * MLDSA_POLYETA_PACKEDBYTES;

    noxtls_mld_polyveck_unpack_t0(t0, sk);
}

MLD_INTERNAL_API
void noxtls_mld_pack_sig_c_h(uint8_t sig[MLDSA_CRYPTO_BYTES],
                      const uint8_t c[MLDSA_CTILDEBYTES],
                      const noxtls_mld_polyveck *h,
                      unsigned int number_of_hints)
{
    unsigned int i;
    unsigned int j;
    unsigned int hint_cursor;
    uint8_t *packed_hints;

    if(number_of_hints > MLDSA_OMEGA) {
        number_of_hints = MLDSA_OMEGA;
    }

    noxtls_mld_memcpy(sig, c, MLDSA_CTILDEBYTES);

    packed_hints = sig + MLDSA_CTILDEBYTES + MLDSA_L * MLDSA_POLYZ_PACKEDBYTES;
    noxtls_mld_memset(packed_hints, 0, MLDSA_POLYVECH_PACKEDBYTES);

    hint_cursor = 0u;
    for(i = 0u; i < MLDSA_K; ++i) {
        for(j = 0u; j < MLDSA_N; ++j) {
            if(h->vec[i].coeffs[j] != 0 && hint_cursor < number_of_hints) {
                packed_hints[hint_cursor++] = (uint8_t)j;
            }
        }
        packed_hints[MLDSA_OMEGA + i] = (uint8_t)hint_cursor;
    }
}

MLD_INTERNAL_API
void noxtls_mld_pack_sig_z(uint8_t sig[MLDSA_CRYPTO_BYTES],
                    const noxtls_mld_poly *zi,
                    unsigned int index)
{
    uint8_t *z_slot;

    if(index >= MLDSA_L) {
        return;
    }

    z_slot = sig + MLDSA_CTILDEBYTES + index * MLDSA_POLYZ_PACKEDBYTES;
    noxtls_mld_polyz_pack(z_slot, zi);
}

MLD_INTERNAL_API
int noxtls_mld_unpack_sig(uint8_t c[MLDSA_CTILDEBYTES],
                   noxtls_mld_polyvecl *z,
                   noxtls_mld_polyveck *h,
                   const uint8_t sig[MLDSA_CRYPTO_BYTES])
{
    const uint8_t *z_src;
    const uint8_t *hints_src;

    noxtls_mld_memcpy(c, sig, MLDSA_CTILDEBYTES);

    z_src = sig + MLDSA_CTILDEBYTES;
    noxtls_mld_polyvecl_unpack_z(z, z_src);

    hints_src = z_src + MLDSA_L * MLDSA_POLYZ_PACKEDBYTES;
    return noxtls_mld_unpack_hints(h, hints_src);
}
