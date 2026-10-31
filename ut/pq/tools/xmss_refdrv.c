/*
 * xmss_refdrv.c - known-answer driver for the XMSS reference implementation.
 *
 * Offline tool used to produce the input of ut/pq/tools/gen_xmss_vectors.py
 * (not built by the NoxTLS build).  Link it against
 * https://github.com/XMSS/xmss-reference (commit
 * 171ccbd26f098542a67eb5d2b128281c80bd71a6): params.c hash.c fips202.c
 * hash_address.c utils.c wots.c xmss_commons.c xmss_core.c and OpenSSL
 * libcrypto, e.g.
 *   cc -O2 -I<ref> xmss_refdrv.c <ref>/params.c <ref>/hash.c <ref>/fips202.c \
 *      <ref>/hash_address.c <ref>/utils.c <ref>/wots.c <ref>/xmss_commons.c \
 *      <ref>/xmss_core.c -lcrypto
 * On LLP64 targets (Windows) remove the "(unsigned long)" cast in front of
 * bytes_to_ull() in xmss_core.c:xmssmt_core_sign(); it truncates indices
 * >= 2^32 (XMSS^MT h = 40 / 60).  That one-token change was applied when the
 * checked-in vectors were generated (clang 22, x86_64-w64-windows-gnu,
 * MSYS2 OpenSSL 1.1.1t).
 *
 * usage:  xmss_refdrv <name> <idx> <msglen> <seed_mul> <seed_add> <full_sig 0|1>
 * output: KAT <name> <idx> <msglen> OID=.. PK=.. SK=.. SIGLEN=.. SIGSHA256=.. [SIG=..]
 * Seeds: SK_SEED || SK_PRF || PUB_SEED, byte i = (i * mul + add) & 0xff (i < 3n).
 * Message: byte i = (i * 7 + 37) & 0xff.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/sha.h>

#include "params.h"
#include "xmss_core.h"
#include "utils.h"

void randombytes(unsigned char *x, unsigned long long xlen)
{
    (void)x; (void)xlen;
    abort();
}

static void hex(const unsigned char *b, unsigned long long n)
{
    unsigned long long i;
    for (i = 0; i < n; i++) printf("%02x", b[i]);
}

int main(int argc, char **argv)
{
    xmss_params params;
    uint32_t oid = 0;
    int mt = 0;
    if (argc < 7) return 2;
    const char *name = argv[1];
    unsigned long long idx = strtoull(argv[2], NULL, 0);
    unsigned long msglen = strtoul(argv[3], NULL, 0);
    unsigned int mul = (unsigned int)strtoul(argv[4], NULL, 0);
    unsigned int add = (unsigned int)strtoul(argv[5], NULL, 0);
    int full = atoi(argv[6]);

    if (strncmp(name, "XMSSMT-", 7) == 0) {
        mt = 1;
        if (xmssmt_str_to_oid(&oid, name) || xmssmt_parse_oid(&params, oid)) return 3;
    } else {
        if (xmss_str_to_oid(&oid, name) || xmss_parse_oid(&params, oid)) return 3;
    }
    unsigned char *seed = malloc(3 * params.n);
    unsigned char *pk = malloc(params.pk_bytes);
    unsigned char *sk = malloc(params.sk_bytes);
    unsigned char *msg = malloc(msglen + 1);
    unsigned char *sm = malloc(params.sig_bytes + msglen + 1);
    unsigned long long smlen = 0, i;
    unsigned char d[32];

    for (i = 0; i < 3 * params.n; i++) seed[i] = (unsigned char)((i * mul + add) & 0xff);
    for (i = 0; i < msglen; i++) msg[i] = (unsigned char)((i * 7 + 37) & 0xff);
    xmssmt_core_seed_keypair(&params, pk, sk, seed);
    printf("KAT %s %llu %lu OID=%08x PK=%08x", name, idx, msglen, oid, oid);
    hex(pk, params.pk_bytes);
    printf(" SK=%08x", oid);
    ull_to_bytes(sk, params.index_bytes, idx);
    hex(sk, params.sk_bytes);
    if (mt) xmssmt_core_sign(&params, sk, sm, &smlen, msg, msglen);
    else xmss_core_sign(&params, sk, sm, &smlen, msg, msglen);
    SHA256(sm, params.sig_bytes, d);
    printf(" SIGLEN=%u SIGSHA256=", params.sig_bytes);
    hex(d, 32);
    if (full) { printf(" SIG="); hex(sm, params.sig_bytes); }
    printf("\n");
    return 0;
}
