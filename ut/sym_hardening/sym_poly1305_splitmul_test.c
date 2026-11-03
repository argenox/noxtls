/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    sym_poly1305_splitmul_test.c
* Summary: Host check of the fixed-time Poly1305 limb multiply used on
*          Cortex-M3 (NOXTLS_POLY1305_SPLIT_MUL=1): the 16-bit split product
*          equals the native 64-bit product, and the MAC built on it matches
*          RFC 8439 section 2.5.2 and the AEAD vector of section 2.8.2.
*****************************************************************************/
#include <stdio.h>
#include <string.h>

#undef NOXTLS_POLY1305_SPLIT_MUL
#define NOXTLS_POLY1305_SPLIT_MUL 1
#include "../../noxtls-lib/encryption/chacha20/noxtls_chacha20_poly1305.c"

#include "crypto_sym_test_util.h"

#if NOXTLS_FEATURE_CHACHA20_POLY1305
int main(void)
{
    static const uint32_t edge[] = { 0U, 1U, 0xFFFFU, 0x10000U, 0x3FFFFFFU, 0x13FFFFFBU,
                                     0x7FFFFFFFU, 0x80000000U, 0xFFFFFFFFU };
    uint32_t i;
    uint32_t j;
    uint32_t x = 0x12345678U;
    uint8_t key[32];
    uint8_t tag[16];
    const char *msg = "Cryptographic Forum Research Group";

    cs_section("split multiply equals native multiply");
    for (i = 0U; i < (uint32_t)(sizeof(edge) / sizeof(edge[0])); i += 1U) {
        for (j = 0U; j < (uint32_t)(sizeof(edge) / sizeof(edge[0])); j += 1U) {
            CHECK(poly1305_mul(edge[i], edge[j]) == ((uint64_t)edge[i] * (uint64_t)edge[j]));
        }
    }
    for (i = 0U; i < 200000U; i += 1U) {
        uint32_t a;
        uint32_t b;
        x ^= x << 13; x ^= x >> 17; x ^= x << 5; a = x;
        x ^= x << 13; x ^= x >> 17; x ^= x << 5; b = x;
        if (!CHECK(poly1305_mul(a, b) == ((uint64_t)a * (uint64_t)b))) {
            break;
        }
    }

    cs_section("RFC 8439 2.5.2 with the split multiply");
    (void)cs_hex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b", key, sizeof(key));
    CHECK_RC(noxtls_poly1305_mac(key, (const uint8_t *)msg, (uint32_t)strlen(msg), tag), NOXTLS_RETURN_SUCCESS);
    EXPECT_HEX("tag", tag, 16U, "a8061dc1305136c6c22b8baf0c0127a9");

    cs_section("RFC 8439 2.8.2 AEAD with the split multiply");
    {
        static const char *pt =
            "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        uint8_t akey[32];
        uint8_t nonce[12];
        uint8_t aad[12];
        uint8_t ct[128];
        (void)cs_hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f", akey, sizeof(akey));
        (void)cs_hex("070000004041424344454647", nonce, sizeof(nonce));
        (void)cs_hex("50515253c0c1c2c3c4c5c6c7", aad, sizeof(aad));
        CHECK_RC(noxtls_chacha20_poly1305_encrypt(akey, nonce, aad, 12U, (const uint8_t *)pt,
                                                  (uint32_t)strlen(pt), ct, tag), NOXTLS_RETURN_SUCCESS);
        EXPECT_HEX("aead tag", tag, 16U, "1ae10b594f09e26a7e902ecbd0600691");
    }
    (void)printf("sym_poly1305_splitmul_test: %u checks, %u failures\n", (unsigned)g_cs_checks, (unsigned)g_cs_failures);
    return (g_cs_failures == 0U) ? 0 : 1;
}
#else
int main(void)
{
    (void)printf("sym_poly1305_splitmul_test: ChaCha20-Poly1305 not enabled, skipped\n");
    return 0;
}
#endif
