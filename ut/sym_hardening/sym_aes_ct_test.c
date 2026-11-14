/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    sym_aes_ct_test.c
* Summary: Known-answer and differential tests for the software AES core.
*
* Runs against whichever core the build selected (NOXTLS_AES_CONSTANT_TIME:
* table-free constant-time core, or T-tables), and against any compiled-in
* block backend (AES-NI, ARMv8 Apple):
*  - FIPS 197 Appendix C vectors, AES-128/192/256, encrypt and decrypt;
*  - NIST SP 800-38A F.1 ECB vectors (four blocks per key size);
*  - 3 x 1000 random keys and blocks against an independent textbook AES
*    whose S-box is derived here from GF(2^8) inversion and the affine map;
*  - the streaming context API (ECB/CBC) against the same reference;
*  - noxtls_aes_sub_bytes() over all 256 inputs.
*****************************************************************************/

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "noxtls_common.h"
#include "encryption/aes/noxtls_aes.h"
#include "encryption/aes/noxtls_aes_internal.h"

#include "crypto_sym_test_util.h"

#if NOXTLS_FEATURE_AES && NOXTLS_FEATURE_AES_ECB && NOXTLS_FEATURE_AES_128 && \
    NOXTLS_FEATURE_AES_192 && NOXTLS_FEATURE_AES_256

#include "sym_aes_ref.h"

/* ---- tests ---- */

static const noxtls_aes_type_t k_types[3] = { NOXTLS_AES_128_BIT, NOXTLS_AES_192_BIT, NOXTLS_AES_256_BIT };
static const uint32_t k_nk[3] = { 4U, 6U, 8U };

static void test_reference_self_check(void)
{
    /* FIPS 197 C.1 through the reference itself, so a broken reference cannot
     * make the differential checks below pass vacuously. */
    uint8_t key[16];
    uint8_t pt[16];
    uint8_t ct[16];
    cs_section("reference AES self-check");
    (void)cs_hex("000102030405060708090a0b0c0d0e0f", key, sizeof(key));
    (void)cs_hex("00112233445566778899aabbccddeeff", pt, sizeof(pt));
    ref_encrypt(key, 4U, pt, ct);
    EXPECT_HEX("ref enc", ct, 16U, "69c4e0d86a7b0430d8cdb78070b4c55a");
    ref_decrypt(key, 4U, ct, ct);
    EXPECT_MEM("ref dec", ct, pt, 16U);
    CHECK(g_sbox[0x00] == 0x63U);
    CHECK(g_sbox[0x53] == 0xEDU);
    CHECK(g_inv_sbox[0x63] == 0x00U);
}

static void test_fips197(void)
{
    static const char *const keys[3] = {
        "000102030405060708090a0b0c0d0e0f",
        "000102030405060708090a0b0c0d0e0f1011121314151617",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    };
    static const char *const cts[3] = {
        "69c4e0d86a7b0430d8cdb78070b4c55a",
        "dda97ca4864cdfe06eaf70a0ec0d7191",
        "8ea2b7ca516745bfeafc49904b496089",
    };
    uint32_t k;
    for (k = 0U; k < 3U; k += 1U) {
        uint8_t key[32];
        uint8_t pt[16];
        uint8_t out[16];
        uint32_t klen = cs_hex(keys[k], key, sizeof(key));
        cs_section("FIPS 197 appendix C");
        (void)cs_hex("00112233445566778899aabbccddeeff", pt, sizeof(pt));
        CHECK(klen == 4U * k_nk[k]);
        CHECK_RC(noxtls_aes_encrypt_ecb(key, pt, 16U, NULL, out, k_types[k]), NOXTLS_RETURN_SUCCESS);
        EXPECT_HEX("encrypt", out, 16U, cts[k]);
        CHECK_RC(noxtls_aes_decrypt_ecb(key, out, 16U, NULL, out, k_types[k]), NOXTLS_RETURN_SUCCESS);
        EXPECT_MEM("decrypt", out, pt, 16U);
    }
}

static void test_sp800_38a_ecb(void)
{
    static const char *const keys[3] = {
        "2b7e151628aed2a6abf7158809cf4f3c",
        "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
    };
    static const char *const pt_hex =
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52ef"
        "f69f2445df4f9b17ad2b417be66c3710";
    static const char *const cts[3] = {
        "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf"
        "43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4",
        "bd334f1d6e45f25ff712a214571fa5cc974104846d0ad3ad7734ecb3ecee4eef"
        "ef7afd2270e2e60adce0ba2face6444e9a4b41ba738d6c72fb16691603c18e0e",
        "f3eed1bdb5d2a03c064b5a7e3db181f8591ccb10d410ed26dc5ba74a31362870"
        "b6ed21b99ca6f4f9f153e7b1beafed1d23304b7a39f9f3ff067d8d8f9e24ecc7",
    };
    uint32_t k;
    for (k = 0U; k < 3U; k += 1U) {
        uint8_t key[32];
        uint8_t pt[64];
        uint8_t out[64];
        cs_section("SP 800-38A F.1 ECB");
        (void)cs_hex(keys[k], key, sizeof(key));
        (void)cs_hex(pt_hex, pt, sizeof(pt));
        CHECK_RC(noxtls_aes_encrypt_ecb(key, pt, 64U, NULL, out, k_types[k]), NOXTLS_RETURN_SUCCESS);
        EXPECT_HEX("encrypt", out, 64U, cts[k]);
        CHECK_RC(noxtls_aes_decrypt_ecb(key, out, 64U, NULL, out, k_types[k]), NOXTLS_RETURN_SUCCESS);
        EXPECT_MEM("decrypt", out, pt, 64U);
    }
}

static void test_random_differential(void)
{
    uint32_t k;
    uint32_t n;
    cs_section("random keys vs reference AES");
    for (k = 0U; k < 3U; k += 1U) {
        for (n = 0U; n < 1000U; n += 1U) {
            uint8_t key[32];
            uint8_t pt[16];
            uint8_t exp[16];
            uint8_t out[16];
            uint8_t back[16];
            cs_fill(key, sizeof(key), 0x1000U + (k * 7919U) + n);
            cs_fill(pt, sizeof(pt), 0x51000U + (k * 104729U) + n);
            ref_encrypt(key, k_nk[k], pt, exp);
            CHECK_RC(noxtls_aes_encrypt_ecb(key, pt, 16U, NULL, out, k_types[k]), NOXTLS_RETURN_SUCCESS);
            if (!EXPECT_MEM("encrypt", out, exp, 16U)) {
                return;
            }
            ref_decrypt(key, k_nk[k], pt, exp);
            CHECK_RC(noxtls_aes_decrypt_ecb(key, pt, 16U, NULL, back, k_types[k]), NOXTLS_RETURN_SUCCESS);
            if (!EXPECT_MEM("decrypt", back, exp, 16U)) {
                return;
            }
        }
    }
}

#if NOXTLS_FEATURE_AES_CBC
static void test_streaming_cbc(void)
{
    uint32_t k;
    cs_section("streaming CBC vs reference AES");
    for (k = 0U; k < 3U; k += 1U) {
        noxtls_aes_context_t ctx;
        uint8_t key[32];
        uint8_t iv[16];
        uint8_t pt[80];
        uint8_t exp[80];
        uint8_t out[96];
        uint8_t back[96];
        uint8_t chain[16];
        uint32_t olen = 0U;
        uint32_t flen = 0U;
        uint32_t b;
        uint32_t i;
        cs_fill(key, sizeof(key), 0xC0DEU + k);
        cs_fill(iv, sizeof(iv), 0xBEEFU + k);
        cs_fill(pt, sizeof(pt), 0xF00DU + k);
        memcpy(chain, iv, 16U);
        for (b = 0U; b < 5U; b += 1U) {
            uint8_t blk[16];
            for (i = 0U; i < 16U; i += 1U) {
                blk[i] = (uint8_t)(pt[16U * b + i] ^ chain[i]);
            }
            ref_encrypt(key, k_nk[k], blk, &exp[16U * b]);
            memcpy(chain, &exp[16U * b], 16U);
        }
        CHECK_RC(noxtls_aes_init(&ctx, key, iv, k_types[k], NOXTLS_AES_CBC, NOXTLS_AES_OP_ENCRYPT), NOXTLS_RETURN_SUCCESS);
        CHECK_RC(noxtls_aes_update(&ctx, pt, 37U, out, &olen), NOXTLS_RETURN_SUCCESS);
        CHECK(olen == 32U);
        CHECK_RC(noxtls_aes_update(&ctx, &pt[37], 43U, &out[32], &olen), NOXTLS_RETURN_SUCCESS);
        CHECK(olen == 48U);
        CHECK_RC(noxtls_aes_final(&ctx, &out[80], &flen), NOXTLS_RETURN_SUCCESS);
        CHECK(flen == 0U);
        EXPECT_MEM("cbc encrypt", out, exp, 80U);

        CHECK_RC(noxtls_aes_init(&ctx, key, iv, k_types[k], NOXTLS_AES_CBC, NOXTLS_AES_OP_DECRYPT), NOXTLS_RETURN_SUCCESS);
        CHECK_RC(noxtls_aes_update(&ctx, exp, 80U, back, &olen), NOXTLS_RETURN_SUCCESS);
        CHECK(olen == 80U);
        CHECK_RC(noxtls_aes_final(&ctx, &back[80], &flen), NOXTLS_RETURN_SUCCESS);
        EXPECT_MEM("cbc decrypt", back, pt, 80U);
    }
}
#endif

static void test_sub_bytes(void)
{
    uint32_t base;
    cs_section("noxtls_aes_sub_bytes all inputs");
    for (base = 0U; base < 256U; base += 16U) {
        uint8_t st[4][4];
        uint32_t i;
        for (i = 0U; i < 16U; i += 1U) {
            st[i / 4U][i % 4U] = (uint8_t)(base + i);
        }
        noxtls_aes_sub_bytes(st);
        for (i = 0U; i < 16U; i += 1U) {
            if (!CHECK(st[i / 4U][i % 4U] == g_sbox[base + i])) {
                (void)fprintf(stderr, "    input %02x\n", (unsigned)(base + i));
            }
        }
    }
}

int main(void)
{
    ref_build_sbox();
    (void)printf("sym_aes_ct_test: software core = %s\n",
#if defined(NOXTLS_AES_CONSTANT_TIME) && NOXTLS_AES_CONSTANT_TIME
                 "constant-time (table-free)"
#else
                 "T-table (or not reported by config)"
#endif
                 );
    (void)printf("sym_aes_ct_test: block backend = %u (0 software, 1 AES-NI, 2 ARMv8 Apple, 3 port)\n",
                 (unsigned)noxtls_aes_get_accel_backend());
    test_reference_self_check();
    test_fips197();
    test_sp800_38a_ecb();
    test_random_differential();
#if NOXTLS_FEATURE_AES_CBC
    test_streaming_cbc();
#endif
    test_sub_bytes();
    (void)printf("sym_aes_ct_test: %u checks, %u failures\n", (unsigned)g_cs_checks, (unsigned)g_cs_failures);
    return (g_cs_failures == 0U) ? 0 : 1;
}

#else
int main(void)
{
    (void)printf("sym_aes_ct_test: AES-128/192/256 ECB not enabled, skipped\n");
    return 0;
}
#endif
