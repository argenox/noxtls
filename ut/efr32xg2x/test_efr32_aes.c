/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
* This file is part of the NoxTLS Library.
*
* Licensed under the GNU General Public License v2.0 or later,
* or alternatively under a commercial license from
* Argenox Technologies LLC.
*
* See the LICENSE file in the project root for full details.
* CONTACT: info@argenox.com
*
*
* File:    test_efr32_aes.c
* Summary: Tests of the RADIOAES driver: ECB, CBC, CTR and CCM
*
*****************************************************************************/

/**
 * @file test_efr32_aes.c
 * @brief ECB / CBC / CTR / CCM through the RADIOAES descriptor model: published vectors,
 *        lengths from 0 to the largest request, chunking, bounce buffers, masking,
 *        capability gating, hardware faults and the busy / disabled fallbacks.
 * @ingroup noxtls_efr32_ut
 *
 * Vectors: FIPS 197 Appendix C.1 / C.3, NIST SP 800-38A F.2.1 / F.5.1 and NIST
 * SP 800-38C Appendix C Examples 1-3. Larger requests are compared with the NoxTLS
 * software implementation (ut_sw_begin() forces the software path).
 */

#include <stdint.h>
#include <string.h>

#include "runner.h"
#include "test_assert.h"

#include "ut_efr32_mock.h"
#include "noxtls_aes.h"
#include "noxtls_aes_ccm.h"

/** @brief Largest AES request of the test build. */
#define UT_MAX_REQ      70000U

/** FIPS 197 C.1 / C.3 key (first 32 bytes of 00 01 02 ...). */
static const char * const s_c_key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
/** FIPS 197 C plaintext. */
static const char * const s_c_pt = "00112233445566778899aabbccddeeff";
/** SP 800-38A key. */
static const char * const s_a_key = "2b7e151628aed2a6abf7158809cf4f3c";
/** SP 800-38A plaintext blocks 1 and 2. */
static const char * const s_a_pt = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51";

/**
 * @brief Software reference of a plain cipher (the engines look owned, so NoxTLS computes it).
 * @internal
 *
 * @param[in]  mode    0 ECB, 1 CBC, 2 CTR.
 * @param[in]  decrypt Direction.
 * @param[in]  key     Key.
 * @param[in]  klen    Key bytes.
 * @param[in]  iv      IV.
 * @param[in]  in      Input.
 * @param[out] out     Output.
 * @param[in]  len     Bytes.
 */
static void ut_ref(uint32_t mode, uint8_t decrypt, const uint8_t *key, uint32_t klen, const uint8_t *iv, const uint8_t *in,
                   uint8_t *out, uint32_t len)
{
    noxtls_aes_type_t t = (klen == 16U) ? NOXTLS_AES_128_BIT : ((klen == 24U) ? NOXTLS_AES_192_BIT : NOXTLS_AES_256_BIT);

    ut_sw_begin();
    if (mode == 0U) {
        (void)((decrypt != 0U) ? noxtls_aes_decrypt_ecb(key, in, len, NULL, out, t) : noxtls_aes_encrypt_ecb(key, in, len, NULL, out, t));
    } else if (mode == 1U) {
        (void)((decrypt != 0U) ? noxtls_aes_decrypt_cbc(key, in, len, iv, out, t) : noxtls_aes_encrypt_cbc(key, in, len, iv, out, t));
    } else {
        (void)noxtls_aes_encrypt_ctr(key, in, len, iv, out, t);
    }
    ut_sw_end();
}

/**
 * @brief Fill a buffer with a deterministic pattern.
 * @internal
 *
 * @param[out] p    Buffer.
 * @param[in]  n    Bytes.
 * @param[in]  seed Seed.
 */
static void ut_fill(uint8_t *p, uint32_t n, uint32_t seed)
{
    uint32_t i;

    for (i = 0U; i < n; i++) {
        p[i] = (uint8_t)((i * 7U) + seed + (i >> 5));
    }
}

REGISTER_TEST(test_aes_ecb_fips197)
{
    uint8_t key[32];
    uint8_t pt[16];
    uint8_t ct128[16];
    uint8_t ct256[16];

    ut_setup();
    (void)ut_hex(s_c_key, g_ut_ram.aux);
    (void)ut_hex(s_c_pt, pt);
    (void)ut_hex("69c4e0d86a7b0430d8cdb78070b4c55a", ct128);
    (void)ut_hex("8ea2b7ca516745bfeafc49904b496089", ct256);
    (void)memcpy(key, g_ut_ram.aux, sizeof(key));
    (void)memcpy(g_ut_ram.in, pt, 16U);
    UTNOX_EQUALS(noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_ECB, 0U, g_ut_ram.aux, 16U, NULL, g_ut_ram.in, g_ut_ram.out, 16U),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(g_ut_ram.out, ct128, 16U);
    UTNOX_EQUALS(noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_ECB, 1U, g_ut_ram.aux, 16U, NULL, g_ut_ram.out, g_ut_ram.in, 16U),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(g_ut_ram.in, pt, 16U);
    UTNOX_EQUALS(noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_ECB, 0U, g_ut_ram.aux, 32U, NULL, g_ut_ram.in, g_ut_ram.out, 16U),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(g_ut_ram.out, ct256, 16U);
    UTNOX_EQUALS(noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_ECB, 1U, g_ut_ram.aux, 32U, NULL, g_ut_ram.out, g_ut_ram.in, 16U),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(g_ut_ram.in, pt, 16U);
    UTNOX_EQUALS(g_ut.aes_jobs, 4U);
    UTNOX_IS_TRUE(ut_clean() != 0U);
    /* The key is not left behind in the staging buffers or the caller's key buffer is untouched. */
    UTNOX_MEM_EQUAL(g_ut_ram.aux, key, 32U);
    UTNOX_EQUALS(noxtls_efr32_stats()->aes_acquires, 4U);
    return 0;
}

REGISTER_TEST(test_aes_ecb_lengths_match_software)
{
    static const uint32_t lens[] = { 16U, 32U, 48U, 256U, 272U, 1024U, 16640U, UT_MAX_REQ };
    uint32_t i;

    ut_setup();
    (void)ut_hex(s_c_key, g_ut_ram.aux);
    for (i = 0U; i < (sizeof(lens) / sizeof(lens[0])); i++) {
        uint32_t k;

        for (k = 0U; k < 2U; k++) {
            uint32_t klen = (k == 0U) ? 16U : 32U;

            ut_fill(g_ut_ram.in, lens[i], i);
            UTNOX_EQUALS(noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_ECB, 0U, g_ut_ram.aux, klen, NULL, g_ut_ram.in, g_ut_ram.out, lens[i]),
                         NOXTLS_RETURN_SUCCESS);
            ut_ref(0U, 0U, g_ut_ram.aux, klen, NULL, g_ut_ram.in, g_ut_ram.aux2, lens[i]);
            UTNOX_MEM_EQUAL(g_ut_ram.out, g_ut_ram.aux2, lens[i]);
        }
    }
    UTNOX_IS_TRUE(ut_clean() != 0U);
    return 0;
}

REGISTER_TEST(test_aes_length_bounds)
{
    ut_setup();
    (void)ut_hex(s_c_key, g_ut_ram.aux);
    /* Zero length: success without touching the engine. */
    UTNOX_EQUALS(noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_ECB, 0U, g_ut_ram.aux, 16U, NULL, g_ut_ram.in, g_ut_ram.out, 0U), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_ECB, 0U, g_ut_ram.aux, 16U, NULL, NULL, NULL, 0U), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(g_ut.aes_jobs, 0U);
    UTNOX_EQUALS(noxtls_efr32_stats()->aes_acquires, 0U);
    /* Not a multiple of the block size. */
    UTNOX_EQUALS(noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_ECB, 0U, g_ut_ram.aux, 16U, NULL, g_ut_ram.in, g_ut_ram.out, 15U),
                 NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_EQUALS(noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_ECB, 0U, g_ut_ram.aux, 16U, NULL, g_ut_ram.in, g_ut_ram.out, 17U),
                 NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_EQUALS(noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_CBC, 0U, g_ut_ram.aux, 16U, g_ut_ram.aux2, g_ut_ram.in, g_ut_ram.out, 1U),
                 NOXTLS_RETURN_INVALID_PARAM);
    /* One block over the largest request goes to software. */
    UTNOX_EQUALS(noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_ECB, 0U, g_ut_ram.aux, 16U, NULL, g_ut_ram.in, g_ut_ram.out, UT_MAX_REQ + 16U),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_CTR, 0U, g_ut_ram.aux, 16U, g_ut_ram.aux2, g_ut_ram.in, g_ut_ram.out, UT_MAX_REQ + 1U),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(g_ut.aes_jobs, 0U);
    return 0;
}

REGISTER_TEST(test_aes_argument_errors)
{
    uint8_t * const iv = g_ut_ram.aux2;

    ut_setup();
    (void)ut_hex(s_c_key, g_ut_ram.aux);
    UTNOX_EQUALS(noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_ECB, 0U, NULL, 16U, NULL, g_ut_ram.in, g_ut_ram.out, 16U), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_ECB, 0U, g_ut_ram.aux, 16U, NULL, NULL, g_ut_ram.out, 16U), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_ECB, 0U, g_ut_ram.aux, 16U, NULL, g_ut_ram.in, NULL, 16U), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_CBC, 0U, g_ut_ram.aux, 16U, NULL, g_ut_ram.in, g_ut_ram.out, 16U), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_CTR, 0U, g_ut_ram.aux, 16U, NULL, g_ut_ram.in, g_ut_ram.out, 16U), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_efr32_aes_crypt((noxtls_efr32_aes_mode_t)7, 0U, g_ut_ram.aux, 16U, iv, g_ut_ram.in, g_ut_ram.out, 16U),
                 NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_EQUALS(noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_ECB, 0U, g_ut_ram.aux, 0U, NULL, g_ut_ram.in, g_ut_ram.out, 16U), NOXTLS_RETURN_INVALID_KEY_SIZE);
    UTNOX_EQUALS(noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_ECB, 0U, g_ut_ram.aux, 15U, NULL, g_ut_ram.in, g_ut_ram.out, 16U), NOXTLS_RETURN_INVALID_KEY_SIZE);
    UTNOX_EQUALS(noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_ECB, 0U, g_ut_ram.aux, 33U, NULL, g_ut_ram.in, g_ut_ram.out, 16U), NOXTLS_RETURN_INVALID_KEY_SIZE);
    UTNOX_EQUALS(g_ut.aes_jobs, 0U);
    return 0;
}

REGISTER_TEST(test_aes_capability_gating)
{
    ut_setup();
    (void)ut_hex(s_c_key, g_ut_ram.aux);
    /* The EFR32MG26 engine has no 192-bit keys (g_Keysize = 5). */
    UTNOX_EQUALS(noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_ECB, 0U, g_ut_ram.aux, 24U, NULL, g_ut_ram.in, g_ut_ram.out, 16U), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_efr32_aes_caps()->valid, 1U);
    UTNOX_EQUALS(noxtls_efr32_aes_caps()->modes, 0x127U);
    UTNOX_EQUALS(noxtls_efr32_aes_caps()->keys, 5U);
    UTNOX_EQUALS(noxtls_efr32_aes_caps()->ctr_bits, 128U);
    UTNOX_EQUALS(noxtls_efr32_aes_caps()->masking, 0U);
    UTNOX_EQUALS(noxtls_efr32_aes_caps()->inclips, 1U);
    UTNOX_EQUALS(g_ut.aes_jobs, 0U);
    /* A part with 192-bit keys: the configuration word selects them. */
    ut_set_caps(NOXTLS_EFR32_INCL_AES, 0x07010127U, 0x80U);
    UTNOX_EQUALS(noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_ECB, 0U, g_ut_ram.aux, 24U, NULL, g_ut_ram.in, g_ut_ram.out, 16U), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(g_ut.aes_last_cfg & 0xCU, NOXTLS_EFR32_AES_CFG_KEY_192);
    /* No BA411E at all. */
    ut_set_caps(0U, 0x05010127U, 0x80U);
    UTNOX_EQUALS(noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_ECB, 0U, g_ut_ram.aux, 16U, NULL, g_ut_ram.in, g_ut_ram.out, 16U), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_efr32_aes_caps()->modes, 0U);
    /* A mode the engine lacks (no CBC). */
    ut_set_caps(NOXTLS_EFR32_INCL_AES, 0x05010125U, 0x80U);
    UTNOX_EQUALS(noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_CBC, 0U, g_ut_ram.aux, 16U, g_ut_ram.aux2, g_ut_ram.in, g_ut_ram.out, 16U),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_ECB, 0U, g_ut_ram.aux, 16U, NULL, g_ut_ram.in, g_ut_ram.out, 16U), NOXTLS_RETURN_SUCCESS);
    /* Modes can be switched off at run time (failed self-test). */
    ut_set_caps(NOXTLS_EFR32_INCL_AES, 0x05010127U, 0x80U);
    noxtls_efr32_aes_set_modes_disabled(UINT32_C(1) << NOXTLS_EFR32_AES_MODE_ECB);
    UTNOX_EQUALS(noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_ECB, 0U, g_ut_ram.aux, 16U, NULL, g_ut_ram.in, g_ut_ram.out, 16U), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_CTR, 0U, g_ut_ram.aux, 16U, g_ut_ram.aux2, g_ut_ram.in, g_ut_ram.out, 16U), NOXTLS_RETURN_SUCCESS);
    noxtls_efr32_aes_set_modes_disabled(0U);
    UTNOX_EQUALS(noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_ECB, 0U, g_ut_ram.aux, 16U, NULL, g_ut_ram.in, g_ut_ram.out, 16U), NOXTLS_RETURN_SUCCESS);
    UTNOX_IS_TRUE(ut_clean() != 0U);
    return 0;
}

REGISTER_TEST(test_aes_cbc_sp800_38a_and_chaining)
{
    uint8_t pt[32];
    uint8_t ct[32];
    uint8_t iv[16];
    uint8_t iv_next[16];

    ut_setup();
    (void)ut_hex(s_a_key, g_ut_ram.aux);
    (void)ut_hex(s_a_pt, pt);
    (void)ut_hex("7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2", ct);
    (void)ut_hex("000102030405060708090a0b0c0d0e0f", iv);
    (void)memcpy(g_ut_ram.in, pt, 32U);
    (void)memcpy(g_ut_ram.aux2, iv, 16U);
    UTNOX_EQUALS(noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_CBC, 0U, g_ut_ram.aux, 16U, g_ut_ram.aux2, g_ut_ram.in, g_ut_ram.out, 32U),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(g_ut_ram.out, ct, 32U);
    /* The IV becomes the last ciphertext block (chaining across calls). */
    (void)memcpy(iv_next, &ct[16], 16U);
    UTNOX_MEM_EQUAL(g_ut_ram.aux2, iv_next, 16U);
    (void)memcpy(g_ut_ram.aux2, iv, 16U);
    UTNOX_EQUALS(noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_CBC, 1U, g_ut_ram.aux, 16U, g_ut_ram.aux2, g_ut_ram.out, g_ut_ram.in, 32U),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(g_ut_ram.in, pt, 32U);
    /* Decrypt chaining value: the last ciphertext block. */
    UTNOX_MEM_EQUAL(g_ut_ram.aux2, iv_next, 16U);
    /* In place, both directions. */
    (void)memcpy(g_ut_ram.in, pt, 32U);
    (void)memcpy(g_ut_ram.aux2, iv, 16U);
    UTNOX_EQUALS(noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_CBC, 0U, g_ut_ram.aux, 16U, g_ut_ram.aux2, g_ut_ram.in, g_ut_ram.in, 32U),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(g_ut_ram.in, ct, 32U);
    (void)memcpy(g_ut_ram.aux2, iv, 16U);
    UTNOX_EQUALS(noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_CBC, 1U, g_ut_ram.aux, 16U, g_ut_ram.aux2, g_ut_ram.in, g_ut_ram.in, 32U),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(g_ut_ram.in, pt, 32U);
    UTNOX_IS_TRUE(ut_clean() != 0U);
    return 0;
}

REGISTER_TEST(test_aes_chunked_chaining_matches_software)
{
    static const uint32_t lens[] = { 256U, 272U, 1024U, 1040U };
    uint32_t i;
    uint32_t mode;

    ut_setup();
    (void)ut_hex(s_c_key, g_ut_ram.aux);
    for (i = 0U; i < (sizeof(lens) / sizeof(lens[0])); i++) {
        for (mode = 1U; mode < 3U; mode++) {
            uint8_t d;

            for (d = 0U; d < 2U; d++) {
                ut_fill(g_ut_ram.in, lens[i], (i * 3U) + mode);
                ut_fill(g_ut_ram.aux2, 16U, 0xF0U);
                (void)memcpy(&g_ut_ram.aux2[64], g_ut_ram.aux2, 16U);
                UTNOX_EQUALS(noxtls_efr32_aes_crypt((noxtls_efr32_aes_mode_t)mode, d, g_ut_ram.aux, 32U, g_ut_ram.aux2, g_ut_ram.in,
                                                    g_ut_ram.out, lens[i]), NOXTLS_RETURN_SUCCESS);
                ut_ref(mode, d, g_ut_ram.aux, 32U, &g_ut_ram.aux2[64], g_ut_ram.in, &g_ut_ram.aux2[2048], lens[i]);
                UTNOX_MEM_EQUAL(g_ut_ram.out, &g_ut_ram.aux2[2048], lens[i]);
            }
        }
    }
    UTNOX_IS_TRUE(ut_clean() != 0U);
    return 0;
}

REGISTER_TEST(test_aes_ctr_lengths_and_counter)
{
    static const uint32_t lens[] = { 1U, 15U, 16U, 17U, 31U, 33U, 300U, 4097U };
    uint32_t i;

    ut_setup();
    (void)ut_hex(s_a_key, g_ut_ram.aux);
    for (i = 0U; i < (sizeof(lens) / sizeof(lens[0])); i++) {
        uint8_t iv0[16];
        uint32_t blocks = (lens[i] + 15U) / 16U;
        uint8_t expect[16];
        uint32_t j;
        uint32_t carry;

        (void)ut_hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", iv0);
        (void)memcpy(g_ut_ram.aux2, iv0, 16U);
        ut_fill(g_ut_ram.in, lens[i], i);
        UTNOX_EQUALS(noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_CTR, 0U, g_ut_ram.aux, 16U, g_ut_ram.aux2, g_ut_ram.in, g_ut_ram.out, lens[i]),
                     NOXTLS_RETURN_SUCCESS);
        ut_ref(2U, 0U, g_ut_ram.aux, 16U, iv0, g_ut_ram.in, &g_ut_ram.aux2[256], lens[i]);
        UTNOX_MEM_EQUAL(g_ut_ram.out, &g_ut_ram.aux2[256], lens[i]);
        /* The counter advanced by the number of blocks, carrying through the low bytes. */
        (void)memcpy(expect, iv0, 16U);
        carry = blocks;
        for (j = 16U; (j > 0U) && (carry != 0U); j--) {
            uint32_t sum = (uint32_t)expect[j - 1U] + (carry & 0xFFU);

            expect[j - 1U] = (uint8_t)sum;
            carry = (carry >> 8) + (sum >> 8);
        }
        UTNOX_MEM_EQUAL(g_ut_ram.aux2, expect, 16U);
    }
    /* Decrypt flag is ignored by CTR; in place works. */
    (void)ut_hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", g_ut_ram.aux2);
    ut_fill(g_ut_ram.in, 40U, 9U);
    (void)memcpy(g_ut_ram.out, g_ut_ram.in, 40U);
    UTNOX_EQUALS(noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_CTR, 1U, g_ut_ram.aux, 16U, g_ut_ram.aux2, g_ut_ram.out, g_ut_ram.out, 40U),
                 NOXTLS_RETURN_SUCCESS);
    (void)ut_hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", g_ut_ram.aux2);
    UTNOX_EQUALS(noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_CTR, 0U, g_ut_ram.aux, 16U, g_ut_ram.aux2, g_ut_ram.out, g_ut_ram.out, 40U),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(g_ut_ram.out, g_ut_ram.in, 40U);
    UTNOX_IS_TRUE(ut_clean() != 0U);
    return 0;
}

REGISTER_TEST(test_aes_ctr_counter_wraps_128_bits)
{
    uint8_t expect[16];

    ut_setup();
    (void)ut_hex(s_a_key, g_ut_ram.aux);
    (void)memset(g_ut_ram.aux2, 0xFF, 16U);
    ut_fill(g_ut_ram.in, 48U, 1U);
    UTNOX_EQUALS(noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_CTR, 0U, g_ut_ram.aux, 16U, g_ut_ram.aux2, g_ut_ram.in, g_ut_ram.out, 48U),
                 NOXTLS_RETURN_SUCCESS);
    (void)memset(expect, 0, sizeof(expect));
    expect[15] = 2U;
    UTNOX_MEM_EQUAL(g_ut_ram.aux2, expect, 16U);
    UTNOX_IS_TRUE(ut_clean() != 0U);
    return 0;
}

REGISTER_TEST(test_aes_ctr_with_short_engine_counter_uses_ecb_keystream)
{
    static const uint32_t lens[] = { 1U, 16U, 17U, 300U };
    uint32_t i;

    ut_setup();
    ut_set_caps(NOXTLS_EFR32_INCL_AES, 0x05010127U, 16U);
    (void)ut_hex(s_a_key, g_ut_ram.aux);
    for (i = 0U; i < (sizeof(lens) / sizeof(lens[0])); i++) {
        uint8_t iv0[16];

        (void)memset(iv0, 0xFF, 16U);
        (void)memcpy(g_ut_ram.aux2, iv0, 16U);
        ut_fill(g_ut_ram.in, lens[i], i);
        g_ut.aes_jobs = 0U;
        UTNOX_EQUALS(noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_CTR, 0U, g_ut_ram.aux, 16U, g_ut_ram.aux2, g_ut_ram.in, g_ut_ram.out, lens[i]),
                     NOXTLS_RETURN_SUCCESS);
        ut_ref(2U, 0U, g_ut_ram.aux, 16U, iv0, g_ut_ram.in, &g_ut_ram.aux2[256], lens[i]);
        UTNOX_MEM_EQUAL(g_ut_ram.out, &g_ut_ram.aux2[256], lens[i]);
        /* ECB jobs only (mode bit ECB, no context load). */
        UTNOX_EQUALS((g_ut.aes_last_cfg >> NOXTLS_EFR32_AES_CFG_MODE_POS) & 0x1FFU, 1U);
        UTNOX_EQUALS(g_ut.aes_last_cfg & NOXTLS_EFR32_AES_CFG_CX_LOAD, 0U);
    }
    UTNOX_IS_TRUE(ut_clean() != 0U);
    return 0;
}

REGISTER_TEST(test_aes_cbc_composed_from_ecb)
{
    static const uint32_t lens[] = { 16U, 48U, 128U, 384U, 600U };
    uint32_t i;

    ut_setup();
    noxtls_efr32_aes_set_cbc_native(0U);
    (void)ut_hex(s_c_key, g_ut_ram.aux);
    for (i = 0U; i < (sizeof(lens) / sizeof(lens[0])); i++) {
        uint8_t d;

        for (d = 0U; d < 2U; d++) {
            uint32_t n = lens[i] & ~15U;

            ut_fill(g_ut_ram.in, n, i);
            ut_fill(g_ut_ram.aux2, 16U, 3U);
            (void)memcpy(&g_ut_ram.aux2[512], g_ut_ram.aux2, 16U);
            UTNOX_EQUALS(noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_CBC, d, g_ut_ram.aux, 16U, g_ut_ram.aux2, g_ut_ram.in, g_ut_ram.out, n),
                         NOXTLS_RETURN_SUCCESS);
            ut_ref(1U, d, g_ut_ram.aux, 16U, &g_ut_ram.aux2[512], g_ut_ram.in, &g_ut_ram.aux2[1024], n);
            UTNOX_MEM_EQUAL(g_ut_ram.out, &g_ut_ram.aux2[1024], n);
            UTNOX_EQUALS((g_ut.aes_last_cfg >> NOXTLS_EFR32_AES_CFG_MODE_POS) & 0x1FFU, 1U);
        }
    }
    noxtls_efr32_aes_set_cbc_native(1U);
    UTNOX_IS_TRUE(ut_clean() != 0U);
    return 0;
}

REGISTER_TEST(test_aes_unreachable_buffers_are_bounced)
{
    uint8_t in[300];
    uint8_t out[300];
    uint8_t ref[300];
    uint8_t iv[16];
    uint32_t mode;

    ut_setup();
    (void)ut_hex(s_c_key, g_ut_ram.aux);
    /* Stack buffers lie outside the window of the host tests: input and output are bounced in 128-byte jobs. */
    for (mode = 0U; mode < 3U; mode++) {
        uint8_t d;

        for (d = 0U; d < 2U; d++) {
            uint32_t n = (mode == 2U) ? 299U : 288U;

            ut_fill(in, n, mode);
            (void)memset(iv, 0x5A, sizeof(iv));
            (void)memcpy(&g_ut_ram.aux2[64], iv, sizeof(iv));
            ut_ref(mode, d, g_ut_ram.aux, 16U, &g_ut_ram.aux2[64], in, ref, n);
            g_ut.aes_jobs = 0U;
            UTNOX_EQUALS(noxtls_efr32_aes_crypt((noxtls_efr32_aes_mode_t)mode, d, g_ut_ram.aux, 16U, (mode == 0U) ? NULL : iv, in, out, n),
                         NOXTLS_RETURN_SUCCESS);
            UTNOX_MEM_EQUAL(out, ref, n);
            UTNOX_IS_TRUE(g_ut.aes_jobs >= 3U);
        }
    }
    /* Only the input unreachable, only the output unreachable. */
    ut_fill(in, 128U, 1U);
    UTNOX_EQUALS(noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_ECB, 0U, g_ut_ram.aux, 16U, NULL, in, g_ut_ram.out, 128U), NOXTLS_RETURN_SUCCESS);
    ut_ref(0U, 0U, g_ut_ram.aux, 16U, NULL, in, ref, 128U);
    UTNOX_MEM_EQUAL(g_ut_ram.out, ref, 128U);
    ut_fill(g_ut_ram.in, 128U, 2U);
    UTNOX_EQUALS(noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_ECB, 0U, g_ut_ram.aux, 16U, NULL, g_ut_ram.in, out, 128U), NOXTLS_RETURN_SUCCESS);
    ut_ref(0U, 0U, g_ut_ram.aux, 16U, NULL, g_ut_ram.in, ref, 128U);
    UTNOX_MEM_EQUAL(out, ref, 128U);
    UTNOX_IS_TRUE(ut_clean() != 0U);
    return 0;
}

REGISTER_TEST(test_aes_misaligned_buffers_are_bounced_when_alignment_required)
{
    uint8_t ref[96];

    ut_setup();
    (void)ut_hex(s_c_key, g_ut_ram.aux);
    noxtls_efr32_set_dma_window((uintptr_t)&g_ut & ~(uintptr_t)UINT32_MAX, (uintptr_t)UINT32_MAX,
                                (uintptr_t)&g_ut & ~(uintptr_t)UINT32_MAX, (uintptr_t)UINT32_MAX, 4U);
    ut_fill(&g_ut_ram.in[1], 96U, 4U);
    UTNOX_EQUALS(noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_ECB, 0U, g_ut_ram.aux, 16U, NULL, &g_ut_ram.in[1], &g_ut_ram.out[1], 96U),
                 NOXTLS_RETURN_SUCCESS);
    ut_ref(0U, 0U, g_ut_ram.aux, 16U, NULL, &g_ut_ram.in[1], ref, 96U);
    UTNOX_MEM_EQUAL(&g_ut_ram.out[1], ref, 96U);
    UTNOX_IS_TRUE(ut_clean() != 0U);
    return 0;
}

REGISTER_TEST(test_aes_masking_engine_gets_a_fresh_mask_word)
{
    uint32_t first;

    ut_setup();
    ut_set_caps(NOXTLS_EFR32_INCL_AES, 0x05030127U, 0x80U);
    UTNOX_EQUALS(noxtls_efr32_aes_caps()->masking, 0U);
    (void)ut_hex(s_c_key, g_ut_ram.aux);
    UTNOX_EQUALS(noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_ECB, 0U, g_ut_ram.aux, 16U, NULL, g_ut_ram.in, g_ut_ram.out, 16U), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_efr32_aes_caps()->masking, 1U);
    UTNOX_EQUALS(g_ut.aes_mask_seen & NOXTLS_EFR32_AES_MASK_TOP_BIT, NOXTLS_EFR32_AES_MASK_TOP_BIT);
    first = g_ut.aes_mask_seen;
    UTNOX_EQUALS(g_ut.se_cmds, 1U);
    UTNOX_EQUALS(noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_ECB, 0U, g_ut_ram.aux, 16U, NULL, g_ut_ram.in, g_ut_ram.out, 16U), NOXTLS_RETURN_SUCCESS);
    UTNOX_NOT_EQUALS(g_ut.aes_mask_seen, first);
    /* Seeded once. */
    UTNOX_EQUALS(g_ut.se_cmds, 1U);
    UTNOX_IS_TRUE(ut_clean() != 0U);
    return 0;
}

REGISTER_TEST(test_aes_masking_without_entropy_is_not_started)
{
    ut_setup();
    ut_set_caps(NOXTLS_EFR32_INCL_AES, 0x05030127U, 0x80U);
    (void)ut_hex(s_c_key, g_ut_ram.aux);
    g_ut.se_force = 1U;
    g_ut.se_force_resp = NOXTLS_EFR32_SE_RESP_INTERNAL;
    UTNOX_EQUALS(noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_ECB, 0U, g_ut_ram.aux, 16U, NULL, g_ut_ram.in, g_ut_ram.out, 16U),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(g_ut.aes_jobs, 0U);
    /* The same for CCM. */
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(0U, g_ut_ram.aux, 16U, g_ut_ram.aux2, 12U, NULL, 0U, g_ut_ram.in, g_ut_ram.out, 16U, &g_ut_ram.aux2[64], 8U),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(g_ut.aes_jobs, 0U);
    g_ut.se_force = 0U;
    UTNOX_EQUALS(noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_ECB, 0U, g_ut_ram.aux, 16U, NULL, g_ut_ram.in, g_ut_ram.out, 16U), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(0U, g_ut_ram.aux, 16U, g_ut_ram.aux2, 12U, NULL, 0U, g_ut_ram.in, g_ut_ram.out, 16U, &g_ut_ram.aux2[64], 8U),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_IS_TRUE(ut_clean() != 0U);
    return 0;
}

REGISTER_TEST(test_aes_busy_and_disabled_engine_fall_back)
{
    ut_setup();
    (void)ut_hex(s_c_key, g_ut_ram.aux);
    UTNOX_EQUALS(noxtls_efr32_aes_acquire(), NOXTLS_RETURN_SUCCESS);
    /* Another driver (BlueNox CCM between packets) owns the engine: never waits, software serves it. */
    UTNOX_EQUALS(noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_ECB, 0U, g_ut_ram.aux, 16U, NULL, g_ut_ram.in, g_ut_ram.out, 16U), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(0U, g_ut_ram.aux, 16U, g_ut_ram.aux2, 12U, NULL, 0U, g_ut_ram.in, g_ut_ram.out, 16U, &g_ut_ram.aux2[64], 8U),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(g_ut.aes_jobs, 0U);
    UTNOX_EQUALS(noxtls_efr32_stats()->aes_busy, 2U);
    noxtls_efr32_aes_release();
    noxtls_efr32_set_enabled(NOXTLS_EFR32_UNIT_AES, 0U);
    UTNOX_EQUALS(noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_ECB, 0U, g_ut_ram.aux, 16U, NULL, g_ut_ram.in, g_ut_ram.out, 16U), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_efr32_stats()->aes_busy, 2U);
    noxtls_efr32_set_enabled(NOXTLS_EFR32_UNIT_AES, 1U);
    UTNOX_EQUALS(noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_ECB, 0U, g_ut_ram.aux, 16U, NULL, g_ut_ram.in, g_ut_ram.out, 16U), NOXTLS_RETURN_SUCCESS);
    return 0;
}

REGISTER_TEST(test_aes_hardware_faults_wipe_and_recover)
{
    uint8_t iv[16];

    ut_setup();
    (void)ut_hex(s_c_key, g_ut_ram.aux);
    ut_fill(g_ut_ram.in, 64U, 1U);
    (void)memset(iv, 0x11, sizeof(iv));
    (void)memcpy(g_ut_ram.aux2, iv, sizeof(iv));
    /* Bus error: FAILED, output wiped, IV unchanged, soft reset issued, engine released. */
    g_ut.aes_bus_error = 1U;
    (void)memset(g_ut_ram.out, 0xA5, 64U);
    UTNOX_EQUALS(noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_CBC, 0U, g_ut_ram.aux, 16U, g_ut_ram.aux2, g_ut_ram.in, g_ut_ram.out, 64U), NOXTLS_RETURN_FAILED);
    UTNOX_IS_TRUE(noxtls_efr32_is_zero(g_ut_ram.out, 64U) != 0U);
    UTNOX_MEM_EQUAL(g_ut_ram.aux2, iv, 16U);
    UTNOX_EQUALS(g_ut.aes_resets, 1U);
    UTNOX_EQUALS(noxtls_efr32_stats()->aes_errors, 1U);
    g_ut.aes_bus_error = 0U;
    UTNOX_EQUALS(noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_ECB, 0U, g_ut_ram.aux, 16U, NULL, g_ut_ram.in, g_ut_ram.out, 64U), NOXTLS_RETURN_SUCCESS);
    /* Engine that never finishes: bounded wait, TIMEOUT, reset. */
    g_ut.aes_hang = 1U;
    UTNOX_EQUALS(noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_ECB, 0U, g_ut_ram.aux, 16U, NULL, g_ut_ram.in, g_ut_ram.out, 64U), NOXTLS_RETURN_TIMEOUT);
    UTNOX_EQUALS(noxtls_efr32_stats()->aes_timeouts, 1U);
    UTNOX_EQUALS(g_ut.aes_resets, 2U);
    UTNOX_EQUALS(noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_ECB, 0U, g_ut_ram.aux, 16U, NULL, g_ut_ram.in, g_ut_ram.out, 64U), NOXTLS_RETURN_SUCCESS);
    /* A reset that never completes is also bounded. */
    g_ut.aes_hang = 1U;
    g_ut.aes_softrst_stuck = 1U;
    UTNOX_EQUALS(noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_ECB, 0U, g_ut_ram.aux, 16U, NULL, g_ut_ram.in, g_ut_ram.out, 64U), NOXTLS_RETURN_TIMEOUT);
    g_ut.aes_softrst_stuck = 0U;
    /* Failure in the middle of a multi-job request wipes everything produced so far. */
    g_ut.aes_jobs_fail_after = (uint8_t)(g_ut.aes_jobs + 3U);
    ut_fill(g_ut_ram.in, 1024U, 1U);
    UTNOX_EQUALS(noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_ECB, 0U, g_ut_ram.aux, 16U, NULL, g_ut_ram.in, g_ut_ram.out, 1024U), NOXTLS_RETURN_FAILED);
    UTNOX_IS_TRUE(noxtls_efr32_is_zero(g_ut_ram.out, 1024U) != 0U);
    g_ut.aes_jobs_fail_after = 0U;
    /* The lock was released on every path. */
    UTNOX_EQUALS(noxtls_efr32_aes_acquire(), NOXTLS_RETURN_SUCCESS);
    noxtls_efr32_aes_release();
    return 0;
}

REGISTER_TEST(test_aes_ccm_sp800_38c_examples)
{
    uint8_t key[16];
    uint8_t nonce[13];
    uint8_t aad[20];
    uint8_t pt[24];
    uint8_t expect[24 + 8];
    uint8_t tag[16];

    ut_setup();
    (void)ut_hex("404142434445464748494a4b4c4d4e4f", key);
    (void)memcpy(g_ut_ram.aux, key, 16U);
    /* Example 1: Nlen 7, Tlen 4, Alen 8, Plen 4. */
    (void)ut_hex("10111213141516", nonce);
    (void)ut_hex("0001020304050607", aad);
    (void)ut_hex("20212223", pt);
    (void)ut_hex("7162015b4dac255d", expect);
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(0U, g_ut_ram.aux, 16U, nonce, 7U, aad, 8U, pt, g_ut_ram.out, 4U, tag, 4U), NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(g_ut_ram.out, expect, 4U);
    UTNOX_MEM_EQUAL(tag, &expect[4], 4U);
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(1U, g_ut_ram.aux, 16U, nonce, 7U, aad, 8U, g_ut_ram.out, g_ut_ram.in, 4U, tag, 4U), NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(g_ut_ram.in, pt, 4U);
    /* Example 2: Nlen 8, Tlen 6, Alen 16, Plen 16. */
    (void)ut_hex("1011121314151617", nonce);
    (void)ut_hex("000102030405060708090a0b0c0d0e0f", aad);
    (void)ut_hex("202122232425262728292a2b2c2d2e2f", pt);
    (void)ut_hex("d2a1f0e051ea5f62081a7792073d593d1fc64fbfaccd", expect);
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(0U, g_ut_ram.aux, 16U, nonce, 8U, aad, 16U, pt, g_ut_ram.out, 16U, tag, 6U), NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(g_ut_ram.out, expect, 16U);
    UTNOX_MEM_EQUAL(tag, &expect[16], 6U);
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(1U, g_ut_ram.aux, 16U, nonce, 8U, aad, 16U, g_ut_ram.out, g_ut_ram.in, 16U, tag, 6U), NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(g_ut_ram.in, pt, 16U);
    /* Example 3: Nlen 12, Tlen 8, Alen 20, Plen 24. */
    (void)ut_hex("101112131415161718191a1b", nonce);
    (void)ut_hex("000102030405060708090a0b0c0d0e0f10111213", aad);
    (void)ut_hex("202122232425262728292a2b2c2d2e2f3031323334353637", pt);
    (void)ut_hex("e3b201a9f5b71a7a9b1ceaeccd97e70b6176aad9a4428aa5484392fbc1b09951", expect);
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(0U, g_ut_ram.aux, 16U, nonce, 12U, aad, 20U, pt, g_ut_ram.out, 24U, tag, 8U), NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(g_ut_ram.out, expect, 24U);
    UTNOX_MEM_EQUAL(tag, &expect[24], 8U);
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(1U, g_ut_ram.aux, 16U, nonce, 12U, aad, 20U, g_ut_ram.out, g_ut_ram.in, 24U, tag, 8U), NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(g_ut_ram.in, pt, 24U);
    UTNOX_IS_TRUE(ut_clean() != 0U);
    return 0;
}

REGISTER_TEST(test_aes_ccm_lengths_match_software)
{
    static const uint32_t plens[] = { 0U, 1U, 15U, 16U, 17U, 31U, 32U, 1024U, 16640U };
    static const uint32_t alens[] = { 0U, 1U, 13U, 16U, 17U, 100U };
    uint32_t i;
    uint32_t j;

    ut_setup();
    (void)ut_hex("404142434445464748494a4b4c4d4e4f", g_ut_ram.aux);
    ut_fill(&g_ut_ram.aux[64], 12U, 1U);
    for (i = 0U; i < (sizeof(plens) / sizeof(plens[0])); i++) {
        for (j = 0U; j < (sizeof(alens) / sizeof(alens[0])); j++) {
            uint32_t tl = 4U + (2U * ((i + j) % 7U));
            uint32_t nl = 7U + ((i + j) % 7U);
            uint32_t klen = (((i + j) % 2U) == 0U) ? 16U : 32U;

            ut_fill(g_ut_ram.in, plens[i], j);
            ut_fill(g_ut_ram.aux2, alens[j] + 1U, i);
            UTNOX_EQUALS(noxtls_efr32_aes_ccm(0U, g_ut_ram.aux, klen, &g_ut_ram.aux[64], nl, g_ut_ram.aux2, alens[j], g_ut_ram.in,
                                              g_ut_ram.out, plens[i], &g_ut_ram.aux[200], tl), NOXTLS_RETURN_SUCCESS);
            ut_sw_begin();
            UTNOX_EQUALS(noxtls_aes_ccm_encrypt(g_ut_ram.aux, (klen == 16U) ? NOXTLS_AES_128_BIT : NOXTLS_AES_256_BIT, &g_ut_ram.aux[64],
                                                nl, g_ut_ram.aux2, alens[j], g_ut_ram.in, plens[i], &g_ut_ram.aux2[2048],
                                                &g_ut_ram.aux[240], tl), NOXTLS_RETURN_SUCCESS);
            ut_sw_end();
            UTNOX_MEM_EQUAL(g_ut_ram.out, &g_ut_ram.aux2[2048], plens[i]);
            UTNOX_MEM_EQUAL(&g_ut_ram.aux[200], &g_ut_ram.aux[240], tl);
            /* Decrypt in place and compare with the plaintext. */
            UTNOX_EQUALS(noxtls_efr32_aes_ccm(1U, g_ut_ram.aux, klen, &g_ut_ram.aux[64], nl, g_ut_ram.aux2, alens[j], g_ut_ram.out,
                                              g_ut_ram.out, plens[i], &g_ut_ram.aux[200], tl), NOXTLS_RETURN_SUCCESS);
            UTNOX_MEM_EQUAL(g_ut_ram.out, g_ut_ram.in, plens[i]);
        }
    }
    UTNOX_IS_TRUE(ut_clean() != 0U);
    return 0;
}

REGISTER_TEST(test_aes_ccm_long_aad_uses_32bit_length_encoding)
{
    ut_setup();
    (void)ut_hex("404142434445464748494a4b4c4d4e4f", g_ut_ram.aux);
    ut_fill(&g_ut_ram.aux[64], 12U, 1U);
    ut_fill(g_ut_ram.aux2, 0xFF00U, 5U);
    ut_fill(g_ut_ram.in, 40U, 6U);
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(0U, g_ut_ram.aux, 16U, &g_ut_ram.aux[64], 12U, g_ut_ram.aux2, 0xFF00U, g_ut_ram.in, g_ut_ram.out, 40U,
                                      &g_ut_ram.aux[200], 16U), NOXTLS_RETURN_SUCCESS);
    ut_sw_begin();
    UTNOX_EQUALS(noxtls_aes_ccm_encrypt(g_ut_ram.aux, NOXTLS_AES_128_BIT, &g_ut_ram.aux[64], 12U, g_ut_ram.aux2, 0xFF00U, g_ut_ram.in, 40U,
                                        &g_ut_ram.aux[300], &g_ut_ram.aux[400], 16U), NOXTLS_RETURN_SUCCESS);
    ut_sw_end();
    UTNOX_MEM_EQUAL(g_ut_ram.out, &g_ut_ram.aux[300], 40U);
    UTNOX_MEM_EQUAL(&g_ut_ram.aux[200], &g_ut_ram.aux[400], 16U);
    /* Just below the threshold keeps the 2-byte encoding. */
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(0U, g_ut_ram.aux, 16U, &g_ut_ram.aux[64], 12U, g_ut_ram.aux2, 0xFEFFU, g_ut_ram.in, g_ut_ram.out, 40U,
                                      &g_ut_ram.aux[200], 16U), NOXTLS_RETURN_SUCCESS);
    UTNOX_IS_TRUE(ut_clean() != 0U);
    return 0;
}

REGISTER_TEST(test_aes_ccm_authentication_failures)
{
    uint8_t tag[16];

    ut_setup();
    (void)ut_hex("404142434445464748494a4b4c4d4e4f", g_ut_ram.aux);
    ut_fill(&g_ut_ram.aux[64], 12U, 1U);
    ut_fill(g_ut_ram.in, 48U, 2U);
    ut_fill(g_ut_ram.aux2, 20U, 3U);
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(0U, g_ut_ram.aux, 16U, &g_ut_ram.aux[64], 12U, g_ut_ram.aux2, 20U, g_ut_ram.in, g_ut_ram.out, 48U, tag, 16U),
                 NOXTLS_RETURN_SUCCESS);
    /* Wrong tag, wrong ciphertext, wrong AAD, wrong nonce: BAD_DATA and no plaintext released. */
    tag[3] ^= 0x01U;
    (void)memset(g_ut_ram.in, 0xA5, 48U);
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(1U, g_ut_ram.aux, 16U, &g_ut_ram.aux[64], 12U, g_ut_ram.aux2, 20U, g_ut_ram.out, g_ut_ram.in, 48U, tag, 16U),
                 NOXTLS_RETURN_BAD_DATA);
    UTNOX_IS_TRUE(noxtls_efr32_is_zero(g_ut_ram.in, 48U) != 0U);
    tag[3] ^= 0x01U;
    g_ut_ram.out[10] ^= 0x80U;
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(1U, g_ut_ram.aux, 16U, &g_ut_ram.aux[64], 12U, g_ut_ram.aux2, 20U, g_ut_ram.out, g_ut_ram.in, 48U, tag, 16U),
                 NOXTLS_RETURN_BAD_DATA);
    g_ut_ram.out[10] ^= 0x80U;
    g_ut_ram.aux2[0] ^= 0x01U;
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(1U, g_ut_ram.aux, 16U, &g_ut_ram.aux[64], 12U, g_ut_ram.aux2, 20U, g_ut_ram.out, g_ut_ram.in, 48U, tag, 16U),
                 NOXTLS_RETURN_BAD_DATA);
    g_ut_ram.aux2[0] ^= 0x01U;
    g_ut_ram.aux[64] ^= 0x01U;
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(1U, g_ut_ram.aux, 16U, &g_ut_ram.aux[64], 12U, g_ut_ram.aux2, 20U, g_ut_ram.out, g_ut_ram.in, 48U, tag, 16U),
                 NOXTLS_RETURN_BAD_DATA);
    g_ut_ram.aux[64] ^= 0x01U;
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(1U, g_ut_ram.aux, 16U, &g_ut_ram.aux[64], 12U, g_ut_ram.aux2, 20U, g_ut_ram.out, g_ut_ram.in, 48U, tag, 16U),
                 NOXTLS_RETURN_SUCCESS);
    /* Empty payload: tag only. */
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(0U, g_ut_ram.aux, 16U, &g_ut_ram.aux[64], 12U, g_ut_ram.aux2, 20U, NULL, NULL, 0U, tag, 8U), NOXTLS_RETURN_SUCCESS);
    tag[0] ^= 0xFFU;
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(1U, g_ut_ram.aux, 16U, &g_ut_ram.aux[64], 12U, g_ut_ram.aux2, 20U, NULL, NULL, 0U, tag, 8U),
                 NOXTLS_RETURN_BAD_DATA);
    UTNOX_IS_TRUE(ut_clean() != 0U);
    return 0;
}

REGISTER_TEST(test_aes_ccm_parameter_errors)
{
    uint8_t tag[16];

    ut_setup();
    (void)ut_hex("404142434445464748494a4b4c4d4e4f", g_ut_ram.aux);
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(0U, NULL, 16U, g_ut_ram.aux, 12U, NULL, 0U, g_ut_ram.in, g_ut_ram.out, 16U, tag, 8U), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(0U, g_ut_ram.aux, 16U, NULL, 12U, NULL, 0U, g_ut_ram.in, g_ut_ram.out, 16U, tag, 8U), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(0U, g_ut_ram.aux, 16U, g_ut_ram.aux, 12U, NULL, 0U, g_ut_ram.in, g_ut_ram.out, 16U, NULL, 8U), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(0U, g_ut_ram.aux, 16U, g_ut_ram.aux, 12U, NULL, 1U, g_ut_ram.in, g_ut_ram.out, 16U, tag, 8U), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(0U, g_ut_ram.aux, 16U, g_ut_ram.aux, 12U, NULL, 0U, NULL, g_ut_ram.out, 16U, tag, 8U), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(0U, g_ut_ram.aux, 16U, g_ut_ram.aux, 12U, NULL, 0U, g_ut_ram.in, NULL, 16U, tag, 8U), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(0U, g_ut_ram.aux, 17U, g_ut_ram.aux, 12U, NULL, 0U, g_ut_ram.in, g_ut_ram.out, 16U, tag, 8U),
                 NOXTLS_RETURN_INVALID_KEY_SIZE);
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(0U, g_ut_ram.aux, 16U, g_ut_ram.aux, 6U, NULL, 0U, g_ut_ram.in, g_ut_ram.out, 16U, tag, 8U), NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(0U, g_ut_ram.aux, 16U, g_ut_ram.aux, 14U, NULL, 0U, g_ut_ram.in, g_ut_ram.out, 16U, tag, 8U), NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(0U, g_ut_ram.aux, 16U, g_ut_ram.aux, 12U, NULL, 0U, g_ut_ram.in, g_ut_ram.out, 16U, tag, 3U), NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(0U, g_ut_ram.aux, 16U, g_ut_ram.aux, 12U, NULL, 0U, g_ut_ram.in, g_ut_ram.out, 16U, tag, 5U), NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(0U, g_ut_ram.aux, 16U, g_ut_ram.aux, 12U, NULL, 0U, g_ut_ram.in, g_ut_ram.out, 16U, tag, 18U), NOXTLS_RETURN_INVALID_PARAM);
    /* Nonce 13 leaves two length bytes: a 65536-byte payload does not fit (SP 800-38C A.1). */
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(0U, g_ut_ram.aux, 16U, g_ut_ram.aux, 13U, NULL, 0U, g_ut_ram.in, g_ut_ram.out, 65536U, tag, 8U),
                 NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(0U, g_ut_ram.aux, 16U, g_ut_ram.aux, 13U, NULL, 0U, g_ut_ram.in, g_ut_ram.out, 65535U, tag, 8U),
                 NOXTLS_RETURN_SUCCESS);
    /* Over the largest request (payload or AAD): software. */
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(0U, g_ut_ram.aux, 16U, g_ut_ram.aux, 12U, NULL, 0U, g_ut_ram.in, g_ut_ram.out, UT_MAX_REQ + 1U, tag, 8U),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(0U, g_ut_ram.aux, 16U, g_ut_ram.aux, 12U, g_ut_ram.aux2, UT_MAX_REQ + 1U, g_ut_ram.in, g_ut_ram.out, 16U, tag, 8U),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    /* 192-bit keys are not in the engine. */
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(0U, g_ut_ram.aux, 24U, g_ut_ram.aux, 12U, NULL, 0U, g_ut_ram.in, g_ut_ram.out, 16U, tag, 8U),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    /* CCM disabled at run time or missing in the part. */
    noxtls_efr32_aes_set_modes_disabled(UINT32_C(1) << NOXTLS_EFR32_AES_MODE_CCM);
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(0U, g_ut_ram.aux, 16U, g_ut_ram.aux, 12U, NULL, 0U, g_ut_ram.in, g_ut_ram.out, 16U, tag, 8U),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    noxtls_efr32_aes_set_modes_disabled(0U);
    ut_set_caps(NOXTLS_EFR32_INCL_AES, 0x05010107U, 0x80U);
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(0U, g_ut_ram.aux, 16U, g_ut_ram.aux, 12U, NULL, 0U, g_ut_ram.in, g_ut_ram.out, 16U, tag, 8U),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_IS_TRUE(ut_clean() != 0U);
    return 0;
}

REGISTER_TEST(test_aes_ccm_empty_payload_known_answers_and_failures)
{
    /* Independent vectors: PyCryptodome AES.MODE_CCM, key 99AD1B52.., nonce 30..3C, 4 octet tag, 1 octet AAD.
     * The engine's own empty-payload chain did not reproduce them on EFR32MG26 silicon, so len 0 is composed
     * from CBC-MAC and one ECB block. */
    static const uint8_t k_key[16] = { 0x99U, 0xADU, 0x1BU, 0x52U, 0x26U, 0xA3U, 0x7EU, 0x3EU,
                                       0x05U, 0x8EU, 0x3BU, 0x8EU, 0x27U, 0xC2U, 0xC6U, 0x66U };
    static const uint8_t k_tag2[4] = { 0xCDU, 0x3CU, 0xA0U, 0x5BU };
    static const uint8_t k_tag3[4] = { 0x57U, 0xDAU, 0x47U, 0xC9U };
    uint8_t nonce[13];
    uint8_t aad = 0x02U;
    uint8_t tag[16];
    uint32_t i;

    ut_setup();
    for (i = 0U; i < sizeof(nonce); i++) {
        nonce[i] = (uint8_t)(0x30U + i);
    }
    (void)memcpy(g_ut_ram.aux, k_key, 16U);
    (void)memcpy(g_ut_ram.aux2, nonce, 13U);
    g_ut_ram.aux2[16] = aad;
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(0U, g_ut_ram.aux, 16U, g_ut_ram.aux2, 13U, &g_ut_ram.aux2[16], 1U, NULL, NULL, 0U, tag, 4U),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(tag, k_tag2, 4U);
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(1U, g_ut_ram.aux, 16U, g_ut_ram.aux2, 13U, &g_ut_ram.aux2[16], 1U, NULL, NULL, 0U, tag, 4U),
                 NOXTLS_RETURN_SUCCESS);
    g_ut_ram.aux2[16] = 0x03U;
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(0U, g_ut_ram.aux, 16U, g_ut_ram.aux2, 13U, &g_ut_ram.aux2[16], 1U, NULL, NULL, 0U, tag, 4U),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(tag, k_tag3, 4U);
    /* No AAD at all: B0 only. */
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(0U, g_ut_ram.aux, 16U, g_ut_ram.aux2, 13U, NULL, 0U, NULL, NULL, 0U, tag, 16U), NOXTLS_RETURN_SUCCESS);
    /* The 6 octet AAD length encoding with an empty payload. */
    ut_fill(g_ut_ram.in, 0xFF00U, 5U);
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(0U, g_ut_ram.aux, 16U, &g_ut_ram.aux[64], 12U, g_ut_ram.in, 0xFF00U, NULL, NULL, 0U, &g_ut_ram.aux[200], 16U),
                 NOXTLS_RETURN_SUCCESS);
    ut_sw_begin();
    UTNOX_EQUALS(noxtls_aes_ccm_encrypt(g_ut_ram.aux, NOXTLS_AES_128_BIT, &g_ut_ram.aux[64], 12U, g_ut_ram.in, 0xFF00U, g_ut_ram.in, 0U,
                                        &g_ut_ram.aux2[2048], &g_ut_ram.aux[240], 16U), NOXTLS_RETURN_SUCCESS);
    ut_sw_end();
    UTNOX_MEM_EQUAL(&g_ut_ram.aux[200], &g_ut_ram.aux[240], 16U);

    /* CCM disabled at run time. */
    noxtls_efr32_aes_set_modes_disabled(UINT32_C(1) << NOXTLS_EFR32_AES_MODE_CCM);
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(0U, g_ut_ram.aux, 16U, g_ut_ram.aux2, 13U, NULL, 0U, NULL, NULL, 0U, tag, 4U), NOXTLS_RETURN_NOT_SUPPORTED);
    noxtls_efr32_aes_set_modes_disabled(0U);

    /* A failing CBC job and a failing ECB job (the one after the CBC-MAC blocks). The job counter is 8 bit
     * in the mock knob, so start from a fresh mock. */
    ut_setup();
    (void)memcpy(g_ut_ram.aux, k_key, 16U);
    (void)memcpy(g_ut_ram.aux2, nonce, 13U);
    g_ut_ram.aux2[16] = aad;
    g_ut.aes_jobs_fail_after = (uint8_t)(g_ut.aes_jobs + 1U);
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(0U, g_ut_ram.aux, 16U, g_ut_ram.aux2, 13U, NULL, 0U, NULL, NULL, 0U, tag, 4U), NOXTLS_RETURN_FAILED);
    /* One CBC-MAC job (B0, the AAD length and one AAD byte fit one batch) and the ECB job: the second job fails. */
    g_ut.aes_jobs_fail_after = (uint8_t)(g_ut.aes_jobs + 2U);
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(0U, g_ut_ram.aux, 16U, g_ut_ram.aux2, 13U, &g_ut_ram.aux2[16], 1U, NULL, NULL, 0U, tag, 4U),
                 NOXTLS_RETURN_FAILED);
    /* A 100-byte AAD needs two CBC-MAC batches and the ECB job: each of the three jobs can fail. */
    ut_fill(g_ut_ram.in, 100U, 3U);
    g_ut.aes_jobs_fail_after = (uint8_t)(g_ut.aes_jobs + 2U);
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(0U, g_ut_ram.aux, 16U, g_ut_ram.aux2, 13U, g_ut_ram.in, 100U, NULL, NULL, 0U, tag, 4U),
                 NOXTLS_RETURN_FAILED);
    g_ut.aes_jobs_fail_after = (uint8_t)(g_ut.aes_jobs + 3U);
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(0U, g_ut_ram.aux, 16U, g_ut_ram.aux2, 13U, g_ut_ram.in, 100U, NULL, NULL, 0U, tag, 4U),
                 NOXTLS_RETURN_FAILED);
    g_ut.aes_jobs_fail_after = 0U;
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(0U, g_ut_ram.aux, 16U, g_ut_ram.aux2, 13U, NULL, 0U, NULL, NULL, 0U, tag, 4U), NOXTLS_RETURN_SUCCESS);
    UTNOX_IS_TRUE(ut_clean() != 0U);
    return 0;
}

REGISTER_TEST(test_aes_ccm_bounce_and_unreachable)
{
    uint8_t in[200];
    uint8_t out[200];
    uint8_t aad[200];
    uint8_t tag[16];
    uint8_t ref[200];
    uint8_t rtag[16];

    ut_setup();
    (void)ut_hex("404142434445464748494a4b4c4d4e4f", g_ut_ram.aux);
    ut_fill(&g_ut_ram.aux[64], 12U, 1U);
    ut_fill(in, 100U, 1U);
    ut_fill(aad, 100U, 2U);
    /* Payload and AAD of 100 bytes on the stack fit the 128-byte bounce buffers. */
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(0U, g_ut_ram.aux, 16U, &g_ut_ram.aux[64], 12U, aad, 100U, in, out, 100U, tag, 8U), NOXTLS_RETURN_SUCCESS);
    ut_sw_begin();
    UTNOX_EQUALS(noxtls_aes_ccm_encrypt(g_ut_ram.aux, NOXTLS_AES_128_BIT, &g_ut_ram.aux[64], 12U, aad, 100U, in, 100U, ref, rtag, 8U),
                 NOXTLS_RETURN_SUCCESS);
    ut_sw_end();
    UTNOX_MEM_EQUAL(out, ref, 100U);
    UTNOX_MEM_EQUAL(tag, rtag, 8U);
    /* Input reachable, output not; and the other way round. */
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(0U, g_ut_ram.aux, 16U, &g_ut_ram.aux[64], 12U, g_ut_ram.aux2, 10U, g_ut_ram.in, out, 100U, tag, 8U),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(0U, g_ut_ram.aux, 16U, &g_ut_ram.aux[64], 12U, g_ut_ram.aux2, 10U, in, g_ut_ram.out, 100U, tag, 8U),
                 NOXTLS_RETURN_SUCCESS);
    /* Larger than the bounce buffer and unreachable: software. */
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(0U, g_ut_ram.aux, 16U, &g_ut_ram.aux[64], 12U, NULL, 0U, in, out, 200U, tag, 8U), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(0U, g_ut_ram.aux, 16U, &g_ut_ram.aux[64], 12U, NULL, 0U, g_ut_ram.in, out, 200U, tag, 8U),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(0U, g_ut_ram.aux, 16U, &g_ut_ram.aux[64], 12U, aad, 200U, g_ut_ram.in, g_ut_ram.out, 16U, tag, 8U),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_IS_TRUE(ut_clean() != 0U);
    return 0;
}

REGISTER_TEST(test_aes_ccm_faults_and_busy)
{
    uint8_t tag[16];

    ut_setup();
    (void)ut_hex("404142434445464748494a4b4c4d4e4f", g_ut_ram.aux);
    ut_fill(g_ut_ram.in, 32U, 1U);
    g_ut.aes_bus_error = 1U;
    (void)memset(g_ut_ram.out, 0xA5, 32U);
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(0U, g_ut_ram.aux, 16U, &g_ut_ram.aux[64], 12U, NULL, 0U, g_ut_ram.in, g_ut_ram.out, 32U, tag, 8U),
                 NOXTLS_RETURN_FAILED);
    UTNOX_IS_TRUE(noxtls_efr32_is_zero(g_ut_ram.out, 32U) != 0U);
    g_ut.aes_bus_error = 0U;
    g_ut.aes_hang = 1U;
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(1U, g_ut_ram.aux, 16U, &g_ut_ram.aux[64], 12U, NULL, 0U, g_ut_ram.in, g_ut_ram.out, 32U, tag, 8U),
                 NOXTLS_RETURN_TIMEOUT);
    g_ut.aes_hang = 0U;
    UTNOX_EQUALS(noxtls_efr32_aes_acquire(), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(0U, g_ut_ram.aux, 16U, &g_ut_ram.aux[64], 12U, NULL, 0U, g_ut_ram.in, g_ut_ram.out, 32U, tag, 8U),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    noxtls_efr32_aes_release();
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(0U, g_ut_ram.aux, 16U, &g_ut_ram.aux[64], 12U, NULL, 0U, g_ut_ram.in, g_ut_ram.out, 32U, tag, 8U),
                 NOXTLS_RETURN_SUCCESS);
    return 0;
}
