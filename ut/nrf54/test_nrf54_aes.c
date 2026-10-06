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
* File:    test_nrf54_aes.c
* Summary: Tests of the BA411 AES-ECB/CBC/CTR backend and the NoxTLS AES ports
*
*****************************************************************************/

/**
 * @file test_nrf54_aes.c
 * @brief NIST SP 800-38A Appendix F vectors through the NoxTLS AES API on the
 *        mocked CRACEN (native CTR on the nRF54L15 model, keystream CTR on the
 *        16-bit-counter nRF54LM20 model), bounce, chunking, key reference,
 *        block ports, DRBG and error paths.
 * @ingroup noxtls_nrf54_ut
 */

#include <stdint.h>
#include <string.h>

#include "runner.h"
#include "test_assert.h"

#include "ut_nrf54_mock.h"
#include "ut_nrf54_ref.h"
#include "noxtls_aes.h"
#include "noxtls_aes_accel.h"
#include "drbg/noxtls_drbg.h"

/** SP 800-38A F plaintext (4 blocks). */
static const char s_pt[] = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
                           "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";
/** SP 800-38A CBC IV. */
static const char s_cbc_iv[] = "000102030405060708090a0b0c0d0e0f";
/** SP 800-38A CTR initial counter block. */
static const char s_ctr_iv[] = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";

/** One SP 800-38A key size. */
typedef struct {
    noxtls_aes_type_t type; /**< Key size selector. */
    const char *key;        /**< Key. */
    const char *ecb;        /**< F.1 ciphertext. */
    const char *cbc;        /**< F.2 ciphertext. */
    const char *ctr;        /**< F.5 ciphertext. */
} ut_aes_kat_t;

/** F.1.1/F.2.1/F.5.1, F.1.3/F.2.3/F.5.3, F.1.5/F.2.5/F.5.5. */
static const ut_aes_kat_t s_kat[3] = {
    { NOXTLS_AES_128_BIT, "2b7e151628aed2a6abf7158809cf4f3c",
      "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4",
      "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7",
      "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee" },
    { NOXTLS_AES_192_BIT, "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
      "bd334f1d6e45f25ff712a214571fa5cc974104846d0ad3ad7734ecb3ecee4eefef7afd2270e2e60adce0ba2face6444e9a4b41ba738d6c72fb16691603c18e0e",
      "4f021db243bc633d7178183a9fa071e8b4d9ada9ad7dedf4e5e738763f69145a571b242012fb7ae07fa9baac3df102e008b0e27988598881d920a9e64f5615cd",
      "1abc932417521ca24f2b0459fe7e6e0b090339ec0aa6faefd5ccc2c6f4ce8e941e36b26bd1ebc670d1bd1d665620abf74f78a7f6d29809585a97daec58c6b050" },
    { NOXTLS_AES_256_BIT, "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
      "f3eed1bdb5d2a03c064b5a7e3db181f8591ccb10d410ed26dc5ba74a31362870b6ed21b99ca6f4f9f153e7b1beafed1d23304b7a39f9f3ff067d8d8f9e24ecc7",
      "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b",
      "601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6" },
};

/**
 * @brief Run every mode of one key in both directions; the buffers live in the DMA window.
 *
 * @param[in] k   Vector.
 * @param[in] hw  Non-zero when the engine must have served the request.
 *
 * @return Bit mask of the failed checks (0: all passed).
 */
static uint32_t ut_aes_kat(const ut_aes_kat_t *k, uint8_t hw)
{
    uint8_t key[32];
    uint8_t pt[64];
    uint8_t ct[64];
    uint8_t iv[16];
    uint32_t fails = 0U;
    uint32_t jobs = noxtls_nrf54_cracen_stats()->cm_jobs;

    (void)ut_hex(k->key, key, sizeof(key));
    (void)ut_hex(s_pt, pt, sizeof(pt));
    (void)memcpy(g_ut_ram.in, pt, 64U);
    (void)ut_hex(k->ecb, ct, sizeof(ct));
    fails |= (noxtls_aes_encrypt_ecb(key, g_ut_ram.in, 64U, NULL, g_ut_ram.out, k->type) != NOXTLS_RETURN_SUCCESS) ? (UINT32_C(1) << 1) : 0U;
    fails |= (memcmp(g_ut_ram.out, ct, 64U) != 0) ? (UINT32_C(1) << 2) : 0U;
    fails |= (noxtls_aes_decrypt_ecb(key, g_ut_ram.out, 64U, NULL, g_ut_ram.out, k->type) != NOXTLS_RETURN_SUCCESS) ? (UINT32_C(1) << 3) : 0U;
    fails |= (memcmp(g_ut_ram.out, pt, 64U) != 0) ? (UINT32_C(1) << 4) : 0U;
    (void)ut_hex(s_cbc_iv, iv, sizeof(iv));
    (void)ut_hex(k->cbc, ct, sizeof(ct));
    fails |= (noxtls_aes_encrypt_cbc(key, g_ut_ram.in, 64U, iv, g_ut_ram.out, k->type) != NOXTLS_RETURN_SUCCESS) ? (UINT32_C(1) << 5) : 0U;
    fails |= (memcmp(g_ut_ram.out, ct, 64U) != 0) ? (UINT32_C(1) << 6) : 0U;
    /* CBC decryption: in place on the engine (chaining value saved before the job); the
     * NoxTLS software CBC decryption needs distinct buffers. */
    (void)memcpy(g_ut_ram.in, g_ut_ram.out, 64U);
    fails |= (noxtls_aes_decrypt_cbc(key, g_ut_ram.in, 64U, iv, (hw != 0U) ? g_ut_ram.in : g_ut_ram.out, k->type) !=
              NOXTLS_RETURN_SUCCESS) ? (UINT32_C(1) << 7) : 0U;
    fails |= (memcmp((hw != 0U) ? g_ut_ram.in : g_ut_ram.out, pt, 64U) != 0) ? (UINT32_C(1) << 8) : 0U;
    (void)memcpy(g_ut_ram.in, pt, 64U);
    (void)ut_hex(s_ctr_iv, iv, sizeof(iv));
    (void)ut_hex(k->ctr, ct, sizeof(ct));
    fails |= (noxtls_aes_encrypt_ctr(key, g_ut_ram.in, 64U, iv, g_ut_ram.out, k->type) != NOXTLS_RETURN_SUCCESS) ? (UINT32_C(1) << 9) : 0U;
    fails |= (memcmp(g_ut_ram.out, ct, 64U) != 0) ? (UINT32_C(1) << 10) : 0U;
    /* Partial last block (37 bytes). */
    (void)memset(g_ut_ram.out, 0, 64U);
    fails |= (noxtls_aes_encrypt_ctr(key, g_ut_ram.in, 37U, iv, g_ut_ram.out, k->type) != NOXTLS_RETURN_SUCCESS) ? (UINT32_C(1) << 11) : 0U;
    fails |= (memcmp(g_ut_ram.out, ct, 37U) != 0) ? (UINT32_C(1) << 12) : 0U;
    fails |= (g_ut_ram.out[37] != 0U) ? (UINT32_C(1) << 13) : 0U;
    if ((hw != 0U) && (noxtls_nrf54_cracen_stats()->cm_jobs == jobs)) {
        fails |= UINT32_C(1) << 31;
    }
    return fails;
}

REGISTER_TEST(test_aes_sp800_38a)
{
    uint8_t chip;
    uint32_t i;

    for (chip = 0U; chip < 2U; chip++) {
        ut_setup(chip);
        for (i = 0U; i < 3U; i++) {
            /* AES-192 on CRACEN Lite is served by software (engine lacks it). */
            uint8_t hw = ((chip != 0U) || (s_kat[i].type != NOXTLS_AES_192_BIT)) ? 1U : 0U;

            UTNOX_EQUALS(ut_aes_kat(&s_kat[i], hw) | ((uint32_t)i << 24) | ((uint32_t)chip << 28),
                         ((uint32_t)i << 24) | ((uint32_t)chip << 28));
        }
        UTNOX_EQUALS(g_ut.err[0], 0);
    }
    return 0;
}

REGISTER_TEST(test_aes_bounce_chunks_irq)
{
    uint8_t key[16];
    uint8_t iv[16];
    uint8_t far_in[300];
    uint8_t far_out[300];
    uint8_t expect[300];
    ut_aes_key_t rk;
    uint32_t i;
    uint8_t chip;

    (void)ut_hex(s_kat[0].key, key, sizeof(key));
    (void)ut_aes_setkey(&rk, key, 16U);
    for (i = 0U; i < sizeof(far_in); i++) {
        far_in[i] = (uint8_t)(i * 13U);
    }
    for (i = 0U; i < 288U; i += 16U) {
        ut_aes_encrypt(&rk, &far_in[i], &expect[i]);
    }
    for (chip = 0U; chip < 2U; chip++) {
        ut_setup(chip);
        if (chip != 0U) {
            ut_port_irq();
        }
        /* Stack buffers are outside the window: bounced in 128-byte pieces. */
        UTNOX_EQUALS(noxtls_aes_encrypt_ecb(key, far_in, 288U, NULL, far_out, NOXTLS_AES_128_BIT), NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(memcmp(far_out, expect, 288U), 0);
        /* In the window: chunks of 256 bytes. */
        (void)memcpy(g_ut_ram.in, far_in, 288U);
        UTNOX_EQUALS(noxtls_aes_encrypt_ecb(key, g_ut_ram.in, 288U, NULL, g_ut_ram.out, NOXTLS_AES_128_BIT),
                     NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(memcmp(g_ut_ram.out, expect, 288U), 0);
        /* CBC across chunks and bounce, compared with the software path. */
        (void)ut_hex(s_cbc_iv, iv, sizeof(iv));
        UTNOX_EQUALS(noxtls_aes_encrypt_cbc(key, far_in, 288U, iv, far_out, NOXTLS_AES_128_BIT), NOXTLS_RETURN_SUCCESS);
        noxtls_nrf54_cracen_set_enabled(0U);
        UTNOX_EQUALS(noxtls_aes_encrypt_cbc(key, far_in, 288U, iv, expect, NOXTLS_AES_128_BIT), NOXTLS_RETURN_SUCCESS);
        noxtls_nrf54_cracen_set_enabled(1U);
        UTNOX_EQUALS(memcmp(far_out, expect, 288U), 0);
        UTNOX_EQUALS(noxtls_aes_decrypt_cbc(key, expect, 288U, iv, far_out, NOXTLS_AES_128_BIT), NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(memcmp(far_out, far_in, 288U), 0);
        /* CTR of 300 bytes through bounce / keystream, compared with software. */
        (void)ut_hex(s_ctr_iv, iv, sizeof(iv));
        UTNOX_EQUALS(noxtls_aes_encrypt_ctr(key, far_in, 300U, iv, far_out, NOXTLS_AES_128_BIT), NOXTLS_RETURN_SUCCESS);
        noxtls_nrf54_cracen_set_enabled(0U);
        UTNOX_EQUALS(noxtls_aes_encrypt_ctr(key, far_in, 300U, iv, expect, NOXTLS_AES_128_BIT), NOXTLS_RETURN_SUCCESS);
        noxtls_nrf54_cracen_set_enabled(1U);
        UTNOX_EQUALS(memcmp(far_out, expect, 300U), 0);
        (void)ut_hex(s_kat[0].key, key, sizeof(key));
        for (i = 0U; i < 288U; i += 16U) {
            ut_aes_encrypt(&rk, &far_in[i], &expect[i]);
        }
        UTNOX_EQUALS(g_ut.err[0], 0);
    }
    return 0;
}

REGISTER_TEST(test_aes_ctr_counter_carry)
{
    uint8_t key[16] = { 0U };
    uint8_t iv[16];
    uint8_t a[96];
    uint8_t b[96];
    uint8_t chip;

    /* Counter 0x...FFFF FFFE: the 128-bit increment carries across bytes (keystream / native). */
    for (chip = 0U; chip < 2U; chip++) {
        ut_setup(chip);
        (void)memset(iv, 0xFF, sizeof(iv));
        iv[15] = 0xFEU;
        iv[0] = 0x01U;
        (void)memset(g_ut_ram.in, 0x5A, 96U);
        UTNOX_EQUALS(noxtls_nrf54_aes_crypt(NOXTLS_NRF54_AES_CTR, 0U, key, 16U, iv, g_ut_ram.in, a, 96U),
                     NOXTLS_RETURN_SUCCESS);
        /* The IV now holds the next counter block: 0x02 00..00 0x04. */
        UTNOX_EQUALS(iv[0], 0x02U);
        UTNOX_EQUALS(iv[1], 0x00U);
        UTNOX_EQUALS(iv[15], 0x04U);
        (void)memset(iv, 0xFF, sizeof(iv));
        iv[15] = 0xFEU;
        iv[0] = 0x01U;
        noxtls_nrf54_cracen_set_enabled(0U);
        UTNOX_EQUALS(noxtls_aes_encrypt_ctr(key, g_ut_ram.in, 96U, iv, b, NOXTLS_AES_128_BIT), NOXTLS_RETURN_SUCCESS);
        noxtls_nrf54_cracen_set_enabled(1U);
        UTNOX_EQUALS(memcmp(a, b, 96U), 0);
        /* All-ones counter wraps to zero; a request shorter than one block. */
        (void)memset(iv, 0xFF, sizeof(iv));
        UTNOX_EQUALS(noxtls_nrf54_aes_crypt(NOXTLS_NRF54_AES_CTR, 0U, key, 16U, iv, g_ut_ram.in, a, 40U),
                     NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(iv[0], 0x00U);
        UTNOX_EQUALS(iv[15], 0x02U);
        UTNOX_EQUALS(noxtls_nrf54_aes_crypt(NOXTLS_NRF54_AES_CTR, 0U, key, 16U, iv, g_ut_ram.in, a, 5U),
                     NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(iv[15], 0x03U);
    }
    /* Hardware timeout through the mode port is an error, not a silent fallback. */
    ut_setup(0U);
    g_ut.hang = 1U;
    UTNOX_EQUALS(noxtls_aes_encrypt_ecb(key, g_ut_ram.in, 16U, NULL, a, NOXTLS_AES_128_BIT), NOXTLS_RETURN_FAILED);
    return 0;
}

REGISTER_TEST(test_aes_keyref_and_errors)
{
    uint8_t key[32];
    uint8_t iv[16] = { 0U };
    uint8_t expect[16];
    ut_aes_key_t rk;

    ut_setup(1U);
    (void)ut_hex(s_kat[2].key, key, sizeof(key));
    (void)memcpy(g_ut_ram.prot, key, 32U);
    (void)ut_aes_setkey(&rk, key, 32U);
    ut_aes_encrypt(&rk, g_ut_ram.in, expect);
    UTNOX_EQUALS(noxtls_nrf54_aes_crypt_keyref(NOXTLS_NRF54_AES_ECB, 0U, (uintptr_t)g_ut_ram.prot, 32U, NULL,
                                               g_ut_ram.in, g_ut_ram.out, 16U), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(memcmp(g_ut_ram.out, expect, 16U), 0);
    UTNOX_EQUALS(g_ut.last_key_addr, (uint32_t)(uintptr_t)g_ut_ram.prot);
    /* Arguments. */
    UTNOX_EQUALS(noxtls_nrf54_aes_crypt(NOXTLS_NRF54_AES_ECB, 0U, NULL, 16U, NULL, g_ut_ram.in, g_ut_ram.out, 16U),
                 NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_nrf54_aes_crypt(NOXTLS_NRF54_AES_ECB, 0U, key, 16U, NULL, NULL, g_ut_ram.out, 16U),
                 NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_nrf54_aes_crypt(NOXTLS_NRF54_AES_ECB, 0U, key, 16U, NULL, g_ut_ram.in, NULL, 16U),
                 NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_nrf54_aes_crypt(NOXTLS_NRF54_AES_CBC, 0U, key, 16U, NULL, g_ut_ram.in, g_ut_ram.out, 16U),
                 NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_nrf54_aes_crypt((noxtls_nrf54_aes_mode_t)9, 0U, key, 16U, iv, g_ut_ram.in, g_ut_ram.out, 16U),
                 NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_EQUALS(noxtls_nrf54_aes_crypt(NOXTLS_NRF54_AES_ECB, 0U, key, 20U, NULL, g_ut_ram.in, g_ut_ram.out, 16U),
                 NOXTLS_RETURN_INVALID_KEY_SIZE);
    UTNOX_EQUALS(noxtls_nrf54_aes_crypt(NOXTLS_NRF54_AES_CBC, 0U, key, 16U, iv, g_ut_ram.in, g_ut_ram.out, 15U),
                 NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_EQUALS(noxtls_nrf54_aes_crypt(NOXTLS_NRF54_AES_ECB, 0U, key, 16U, NULL, NULL, NULL, 0U),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_nrf54_cracen_stats()->acquires, 1U);
    /* Busy and disabled engine. */
    UTNOX_EQUALS(noxtls_nordic_crypto_try_acquire(), 1);
    UTNOX_EQUALS(noxtls_nrf54_aes_crypt(NOXTLS_NRF54_AES_ECB, 0U, key, 16U, NULL, g_ut_ram.in, g_ut_ram.out, 16U),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    noxtls_nordic_crypto_release();
    /* Mode missing from the engine (BA411 configuration without CBC). */
    ut_setup(1U);
    g_ut.core[UT_IDX(NOXTLS_NRF54_HW_BA411_CFG1)] &= ~(UINT32_C(1) << NOXTLS_NRF54_AES_MODE_CBC);
    UTNOX_EQUALS(noxtls_nrf54_aes_crypt(NOXTLS_NRF54_AES_CBC, 0U, key, 16U, iv, g_ut_ram.in, g_ut_ram.out, 16U),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    /* Job failures: FAILED from the backend and from the NoxTLS mode API (output may be partial). */
    ut_setup(0U);
    UTNOX_EQUALS(noxtls_nrf54_aes_key_supported(24U), 1U);
    g_ut.inject_error = 1U;
    UTNOX_EQUALS(noxtls_nrf54_aes_crypt(NOXTLS_NRF54_AES_ECB, 0U, key, 16U, NULL, g_ut_ram.in, g_ut_ram.out, 16U),
                 NOXTLS_RETURN_FAILED);
    UTNOX_EQUALS(noxtls_nrf54_aes_key_supported(24U), 0U);
    UTNOX_EQUALS(noxtls_nrf54_aes_key_supported(16U), 1U);
    UTNOX_EQUALS(noxtls_nrf54_aes_key_supported(17U), 0U);
    g_ut.inject_error = 1U;
    UTNOX_EQUALS(noxtls_aes_encrypt_ecb(key, g_ut_ram.in, 32U, NULL, g_ut_ram.out, NOXTLS_AES_128_BIT), NOXTLS_RETURN_FAILED);
    g_ut.inject_error = 1U;
    UTNOX_EQUALS(noxtls_nrf54_aes_crypt(NOXTLS_NRF54_AES_CTR, 0U, key, 16U, iv, g_ut_ram.in, g_ut_ram.out, 20U),
                 NOXTLS_RETURN_FAILED);
    ut_setup(1U);
    g_ut.inject_error = 2U;
    UTNOX_EQUALS(noxtls_nrf54_aes_crypt(NOXTLS_NRF54_AES_CTR, 0U, key, 16U, iv, g_ut_ram.in, g_ut_ram.out, 20U),
                 NOXTLS_RETURN_FAILED);
    /* The tail job fails after the full blocks succeeded. */
    g_ut.inject_error = 1U;
    g_ut.fail_skip = 1U;
    UTNOX_EQUALS(noxtls_nrf54_aes_crypt(NOXTLS_NRF54_AES_CTR, 0U, key, 16U, iv, g_ut_ram.in, g_ut_ram.out, 20U),
                 NOXTLS_RETURN_FAILED);
    UTNOX_EQUALS(noxtls_nrf54_aes_crypt(NOXTLS_NRF54_AES_CTR, 0U, key, 16U, iv, g_ut_ram.in, g_ut_ram.out, 20U),
                 NOXTLS_RETURN_SUCCESS);
    return 0;
}

REGISTER_TEST(test_aes_block_ports_and_drbg)
{
    uint8_t key[16];
    uint8_t blk[16];
    uint8_t out[48];
    uint8_t expect[48];
    ut_aes_key_t rk;
    drbg_state_t drbg;
    uint8_t rnd[32];
    uint32_t i;

    ut_setup(0U);
    (void)ut_hex(s_kat[0].key, key, sizeof(key));
    (void)ut_aes_setkey(&rk, key, 16U);
    (void)memset(blk, 0x11, sizeof(blk));
    ut_aes_encrypt(&rk, blk, expect);
    UTNOX_EQUALS(noxtls_aes_accel_port_encrypt_block(key, blk, out, NOXTLS_AES_128_BIT), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(memcmp(out, expect, 16U), 0);
    UTNOX_EQUALS(noxtls_aes_accel_port_decrypt_block(key, out, out, NOXTLS_AES_128_BIT), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(memcmp(out, blk, 16U), 0);
    UTNOX_EQUALS(noxtls_aes_accel_port_encrypt_block(NULL, blk, out, NOXTLS_AES_128_BIT), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_aes_accel_port_encrypt_block(key, NULL, out, NOXTLS_AES_128_BIT), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_aes_accel_port_encrypt_block(key, blk, NULL, NOXTLS_AES_128_BIT), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_aes_accel_port_encrypt_block(key, blk, out, NOXTLS_AES_192_BIT), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_aes_accel_port_encrypt_block(key, blk, out, (noxtls_aes_type_t)7), NOXTLS_RETURN_NOT_SUPPORTED);
    for (i = 0U; i < 48U; i += 16U) {
        ut_aes_encrypt(&rk, &g_ut_ram.in[i], &expect[i]);
    }
    UTNOX_EQUALS(noxtls_aes_accel_port_encrypt_blocks(key, g_ut_ram.in, out, 3U, NOXTLS_AES_128_BIT), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(memcmp(out, expect, 48U), 0);
    UTNOX_EQUALS(noxtls_aes_accel_port_encrypt_blocks(NULL, g_ut_ram.in, out, 3U, NOXTLS_AES_128_BIT), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_aes_accel_port_encrypt_blocks(key, NULL, out, 3U, NOXTLS_AES_128_BIT), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_aes_accel_port_encrypt_blocks(key, g_ut_ram.in, NULL, 3U, NOXTLS_AES_128_BIT), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_aes_accel_port_encrypt_blocks(key, g_ut_ram.in, out, 0x10000000U, NOXTLS_AES_128_BIT),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    /* Mode port: requests it leaves to software. */
    UTNOX_EQUALS(noxtls_aes_mode_accel_port(NOXTLS_AES_ACCEL_MODE_ECB, 0U, key, NOXTLS_AES_128_BIT, NULL, g_ut_ram.in, 0U,
                                            out), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_aes_mode_accel_port(NOXTLS_AES_ACCEL_MODE_ECB, 0U, NULL, NOXTLS_AES_128_BIT, NULL, g_ut_ram.in,
                                            16U, out), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_aes_mode_accel_port(NOXTLS_AES_ACCEL_MODE_ECB, 0U, key, NOXTLS_AES_128_BIT, NULL, NULL, 16U, out),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_aes_mode_accel_port(NOXTLS_AES_ACCEL_MODE_ECB, 0U, key, NOXTLS_AES_128_BIT, NULL, g_ut_ram.in, 16U,
                                            NULL), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_aes_mode_accel_port(NOXTLS_AES_ACCEL_MODE_CTR, 0U, key, NOXTLS_AES_128_BIT, NULL, g_ut_ram.in, 16U,
                                            out), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_aes_mode_accel_port((noxtls_aes_accel_mode_t)5, 0U, key, NOXTLS_AES_128_BIT, NULL, g_ut_ram.in,
                                            16U, out), NOXTLS_RETURN_NOT_SUPPORTED);
    /* CBC with a NULL IV is a zero IV (NoxTLS semantics) and partial blocks stay in software. */
    UTNOX_EQUALS(noxtls_aes_mode_accel_port(NOXTLS_AES_ACCEL_MODE_CBC, 0U, key, NOXTLS_AES_128_BIT, NULL, g_ut_ram.in, 16U,
                                            out), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_aes_mode_accel_port(NOXTLS_AES_ACCEL_MODE_CBC, 0U, key, NOXTLS_AES_128_BIT, NULL, g_ut_ram.in, 17U,
                                            out), NOXTLS_RETURN_NOT_SUPPORTED);
    /* CTR-DRBG: AES blocks through the port, entropy from the TRNG model (auto source). */
    noxtls_drbg_set_entropy_source(NOXTLS_ENTROPY_SOURCE_AUTO);
    UTNOX_EQUALS(drbg_instantiate(&drbg, DRBG_AES128, NULL, 0U, NULL, 0U, NULL, 0U), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(drbg_generate(&drbg, rnd, 256U, NULL, 0U), NOXTLS_RETURN_SUCCESS);
    UTNOX_GREATER_THAN(g_ut.rng_key_writes, 0U);
    UTNOX_EQUALS(g_ut.err[0], 0);
    return 0;
}
