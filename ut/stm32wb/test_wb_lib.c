/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    test_wb_lib.c
* Summary: NoxTLS AES / DRBG entry points routed through the STM32WB ports
*****************************************************************************/

/**
 * @file test_wb_lib.c
 * @brief Integration tests: the real NoxTLS AES modes and DRBG entropy hook running on the peripheral model.
 * @ingroup noxtls_stm32wb_ut
 *
 * Every request is run twice: on the (modelled) hardware, and with AES1 reported busy so the
 * portable software path runs. Both must give the known answer and must agree with each other.
 */

#include "ut_wb_test.h"

#include "drbg/noxtls_drbg.h"
#include "encryption/aes/noxtls_aes.h"
#include "encryption/aes/noxtls_aes_ccm.h"
#include "encryption/aes/noxtls_aes_gcm.h"

static uint8_t s_out[256];
static uint8_t s_tag[16];

static noxtls_aes_type_t type_of(uint8_t key_len)
{
    return (key_len == 16U) ? NOXTLS_AES_128_BIT : NOXTLS_AES_256_BIT;
}

REGISTER_TEST(test_lib_ecb_cbc_ctr_hardware_and_software_agree)
{
    uint32_t i;
    uint32_t pass;

    UT_SETUP();
    for (pass = 0U; pass < 2U; pass++) {
        g_wb.aes_busy = pass;
        for (i = 0U; i < k_ut_wb_modes_count; i++) {
            const ut_wb_mode_vec_t *v = &k_ut_wb_modes[i];
            noxtls_aes_type_t t = type_of(v->key_len);
            uint32_t before = g_wb.aes_computations;

            memset(s_out, 0, sizeof(s_out));
            if (v->mode == 0U) {
                UTNOX_EQUALS(noxtls_aes_encrypt_ecb(v->key, v->pt, v->len, NULL, s_out, t), NOXTLS_RETURN_SUCCESS);
            } else if (v->mode == 1U) {
                UTNOX_EQUALS(noxtls_aes_encrypt_cbc(v->key, v->pt, v->len, v->iv, s_out, t), NOXTLS_RETURN_SUCCESS);
            } else {
                UTNOX_EQUALS(noxtls_aes_encrypt_ctr(v->key, v->pt, v->len, v->iv, s_out, t), NOXTLS_RETURN_SUCCESS);
            }
            UTNOX_MEM_EQUAL(s_out, v->ct, v->len);
            if (pass == 0U) {
                UTNOX_EQUALS(g_wb.aes_computations > before, 1);
            } else {
                UTNOX_EQUALS(g_wb.aes_computations, before);
            }
            if (v->mode == 0U) {
                UTNOX_EQUALS(noxtls_aes_decrypt_ecb(v->key, v->ct, v->len, NULL, s_out, t), NOXTLS_RETURN_SUCCESS);
                UTNOX_MEM_EQUAL(s_out, v->pt, v->len);
            } else if (v->mode == 1U) {
                UTNOX_EQUALS(noxtls_aes_decrypt_cbc(v->key, v->ct, v->len, v->iv, s_out, t), NOXTLS_RETURN_SUCCESS);
                UTNOX_MEM_EQUAL(s_out, v->pt, v->len);
            } else {
                /* CTR decryption is the encryption operation. */
            }
        }
    }
    g_wb.aes_busy = 0U;
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_lib_gcm_hardware_and_software_agree)
{
    uint32_t i;
    uint32_t pass;

    UT_SETUP();
    for (pass = 0U; pass < 2U; pass++) {
        g_wb.aes_busy = pass;
        for (i = 0U; i < k_ut_wb_gcm_count; i++) {
            const ut_wb_gcm_vec_t *v = &k_ut_wb_gcm[i];
            noxtls_aes_type_t t = type_of(v->key_len);
            uint32_t before = g_wb.aes_computations;

            memset(s_out, 0, sizeof(s_out));
            UTNOX_EQUALS(noxtls_aes_gcm_encrypt(v->key, t, v->nonce, v->aad, v->aad_len, v->pt, v->len, s_out, s_tag),
                         NOXTLS_RETURN_SUCCESS);
            UTNOX_MEM_EQUAL(s_out, v->ct, v->len);
            UTNOX_MEM_EQUAL(s_tag, v->tag, 16U);
            UTNOX_EQUALS(g_wb.aes_computations > before, (pass == 0U) ? 1 : 0);
            memset(s_out, 0, sizeof(s_out));
            UTNOX_EQUALS(noxtls_aes_gcm_decrypt(v->key, t, v->nonce, v->aad, v->aad_len, v->ct, v->len, v->tag, s_out),
                         NOXTLS_RETURN_SUCCESS);
            UTNOX_MEM_EQUAL(s_out, v->pt, v->len);
            memcpy(s_tag, v->tag, 16U);
            s_tag[7] ^= 0x10U;
            UTNOX_NOT_EQUALS(noxtls_aes_gcm_decrypt(v->key, t, v->nonce, v->aad, v->aad_len, v->ct, v->len, s_tag,
                                                    s_out), NOXTLS_RETURN_SUCCESS);
        }
    }
    g_wb.aes_busy = 0U;
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_lib_ccm_hardware_and_software_agree)
{
    uint32_t i;
    uint32_t pass;

    UT_SETUP();
    for (pass = 0U; pass < 2U; pass++) {
        g_wb.aes_busy = pass;
        for (i = 0U; i < k_ut_wb_ccm_count; i++) {
            const ut_wb_ccm_vec_t *v = &k_ut_wb_ccm[i];
            noxtls_aes_type_t t = type_of(v->key_len);
            uint32_t before = g_wb.aes_computations;

            memset(s_out, 0, sizeof(s_out));
            memset(s_tag, 0, sizeof(s_tag));
            UTNOX_EQUALS(noxtls_aes_ccm_encrypt(v->key, t, v->nonce, v->nonce_len, v->aad, v->aad_len, v->pt, v->len,
                                                s_out, s_tag, v->tag_len), NOXTLS_RETURN_SUCCESS);
            UTNOX_MEM_EQUAL(s_out, v->ct, v->len);
            UTNOX_MEM_EQUAL(s_tag, v->tag, v->tag_len);
            UTNOX_EQUALS(g_wb.aes_computations > before, (pass == 0U) ? 1 : 0);
            memset(s_out, 0, sizeof(s_out));
            UTNOX_EQUALS(noxtls_aes_ccm_decrypt(v->key, t, v->nonce, v->nonce_len, v->aad, v->aad_len, v->ct, v->len,
                                                v->tag, v->tag_len, s_out), NOXTLS_RETURN_SUCCESS);
            UTNOX_MEM_EQUAL(s_out, v->pt, v->len);
            memcpy(s_tag, v->tag, v->tag_len);
            s_tag[0] ^= 0x01U;
            UTNOX_NOT_EQUALS(noxtls_aes_ccm_decrypt(v->key, t, v->nonce, v->nonce_len, v->aad, v->aad_len, v->ct,
                                                    v->len, s_tag, v->tag_len, s_out), NOXTLS_RETURN_SUCCESS);
        }
    }
    g_wb.aes_busy = 0U;
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_lib_ccm_long_additional_data_matches_software)
{
    /* 0xFF00 bytes or more of additional data use the 6-byte length encoding: hardware and software agree. */
    static uint8_t aad[65300];
    static uint8_t ct_hw[32];
    static uint8_t ct_sw[32];
    uint8_t tag_hw[16];
    uint8_t tag_sw[16];
    const ut_wb_ccm_vec_t *v = &k_ut_wb_ccm[1];
    uint32_t i;

    UT_SETUP();
    for (i = 0U; i < sizeof(aad); i++) {
        aad[i] = (uint8_t)(i * 7U);
    }
    UTNOX_EQUALS(noxtls_aes_ccm_encrypt(v->key, type_of(v->key_len), v->nonce, v->nonce_len, aad, sizeof(aad), v->pt,
                                        v->len, ct_hw, tag_hw, v->tag_len), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(g_wb.aes_computations > 4000U, 1);
    g_wb.aes_busy = 1U;
    UTNOX_EQUALS(noxtls_aes_ccm_encrypt(v->key, type_of(v->key_len), v->nonce, v->nonce_len, aad, sizeof(aad), v->pt,
                                        v->len, ct_sw, tag_sw, v->tag_len), NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(ct_hw, ct_sw, v->len);
    UTNOX_MEM_EQUAL(tag_hw, tag_sw, v->tag_len);
    g_wb.aes_busy = 0U;
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_lib_aes192_stays_in_software)
{
    /* NIST SP 800-38A F.1.3, ECB-AES192 block 1. */
    static const uint8_t key[24] = { 0x8E, 0x73, 0xB0, 0xF7, 0xDA, 0x0E, 0x64, 0x52, 0xC8, 0x10, 0xF3, 0x2B,
                                     0x80, 0x90, 0x79, 0xE5, 0x62, 0xF8, 0xEA, 0xD2, 0x52, 0x2C, 0x6B, 0x7B };
    static const uint8_t pt[16] = { 0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96,
                                    0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A };
    static const uint8_t ct[16] = { 0xBD, 0x33, 0x4F, 0x1D, 0x6E, 0x45, 0xF2, 0x5F,
                                    0xF7, 0x12, 0xA2, 0x14, 0x57, 0x1F, 0xA5, 0xCC };

    UT_SETUP();
    UTNOX_EQUALS(noxtls_aes_encrypt_ecb(key, pt, 16U, NULL, s_out, NOXTLS_AES_192_BIT), NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(s_out, ct, 16U);
    UTNOX_EQUALS(g_wb.aes_cr_writes, 0U);
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_lib_entropy_comes_from_the_rng)
{
    uint8_t buf[16];
    noxtls_return_t rc;

    UT_SETUP();
    noxtls_drbg_set_entropy_source(NOXTLS_ENTROPY_SOURCE_AUTO);
    ut_wb_rng_script_counter(8U);
    rc = noxtls_drbg_get_entropy(buf, sizeof(buf));
    UTNOX_EQUALS(rc, NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(buf[0], 0x04U);
    UTNOX_EQUALS(buf[4], 0x15U);
    UTNOX_EQUALS(buf[12], 0x37U);
    UTNOX_EQUALS(g_wb.sem_takes, 1U);
    UT_CLEAN();
    return 0;
}
