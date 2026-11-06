/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    test_wb_aead.c
* Summary: AES1 GCM / GMAC / CCM driver tests
*****************************************************************************/

/**
 * @file test_wb_aead.c
 * @brief Known-answer, parameter and fault tests of noxtls_stm32wb_aes_gcm() / noxtls_stm32wb_aes_ccm().
 * @ingroup noxtls_stm32wb_ut
 */

#include "ut_wb_test.h"

#define T_MAX 128U

static uint8_t s_out[T_MAX];
static uint8_t s_back[T_MAX];
static uint8_t s_tag[16];

REGISTER_TEST(test_gcm_known_answers)
{
    uint32_t i;

    UT_SETUP();
    for (i = 0U; i < k_ut_wb_gcm_count; i++) {
        const ut_wb_gcm_vec_t *v = &k_ut_wb_gcm[i];

        memset(s_out, 0xEE, sizeof(s_out));
        memset(s_tag, 0, sizeof(s_tag));
        UTNOX_EQUALS(noxtls_stm32wb_aes_gcm(0U, v->key, v->key_len, v->nonce, v->aad, v->aad_len, v->pt, s_out,
                                            v->len, s_tag), NOXTLS_RETURN_SUCCESS);
        UTNOX_MEM_EQUAL(s_out, v->ct, v->len);
        UTNOX_MEM_EQUAL(s_tag, v->tag, 16U);
        UT_AES_WIPED();
        /* Decrypt + verify. */
        memcpy(s_tag, v->tag, 16U);
        UTNOX_EQUALS(noxtls_stm32wb_aes_gcm(1U, v->key, v->key_len, v->nonce, v->aad, v->aad_len, v->ct, s_back,
                                            v->len, s_tag), NOXTLS_RETURN_SUCCESS);
        UTNOX_MEM_EQUAL(s_back, v->pt, v->len);
        /* In place, both directions. */
        memcpy(s_back, v->pt, v->len);
        UTNOX_EQUALS(noxtls_stm32wb_aes_gcm(0U, v->key, v->key_len, v->nonce, v->aad, v->aad_len, s_back, s_back,
                                            v->len, s_tag), NOXTLS_RETURN_SUCCESS);
        UTNOX_MEM_EQUAL(s_back, v->ct, v->len);
        UTNOX_MEM_EQUAL(s_tag, v->tag, 16U);
        UTNOX_EQUALS(noxtls_stm32wb_aes_gcm(1U, v->key, v->key_len, v->nonce, v->aad, v->aad_len, s_back, s_back,
                                            v->len, s_tag), NOXTLS_RETURN_SUCCESS);
        UTNOX_MEM_EQUAL(s_back, v->pt, v->len);
    }
    /* The tag is always produced in encryption mode, the payload NPBLB only for GCM encryption. */
    UTNOX_EQUALS(g_wb.aes_final_mode_bad, 0U);
    UTNOX_EQUALS(g_wb.aes_final_mode_ok, k_ut_wb_gcm_count * 4U);
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_gcm_gmac_has_no_payload_buffers)
{
    /* Vector 1 is AAD only (GMAC): in / out may be NULL. */
    const ut_wb_gcm_vec_t *v = &k_ut_wb_gcm[1];

    UT_SETUP();
    UTNOX_EQUALS(v->len, 0U);
    UTNOX_EQUALS(noxtls_stm32wb_aes_gcm(0U, v->key, v->key_len, v->nonce, v->aad, v->aad_len, NULL, NULL, 0U, s_tag),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(s_tag, v->tag, 16U);
    memcpy(s_tag, v->tag, 16U);
    UTNOX_EQUALS(noxtls_stm32wb_aes_gcm(1U, v->key, v->key_len, v->nonce, v->aad, v->aad_len, NULL, NULL, 0U, s_tag),
                 NOXTLS_RETURN_SUCCESS);
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_gcm_authentication_failure_wipes_plaintext)
{
    const ut_wb_gcm_vec_t *v = &k_ut_wb_gcm[5];
    uint32_t i;
    uint8_t tag[16];

    UT_SETUP();
    for (i = 0U; i < 16U; i++) {
        memcpy(tag, v->tag, 16U);
        tag[i] = (uint8_t)(tag[i] ^ 0x01U);
        memset(s_out, 0xEE, sizeof(s_out));
        UTNOX_EQUALS(noxtls_stm32wb_aes_gcm(1U, v->key, v->key_len, v->nonce, v->aad, v->aad_len, v->ct, s_out,
                                            v->len, tag), NOXTLS_RETURN_BAD_DATA);
        for (uint32_t j = 0U; j < v->len; j++) {
            UTNOX_EQUALS(s_out[j], 0U);
        }
    }
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_gcm_rejects_bad_parameters)
{
    const ut_wb_gcm_vec_t *v = &k_ut_wb_gcm[5];
    uint8_t buf[16] = { 0 };

    UT_SETUP();
    UTNOX_EQUALS(noxtls_stm32wb_aes_gcm(0U, NULL, 16U, v->nonce, v->aad, v->aad_len, v->pt, s_out, v->len, s_tag),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_stm32wb_aes_gcm(0U, v->key, 16U, NULL, v->aad, v->aad_len, v->pt, s_out, v->len, s_tag),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_stm32wb_aes_gcm(0U, v->key, 16U, v->nonce, v->aad, v->aad_len, v->pt, s_out, v->len, NULL),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_stm32wb_aes_gcm(0U, v->key, 16U, v->nonce, NULL, 1U, v->pt, s_out, v->len, s_tag),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_stm32wb_aes_gcm(0U, v->key, 16U, v->nonce, v->aad, v->aad_len, NULL, s_out, 1U, s_tag),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_stm32wb_aes_gcm(0U, v->key, 16U, v->nonce, v->aad, v->aad_len, v->pt, NULL, 1U, s_tag),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    /* AES-192 is not in the hardware. */
    UTNOX_EQUALS(noxtls_stm32wb_aes_gcm(0U, v->key, 24U, v->nonce, v->aad, v->aad_len, v->pt, s_out, v->len, s_tag),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    /* Lengths the 32-bit final-block fields cannot carry (MAX + 1). */
    UTNOX_EQUALS(noxtls_stm32wb_aes_gcm(0U, v->key, 16U, v->nonce, buf, NOXTLS_STM32WB_CONFIG_AES_MAX_LEN + 1U,
                                        v->pt, s_out, v->len, s_tag), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_stm32wb_aes_gcm(0U, v->key, 16U, v->nonce, v->aad, v->aad_len, buf, buf,
                                        NOXTLS_STM32WB_CONFIG_AES_MAX_LEN + 1U, s_tag), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(g_wb.aes_cr_writes, 0U);
    /* Busy hardware. */
    g_wb.aes_busy = 1U;
    UTNOX_EQUALS(noxtls_stm32wb_aes_gcm(0U, v->key, 16U, v->nonce, v->aad, v->aad_len, v->pt, s_out, v->len, s_tag),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_gcm_faults_in_every_phase)
{
    /* Vector 5: 13 bytes AAD, 31 bytes payload: init, header, full block, tail block, final = 5 operations. */
    const ut_wb_gcm_vec_t *v = &k_ut_wb_gcm[5];
    uint32_t at;
    uint32_t kind;

    UT_SETUP();
    UTNOX_EQUALS(v->aad_len, 13U);
    UTNOX_EQUALS(v->len, 31U);
    for (kind = 1U; kind <= 3U; kind += 2U) {
        for (at = 1U; at <= 5U; at++) {
            ut_wb_reset();
            g_wb.aes_fault_at = at;
            g_wb.aes_fault_kind = kind;
            UTNOX_EQUALS(noxtls_stm32wb_aes_gcm(0U, v->key, v->key_len, v->nonce, v->aad, v->aad_len, v->pt, s_out,
                                                v->len, s_tag), NOXTLS_RETURN_FAILED);
            UT_AES_WIPED();
            UT_CLEAN();
        }
    }
    ut_wb_reset();
    UTNOX_EQUALS(noxtls_stm32wb_aes_gcm(0U, v->key, v->key_len, v->nonce, v->aad, v->aad_len, v->pt, s_out, v->len,
                                        s_tag), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(g_wb.aes_computations, 5U);
    return 0;
}

REGISTER_TEST(test_gcm_fault_in_first_of_several_payload_blocks)
{
    /* Vector 6: 32 bytes AAD (2 header blocks), 64 bytes payload (4 blocks): operation 4 is the first payload block. */
    const ut_wb_gcm_vec_t *v = &k_ut_wb_gcm[6];

    UT_SETUP();
    UTNOX_EQUALS(v->len, 64U);
    g_wb.aes_fault_at = 4U;
    g_wb.aes_fault_kind = 2U;
    UTNOX_EQUALS(noxtls_stm32wb_aes_gcm(0U, v->key, v->key_len, v->nonce, v->aad, v->aad_len, v->pt, s_out, v->len,
                                        s_tag), NOXTLS_RETURN_FAILED);
    UT_AES_WIPED();
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_ccm_known_answers)
{
    uint32_t i;

    UT_SETUP();
    for (i = 0U; i < k_ut_wb_ccm_count; i++) {
        const ut_wb_ccm_vec_t *v = &k_ut_wb_ccm[i];

        memset(s_out, 0xEE, sizeof(s_out));
        memset(s_tag, 0, sizeof(s_tag));
        UTNOX_EQUALS(noxtls_stm32wb_aes_ccm(0U, v->key, v->key_len, v->nonce, v->nonce_len, v->aad, v->aad_len,
                                            v->pt, s_out, v->len, s_tag, v->tag_len), NOXTLS_RETURN_SUCCESS);
        UTNOX_MEM_EQUAL(s_out, v->ct, v->len);
        UTNOX_MEM_EQUAL(s_tag, v->tag, v->tag_len);
        UT_AES_WIPED();
        memcpy(s_tag, v->tag, v->tag_len);
        UTNOX_EQUALS(noxtls_stm32wb_aes_ccm(1U, v->key, v->key_len, v->nonce, v->nonce_len, v->aad, v->aad_len,
                                            v->ct, s_back, v->len, s_tag, v->tag_len), NOXTLS_RETURN_SUCCESS);
        UTNOX_MEM_EQUAL(s_back, v->pt, v->len);
        memcpy(s_back, v->pt, v->len);
        UTNOX_EQUALS(noxtls_stm32wb_aes_ccm(0U, v->key, v->key_len, v->nonce, v->nonce_len, v->aad, v->aad_len,
                                            s_back, s_back, v->len, s_tag, v->tag_len), NOXTLS_RETURN_SUCCESS);
        UTNOX_MEM_EQUAL(s_back, v->ct, v->len);
        UTNOX_EQUALS(noxtls_stm32wb_aes_ccm(1U, v->key, v->key_len, v->nonce, v->nonce_len, v->aad, v->aad_len,
                                            s_back, s_back, v->len, s_tag, v->tag_len), NOXTLS_RETURN_SUCCESS);
        UTNOX_MEM_EQUAL(s_back, v->pt, v->len);
    }
    UTNOX_EQUALS(g_wb.aes_final_mode_bad, 0U);
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_ccm_authentication_failure_wipes_plaintext)
{
    const ut_wb_ccm_vec_t *v = &k_ut_wb_ccm[3];
    uint8_t tag[16];
    uint32_t i;

    UT_SETUP();
    for (i = 0U; i < v->tag_len; i++) {
        memcpy(tag, v->tag, v->tag_len);
        tag[i] = (uint8_t)(tag[i] ^ 0x80U);
        memset(s_out, 0xEE, sizeof(s_out));
        UTNOX_EQUALS(noxtls_stm32wb_aes_ccm(1U, v->key, v->key_len, v->nonce, v->nonce_len, v->aad, v->aad_len,
                                            v->ct, s_out, v->len, tag, v->tag_len), NOXTLS_RETURN_BAD_DATA);
        for (uint32_t j = 0U; j < v->len; j++) {
            UTNOX_EQUALS(s_out[j], 0U);
        }
    }
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_ccm_rejects_bad_parameters)
{
    const ut_wb_ccm_vec_t *v = &k_ut_wb_ccm[1];
    uint8_t buf[16] = { 0 };

    UT_SETUP();
    /* Nonce 7..13, tag 4..16 even (SP 800-38C A.1). */
    UTNOX_EQUALS(noxtls_stm32wb_aes_ccm(0U, v->key, 16U, v->nonce, 6U, v->aad, v->aad_len, v->pt, s_out, v->len,
                                        s_tag, 8U), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_stm32wb_aes_ccm(0U, v->key, 16U, v->nonce, 14U, v->aad, v->aad_len, v->pt, s_out, v->len,
                                        s_tag, 8U), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_stm32wb_aes_ccm(0U, v->key, 16U, v->nonce, 12U, v->aad, v->aad_len, v->pt, s_out, v->len,
                                        s_tag, 2U), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_stm32wb_aes_ccm(0U, v->key, 16U, v->nonce, 12U, v->aad, v->aad_len, v->pt, s_out, v->len,
                                        s_tag, 7U), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_stm32wb_aes_ccm(0U, v->key, 16U, v->nonce, 12U, v->aad, v->aad_len, v->pt, s_out, v->len,
                                        s_tag, 18U), NOXTLS_RETURN_NOT_SUPPORTED);
    /* Payload does not fit the length field: nonce 13 leaves L = 2 bytes. */
    UTNOX_EQUALS(noxtls_stm32wb_aes_ccm(0U, v->key, 16U, v->nonce, 13U, v->aad, v->aad_len, buf, buf, 65536U,
                                        s_tag, 8U), NOXTLS_RETURN_NOT_SUPPORTED);
    /* NULL arguments, missing payload buffers, AES-192, oversized AAD. */
    UTNOX_EQUALS(noxtls_stm32wb_aes_ccm(0U, NULL, 16U, v->nonce, 12U, v->aad, v->aad_len, v->pt, s_out, v->len,
                                        s_tag, 8U), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_stm32wb_aes_ccm(0U, v->key, 16U, NULL, 12U, v->aad, v->aad_len, v->pt, s_out, v->len,
                                        s_tag, 8U), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_stm32wb_aes_ccm(0U, v->key, 16U, v->nonce, 12U, v->aad, v->aad_len, v->pt, s_out, v->len,
                                        NULL, 8U), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_stm32wb_aes_ccm(0U, v->key, 16U, v->nonce, 12U, NULL, 1U, v->pt, s_out, v->len, s_tag, 8U),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_stm32wb_aes_ccm(0U, v->key, 16U, v->nonce, 12U, v->aad, v->aad_len, NULL, s_out, 1U, s_tag,
                                        8U), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_stm32wb_aes_ccm(0U, v->key, 16U, v->nonce, 12U, v->aad, v->aad_len, v->pt, NULL, 1U, s_tag,
                                        8U), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_stm32wb_aes_ccm(0U, v->key, 24U, v->nonce, 12U, v->aad, v->aad_len, v->pt, s_out, v->len,
                                        s_tag, 8U), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_stm32wb_aes_ccm(0U, v->key, 16U, v->nonce, 12U, buf, NOXTLS_STM32WB_CONFIG_AES_MAX_LEN + 1U,
                                        v->pt, s_out, v->len, s_tag, 8U), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_stm32wb_aes_ccm(0U, v->key, 16U, v->nonce, 12U, v->aad, v->aad_len, buf, buf,
                                        NOXTLS_STM32WB_CONFIG_AES_MAX_LEN + 1U, s_tag, 8U),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(g_wb.aes_cr_writes, 0U);
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_ccm_faults_in_every_phase)
{
    /* Vector 1: nonce 12, tag 8, 20 bytes AAD (22 with the length prefix = 2 blocks), 24 bytes payload:
     * init, 2 header blocks, 1 full + 1 partial payload block, final = 6 operations. */
    const ut_wb_ccm_vec_t *v = &k_ut_wb_ccm[1];
    uint32_t at;
    uint32_t kind;

    UT_SETUP();
    UTNOX_EQUALS(v->aad_len, 20U);
    UTNOX_EQUALS(v->len, 24U);
    for (kind = 1U; kind <= 3U; kind += 2U) {
        for (at = 1U; at <= 6U; at++) {
            ut_wb_reset();
            g_wb.aes_fault_at = at;
            g_wb.aes_fault_kind = kind;
            UTNOX_EQUALS(noxtls_stm32wb_aes_ccm(0U, v->key, v->key_len, v->nonce, v->nonce_len, v->aad, v->aad_len,
                                                v->pt, s_out, v->len, s_tag, v->tag_len), NOXTLS_RETURN_FAILED);
            UT_AES_WIPED();
            UT_CLEAN();
        }
    }
    ut_wb_reset();
    UTNOX_EQUALS(noxtls_stm32wb_aes_ccm(0U, v->key, v->key_len, v->nonce, v->nonce_len, v->aad, v->aad_len, v->pt,
                                        s_out, v->len, s_tag, v->tag_len), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(g_wb.aes_computations, 6U);
    return 0;
}

REGISTER_TEST(test_ccm_long_additional_data_uses_six_byte_length_prefix)
{
    /* Additional data of 0xFF00 bytes or more is encoded as 0xFF 0xFE || 32-bit length (SP 800-38C A.2.2).
     * The model has no CCM encoding check, so compare the block count: 6 + 65280 bytes = 4081 header blocks. */
    static uint8_t aad[65300];
    const ut_wb_ccm_vec_t *v = &k_ut_wb_ccm[1];
    uint32_t i;

    UT_SETUP();
    for (i = 0U; i < sizeof(aad); i++) {
        aad[i] = (uint8_t)i;
    }
    UTNOX_EQUALS(noxtls_stm32wb_aes_ccm(0U, v->key, v->key_len, v->nonce, v->nonce_len, aad, 65280U, v->pt, s_out,
                                        v->len, s_tag, v->tag_len), NOXTLS_RETURN_SUCCESS);
    /* init + ceil((6 + 65280) / 16) header + 2 payload + final. */
    UTNOX_EQUALS(g_wb.aes_computations, 1U + 4081U + 2U + 1U);
    ut_wb_reset();
    UTNOX_EQUALS(noxtls_stm32wb_aes_ccm(0U, v->key, v->key_len, v->nonce, v->nonce_len, aad, 65279U, v->pt, s_out,
                                        v->len, s_tag, v->tag_len), NOXTLS_RETURN_SUCCESS);
    /* 2 + 65279 bytes = 4081 blocks as well, but the short encoding is used. */
    UTNOX_EQUALS(g_wb.aes_computations, 1U + 4081U + 2U + 1U);
    UT_CLEAN();
    return 0;
}
