/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    test_wb_aes.c
* Summary: AES1 ECB / CBC / CTR driver tests
*****************************************************************************/

/**
 * @file test_wb_aes.c
 * @brief Known-answer, parameter, busy and fault tests of noxtls_stm32wb_aes_crypt().
 * @ingroup noxtls_stm32wb_ut
 */

#include "ut_wb_test.h"

/** Largest vector message. */
#define T_MAX 256U

static uint8_t s_buf[T_MAX];
static uint8_t s_out[T_MAX];

REGISTER_TEST(test_aes_modes_known_answers)
{
    uint32_t i;
    const noxtls_stm32wb_aes_stats_t *st = noxtls_stm32wb_aes_stats();
    uint32_t ops0;

    UT_SETUP();
    ops0 = st->operations;
    for (i = 0U; i < k_ut_wb_modes_count; i++) {
        const ut_wb_mode_vec_t *v = &k_ut_wb_modes[i];
        const uint8_t *iv = (v->mode == NOXTLS_STM32WB_AES_MODE_ECB) ? NULL : v->iv;

        memset(s_out, 0, sizeof(s_out));
        UTNOX_EQUALS(noxtls_stm32wb_aes_crypt(v->mode, 0U, v->key, v->key_len, iv, v->pt, s_out, v->len),
                     NOXTLS_RETURN_SUCCESS);
        UTNOX_MEM_EQUAL(s_out, v->ct, v->len);
        UT_AES_WIPED();
        /* Decrypt (CTR decrypt is the same operation). */
        memset(s_out, 0, sizeof(s_out));
        UTNOX_EQUALS(noxtls_stm32wb_aes_crypt(v->mode, 1U, v->key, v->key_len, iv, v->ct, s_out, v->len),
                     NOXTLS_RETURN_SUCCESS);
        UTNOX_MEM_EQUAL(s_out, v->pt, v->len);
        UT_AES_WIPED();
        /* In place. */
        memcpy(s_buf, v->pt, v->len);
        UTNOX_EQUALS(noxtls_stm32wb_aes_crypt(v->mode, 0U, v->key, v->key_len, iv, s_buf, s_buf, v->len),
                     NOXTLS_RETURN_SUCCESS);
        UTNOX_MEM_EQUAL(s_buf, v->ct, v->len);
        memcpy(s_buf, v->ct, v->len);
        UTNOX_EQUALS(noxtls_stm32wb_aes_crypt(v->mode, 1U, v->key, v->key_len, iv, s_buf, s_buf, v->len),
                     NOXTLS_RETURN_SUCCESS);
        UTNOX_MEM_EQUAL(s_buf, v->pt, v->len);
    }
    UTNOX_EQUALS(st->operations - ops0, k_ut_wb_modes_count * 4U);
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_aes_key_registers_follow_rm0434_order)
{
    uint8_t key[32];
    uint8_t blk[16] = { 0 };
    uint32_t i;

    UT_SETUP();
    for (i = 0U; i < 32U; i++) {
        key[i] = (uint8_t)(i + 1U);
    }
    /* The wipe hides the registers after the call, so look at them from inside the operation. */
    UTNOX_EQUALS(noxtls_stm32wb_aes_open(key, 32U, 0U, blk), NOXTLS_RETURN_SUCCESS);
    /* First key word (bytes 01..04) lands in the highest key register, KEYR7. */
    UTNOX_EQUALS(g_wb.aes_key[7], 0x01020304U);
    UTNOX_EQUALS(g_wb.aes_key[0], 0x1D1E1F20U);
    UTNOX_EQUALS(g_wb.aes_cr & 0x40000U, 0x40000U);
    UTNOX_EQUALS(g_wb.aes_iv[3], 0U);
    noxtls_stm32wb_aes_close();
    UTNOX_EQUALS(noxtls_stm32wb_aes_open(key, 16U, 0U, NULL), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(g_wb.aes_key[3], 0x01020304U);
    UTNOX_EQUALS(g_wb.aes_key[0], 0x0D0E0F10U);
    UTNOX_EQUALS(g_wb.aes_cr & 0x40000U, 0U);
    noxtls_stm32wb_aes_close();
    UT_AES_WIPED();
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_aes_rejects_bad_parameters)
{
    const uint8_t key[32] = { 1 };
    const uint8_t iv[16] = { 2 };
    const noxtls_stm32wb_aes_stats_t *st = noxtls_stm32wb_aes_stats();
    uint32_t declined0;

    UT_SETUP();
    declined0 = st->declined;
    /* Key size the hardware lacks (AES-192) and nonsense sizes. */
    UTNOX_EQUALS(noxtls_stm32wb_aes_crypt(NOXTLS_STM32WB_AES_MODE_ECB, 0U, key, 24U, NULL, s_buf, s_out, 16U),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_stm32wb_aes_crypt(NOXTLS_STM32WB_AES_MODE_ECB, 0U, key, 0U, NULL, s_buf, s_out, 16U),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_stm32wb_aes_crypt(NOXTLS_STM32WB_AES_MODE_ECB, 0U, key, 33U, NULL, s_buf, s_out, 16U),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    /* Unknown mode, zero length, partial blocks for ECB / CBC. */
    UTNOX_EQUALS(noxtls_stm32wb_aes_crypt(3U, 0U, key, 16U, iv, s_buf, s_out, 16U), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_stm32wb_aes_crypt(NOXTLS_STM32WB_AES_MODE_ECB, 0U, key, 16U, NULL, s_buf, s_out, 0U),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_stm32wb_aes_crypt(NOXTLS_STM32WB_AES_MODE_ECB, 0U, key, 16U, NULL, s_buf, s_out, 17U),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_stm32wb_aes_crypt(NOXTLS_STM32WB_AES_MODE_CBC, 0U, key, 16U, iv, s_buf, s_out, 15U),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    /* Missing IV for CBC / CTR. */
    UTNOX_EQUALS(noxtls_stm32wb_aes_crypt(NOXTLS_STM32WB_AES_MODE_CBC, 0U, key, 16U, NULL, s_buf, s_out, 16U),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_stm32wb_aes_crypt(NOXTLS_STM32WB_AES_MODE_CTR, 0U, key, 16U, NULL, s_buf, s_out, 16U),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    /* NULL buffers. */
    UTNOX_EQUALS(noxtls_stm32wb_aes_crypt(NOXTLS_STM32WB_AES_MODE_ECB, 0U, NULL, 16U, NULL, s_buf, s_out, 16U),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_stm32wb_aes_crypt(NOXTLS_STM32WB_AES_MODE_ECB, 0U, key, 16U, NULL, NULL, s_out, 16U),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_stm32wb_aes_crypt(NOXTLS_STM32WB_AES_MODE_ECB, 0U, key, 16U, NULL, s_buf, NULL, 16U),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(st->declined - declined0, 12U);
    /* None of the above touched the hardware. */
    UTNOX_EQUALS(g_wb.aes_cr_writes, 0U);
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_aes_minimum_and_maximum_lengths)
{
    static uint8_t big[4096];
    static uint8_t big_out[4096];
    const uint8_t key[16] = { 7 };
    const uint8_t iv[16] = { 9 };
    uint8_t one[1] = { 0x5A };
    uint8_t one_out[1];
    uint32_t i;

    UT_SETUP();
    for (i = 0U; i < sizeof(big); i++) {
        big[i] = (uint8_t)i;
    }
    /* MIN: one byte of CTR; one block of ECB. */
    UTNOX_EQUALS(noxtls_stm32wb_aes_crypt(NOXTLS_STM32WB_AES_MODE_CTR, 0U, key, 16U, iv, one, one_out, 1U),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_stm32wb_aes_crypt(NOXTLS_STM32WB_AES_MODE_CTR, 0U, key, 16U, iv, one_out, one, 1U),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(one[0], 0x5AU);
    /* Large buffers round trip in every mode. */
    for (i = 0U; i < 3U; i++) {
        UTNOX_EQUALS(noxtls_stm32wb_aes_crypt(i, 0U, key, 16U, (i == 0U) ? NULL : iv, big, big_out, sizeof(big)),
                     NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(noxtls_stm32wb_aes_crypt(i, 1U, key, 16U, (i == 0U) ? NULL : iv, big_out, big_out, sizeof(big)),
                     NOXTLS_RETURN_SUCCESS);
        UTNOX_MEM_EQUAL(big_out, big, sizeof(big));
    }
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_aes_busy_hardware_and_semaphore_fall_back)
{
    const uint8_t key[16] = { 1 };
    const noxtls_stm32wb_aes_stats_t *st = noxtls_stm32wb_aes_stats();
    uint32_t declined0;

    UT_SETUP();
    declined0 = st->declined;
    /* SR.BUSY set: nothing is started and the lock is released again. */
    g_wb.aes_busy = 1U;
    UTNOX_EQUALS(noxtls_stm32wb_aes_crypt(NOXTLS_STM32WB_AES_MODE_ECB, 0U, key, 16U, NULL, s_buf, s_out, 16U),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(g_wb.aes_cr_writes, 0U);
    g_wb.aes_busy = 0U;
    UTNOX_EQUALS(noxtls_stm32wb_aes_crypt(NOXTLS_STM32WB_AES_MODE_ECB, 0U, key, 16U, NULL, s_buf, s_out, 16U),
                 NOXTLS_RETURN_SUCCESS);
    /* AES1 already owned by this CPU. */
    UTNOX_EQUALS(noxtls_stm32wb_lock(NOXTLS_STM32WB_RES_AES1), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_stm32wb_aes_crypt(NOXTLS_STM32WB_AES_MODE_ECB, 0U, key, 16U, NULL, s_buf, s_out, 16U),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    noxtls_stm32wb_unlock(NOXTLS_STM32WB_RES_AES1);
    UTNOX_EQUALS(st->declined - declined0, 2U);
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_aes_hardware_faults_are_reported_and_cleaned_up)
{
    const uint8_t key[32] = { 3 };
    const uint8_t iv[16] = { 4 };
    const noxtls_stm32wb_aes_stats_t *st = noxtls_stm32wb_aes_stats();
    uint32_t errs0;
    uint32_t kind;
    uint32_t at;

    UT_SETUP();
    errs0 = st->hw_errors;
    /* Fail the first, a middle and the partial last block with a read error, a write error and a hang. */
    for (kind = 1U; kind <= 3U; kind++) {
        for (at = 1U; at <= 3U; at++) {
            ut_wb_reset();
            g_wb.aes_fault_at = at;
            g_wb.aes_fault_kind = kind;
            UTNOX_EQUALS(noxtls_stm32wb_aes_crypt(NOXTLS_STM32WB_AES_MODE_CTR, 0U, key, 32U, iv, s_buf, s_out, 40U),
                         NOXTLS_RETURN_FAILED);
            UT_AES_WIPED();
            UTNOX_EQUALS(g_wb.aes_rderr + g_wb.aes_wrerr, 0U);
            UT_CLEAN();
        }
    }
    UTNOX_EQUALS(st->hw_errors - errs0, 9U);
    /* The next request after a fault works. */
    ut_wb_reset();
    UTNOX_EQUALS(noxtls_stm32wb_aes_crypt(NOXTLS_STM32WB_AES_MODE_ECB, 0U, key, 32U, NULL, s_buf, s_out, 16U),
                 NOXTLS_RETURN_SUCCESS);
    return 0;
}

REGISTER_TEST(test_aes_ctr_reloads_iv_across_32bit_wrap)
{
    /* Counter block ...FFFFFFFF: the hardware wraps its 32-bit counter, the driver carries into byte 11. */
    uint8_t iv[16] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    const uint8_t key[16] = { 5 };
    uint8_t zero[48] = { 0 };
    uint8_t ks[48];
    uint8_t first[16];
    uint8_t second[16];
    uint8_t expect_iv[16];

    UT_SETUP();
    memcpy(expect_iv, iv, 16U);
    expect_iv[11] = 0U;
    expect_iv[10] = 11U;
    expect_iv[12] = expect_iv[13] = expect_iv[14] = expect_iv[15] = 0U;
    UTNOX_EQUALS(noxtls_stm32wb_aes_crypt(NOXTLS_STM32WB_AES_MODE_CTR, 0U, key, 16U, iv, zero, ks, 48U),
                 NOXTLS_RETURN_SUCCESS);
    /* Keystream blocks 0 and 1 are E(K, iv) and E(K, iv + 1) with a full 128-bit increment. */
    UTNOX_EQUALS(noxtls_stm32wb_aes_crypt(NOXTLS_STM32WB_AES_MODE_ECB, 0U, key, 16U, NULL, iv, first, 16U),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_stm32wb_aes_crypt(NOXTLS_STM32WB_AES_MODE_ECB, 0U, key, 16U, NULL, expect_iv, second, 16U),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(ks, first, 16U);
    UTNOX_MEM_EQUAL(&ks[16], second, 16U);
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_aes_ctr_fault_before_the_counter_wrap_chunk_ends)
{
    /* Counter ...FFFFFFFF: the first chunk is one block, so a fault in it leaves data unprocessed. */
    uint8_t iv[16] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0xFF, 0xFF, 0xFF, 0xFF };
    const uint8_t key[16] = { 6 };

    UT_SETUP();
    g_wb.aes_fault_at = 1U;
    g_wb.aes_fault_kind = 1U;
    UTNOX_EQUALS(noxtls_stm32wb_aes_crypt(NOXTLS_STM32WB_AES_MODE_CTR, 0U, key, 16U, iv, s_buf, s_out, 32U),
                 NOXTLS_RETURN_FAILED);
    UT_AES_WIPED();
    UT_CLEAN();
    return 0;
}
