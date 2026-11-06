/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    test_wb_pka.c
* Summary: PKA driver tests (P-256 multiply, point check, ECDSA, modular exponentiation)
*****************************************************************************/

/**
 * @file test_wb_pka.c
 * @brief Known-answer, parameter, busy and fault tests of the noxtls_stm32wb_pka_* functions.
 * @ingroup noxtls_stm32wb_ut
 */

#include "ut_wb_test.h"
#include "ut_wb_ref.h"

/** NIST P-256 domain (SP 800-186), written independently of the driver tables. */
static const uint8_t k_p[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static const uint8_t k_a[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC};
static const uint8_t k_b[32] = {
    0x5A, 0xC6, 0x35, 0xD8, 0xAA, 0x3A, 0x93, 0xE7, 0xB3, 0xEB, 0xBD, 0x55, 0x76, 0x98, 0x86, 0xBC,
    0x65, 0x1D, 0x06, 0xB0, 0xCC, 0x53, 0xB0, 0xF6, 0x3B, 0xCE, 0x3C, 0x3E, 0x27, 0xD2, 0x60, 0x4B};
static const uint8_t k_n[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51};

static uint8_t s_rx[32];
static uint8_t s_ry[32];
static uint8_t s_r[32];
static uint8_t s_s[32];

/** The PKA RAM and control register hold no operand after a call. */
static int pka_wiped(void)
{
    uint32_t i;

    for (i = 0U; i < UT_WB_PKA_WORDS; i++) {
        if (g_wb.pka_ram[i] != 0U) {
            return 0;
        }
    }
    return (g_wb.pka_cr == 0U) ? 1 : 0;
}

REGISTER_TEST(test_pka_is_p256_identifies_the_domain)
{
    uint8_t p[32];
    uint8_t a[32];
    uint8_t b[32];
    uint8_t n[32];
    uint32_t i;

    UT_SETUP();
    UTNOX_EQUALS(noxtls_stm32wb_pka_is_p256(k_p, k_a, k_b, k_n), 1U);
    UTNOX_EQUALS(noxtls_stm32wb_pka_is_p256(NULL, k_a, k_b, k_n), 0U);
    UTNOX_EQUALS(noxtls_stm32wb_pka_is_p256(k_p, NULL, k_b, k_n), 0U);
    UTNOX_EQUALS(noxtls_stm32wb_pka_is_p256(k_p, k_a, NULL, k_n), 0U);
    UTNOX_EQUALS(noxtls_stm32wb_pka_is_p256(k_p, k_a, k_b, NULL), 0U);
    for (i = 0U; i < 32U; i += 31U) {
        memcpy(p, k_p, 32U);
        memcpy(a, k_a, 32U);
        memcpy(b, k_b, 32U);
        memcpy(n, k_n, 32U);
        p[i] ^= 1U;
        UTNOX_EQUALS(noxtls_stm32wb_pka_is_p256(p, k_a, k_b, k_n), 0U);
        a[i] ^= 1U;
        UTNOX_EQUALS(noxtls_stm32wb_pka_is_p256(k_p, a, k_b, k_n), 0U);
        b[i] ^= 1U;
        UTNOX_EQUALS(noxtls_stm32wb_pka_is_p256(k_p, k_a, b, k_n), 0U);
        n[i] ^= 1U;
        UTNOX_EQUALS(noxtls_stm32wb_pka_is_p256(k_p, k_a, k_b, n), 0U);
    }
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_pka_scalar_multiply_known_answers)
{
    uint32_t i;
    const noxtls_stm32wb_pka_stats_t *st = noxtls_stm32wb_pka_stats();
    uint32_t ops0;

    UT_SETUP();
    ops0 = st->operations;
    for (i = 0U; i < k_ut_wb_mul_count; i++) {
        const ut_wb_mul_vec_t *v = &k_ut_wb_mul[i];

        g_wb.pka_starts = 0U;
        UTNOX_EQUALS(noxtls_stm32wb_pka_p256_mul(v->k, v->px, v->py, s_rx, s_ry), NOXTLS_RETURN_SUCCESS);
        UTNOX_MEM_EQUAL(s_rx, v->rx, 32U);
        UTNOX_MEM_EQUAL(s_ry, v->ry, 32U);
        /* Multiply plus the point check of the result. */
        UTNOX_EQUALS(g_wb.pka_starts, 2U);
        UTNOX_EQUALS(g_wb.pka_last_mode, 0x28U);
        UTNOX_EQUALS(pka_wiped(), 1);
        UTNOX_EQUALS(g_wb.sem_takes, i + 1U);
        UTNOX_EQUALS(g_wb.sem_releases, i + 1U);
    }
    UTNOX_EQUALS(st->operations - ops0, k_ut_wb_mul_count);
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_pka_scalar_multiply_scalar_width)
{
    /* k = 1 (1 bit) and k = 0xFF (8 bits): the bit length written is the exact one, the model checks it. */
    UT_SETUP();
    UTNOX_EQUALS(noxtls_stm32wb_pka_p256_mul(k_ut_wb_mul[0].k, k_ut_wb_mul[0].px, k_ut_wb_mul[0].py, s_rx, s_ry),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(g_wb.proto_err, 0U);
    UTNOX_EQUALS(noxtls_stm32wb_pka_p256_mul(k_ut_wb_mul[4].k, k_ut_wb_mul[4].px, k_ut_wb_mul[4].py, s_rx, s_ry),
                 NOXTLS_RETURN_SUCCESS);
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_pka_scalar_multiply_rejections)
{
    uint8_t zero[32] = { 0 };
    const ut_wb_mul_vec_t *v = &k_ut_wb_mul[1];
    const noxtls_stm32wb_pka_stats_t *st = noxtls_stm32wb_pka_stats();
    uint32_t declined0;

    UT_SETUP();
    declined0 = st->declined;
    UTNOX_EQUALS(noxtls_stm32wb_pka_p256_mul(NULL, v->px, v->py, s_rx, s_ry), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_stm32wb_pka_p256_mul(v->k, NULL, v->py, s_rx, s_ry), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_stm32wb_pka_p256_mul(v->k, v->px, NULL, s_rx, s_ry), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_stm32wb_pka_p256_mul(v->k, v->px, v->py, NULL, s_ry), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_stm32wb_pka_p256_mul(v->k, v->px, v->py, s_rx, NULL), NOXTLS_RETURN_NOT_SUPPORTED);
    /* A zero scalar is not sent to the hardware. */
    UTNOX_EQUALS(noxtls_stm32wb_pka_p256_mul(zero, v->px, v->py, s_rx, s_ry), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(g_wb.pka_starts, 0U);
    /* PKA busy / owned by CPU2. */
    g_wb.pka_busy = 1U;
    UTNOX_EQUALS(noxtls_stm32wb_pka_p256_mul(v->k, v->px, v->py, s_rx, s_ry), NOXTLS_RETURN_NOT_SUPPORTED);
    g_wb.pka_busy = 0U;
    ut_wb_cpu2_take(NOXTLS_STM32WB_CONFIG_HSEM_ID_PKA);
    UTNOX_EQUALS(noxtls_stm32wb_pka_p256_mul(v->k, v->px, v->py, s_rx, s_ry), NOXTLS_RETURN_NOT_SUPPORTED);
    g_wb.sem_owner[NOXTLS_STM32WB_CONFIG_HSEM_ID_PKA] = 0U;
    UTNOX_EQUALS(st->declined - declined0, 8U);
    UTNOX_EQUALS(g_wb.pka_starts, 0U);
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_pka_scalar_multiply_hardware_errors)
{
    const ut_wb_mul_vec_t *v = &k_ut_wb_mul[1];
    const noxtls_stm32wb_pka_stats_t *st = noxtls_stm32wb_pka_stats();
    uint32_t errs0;
    static const uint8_t k7[32] = { [31] = 7 };
    static uint8_t bad_x[32];
    ut_wb_mul_vec_t bad[1];

    UT_SETUP();
    errs0 = st->hw_errors;
    g_wb.pka_never_end = 1U;
    UTNOX_EQUALS(noxtls_stm32wb_pka_p256_mul(v->k, v->px, v->py, s_rx, s_ry), NOXTLS_RETURN_FAILED);
    UTNOX_EQUALS(pka_wiped(), 1);
    g_wb.pka_never_end = 0U;
    g_wb.pka_ramerr = 1U;
    UTNOX_EQUALS(noxtls_stm32wb_pka_p256_mul(v->k, v->px, v->py, s_rx, s_ry), NOXTLS_RETURN_FAILED);
    g_wb.pka_ramerr = 0U;
    g_wb.pka_addrerr = 1U;
    UTNOX_EQUALS(noxtls_stm32wb_pka_p256_mul(v->k, v->px, v->py, s_rx, s_ry), NOXTLS_RETURN_FAILED);
    g_wb.pka_addrerr = 0U;
    /* The multiply works, the point check of the result fails in hardware. */
    g_wb.pka_starts = 0U;
    g_wb.pka_fault_start = 2U;
    UTNOX_EQUALS(noxtls_stm32wb_pka_p256_mul(v->k, v->px, v->py, s_rx, s_ry), NOXTLS_RETURN_FAILED);
    g_wb.pka_fault_start = 0U;
    /* Outputs are wiped on failure. */
    memset(s_rx, 0xAA, 32U);
    g_wb.pka_never_end = 1U;
    UTNOX_EQUALS(noxtls_stm32wb_pka_p256_mul(v->k, v->px, v->py, s_rx, s_ry), NOXTLS_RETURN_FAILED);
    g_wb.pka_never_end = 0U;
    UTNOX_EQUALS(s_rx[0], 0U);
    UTNOX_EQUALS(s_rx[31], 0U);
    UTNOX_EQUALS(st->hw_errors - errs0, 5U);
    /* A result that is not on the curve is rejected by the point check. */
    memcpy(bad_x, v->rx, 32U);
    bad_x[31] ^= 1U;
    bad[0].k = k7;
    bad[0].px = v->px;
    bad[0].py = v->py;
    bad[0].rx = bad_x;
    bad[0].ry = v->ry;
    g_wb.mul_tab = bad;
    g_wb.mul_n = 1U;
    {
        uint32_t chk0 = st->check_failures;

        UTNOX_EQUALS(noxtls_stm32wb_pka_p256_mul(k7, v->px, v->py, s_rx, s_ry), NOXTLS_RETURN_FAILED);
        UTNOX_EQUALS(st->check_failures - chk0, 1U);
    }
    UTNOX_EQUALS(s_ry[0], 0U);
    /* A scalar the model does not know returns (0, 0): the point at infinity is left to software. */
    g_wb.mul_n = 0U;
    UTNOX_EQUALS(noxtls_stm32wb_pka_p256_mul(k7, v->px, v->py, s_rx, s_ry), NOXTLS_RETURN_NOT_SUPPORTED);
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_pka_scalar_multiply_half_zero_result_is_not_infinity)
{
    static const uint8_t k7[32] = { [31] = 7 };
    static const uint8_t zero[32] = { 0 };
    const ut_wb_mul_vec_t *v = &k_ut_wb_mul[1];
    ut_wb_mul_vec_t tab[1];

    UT_SETUP();
    /* (0, y) is not the (0, 0) infinity encoding: it goes to the point check, which rejects it. */
    tab[0].k = k7;
    tab[0].px = v->px;
    tab[0].py = v->py;
    tab[0].rx = zero;
    tab[0].ry = v->ry;
    g_wb.mul_tab = tab;
    g_wb.mul_n = 1U;
    UTNOX_EQUALS(noxtls_stm32wb_pka_p256_mul(k7, v->px, v->py, s_rx, s_ry), NOXTLS_RETURN_FAILED);
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_pka_point_check)
{
    static const uint8_t big_x[32] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

    UT_SETUP();
    UTNOX_EQUALS(noxtls_stm32wb_pka_p256_check(k_ut_wb_mul[0].rx, k_ut_wb_mul[0].ry), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_stm32wb_pka_p256_check(p256_qx, p256_qy), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_stm32wb_pka_p256_check(p256_bad_x, p256_qy), NOXTLS_RETURN_BAD_DATA);
    UTNOX_EQUALS(noxtls_stm32wb_pka_p256_check(big_x, p256_qy), NOXTLS_RETURN_BAD_DATA);
    UTNOX_EQUALS(noxtls_stm32wb_pka_p256_check(p256_qx, big_x), NOXTLS_RETURN_BAD_DATA);
    UTNOX_EQUALS(pka_wiped(), 1);
    g_wb.pka_force_check = 1U;
    UTNOX_EQUALS(noxtls_stm32wb_pka_p256_check(p256_qx, p256_qy), NOXTLS_RETURN_BAD_DATA);
    g_wb.pka_force_check = 2U;
    UTNOX_EQUALS(noxtls_stm32wb_pka_p256_check(p256_bad_x, p256_qy), NOXTLS_RETURN_SUCCESS);
    g_wb.pka_force_check = 0U;
    UTNOX_EQUALS(noxtls_stm32wb_pka_p256_check(NULL, p256_qy), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_stm32wb_pka_p256_check(p256_qx, NULL), NOXTLS_RETURN_NOT_SUPPORTED);
    g_wb.pka_busy = 1U;
    UTNOX_EQUALS(noxtls_stm32wb_pka_p256_check(p256_qx, p256_qy), NOXTLS_RETURN_NOT_SUPPORTED);
    g_wb.pka_busy = 0U;
    g_wb.pka_never_end = 1U;
    UTNOX_EQUALS(noxtls_stm32wb_pka_p256_check(p256_qx, p256_qy), NOXTLS_RETURN_FAILED);
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_pka_ecdsa_sign_known_answers)
{
    uint32_t i;

    UT_SETUP();
    for (i = 0U; i < k_ut_wb_sign_count; i++) {
        const ut_wb_sign_vec_t *v = &k_ut_wb_sign[i];

        UTNOX_EQUALS(noxtls_stm32wb_pka_p256_sign(v->d, v->k, v->e, s_r, s_s), NOXTLS_RETURN_SUCCESS);
        UTNOX_MEM_EQUAL(s_r, v->r, 32U);
        UTNOX_MEM_EQUAL(s_s, v->s, 32U);
        UTNOX_EQUALS(pka_wiped(), 1);
    }
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_pka_ecdsa_sign_failures)
{
    const ut_wb_sign_vec_t *v = &k_ut_wb_sign[0];
    uint8_t other_k[32];

    UT_SETUP();
    UTNOX_EQUALS(noxtls_stm32wb_pka_p256_sign(NULL, v->k, v->e, s_r, s_s), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_stm32wb_pka_p256_sign(v->d, NULL, v->e, s_r, s_s), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_stm32wb_pka_p256_sign(v->d, v->k, NULL, s_r, s_s), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_stm32wb_pka_p256_sign(v->d, v->k, v->e, NULL, s_s), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_stm32wb_pka_p256_sign(v->d, v->k, v->e, s_r, NULL), NOXTLS_RETURN_NOT_SUPPORTED);
    g_wb.pka_busy = 1U;
    UTNOX_EQUALS(noxtls_stm32wb_pka_p256_sign(v->d, v->k, v->e, s_r, s_s), NOXTLS_RETURN_NOT_SUPPORTED);
    g_wb.pka_busy = 0U;
    /* The PKA reports an operation error (r or s zero): the caller must retry with a new nonce. */
    memcpy(other_k, v->k, 32U);
    other_k[0] ^= 0x40U;
    memset(s_r, 0xAA, 32U);
    UTNOX_EQUALS(noxtls_stm32wb_pka_p256_sign(v->d, other_k, v->e, s_r, s_s), NOXTLS_RETURN_FAILED);
    UTNOX_EQUALS(s_r[0], 0U);
    g_wb.pka_force_sign_err = 1U;
    UTNOX_EQUALS(noxtls_stm32wb_pka_p256_sign(v->d, v->k, v->e, s_r, s_s), NOXTLS_RETURN_FAILED);
    g_wb.pka_force_sign_err = 0U;
    /* An all-zero signature is never accepted even with a clear error word. */
    g_wb.pka_force_sign_zero = 1U;
    UTNOX_EQUALS(noxtls_stm32wb_pka_p256_sign(v->d, v->k, v->e, s_r, s_s), NOXTLS_RETURN_FAILED);
    g_wb.pka_force_sign_zero = 0U;
    g_wb.pka_never_end = 1U;
    UTNOX_EQUALS(noxtls_stm32wb_pka_p256_sign(v->d, v->k, v->e, s_r, s_s), NOXTLS_RETURN_FAILED);
    UTNOX_EQUALS(pka_wiped(), 1);
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_pka_ecdsa_sign_zero_s_only_is_rejected)
{
    /* r valid but s zero: build a one-entry table. */
    static uint8_t zero_s[32];
    ut_wb_sign_vec_t tab[1];
    const ut_wb_sign_vec_t *v = &k_ut_wb_sign[0];

    UT_SETUP();
    tab[0] = *v;
    tab[0].s = zero_s;
    g_wb.sign_tab = tab;
    g_wb.sign_n = 1U;
    UTNOX_EQUALS(noxtls_stm32wb_pka_p256_sign(v->d, v->k, v->e, s_r, s_s), NOXTLS_RETURN_FAILED);
    /* s valid but r zero. */
    tab[0] = *v;
    tab[0].r = zero_s;
    UTNOX_EQUALS(noxtls_stm32wb_pka_p256_sign(v->d, v->k, v->e, s_r, s_s), NOXTLS_RETURN_FAILED);
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_pka_ecdsa_verify)
{
    uint32_t i;
    uint8_t e[32];
    uint8_t r[32];

    UT_SETUP();
    for (i = 0U; i < k_ut_wb_verify_count; i++) {
        const ut_wb_verify_vec_t *v = &k_ut_wb_verify[i];

        g_wb.pka_starts = 0U;
        UTNOX_EQUALS(noxtls_stm32wb_pka_p256_verify(v->qx, v->qy, v->e, v->r, v->s), NOXTLS_RETURN_SUCCESS);
        /* Public-key check, then the verification. */
        UTNOX_EQUALS(g_wb.pka_starts, 2U);
        UTNOX_EQUALS(g_wb.pka_last_mode, 0x26U);
        memcpy(e, v->e, 32U);
        e[31] ^= 1U;
        UTNOX_EQUALS(noxtls_stm32wb_pka_p256_verify(v->qx, v->qy, e, v->r, v->s), NOXTLS_RETURN_BAD_DATA);
        memcpy(r, v->r, 32U);
        r[0] ^= 1U;
        UTNOX_EQUALS(noxtls_stm32wb_pka_p256_verify(v->qx, v->qy, v->e, r, v->s), NOXTLS_RETURN_BAD_DATA);
        UTNOX_EQUALS(pka_wiped(), 1);
    }
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_pka_ecdsa_verify_failures)
{
    const ut_wb_verify_vec_t *v = &k_ut_wb_verify[0];

    UT_SETUP();
    UTNOX_EQUALS(noxtls_stm32wb_pka_p256_verify(NULL, v->qy, v->e, v->r, v->s), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_stm32wb_pka_p256_verify(v->qx, NULL, v->e, v->r, v->s), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_stm32wb_pka_p256_verify(v->qx, v->qy, NULL, v->r, v->s), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_stm32wb_pka_p256_verify(v->qx, v->qy, v->e, NULL, v->s), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_stm32wb_pka_p256_verify(v->qx, v->qy, v->e, v->r, NULL), NOXTLS_RETURN_NOT_SUPPORTED);
    g_wb.pka_busy = 1U;
    UTNOX_EQUALS(noxtls_stm32wb_pka_p256_verify(v->qx, v->qy, v->e, v->r, v->s), NOXTLS_RETURN_NOT_SUPPORTED);
    g_wb.pka_busy = 0U;
    /* A public key off the curve is not a verdict on the signature: software decides, and no verify is run. */
    g_wb.pka_starts = 0U;
    UTNOX_EQUALS(noxtls_stm32wb_pka_p256_verify(p256_bad_x, v->qy, v->e, v->r, v->s), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(g_wb.pka_starts, 1U);
    /* Hardware error during the key check, and during the verification. */
    g_wb.pka_starts = 0U;
    g_wb.pka_fault_start = 1U;
    UTNOX_EQUALS(noxtls_stm32wb_pka_p256_verify(v->qx, v->qy, v->e, v->r, v->s), NOXTLS_RETURN_FAILED);
    UTNOX_EQUALS(g_wb.pka_starts, 1U);
    g_wb.pka_starts = 0U;
    g_wb.pka_fault_start = 2U;
    UTNOX_EQUALS(noxtls_stm32wb_pka_p256_verify(v->qx, v->qy, v->e, v->r, v->s), NOXTLS_RETURN_FAILED);
    g_wb.pka_fault_start = 0U;
    g_wb.pka_force_verify = 1U;
    UTNOX_EQUALS(noxtls_stm32wb_pka_p256_verify(v->qx, v->qy, v->e, v->r, v->s), NOXTLS_RETURN_BAD_DATA);
    g_wb.pka_force_verify = 2U;
    UTNOX_EQUALS(noxtls_stm32wb_pka_p256_verify(v->qx, v->qy, v->r, v->r, v->s), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(pka_wiped(), 1);
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_pka_modexp_known_answers)
{
    static uint8_t out[400];
    uint32_t i;

    UT_SETUP();
    for (i = 0U; i < k_ut_wb_modexp_count; i++) {
        const ut_wb_modexp_vec_t *v = &k_ut_wb_modexp[i];

        memset(out, 0xEE, sizeof(out));
        UTNOX_EQUALS(noxtls_stm32wb_pka_modexp(out, v->base, v->exp, v->exp_len, v->mod, v->mod_len),
                     NOXTLS_RETURN_SUCCESS);
        UTNOX_MEM_EQUAL(out, v->res, v->mod_len);
        UTNOX_EQUALS(pka_wiped(), 1);
    }
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_pka_modexp_strips_leading_zero_bytes)
{
    static uint8_t out[40];
    /* 33-byte modulus whose first byte is zero: a 256-bit operation, the zero byte is restored in the result. */
    const ut_wb_modexp_vec_t *v = &k_ut_wb_modexp[2];

    UT_SETUP();
    UTNOX_EQUALS(v->mod[0], 0U);
    UTNOX_EQUALS(noxtls_stm32wb_pka_modexp(out, v->base, v->exp, v->exp_len, v->mod, v->mod_len),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(g_wb.pka_op_bits, 256U);
    UTNOX_EQUALS(out[0], 0U);
    UTNOX_MEM_EQUAL(out, v->res, v->mod_len);
    /* Leading zero bytes of the exponent are dropped too: exponent 00 00 03. */
    {
        static const uint8_t exp3[3] = { 0, 0, 3 };
        uint8_t expect[8];
        uint8_t got[8];
        const ut_wb_modexp_vec_t *w = &k_ut_wb_modexp[0];

        ut_ref_modexp(expect, w->base, &exp3[2], 1U, w->mod, 8U);
        UTNOX_EQUALS(noxtls_stm32wb_pka_modexp(got, w->base, exp3, 3U, w->mod, 8U), NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(g_wb.pka_exp_bits, 8U);
        UTNOX_MEM_EQUAL(got, expect, 8U);
    }
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_pka_modexp_rejections)
{
    static uint8_t big[400];
    static uint8_t out[400];
    const ut_wb_modexp_vec_t *v = &k_ut_wb_modexp[0];
    uint8_t even[8];
    uint8_t base_hi[8];
    uint8_t short_mod[9] = { 0, 0, 0, 0, 0, 0, 0, 0, 0x0B };
    uint8_t zero_exp[2] = { 0, 0 };
    uint8_t base9[9] = { 0 };
    const noxtls_stm32wb_pka_stats_t *st = noxtls_stm32wb_pka_stats();
    uint32_t declined0;

    UT_SETUP();
    declined0 = st->declined;
    memset(big, 0x11, sizeof(big));
    big[399] = 0x11U;
    UTNOX_EQUALS(noxtls_stm32wb_pka_modexp(NULL, v->base, v->exp, v->exp_len, v->mod, v->mod_len),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_stm32wb_pka_modexp(out, NULL, v->exp, v->exp_len, v->mod, v->mod_len),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_stm32wb_pka_modexp(out, v->base, NULL, v->exp_len, v->mod, v->mod_len),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_stm32wb_pka_modexp(out, v->base, v->exp, v->exp_len, NULL, v->mod_len),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    /* Modulus below 8 bytes and above 392 bytes; exponent 0 and above 392 bytes bytes. */
    UTNOX_EQUALS(noxtls_stm32wb_pka_modexp(out, v->base, v->exp, v->exp_len, v->mod, 7U), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_stm32wb_pka_modexp(out, big, v->exp, v->exp_len, big, 393U), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_stm32wb_pka_modexp(out, v->base, v->exp, 0U, v->mod, v->mod_len), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_stm32wb_pka_modexp(out, v->base, big, 393U, v->mod, v->mod_len), NOXTLS_RETURN_NOT_SUPPORTED);
    /* Even modulus (Montgomery needs odd). */
    memcpy(even, v->mod, 8U);
    even[7] &= 0xFEU;
    UTNOX_EQUALS(noxtls_stm32wb_pka_modexp(out, v->base, v->exp, v->exp_len, even, 8U), NOXTLS_RETURN_NOT_SUPPORTED);
    /* base >= modulus (equal and greater). */
    UTNOX_EQUALS(noxtls_stm32wb_pka_modexp(out, v->mod, v->exp, v->exp_len, v->mod, 8U), NOXTLS_RETURN_NOT_SUPPORTED);
    memset(base_hi, 0xFF, 8U);
    UTNOX_EQUALS(noxtls_stm32wb_pka_modexp(out, base_hi, v->exp, v->exp_len, v->mod, 8U), NOXTLS_RETURN_NOT_SUPPORTED);
    /* Modulus shorter than 8 bytes once its leading zeros are dropped, zero exponent. */
    UTNOX_EQUALS(noxtls_stm32wb_pka_modexp(out, base9, v->exp, v->exp_len, short_mod, 9U), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_stm32wb_pka_modexp(out, v->base, zero_exp, 2U, v->mod, 8U), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(st->declined - declined0, 13U);
    UTNOX_EQUALS(g_wb.pka_starts, 0U);
    /* Busy, owned by CPU2, hardware error. */
    g_wb.pka_busy = 1U;
    UTNOX_EQUALS(noxtls_stm32wb_pka_modexp(out, v->base, v->exp, v->exp_len, v->mod, v->mod_len),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    g_wb.pka_busy = 0U;
    g_wb.pka_never_end = 1U;
    UTNOX_EQUALS(noxtls_stm32wb_pka_modexp(out, v->base, v->exp, v->exp_len, v->mod, v->mod_len),
                 NOXTLS_RETURN_FAILED);
    UTNOX_EQUALS(pka_wiped(), 1);
    UT_CLEAN();
    return 0;
}
