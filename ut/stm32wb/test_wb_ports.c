/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    test_wb_ports.c
* Summary: NoxTLS accelerator port tests (AES, ECC / ECDSA, DRBG entropy, big-number hook)
*****************************************************************************/

/**
 * @file test_wb_ports.c
 * @brief Tests of the noxtls_stm32wb_port_*.c hook functions and of the generic-dispatch block backend.
 * @ingroup noxtls_stm32wb_ut
 */

#include "ut_wb_test.h"

#include "drbg/noxtls_drbg.h"
#include "encryption/aes/noxtls_aes_accel.h"
#include "pkc/ecc/noxtls_ecc.h"
#include "pkc/ecc/noxtls_ecc_accel_port.h"
#include "pkc/ecdsa/noxtls_ecdsa_accel_port.h"
#include "pkc/rsa/noxtls_bn_platform.h"
#include "vendor/st/noxtls_stm32_accel.h"

static uint8_t s_out[256];
static uint8_t s_back[256];
static uint8_t s_tag[16];

/** @brief First vector of a mode with the given key and message size. */
static const ut_wb_mode_vec_t *find_mode(uint8_t mode, uint8_t key_len, uint32_t len)
{
    uint32_t i;

    for (i = 0U; i < k_ut_wb_modes_count; i++) {
        if ((k_ut_wb_modes[i].mode == mode) && (k_ut_wb_modes[i].key_len == key_len) &&
            (k_ut_wb_modes[i].len == len)) {
            return &k_ut_wb_modes[i];
        }
    }
    return NULL;
}

/** Arm a fault on the Nth engine operation counted from now. */
static void arm_fault(uint32_t at, uint32_t kind)
{
    g_wb.aes_computations = 0U;
    g_wb.aes_fault_at = at;
    g_wb.aes_fault_kind = kind;
}

static noxtls_aes_type_t type_of(uint8_t key_len)
{
    return (key_len == 16U) ? NOXTLS_AES_128_BIT : NOXTLS_AES_256_BIT;
}

REGISTER_TEST(test_port_block_ecb_and_key_size_mapping)
{
    const ut_wb_mode_vec_t *v16 = find_mode(0U, 16U, 16U);
    const ut_wb_mode_vec_t *v32 = find_mode(0U, 32U, 16U);

    UT_SETUP();
    UTNOX_IS_NOT_NULL(v16);
    UTNOX_IS_NOT_NULL(v32);
    UTNOX_EQUALS(noxtls_aes_accel_port_encrypt_block(v16->key, v16->pt, s_out, NOXTLS_AES_128_BIT),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(s_out, v16->ct, 16U);
    UTNOX_EQUALS(noxtls_aes_accel_port_decrypt_block(v32->key, v32->ct, s_out, NOXTLS_AES_256_BIT),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(s_out, v32->pt, 16U);
    /* AES-192 and an unknown selector stay in software without touching the hardware. */
    g_wb.aes_cr_writes = 0U;
    UTNOX_EQUALS(noxtls_aes_accel_port_encrypt_block(v16->key, v16->pt, s_out, NOXTLS_AES_192_BIT),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_aes_accel_port_decrypt_block(v16->key, v16->pt, s_out, (noxtls_aes_type_t)9U),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(g_wb.aes_cr_writes, 0U);
    UTNOX_EQUALS(noxtls_aes_accel_port_encrypt_block(NULL, v16->pt, s_out, NOXTLS_AES_128_BIT),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_aes_accel_port_encrypt_block(v16->key, NULL, s_out, NOXTLS_AES_128_BIT),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_aes_accel_port_encrypt_block(v16->key, v16->pt, NULL, NOXTLS_AES_128_BIT),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_port_error_policy_depends_on_aliasing)
{
    const ut_wb_mode_vec_t *v = find_mode(0U, 16U, 16U);

    UT_SETUP();
    /* Busy hardware: always software. */
    g_wb.aes_busy = 1U;
    UTNOX_EQUALS(noxtls_aes_accel_port_encrypt_block(v->key, v->pt, s_out, NOXTLS_AES_128_BIT),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    g_wb.aes_busy = 0U;
    /* Hardware error, separate buffers: the input is intact, software recomputes. */
    arm_fault(1U, 1U);
    UTNOX_EQUALS(noxtls_aes_accel_port_encrypt_block(v->key, v->pt, s_out, NOXTLS_AES_128_BIT),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    /* Hardware error, in place: the input may be gone, so the error is reported. */
    ut_wb_reset();
    arm_fault(1U, 2U);
    memcpy(s_out, v->pt, 16U);
    UTNOX_EQUALS(noxtls_aes_accel_port_encrypt_block(v->key, s_out, s_out, NOXTLS_AES_128_BIT), NOXTLS_RETURN_FAILED);
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_port_encrypt_blocks)
{
    const ut_wb_mode_vec_t *v = find_mode(0U, 16U, 64U);

    UT_SETUP();
    UTNOX_IS_NOT_NULL(v);
    UTNOX_EQUALS(noxtls_aes_accel_port_encrypt_blocks(v->key, v->pt, s_out, 4U, NOXTLS_AES_128_BIT),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(s_out, v->ct, 64U);
    UTNOX_EQUALS(noxtls_aes_accel_port_encrypt_blocks(NULL, v->pt, s_out, 4U, NOXTLS_AES_128_BIT), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_aes_accel_port_encrypt_blocks(v->key, NULL, s_out, 4U, NOXTLS_AES_128_BIT), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_aes_accel_port_encrypt_blocks(v->key, v->pt, NULL, 4U, NOXTLS_AES_128_BIT), NOXTLS_RETURN_NULL);
    /* A block count whose byte length overflows 32 bits is left to software. */
    UTNOX_EQUALS(noxtls_aes_accel_port_encrypt_blocks(v->key, v->pt, s_out, (UINT32_MAX / 16U) + 1U,
                                                      NOXTLS_AES_128_BIT), NOXTLS_RETURN_NOT_SUPPORTED);
    /* In place with a hardware fault. */
    arm_fault(2U, 1U);
    memcpy(s_out, v->pt, 64U);
    UTNOX_EQUALS(noxtls_aes_accel_port_encrypt_blocks(v->key, s_out, s_out, 4U, NOXTLS_AES_128_BIT),
                 NOXTLS_RETURN_FAILED);
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_port_modes)
{
    uint32_t i;
    uint8_t zero_iv[16] = { 0 };
    uint8_t expect[64];
    const ut_wb_mode_vec_t *c = find_mode(1U, 16U, 16U);

    UT_SETUP();
    for (i = 0U; i < k_ut_wb_modes_count; i++) {
        const ut_wb_mode_vec_t *v = &k_ut_wb_modes[i];
        noxtls_aes_accel_mode_t m = (noxtls_aes_accel_mode_t)v->mode;
        const uint8_t *iv = (v->mode == 0U) ? NULL : v->iv;

        UTNOX_EQUALS(noxtls_aes_mode_accel_port(m, 0U, v->key, type_of(v->key_len), iv, v->pt, v->len, s_out),
                     NOXTLS_RETURN_SUCCESS);
        UTNOX_MEM_EQUAL(s_out, v->ct, v->len);
        UTNOX_EQUALS(noxtls_aes_mode_accel_port(m, 1U, v->key, type_of(v->key_len), iv, v->ct, v->len, s_back),
                     NOXTLS_RETURN_SUCCESS);
        UTNOX_MEM_EQUAL(s_back, v->pt, v->len);
    }
    /* A NULL CBC IV is the zero IV: compare with an explicit zero IV through the driver. */
    UTNOX_IS_NOT_NULL(c);
    UTNOX_EQUALS(noxtls_stm32wb_aes_crypt(NOXTLS_STM32WB_AES_MODE_CBC, 0U, c->key, 16U, zero_iv, c->pt, expect, 16U),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_aes_mode_accel_port(NOXTLS_AES_ACCEL_MODE_CBC, 0U, c->key, NOXTLS_AES_128_BIT, NULL, c->pt,
                                            16U, s_out), NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(s_out, expect, 16U);
    /* Software keeps its own semantics for a NULL CTR IV, unknown modes, NULL buffers, AES-192, zero length. */
    g_wb.aes_cr_writes = 0U;
    UTNOX_EQUALS(noxtls_aes_mode_accel_port(NOXTLS_AES_ACCEL_MODE_CTR, 0U, c->key, NOXTLS_AES_128_BIT, NULL, c->pt,
                                            16U, s_out), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_aes_mode_accel_port((noxtls_aes_accel_mode_t)7, 0U, c->key, NOXTLS_AES_128_BIT, c->iv, c->pt,
                                            16U, s_out), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_aes_mode_accel_port(NOXTLS_AES_ACCEL_MODE_ECB, 0U, NULL, NOXTLS_AES_128_BIT, NULL, c->pt,
                                            16U, s_out), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_aes_mode_accel_port(NOXTLS_AES_ACCEL_MODE_ECB, 0U, c->key, NOXTLS_AES_128_BIT, NULL, NULL,
                                            16U, s_out), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_aes_mode_accel_port(NOXTLS_AES_ACCEL_MODE_ECB, 0U, c->key, NOXTLS_AES_128_BIT, NULL, c->pt,
                                            16U, NULL), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_aes_mode_accel_port(NOXTLS_AES_ACCEL_MODE_ECB, 0U, c->key, NOXTLS_AES_192_BIT, NULL, c->pt,
                                            16U, s_out), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_aes_mode_accel_port(NOXTLS_AES_ACCEL_MODE_ECB, 0U, c->key, NOXTLS_AES_128_BIT, NULL, c->pt,
                                            0U, s_out), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(g_wb.aes_cr_writes, 0U);
    /* In-place hardware error is reported, separate buffers fall back. */
    arm_fault(1U, 3U);
    UTNOX_EQUALS(noxtls_aes_mode_accel_port(NOXTLS_AES_ACCEL_MODE_ECB, 0U, c->key, NOXTLS_AES_128_BIT, NULL, c->pt,
                                            16U, s_out), NOXTLS_RETURN_NOT_SUPPORTED);
    ut_wb_reset();
    arm_fault(1U, 3U);
    memcpy(s_out, c->pt, 16U);
    UTNOX_EQUALS(noxtls_aes_mode_accel_port(NOXTLS_AES_ACCEL_MODE_ECB, 0U, c->key, NOXTLS_AES_128_BIT, NULL, s_out,
                                            16U, s_out), NOXTLS_RETURN_FAILED);
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_port_gcm)
{
    uint32_t i;
    const ut_wb_gcm_vec_t *v = &k_ut_wb_gcm[5];

    UT_SETUP();
    for (i = 0U; i < k_ut_wb_gcm_count; i++) {
        const ut_wb_gcm_vec_t *g = &k_ut_wb_gcm[i];

        UTNOX_EQUALS(noxtls_aes_gcm_encrypt_accel_port(g->key, type_of(g->key_len), g->nonce, g->aad, g->aad_len,
                                                       g->pt, g->len, s_out, s_tag), NOXTLS_RETURN_SUCCESS);
        UTNOX_MEM_EQUAL(s_out, g->ct, g->len);
        UTNOX_MEM_EQUAL(s_tag, g->tag, 16U);
        UTNOX_EQUALS(noxtls_aes_gcm_decrypt_accel_port(g->key, type_of(g->key_len), g->nonce, g->aad, g->aad_len,
                                                       g->ct, g->len, g->tag, s_back), NOXTLS_RETURN_SUCCESS);
        UTNOX_MEM_EQUAL(s_back, g->pt, g->len);
    }
    /* Authentication failure is a final answer. */
    memcpy(s_tag, v->tag, 16U);
    s_tag[3] ^= 1U;
    UTNOX_EQUALS(noxtls_aes_gcm_decrypt_accel_port(v->key, type_of(v->key_len), v->nonce, v->aad, v->aad_len, v->ct,
                                                   v->len, s_tag, s_back), NOXTLS_RETURN_BAD_DATA);
    /* No tag, AES-192. */
    UTNOX_EQUALS(noxtls_aes_gcm_decrypt_accel_port(v->key, NOXTLS_AES_128_BIT, v->nonce, v->aad, v->aad_len, v->ct,
                                                   v->len, NULL, s_back), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_aes_gcm_encrypt_accel_port(v->key, NOXTLS_AES_192_BIT, v->nonce, v->aad, v->aad_len, v->pt,
                                                   v->len, s_out, s_tag), NOXTLS_RETURN_NOT_SUPPORTED);
    /* Hardware fault: software for separate buffers, error for in-place. */
    arm_fault(2U, 1U);
    UTNOX_EQUALS(noxtls_aes_gcm_encrypt_accel_port(v->key, NOXTLS_AES_128_BIT, v->nonce, v->aad, v->aad_len, v->pt,
                                                   v->len, s_out, s_tag), NOXTLS_RETURN_NOT_SUPPORTED);
    arm_fault(2U, 1U);
    memcpy(s_out, v->ct, v->len);
    UTNOX_EQUALS(noxtls_aes_gcm_decrypt_accel_port(v->key, NOXTLS_AES_128_BIT, v->nonce, v->aad, v->aad_len, s_out,
                                                   v->len, v->tag, s_out), NOXTLS_RETURN_FAILED);
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_port_ccm)
{
    uint32_t i;
    const ut_wb_ccm_vec_t *v = &k_ut_wb_ccm[1];
    uint8_t tag[16];

    UT_SETUP();
    for (i = 0U; i < k_ut_wb_ccm_count; i++) {
        const ut_wb_ccm_vec_t *c = &k_ut_wb_ccm[i];

        UTNOX_EQUALS(noxtls_aes_ccm_encrypt_accel_port(c->key, type_of(c->key_len), c->nonce, c->nonce_len, c->aad,
                                                       c->aad_len, c->pt, c->len, s_out, s_tag, c->tag_len),
                     NOXTLS_RETURN_SUCCESS);
        UTNOX_MEM_EQUAL(s_out, c->ct, c->len);
        UTNOX_MEM_EQUAL(s_tag, c->tag, c->tag_len);
        UTNOX_EQUALS(noxtls_aes_ccm_decrypt_accel_port(c->key, type_of(c->key_len), c->nonce, c->nonce_len, c->aad,
                                                       c->aad_len, c->ct, c->len, c->tag, c->tag_len, s_back),
                     NOXTLS_RETURN_SUCCESS);
        UTNOX_MEM_EQUAL(s_back, c->pt, c->len);
    }
    memcpy(tag, v->tag, v->tag_len);
    tag[0] ^= 1U;
    UTNOX_EQUALS(noxtls_aes_ccm_decrypt_accel_port(v->key, type_of(v->key_len), v->nonce, v->nonce_len, v->aad,
                                                   v->aad_len, v->ct, v->len, tag, v->tag_len, s_back),
                 NOXTLS_RETURN_BAD_DATA);
    UTNOX_EQUALS(noxtls_aes_ccm_decrypt_accel_port(v->key, type_of(v->key_len), v->nonce, v->nonce_len, v->aad,
                                                   v->aad_len, v->ct, v->len, NULL, v->tag_len, s_back),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_aes_ccm_decrypt_accel_port(v->key, type_of(v->key_len), v->nonce, v->nonce_len, v->aad,
                                                   v->aad_len, v->ct, v->len, v->tag, 17U, s_back),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_aes_ccm_encrypt_accel_port(v->key, NOXTLS_AES_192_BIT, v->nonce, v->nonce_len, v->aad,
                                                   v->aad_len, v->pt, v->len, s_out, s_tag, v->tag_len),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    arm_fault(3U, 2U);
    UTNOX_EQUALS(noxtls_aes_ccm_encrypt_accel_port(v->key, NOXTLS_AES_128_BIT, v->nonce, v->nonce_len, v->aad,
                                                   v->aad_len, v->pt, v->len, s_out, s_tag, v->tag_len),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    ut_wb_reset();
    arm_fault(3U, 2U);
    memcpy(s_out, v->pt, v->len);
    UTNOX_EQUALS(noxtls_aes_ccm_encrypt_accel_port(v->key, NOXTLS_AES_128_BIT, v->nonce, v->nonce_len, v->aad,
                                                   v->aad_len, s_out, v->len, s_out, s_tag, v->tag_len),
                 NOXTLS_RETURN_FAILED);
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_port_aead_in_place_success)
{
    const ut_wb_gcm_vec_t *g = &k_ut_wb_gcm[5];
    const ut_wb_ccm_vec_t *c = &k_ut_wb_ccm[1];

    UT_SETUP();
    memcpy(s_out, g->pt, g->len);
    UTNOX_EQUALS(noxtls_aes_gcm_encrypt_accel_port(g->key, NOXTLS_AES_128_BIT, g->nonce, g->aad, g->aad_len, s_out,
                                                   g->len, s_out, s_tag), NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(s_out, g->ct, g->len);
    UTNOX_EQUALS(noxtls_aes_gcm_decrypt_accel_port(g->key, NOXTLS_AES_128_BIT, g->nonce, g->aad, g->aad_len, s_out,
                                                   g->len, g->tag, s_out), NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(s_out, g->pt, g->len);
    memcpy(s_out, c->pt, c->len);
    UTNOX_EQUALS(noxtls_aes_ccm_encrypt_accel_port(c->key, NOXTLS_AES_128_BIT, c->nonce, c->nonce_len, c->aad,
                                                   c->aad_len, s_out, c->len, s_out, s_tag, c->tag_len),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(s_out, c->ct, c->len);
    UTNOX_EQUALS(noxtls_aes_ccm_decrypt_accel_port(c->key, NOXTLS_AES_128_BIT, c->nonce, c->nonce_len, c->aad,
                                                   c->aad_len, s_out, c->len, c->tag, c->tag_len, s_out),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(s_out, c->pt, c->len);
    /* In-place CCM decryption with a hardware fault is an error, not a software fallback. */
    memcpy(s_out, c->ct, c->len);
    arm_fault(3U, 1U);
    UTNOX_EQUALS(noxtls_aes_ccm_decrypt_accel_port(c->key, NOXTLS_AES_128_BIT, c->nonce, c->nonce_len, c->aad,
                                                   c->aad_len, s_out, c->len, c->tag, c->tag_len, s_out),
                 NOXTLS_RETURN_FAILED);
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_generic_dispatch_block_backend)
{
    const ut_wb_mode_vec_t *v = find_mode(0U, 32U, 16U);

    UT_SETUP();
    UTNOX_EQUALS(noxtls_aes_accel_stm32wb_encrypt_block(v->key, v->pt, s_out, NOXTLS_AES_256_BIT),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(s_out, v->ct, 16U);
    UTNOX_EQUALS(noxtls_aes_accel_stm32wb_decrypt_block(v->key, v->ct, s_out, NOXTLS_AES_256_BIT),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(s_out, v->pt, 16U);
    UTNOX_EQUALS(noxtls_aes_accel_stm32wb_encrypt_block(v->key, v->pt, s_out, NOXTLS_AES_192_BIT),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_aes_accel_stm32wb_decrypt_block(v->key, v->pt, s_out, (noxtls_aes_type_t)5U),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_aes_accel_stm32wb_encrypt_block(v->key, v->pt, s_out, NOXTLS_AES_128_BIT),
                 NOXTLS_RETURN_SUCCESS);
    UT_CLEAN();
    return 0;
}

/* ------------------------------------------------------------------------- */
/* DRBG entropy and big-number hook                                           */
/* ------------------------------------------------------------------------- */

REGISTER_TEST(test_port_entropy_hook)
{
    uint8_t buf[8];

    UT_SETUP();
    ut_wb_rng_script_counter(4U);
    UTNOX_EQUALS(noxtls_drbg_entropy_accel_port(buf, sizeof(buf)), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(buf[0], 0x04U);
    UTNOX_EQUALS(buf[4], 0x15U);
    UTNOX_EQUALS(noxtls_drbg_entropy_accel_port(NULL, 4U), NOXTLS_RETURN_NOT_SUPPORTED);
    ut_wb_cpu2_take(NOXTLS_STM32WB_CONFIG_HSEM_ID_RNG);
    UTNOX_EQUALS(noxtls_drbg_entropy_accel_port(buf, sizeof(buf)), NOXTLS_RETURN_NOT_SUPPORTED);
    g_wb.sem_owner[NOXTLS_STM32WB_CONFIG_HSEM_ID_RNG] = 0U;
    g_wb.rng_pos = g_wb.rng_n;
    UTNOX_EQUALS(noxtls_drbg_entropy_accel_port(buf, sizeof(buf)), NOXTLS_RETURN_NOT_SUPPORTED);
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_port_bn_modexp_hook)
{
    static uint8_t out[400];
    const ut_wb_modexp_vec_t *v = &k_ut_wb_modexp[1];
    uint8_t even[32];

    UT_SETUP();
    noxtls_bn_platform_register(NULL);
    UTNOX_EQUALS(noxtls_bn_platform_try_mod_exp(out, v->base, v->exp, v->exp_len, v->mod, v->mod_len),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    noxtls_stm32wb_bn_register();
    UTNOX_EQUALS(noxtls_bn_platform_try_mod_exp(out, v->base, v->exp, v->exp_len, v->mod, v->mod_len),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(out, v->res, v->mod_len);
    /* Even modulus and hardware errors fall back to the portable code. */
    memcpy(even, v->mod, 32U);
    even[31] &= 0xFEU;
    UTNOX_EQUALS(noxtls_bn_platform_try_mod_exp(out, v->base, v->exp, v->exp_len, even, 32U),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    g_wb.pka_never_end = 1U;
    UTNOX_EQUALS(noxtls_bn_platform_try_mod_exp(out, v->base, v->exp, v->exp_len, v->mod, v->mod_len),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    /* Only the exponentiation is hooked. */
    UTNOX_EQUALS(noxtls_bn_platform_try_mod(out, v->base, 32U, v->mod, 32U), NOXTLS_RETURN_NOT_SUPPORTED);
    noxtls_bn_platform_register(NULL);
    return 0;
}

/* ------------------------------------------------------------------------- */
/* ECC / ECDSA                                                                */
/* ------------------------------------------------------------------------- */

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

static ecc_curve_params_t s_curve;
static ecc_key_t s_key;
static ecc_point_t s_pt;
static ecc_point_t s_res;
static ecdsa_signature_t s_sig;

static void ecc_setup(void)
{
    UT_SETUP();
    memset(&s_curve, 0, sizeof(s_curve));
    s_curve.p = k_p;
    s_curve.a = k_a;
    s_curve.b = k_b;
    s_curve.n = k_n;
    s_curve.size = 32U;
    s_curve.n_size = 32U;
    memset(&s_key, 0, sizeof(s_key));
    s_key.d = (uint8_t *)(uintptr_t)p256_d;
    s_key.curve = &s_curve;
    memcpy(s_key.Q.x, p256_qx, 32U);
    memcpy(s_key.Q.y, p256_qy, 32U);
    s_key.Q.size = 32U;
    memset(&s_pt, 0, sizeof(s_pt));
    memset(&s_res, 0, sizeof(s_res));
    memset(&s_sig, 0, sizeof(s_sig));
}

REGISTER_TEST(test_port_point_multiply)
{
    uint32_t i;
    int32_t last_rc;

    ecc_setup();
    UTNOX_EQUALS(noxtls_ecc_accel_input_echo_ok(), 1);
    for (i = 0U; i < k_ut_wb_mul_count; i++) {
        const ut_wb_mul_vec_t *v = &k_ut_wb_mul[i];

        memcpy(s_pt.x, v->px, 32U);
        memcpy(s_pt.y, v->py, 32U);
        s_pt.size = 32U;
        UTNOX_EQUALS(noxtls_ecc_point_multiply_accel_port(&s_res, v->k, &s_pt, &s_curve), NOXTLS_RETURN_SUCCESS);
        UTNOX_MEM_EQUAL(s_res.x, v->rx, 32U);
        UTNOX_MEM_EQUAL(s_res.y, v->ry, 32U);
        UTNOX_EQUALS(s_res.size, 32U);
    }
    UTNOX_EQUALS(noxtls_ecc_accel_is_ready(), 1);
    UTNOX_EQUALS(noxtls_ecc_accel_operation_count() >= k_ut_wb_mul_count, 1);
    UTNOX_EQUALS(noxtls_ecc_accel_last_rc(), (int32_t)NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_ecc_accel_last_stage(), 2U);
    {
        uint32_t fb = noxtls_ecc_accel_fallback_count();

        noxtls_ecc_accel_note_fallback();
        UTNOX_EQUALS(noxtls_ecc_accel_fallback_count(), fb + 1U);
    }
    last_rc = noxtls_ecc_accel_last_rc();
    UTNOX_EQUALS(last_rc, (int32_t)NOXTLS_RETURN_SUCCESS);
    (void)noxtls_ecc_accel_last_status();
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_port_point_multiply_declines)
{
    const ut_wb_mul_vec_t *v = &k_ut_wb_mul[1];
    uint8_t p2[32];
    ecc_curve_params_t other;

    ecc_setup();
    memcpy(s_pt.x, v->px, 32U);
    memcpy(s_pt.y, v->py, 32U);
    s_pt.size = 32U;
    UTNOX_EQUALS(noxtls_ecc_point_multiply_accel_port(NULL, v->k, &s_pt, &s_curve), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_ecc_point_multiply_accel_port(&s_res, NULL, &s_pt, &s_curve), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_ecc_point_multiply_accel_port(&s_res, v->k, NULL, &s_curve), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_ecc_point_multiply_accel_port(&s_res, v->k, &s_pt, NULL), NOXTLS_RETURN_NOT_SUPPORTED);
    other = s_curve;
    other.size = 48U;
    UTNOX_EQUALS(noxtls_ecc_point_multiply_accel_port(&s_res, v->k, &s_pt, &other), NOXTLS_RETURN_NOT_SUPPORTED);
    memcpy(p2, k_p, 32U);
    p2[31] ^= 1U;
    other = s_curve;
    other.p = p2;
    UTNOX_EQUALS(noxtls_ecc_point_multiply_accel_port(&s_res, v->k, &s_pt, &other), NOXTLS_RETURN_NOT_SUPPORTED);
    s_pt.size = 31U;
    UTNOX_EQUALS(noxtls_ecc_point_multiply_accel_port(&s_res, v->k, &s_pt, &s_curve), NOXTLS_RETURN_NOT_SUPPORTED);
    s_pt.size = 32U;
    UTNOX_EQUALS(g_wb.pka_starts, 0U);
    /* Busy / failing PKA: the portable code recomputes (NOT_SUPPORTED is the only fallback trigger). */
    g_wb.pka_busy = 1U;
    UTNOX_EQUALS(noxtls_ecc_point_multiply_accel_port(&s_res, v->k, &s_pt, &s_curve), NOXTLS_RETURN_NOT_SUPPORTED);
    g_wb.pka_busy = 0U;
    g_wb.pka_never_end = 1U;
    UTNOX_EQUALS(noxtls_ecc_point_multiply_accel_port(&s_res, v->k, &s_pt, &s_curve), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_ecc_accel_last_rc(), (int32_t)NOXTLS_RETURN_NOT_SUPPORTED);
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_port_ecdsa_sign)
{
    uint32_t i;

    ecc_setup();
    for (i = 0U; i < k_ut_wb_sign_count; i++) {
        const ut_wb_sign_vec_t *v = &k_ut_wb_sign[i];

        ut_wb_stub_reset();
        ut_wb_stub_rng_push(v->k);
        UTNOX_EQUALS(noxtls_ecdsa_sign_accel_port(&s_key, v->e, 32U, &s_sig), NOXTLS_RETURN_SUCCESS);
        UTNOX_MEM_EQUAL(s_sig.r, v->r, 32U);
        UTNOX_MEM_EQUAL(s_sig.s, v->s, 32U);
        UTNOX_EQUALS(s_sig.size, 32U);
        UTNOX_EQUALS(ut_wb_stub_rng_calls(), 1U);
    }
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_port_ecdsa_sign_nonce_selection_and_retries)
{
    const ut_wb_sign_vec_t *v = &k_ut_wb_sign[0];
    uint8_t zero[32] = { 0 };
    uint8_t ones[32];
    uint8_t above[32];
    uint8_t other[32];

    ecc_setup();
    memset(ones, 0xFF, 32U);
    memcpy(above, k_n, 32U);
    above[31] = (uint8_t)(k_n[31] + 1U);   /* n + 1 > n */
    memcpy(other, v->k, 32U);
    other[0] ^= 0x40U;
    /* k = 0, k = n, k = n + 1 and k = 2^256 - 1 are all rejected before the PKA is used. */
    ut_wb_stub_reset();
    ut_wb_stub_rng_push(zero);
    ut_wb_stub_rng_push(k_n);
    ut_wb_stub_rng_push(above);
    ut_wb_stub_rng_push(ones);
    ut_wb_stub_rng_push(v->k);
    g_wb.pka_starts = 0U;
    UTNOX_EQUALS(noxtls_ecdsa_sign_accel_port(&s_key, v->e, 32U, &s_sig), NOXTLS_RETURN_NOT_SUPPORTED);
    /* Attempts are bounded: four nonces drawn, none usable. */
    UTNOX_EQUALS(ut_wb_stub_rng_calls(), NOXTLS_STM32WB_CONFIG_ECDSA_SIGN_ATTEMPTS);
    UTNOX_EQUALS(g_wb.pka_starts, 0U);
    /* A rejected nonce followed by a good one. */
    ut_wb_stub_reset();
    ut_wb_stub_rng_push(zero);
    ut_wb_stub_rng_push(v->k);
    UTNOX_EQUALS(noxtls_ecdsa_sign_accel_port(&s_key, v->e, 32U, &s_sig), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(ut_wb_stub_rng_calls(), 2U);
    /* The PKA reports an operation error for the first nonce: a fresh one is drawn. */
    ut_wb_stub_reset();
    ut_wb_stub_rng_push(other);
    ut_wb_stub_rng_push(v->k);
    g_wb.pka_starts = 0U;
    UTNOX_EQUALS(noxtls_ecdsa_sign_accel_port(&s_key, v->e, 32U, &s_sig), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(g_wb.pka_starts, 2U);
    UTNOX_MEM_EQUAL(s_sig.r, v->r, 32U);
    /* A PKA that keeps failing ends in software after the attempt limit. */
    ut_wb_stub_reset();
    ut_wb_stub_rng_push(other);
    g_wb.pka_starts = 0U;
    UTNOX_EQUALS(noxtls_ecdsa_sign_accel_port(&s_key, v->e, 32U, &s_sig), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(g_wb.pka_starts, NOXTLS_STM32WB_CONFIG_ECDSA_SIGN_ATTEMPTS);
    /* Busy PKA: software at once. */
    ut_wb_stub_reset();
    ut_wb_stub_rng_push(v->k);
    g_wb.pka_busy = 1U;
    UTNOX_EQUALS(noxtls_ecdsa_sign_accel_port(&s_key, v->e, 32U, &s_sig), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(ut_wb_stub_rng_calls(), 1U);
    g_wb.pka_busy = 0U;
    /* DRBG failure. */
    ut_wb_stub_reset();
    ut_wb_stub_rng_fail();
    UTNOX_EQUALS(noxtls_ecdsa_sign_accel_port(&s_key, v->e, 32U, &s_sig), NOXTLS_RETURN_NOT_SUPPORTED);
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_port_ecdsa_sign_declines)
{
    const ut_wb_sign_vec_t *v = &k_ut_wb_sign[0];
    ecc_key_t key;
    ecc_curve_params_t other;

    ecc_setup();
    ut_wb_stub_rng_push(v->k);
    UTNOX_EQUALS(noxtls_ecdsa_sign_accel_port(NULL, v->e, 32U, &s_sig), NOXTLS_RETURN_NOT_SUPPORTED);
    key = s_key;
    key.d = NULL;
    UTNOX_EQUALS(noxtls_ecdsa_sign_accel_port(&key, v->e, 32U, &s_sig), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_ecdsa_sign_accel_port(&s_key, NULL, 32U, &s_sig), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_ecdsa_sign_accel_port(&s_key, v->e, 32U, NULL), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_ecdsa_sign_accel_port(&s_key, v->e, 31U, &s_sig), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_ecdsa_sign_accel_port(&s_key, v->e, 48U, &s_sig), NOXTLS_RETURN_NOT_SUPPORTED);
    other = s_curve;
    other.size = 66U;
    key = s_key;
    key.curve = &other;
    UTNOX_EQUALS(noxtls_ecdsa_sign_accel_port(&key, v->e, 32U, &s_sig), NOXTLS_RETURN_NOT_SUPPORTED);
    key.curve = NULL;
    UTNOX_EQUALS(noxtls_ecdsa_sign_accel_port(&key, v->e, 32U, &s_sig), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(ut_wb_stub_rng_calls(), 0U);
    UT_CLEAN();
    return 0;
}

REGISTER_TEST(test_port_ecdsa_verify)
{
    const ut_wb_verify_vec_t *v = &k_ut_wb_verify[0];
    ecc_key_t key;
    ecdsa_signature_t sig;
    uint8_t e[32];

    ecc_setup();
    memcpy(sig.r, v->r, 32U);
    memcpy(sig.s, v->s, 32U);
    sig.size = 32U;
    UTNOX_EQUALS(noxtls_ecdsa_verify_accel_port(&s_key, v->e, 32U, &sig), NOXTLS_RETURN_SUCCESS);
    /* A signature the hardware rejects is a final failure. */
    memcpy(e, v->e, 32U);
    e[5] ^= 1U;
    UTNOX_EQUALS(noxtls_ecdsa_verify_accel_port(&s_key, e, 32U, &sig), NOXTLS_RETURN_FAILED);
    /* Declines. */
    UTNOX_EQUALS(noxtls_ecdsa_verify_accel_port(NULL, v->e, 32U, &sig), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_ecdsa_verify_accel_port(&s_key, NULL, 32U, &sig), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_ecdsa_verify_accel_port(&s_key, v->e, 32U, NULL), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_ecdsa_verify_accel_port(&s_key, v->e, 20U, &sig), NOXTLS_RETURN_NOT_SUPPORTED);
    key = s_key;
    key.curve = NULL;
    UTNOX_EQUALS(noxtls_ecdsa_verify_accel_port(&key, v->e, 32U, &sig), NOXTLS_RETURN_NOT_SUPPORTED);
    key = s_key;
    memcpy(key.Q.x, p256_bad_x, 32U);
    UTNOX_EQUALS(noxtls_ecdsa_verify_accel_port(&key, v->e, 32U, &sig), NOXTLS_RETURN_NOT_SUPPORTED);
    g_wb.pka_busy = 1U;
    UTNOX_EQUALS(noxtls_ecdsa_verify_accel_port(&s_key, v->e, 32U, &sig), NOXTLS_RETURN_NOT_SUPPORTED);
    g_wb.pka_busy = 0U;
    g_wb.pka_never_end = 1U;
    UTNOX_EQUALS(noxtls_ecdsa_verify_accel_port(&s_key, v->e, 32U, &sig), NOXTLS_RETURN_NOT_SUPPORTED);
    UT_CLEAN();
    return 0;
}
