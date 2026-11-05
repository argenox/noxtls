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
* File:    test_efr32_se.c
* Summary: Tests of the Secure Engine mailbox transport, TRNG, SHA-2 and ECC commands
*
*****************************************************************************/

/**
 * @file test_efr32_se.c
 * @brief Mailbox message layout, response mapping, bounded waits and the hung state;
 *        TRNG, SHA-256 / SHA-512 block compression, point multiplication and ECDSA
 *        against FIPS 180-4, SEC 1 / SP 800-186 and RFC 6979 vectors.
 * @ingroup noxtls_efr32_ut
 */

#include <stdint.h>
#include <string.h>

#include "runner.h"
#include "test_assert.h"

#include "ut_efr32_mock.h"

/** P-256 generator x. */
static const char * const s_gx = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
/** P-256 generator y. */
static const char * const s_gy = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
/** 2 * G, x. */
static const char * const s_g2x = "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978";
/** 2 * G, y. */
static const char * const s_g2y = "07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1";
/** RFC 6979 A.2.5 private key. */
static const char * const s_d = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";
/** RFC 6979 A.2.5 public key x. */
static const char * const s_qx = "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6";
/** RFC 6979 A.2.5 public key y. */
static const char * const s_qy = "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299";
/** SHA-256("sample"). */
static const char * const s_h = "af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf";
/** RFC 6979 A.2.5 r. */
static const char * const s_r = "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716";
/** RFC 6979 A.2.5 s. */
static const char * const s_s = "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8";

REGISTER_TEST(test_se_xfer_and_link)
{
    noxtls_efr32_se_xfer_t a;
    noxtls_efr32_se_xfer_t b;

    ut_setup();
    noxtls_efr32_se_xfer_set(&a, g_ut_ram.in, 0x10000005U);
    UTNOX_EQUALS(a.data, (uint32_t)(uintptr_t)g_ut_ram.in);
    UTNOX_EQUALS(a.next, NOXTLS_EFR32_SE_XFER_STOP);
    /* The length field is masked so flags cannot be injected; REALIGN is always set. */
    UTNOX_EQUALS(a.length, 5U | NOXTLS_EFR32_SE_XFER_REALIGN);
    noxtls_efr32_se_xfer_set(&b, NULL, 0U);
    UTNOX_EQUALS(b.data, 0U);
    UTNOX_EQUALS(b.length, NOXTLS_EFR32_SE_XFER_REALIGN);
    noxtls_efr32_se_xfer_link(&a, &b);
    UTNOX_EQUALS(a.next, (uint32_t)(uintptr_t)&b);
    return 0;
}

REGISTER_TEST(test_se_response_mapping)
{
    ut_setup();
    UTNOX_EQUALS(noxtls_efr32_se_map_response(NOXTLS_EFR32_SE_RESP_OK), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_efr32_se_map_response(NOXTLS_EFR32_SE_RESP_INVALID_SIG), NOXTLS_RETURN_BAD_DATA);
    UTNOX_EQUALS(noxtls_efr32_se_map_response(NOXTLS_EFR32_SE_RESP_INVALID_PARAM), NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_EQUALS(noxtls_efr32_se_map_response(NOXTLS_EFR32_SE_RESP_INVALID_CMD), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_efr32_se_map_response(NOXTLS_EFR32_SE_RESP_AUTH_ERROR), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_efr32_se_map_response(NOXTLS_EFR32_SE_RESP_NOT_INIT), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_efr32_se_map_response(NOXTLS_EFR32_SE_RESP_ABORT), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_efr32_se_map_response(NOXTLS_EFR32_SE_RESP_BUS_ERROR), NOXTLS_RETURN_FAILED);
    UTNOX_EQUALS(noxtls_efr32_se_map_response(NOXTLS_EFR32_SE_RESP_INTERNAL), NOXTLS_RETURN_FAILED);
    UTNOX_EQUALS(noxtls_efr32_se_map_response(NOXTLS_EFR32_SE_RESP_CRYPTO_ERROR), NOXTLS_RETURN_FAILED);
    UTNOX_EQUALS(noxtls_efr32_se_map_response(NOXTLS_EFR32_SE_RESP_SELFTEST), NOXTLS_RETURN_FAILED);
    UTNOX_EQUALS(noxtls_efr32_se_map_response(0x00080000U), NOXTLS_RETURN_FAILED);
    return 0;
}

REGISTER_TEST(test_se_run_message_layout_and_waits)
{
    noxtls_efr32_se_cmd_t cmd;
    static noxtls_efr32_se_xfer_t out;

    ut_setup();
    (void)memset(&cmd, 0, sizeof(cmd));
    noxtls_efr32_se_xfer_set(&out, g_ut_ram.out, 8U);
    cmd.command = NOXTLS_EFR32_SE_CMD_TRNG;
    cmd.out = &out;
    cmd.params[0] = 8U;
    cmd.nparams = 1U;
    UTNOX_EQUALS(noxtls_efr32_se_acquire(), NOXTLS_RETURN_SUCCESS);
    /* Room and the response after a few polls: the waits are bounded loops, not fixed delays. */
    g_ut.sem_tx_polls = 5U;
    g_ut.sem_rx_polls = 5U;
    UTNOX_EQUALS(noxtls_efr32_se_run(&cmd, 100U), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(g_ut.se_last_cmd, NOXTLS_EFR32_SE_CMD_TRNG);
    UTNOX_EQUALS(g_ut.se_last_nparams, 1U);
    UTNOX_EQUALS(g_ut.se_last_params[0], 8U);
    UTNOX_EQUALS(g_ut.sem_nwords, 4U);
    UTNOX_EQUALS(g_ut.sem_words[1], 0U);
    UTNOX_EQUALS(g_ut.sem_words[2], (uint32_t)(uintptr_t)&out);
    /* Too many parameters. */
    cmd.nparams = NOXTLS_EFR32_SEM_PARAMS_MAX + 1U;
    UTNOX_EQUALS(noxtls_efr32_se_run(&cmd, 100U), NOXTLS_RETURN_INVALID_PARAM);
    cmd.nparams = 1U;
    /* No room in the mailbox: nothing was sent and the mailbox is not declared hung. */
    g_ut.sem_tx_never = 1U;
    g_ut.se_cmds = 0U;
    UTNOX_EQUALS(noxtls_efr32_se_run(&cmd, 100U), NOXTLS_RETURN_TIMEOUT);
    UTNOX_EQUALS(g_ut.se_cmds, 0U);
    UTNOX_EQUALS(noxtls_efr32_se_is_hung(), 0U);
    g_ut.sem_tx_never = 0U;
    /* The SE does not answer: the buffers may still be in use, so the mailbox is refused afterwards. */
    g_ut.sem_rx_never = 1U;
    UTNOX_EQUALS(noxtls_efr32_se_run(&cmd, 100U), NOXTLS_RETURN_TIMEOUT);
    UTNOX_EQUALS(noxtls_efr32_se_is_hung(), 1U);
    UTNOX_EQUALS(noxtls_efr32_stats()->se_timeouts, 2U);
    noxtls_efr32_se_release();
    g_ut.sem_rx_never = 0U;
    g_ut.sem_rx_ready = 0U;
    UTNOX_EQUALS(noxtls_efr32_se_acquire(), NOXTLS_RETURN_NOT_SUPPORTED);
    noxtls_efr32_se_set_hung(0U);
    UTNOX_EQUALS(noxtls_efr32_se_acquire(), NOXTLS_RETURN_SUCCESS);
    /* An error response is mapped and counted. */
    g_ut.se_force = 1U;
    g_ut.se_force_resp = NOXTLS_EFR32_SE_RESP_INVALID_CMD;
    UTNOX_EQUALS(noxtls_efr32_se_run(&cmd, 100U), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_efr32_stats()->se_errors, 1U);
    noxtls_efr32_se_release();
    UTNOX_IS_TRUE(ut_clean() != 0U);
    return 0;
}

REGISTER_TEST(test_se_trng_lengths)
{
    static const uint32_t lens[] = { 0U, 1U, 3U, 4U, 5U, 63U, 64U, 65U, 200U };
    uint8_t a[200];
    uint8_t b[200];
    uint32_t i;

    ut_setup();
    for (i = 0U; i < (sizeof(lens) / sizeof(lens[0])); i++) {
        (void)memset(a, 0, sizeof(a));
        (void)memset(b, 0, sizeof(b));
        g_ut.se_cmds = 0U;
        UTNOX_EQUALS(noxtls_efr32_se_trng_fill(a, lens[i]), NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(noxtls_efr32_se_trng_fill(b, lens[i]), NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(g_ut.se_cmds, 2U * ((lens[i] + 63U) / 64U));
        if (lens[i] >= 4U) {
            UTNOX_IS_TRUE(memcmp(a, b, lens[i]) != 0);
            UTNOX_IS_TRUE(noxtls_efr32_is_zero(a, lens[i]) == 0U);
        }
        /* No byte beyond the request is written. */
        if (lens[i] < sizeof(a)) {
            UTNOX_EQUALS(a[lens[i]], 0U);
        }
    }
    UTNOX_IS_TRUE(ut_clean() != 0U);
    return 0;
}

REGISTER_TEST(test_se_trng_errors)
{
    uint8_t a[16];

    ut_setup();
    UTNOX_EQUALS(noxtls_efr32_se_trng_fill(NULL, 0U), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_efr32_se_trng_fill(NULL, 4U), NOXTLS_RETURN_NULL);
    /* Disabled operation / unit / busy mailbox: not supported, buffer cleared. */
    (void)memset(a, 0xA5, sizeof(a));
    noxtls_efr32_set_ops_disabled(NOXTLS_EFR32_OP_TRNG);
    UTNOX_EQUALS(noxtls_efr32_se_trng_fill(a, sizeof(a)), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_IS_TRUE(noxtls_efr32_is_zero(a, sizeof(a)) != 0U);
    noxtls_efr32_set_ops_disabled(0U);
    UTNOX_EQUALS(noxtls_efr32_se_acquire(), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_efr32_se_trng_fill(a, sizeof(a)), NOXTLS_RETURN_NOT_SUPPORTED);
    noxtls_efr32_se_release();
    /* Error responses fail the request and clear the output. */
    g_ut.se_force = 1U;
    g_ut.se_force_resp = NOXTLS_EFR32_SE_RESP_INTERNAL;
    (void)memset(a, 0xA5, sizeof(a));
    UTNOX_EQUALS(noxtls_efr32_se_trng_fill(a, sizeof(a)), NOXTLS_RETURN_FAILED);
    UTNOX_IS_TRUE(noxtls_efr32_is_zero(a, sizeof(a)) != 0U);
    g_ut.se_force_resp = NOXTLS_EFR32_SE_RESP_INVALID_PARAM;
    UTNOX_EQUALS(noxtls_efr32_se_trng_fill(a, sizeof(a)), NOXTLS_RETURN_FAILED);
    g_ut.se_force_resp = NOXTLS_EFR32_SE_RESP_INVALID_CMD;
    UTNOX_EQUALS(noxtls_efr32_se_trng_fill(a, sizeof(a)), NOXTLS_RETURN_NOT_SUPPORTED);
    g_ut.se_force = 0U;
    /* A silent SE: TIMEOUT, then the mailbox is refused. */
    g_ut.sem_rx_never = 1U;
    UTNOX_EQUALS(noxtls_efr32_se_trng_fill(a, sizeof(a)), NOXTLS_RETURN_TIMEOUT);
    g_ut.sem_rx_never = 0U;
    g_ut.sem_rx_ready = 0U;
    UTNOX_EQUALS(noxtls_efr32_se_trng_fill(a, sizeof(a)), NOXTLS_RETURN_NOT_SUPPORTED);
    noxtls_efr32_se_set_hung(0U);
    UTNOX_EQUALS(noxtls_efr32_se_trng_fill(a, sizeof(a)), NOXTLS_RETURN_SUCCESS);
    return 0;
}

REGISTER_TEST(test_se_hash_abc_both_algorithms)
{
    static uint8_t block[128];
    uint8_t st[64];
    uint8_t h256[32];
    uint8_t h512[64];
    uint8_t d256[32];
    uint8_t d512[64];

    ut_setup();
    (void)ut_hex("6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19", h256);
    (void)ut_hex("6a09e667f3bcc908bb67ae8584caa73b3c6ef372fe94f82ba54ff53a5f1d36f1510e527fade682d19b05688c2b3e6c1f1f83d9abfb41bd6b5be0cd19137e2179",
                 h512);
    (void)ut_hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", d256);
    (void)ut_hex("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
                 d512);
    (void)memset(block, 0, sizeof(block));
    block[0] = 0x61U;
    block[1] = 0x62U;
    block[2] = 0x63U;
    block[3] = 0x80U;
    block[63] = 0x18U;
    (void)memcpy(st, h256, 32U);
    UTNOX_EQUALS(noxtls_efr32_se_hash_blocks(NOXTLS_EFR32_SE_HASH_SHA256, st, block, 1U), NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(st, d256, 32U);
    UTNOX_EQUALS(g_ut.se_last_cmd, NOXTLS_EFR32_SE_CMD_HASHUPDATE | NOXTLS_EFR32_SE_OPT_HASH_SHA256);
    UTNOX_EQUALS(g_ut.se_last_params[0], 64U);
    block[63] = 0U;
    block[127] = 0x18U;
    (void)memcpy(st, h512, 64U);
    UTNOX_EQUALS(noxtls_efr32_se_hash_blocks(NOXTLS_EFR32_SE_HASH_SHA512, st, block, 1U), NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(st, d512, 64U);
    UTNOX_EQUALS(g_ut.se_last_cmd, NOXTLS_EFR32_SE_CMD_HASHUPDATE | NOXTLS_EFR32_SE_OPT_HASH_SHA512);
    UTNOX_EQUALS(g_ut.se_last_params[0], 128U);
    UTNOX_IS_TRUE(ut_clean() != 0U);
    return 0;
}

REGISTER_TEST(test_se_hash_splits_long_requests)
{
    /* 20 blocks of SHA-256 = 1280 bytes; the test build splits at 256 bytes. */
    static uint8_t data[1280];
    uint8_t st[32];
    uint8_t ref[32];
    noxtls_sha_ctx_t ctx;
    uint32_t i;

    ut_setup();
    for (i = 0U; i < sizeof(data); i++) {
        data[i] = (uint8_t)(i * 13U);
    }
    (void)ut_hex("6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19", st);
    g_ut.se_cmds = 0U;
    UTNOX_EQUALS(noxtls_efr32_se_hash_blocks(NOXTLS_EFR32_SE_HASH_SHA256, st, data, 20U), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(g_ut.se_cmds, 5U);
    ut_sw_begin();
    (void)noxtls_sha_init(&ctx, NOXTLS_HASH_SHA_256);
    (void)noxtls_sha_update(&ctx, data, sizeof(data));
    for (i = 0U; i < 8U; i++) {
        ref[(4U * i)] = (uint8_t)(ctx.u.md32.h[i] >> 24);
        ref[(4U * i) + 1U] = (uint8_t)(ctx.u.md32.h[i] >> 16);
        ref[(4U * i) + 2U] = (uint8_t)(ctx.u.md32.h[i] >> 8);
        ref[(4U * i) + 3U] = (uint8_t)ctx.u.md32.h[i];
    }
    ut_sw_end();
    UTNOX_MEM_EQUAL(st, ref, 32U);
    /* SHA-512: 5 blocks = 640 bytes -> 3 commands (256 + 256 + 128). */
    {
        uint8_t s5[64];
        noxtls_sha_ctx_t c5;
        uint8_t r5[64];

        (void)ut_hex("6a09e667f3bcc908bb67ae8584caa73b3c6ef372fe94f82ba54ff53a5f1d36f1510e527fade682d19b05688c2b3e6c1f1f83d9abfb41bd6b5be0cd19137e2179",
                     s5);
        g_ut.se_cmds = 0U;
        UTNOX_EQUALS(noxtls_efr32_se_hash_blocks(NOXTLS_EFR32_SE_HASH_SHA512, s5, data, 5U), NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(g_ut.se_cmds, 3U);
        ut_sw_begin();
        (void)noxtls_sha_init(&c5, NOXTLS_HASH_SHA_512);
        (void)noxtls_sha_update(&c5, data, 640U);
        for (i = 0U; i < 8U; i++) {
            uint32_t b;

            for (b = 0U; b < 8U; b++) {
                r5[(8U * i) + b] = (uint8_t)(c5.u.sha512_ctx.h[i] >> (8U * (7U - b)));
            }
        }
        ut_sw_end();
        UTNOX_MEM_EQUAL(s5, r5, 64U);
    }
    UTNOX_IS_TRUE(ut_clean() != 0U);
    return 0;
}

REGISTER_TEST(test_se_hash_errors_leave_state_unchanged)
{
    static uint8_t data[512];
    uint8_t st[32];
    uint8_t keep[32];
    uint8_t stack_data[64];

    ut_setup();
    (void)memset(st, 0x33, sizeof(st));
    (void)memcpy(keep, st, sizeof(st));
    UTNOX_EQUALS(noxtls_efr32_se_hash_blocks(7U, st, data, 1U), NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_EQUALS(noxtls_efr32_se_hash_blocks(NOXTLS_EFR32_SE_HASH_SHA256, NULL, data, 1U), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_efr32_se_hash_blocks(NOXTLS_EFR32_SE_HASH_SHA256, st, NULL, 1U), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_efr32_se_hash_blocks(NOXTLS_EFR32_SE_HASH_SHA256, st, NULL, 0U), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_efr32_se_hash_blocks(NOXTLS_EFR32_SE_HASH_SHA256, st, data, 0U), NOXTLS_RETURN_SUCCESS);
    /* 2^26 blocks of 64 bytes overflow 32 bits. */
    UTNOX_EQUALS(noxtls_efr32_se_hash_blocks(NOXTLS_EFR32_SE_HASH_SHA256, st, data, 0x04000000U), NOXTLS_RETURN_NOT_SUPPORTED);
    /* Data the SE cannot reach. */
    UTNOX_EQUALS(noxtls_efr32_se_hash_blocks(NOXTLS_EFR32_SE_HASH_SHA256, st, stack_data, 1U), NOXTLS_RETURN_NOT_SUPPORTED);
    /* Disabled operation, per algorithm. */
    noxtls_efr32_set_ops_disabled(NOXTLS_EFR32_OP_SHA256);
    UTNOX_EQUALS(noxtls_efr32_se_hash_blocks(NOXTLS_EFR32_SE_HASH_SHA256, st, data, 1U), NOXTLS_RETURN_NOT_SUPPORTED);
    noxtls_efr32_set_ops_disabled(NOXTLS_EFR32_OP_SHA512);
    UTNOX_EQUALS(noxtls_efr32_se_hash_blocks(NOXTLS_EFR32_SE_HASH_SHA512, st, data, 1U), NOXTLS_RETURN_NOT_SUPPORTED);
    noxtls_efr32_set_ops_disabled(0U);
    /* A failure in the second command of a split request leaves the caller's state untouched. */
    g_ut.se_fail_first = 0U;
    UTNOX_EQUALS(noxtls_efr32_se_acquire(), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_efr32_se_hash_blocks(NOXTLS_EFR32_SE_HASH_SHA256, st, data, 4U), NOXTLS_RETURN_NOT_SUPPORTED);
    noxtls_efr32_se_release();
    g_ut.se_fail_first = 1U;
    UTNOX_EQUALS(noxtls_efr32_se_hash_blocks(NOXTLS_EFR32_SE_HASH_SHA256, st, data, 8U), NOXTLS_RETURN_FAILED);
    UTNOX_MEM_EQUAL(st, keep, 32U);
    g_ut.se_force = 1U;
    g_ut.se_force_resp = NOXTLS_EFR32_SE_RESP_INVALID_CMD;
    UTNOX_EQUALS(noxtls_efr32_se_hash_blocks(NOXTLS_EFR32_SE_HASH_SHA512, st, data, 1U), NOXTLS_RETURN_NOT_SUPPORTED);
    g_ut.se_force = 0U;
    UTNOX_MEM_EQUAL(st, keep, 32U);
    UTNOX_EQUALS(noxtls_efr32_se_hash_blocks(NOXTLS_EFR32_SE_HASH_SHA256, st, data, 8U), NOXTLS_RETURN_SUCCESS);
    UTNOX_IS_TRUE(memcmp(st, keep, 32U) != 0);
    return 0;
}

REGISTER_TEST(test_se_hash_failure_after_first_command_keeps_state)
{
    static uint8_t data[1024];
    uint8_t st[32];
    uint8_t keep[32];

    ut_setup();
    (void)memset(st, 0x44, sizeof(st));
    (void)memcpy(keep, st, sizeof(st));
    /* 16 blocks = 1024 bytes = four commands in this build; the second one fails. */
    g_ut.se_cmds = 0U;
    g_ut.se_fail_at = 2U;
    UTNOX_EQUALS(noxtls_efr32_se_hash_blocks(NOXTLS_EFR32_SE_HASH_SHA256, st, data, 16U), NOXTLS_RETURN_FAILED);
    UTNOX_EQUALS(g_ut.se_cmds, 2U);
    UTNOX_MEM_EQUAL(st, keep, 32U);
    /* The mailbox was released after the failure. */
    g_ut.se_fail_at = 0U;
    UTNOX_EQUALS(noxtls_efr32_se_hash_blocks(NOXTLS_EFR32_SE_HASH_SHA256, st, data, 16U), NOXTLS_RETURN_SUCCESS);
    return 0;
}

REGISTER_TEST(test_se_ecc_mul_p256_and_p384)
{
    uint8_t k[48] = { 0U };
    uint8_t gx[48];
    uint8_t gy[48];
    uint8_t rx[48];
    uint8_t ry[48];
    uint8_t ex[48];
    uint8_t ey[48];

    ut_setup();
    (void)ut_hex(s_gx, gx);
    (void)ut_hex(s_gy, gy);
    (void)ut_hex(s_g2x, ex);
    (void)ut_hex(s_g2y, ey);
    k[31] = 2U;
    UTNOX_EQUALS(noxtls_efr32_se_ecc_mul(32U, k, gx, gy, rx, ry), NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(rx, ex, 32U);
    UTNOX_MEM_EQUAL(ry, ey, 32U);
    UTNOX_EQUALS(g_ut.se_last_cmd, NOXTLS_EFR32_SE_CMD_DH);
    UTNOX_EQUALS(g_ut.se_last_params[0], 0x8000401FU);
    UTNOX_EQUALS(g_ut.se_last_params[1], 64U);
    /* In-place use of the output buffers as the input point. */
    (void)memcpy(rx, gx, 32U);
    (void)memcpy(ry, gy, 32U);
    UTNOX_EQUALS(noxtls_efr32_se_ecc_mul(32U, k, rx, ry, rx, ry), NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(rx, ex, 32U);
    /* P-384: the generator times 1 is itself... compare with 2 * 2G computed twice. */
    {
        uint8_t g3x[48];
        uint8_t g3y[48];
        uint8_t h3x[48];
        uint8_t h3y[48];
        uint8_t k2[48] = { 0U };
        uint8_t k4[48] = { 0U };
        const ecc_curve_params_t *c = noxtls_ecc_curve_get(NOXTLS_ECC_SECP384R1);

        k2[47] = 2U;
        k4[47] = 4U;
        UTNOX_EQUALS(noxtls_efr32_se_ecc_mul(48U, k2, c->G.x, c->G.y, g3x, g3y), NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(g_ut.se_last_params[0], 0x8000402FU);
        UTNOX_EQUALS(g_ut.se_last_params[1], 96U);
        UTNOX_EQUALS(noxtls_efr32_se_ecc_mul(48U, k2, g3x, g3y, h3x, h3y), NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(noxtls_efr32_se_ecc_mul(48U, k4, c->G.x, c->G.y, g3x, g3y), NOXTLS_RETURN_SUCCESS);
        UTNOX_MEM_EQUAL(g3x, h3x, 48U);
        UTNOX_MEM_EQUAL(g3y, h3y, 48U);
    }
    UTNOX_IS_TRUE(ut_clean() != 0U);
    return 0;
}

REGISTER_TEST(test_se_ecc_mul_errors_and_retries)
{
    uint8_t k[32] = { 0U };
    uint8_t gx[32];
    uint8_t gy[32];
    uint8_t rx[32];
    uint8_t ry[32];

    ut_setup();
    (void)ut_hex(s_gx, gx);
    (void)ut_hex(s_gy, gy);
    k[31] = 2U;
    UTNOX_EQUALS(noxtls_efr32_se_ecc_mul(32U, NULL, gx, gy, rx, ry), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_efr32_se_ecc_mul(32U, k, NULL, gy, rx, ry), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_efr32_se_ecc_mul(32U, k, gx, NULL, rx, ry), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_efr32_se_ecc_mul(32U, k, gx, gy, NULL, ry), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_efr32_se_ecc_mul(32U, k, gx, gy, rx, NULL), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_efr32_se_ecc_mul(24U, k, gx, gy, rx, ry), NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_EQUALS(noxtls_efr32_se_ecc_mul(0U, k, gx, gy, rx, ry), NOXTLS_RETURN_INVALID_PARAM);
    noxtls_efr32_set_ops_disabled(NOXTLS_EFR32_OP_ECC_MUL);
    UTNOX_EQUALS(noxtls_efr32_se_ecc_mul(32U, k, gx, gy, rx, ry), NOXTLS_RETURN_NOT_SUPPORTED);
    noxtls_efr32_set_ops_disabled(0U);
    UTNOX_EQUALS(g_ut.se_cmds, 0U);
    /* The SE point-multiply workaround: two internal errors are retried, three are not. */
    g_ut.se_fail_first = 2U;
    UTNOX_EQUALS(noxtls_efr32_se_ecc_mul(32U, k, gx, gy, rx, ry), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(g_ut.se_cmds, 3U);
    g_ut.se_cmds = 0U;
    g_ut.se_fail_first = 3U;
    (void)memset(rx, 0xA5, sizeof(rx));
    UTNOX_EQUALS(noxtls_efr32_se_ecc_mul(32U, k, gx, gy, rx, ry), NOXTLS_RETURN_FAILED);
    UTNOX_EQUALS(g_ut.se_cmds, 3U);
    UTNOX_IS_TRUE(noxtls_efr32_is_zero(rx, 32U) != 0U);
    UTNOX_IS_TRUE(noxtls_efr32_is_zero(ry, 32U) != 0U);
    /* Other errors are not retried. */
    g_ut.se_cmds = 0U;
    g_ut.se_force = 1U;
    g_ut.se_force_resp = NOXTLS_EFR32_SE_RESP_INVALID_CMD;
    UTNOX_EQUALS(noxtls_efr32_se_ecc_mul(32U, k, gx, gy, rx, ry), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(g_ut.se_cmds, 1U);
    g_ut.se_force = 0U;
    UTNOX_EQUALS(noxtls_efr32_se_acquire(), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_efr32_se_ecc_mul(32U, k, gx, gy, rx, ry), NOXTLS_RETURN_NOT_SUPPORTED);
    noxtls_efr32_se_release();
    return 0;
}

REGISTER_TEST(test_se_ecdsa_rfc6979_verify_and_reject)
{
    uint8_t qx[32];
    uint8_t qy[32];
    uint8_t h[32];
    uint8_t r[32];
    uint8_t s[32];

    ut_setup();
    (void)ut_hex(s_qx, qx);
    (void)ut_hex(s_qy, qy);
    (void)ut_hex(s_h, h);
    (void)ut_hex(s_r, r);
    (void)ut_hex(s_s, s);
    UTNOX_EQUALS(noxtls_efr32_se_ecdsa_verify(32U, qx, qy, h, r, s), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(g_ut.se_last_cmd, NOXTLS_EFR32_SE_CMD_VERIFY);
    UTNOX_EQUALS(g_ut.se_last_params[0], 0x8000201FU);
    UTNOX_EQUALS(g_ut.se_last_params[1], 32U);
    s[31] ^= 1U;
    UTNOX_EQUALS(noxtls_efr32_se_ecdsa_verify(32U, qx, qy, h, r, s), NOXTLS_RETURN_BAD_DATA);
    s[31] ^= 1U;
    h[0] ^= 0x80U;
    UTNOX_EQUALS(noxtls_efr32_se_ecdsa_verify(32U, qx, qy, h, r, s), NOXTLS_RETURN_BAD_DATA);
    h[0] ^= 0x80U;
    UTNOX_EQUALS(noxtls_efr32_se_ecdsa_verify(32U, NULL, qy, h, r, s), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_efr32_se_ecdsa_verify(32U, qx, NULL, h, r, s), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_efr32_se_ecdsa_verify(32U, qx, qy, NULL, r, s), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_efr32_se_ecdsa_verify(32U, qx, qy, h, NULL, s), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_efr32_se_ecdsa_verify(32U, qx, qy, h, r, NULL), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_efr32_se_ecdsa_verify(20U, qx, qy, h, r, s), NOXTLS_RETURN_INVALID_PARAM);
    noxtls_efr32_set_ops_disabled(NOXTLS_EFR32_OP_ECDSA_VERIFY);
    UTNOX_EQUALS(noxtls_efr32_se_ecdsa_verify(32U, qx, qy, h, r, s), NOXTLS_RETURN_NOT_SUPPORTED);
    noxtls_efr32_set_ops_disabled(0U);
    UTNOX_IS_TRUE(ut_clean() != 0U);
    return 0;
}

REGISTER_TEST(test_se_ecdsa_sign_roundtrip_p256_p384)
{
    uint8_t d[32];
    uint8_t qx[32];
    uint8_t qy[32];
    uint8_t h[32];
    uint8_t r[32];
    uint8_t s[32];
    uint8_t d4[48];
    uint8_t h4[48];
    uint8_t r4[48];
    uint8_t s4[48];
    ecc_key_t key;

    ut_setup();
    (void)ut_hex(s_d, d);
    (void)ut_hex(s_qx, qx);
    (void)ut_hex(s_qy, qy);
    (void)ut_hex(s_h, h);
    UTNOX_EQUALS(noxtls_efr32_se_ecdsa_sign(32U, d, h, r, s), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(g_ut.se_last_cmd, NOXTLS_EFR32_SE_CMD_SIGN);
    UTNOX_EQUALS(g_ut.se_last_params[0], 0x8000401FU);
    UTNOX_EQUALS(noxtls_efr32_se_ecdsa_verify(32U, qx, qy, h, r, s), NOXTLS_RETURN_SUCCESS);
    /* P-384. */
    (void)memset(d4, 0x11, sizeof(d4));
    d4[0] = 0x01U;
    (void)memset(h4, 0x22, sizeof(h4));
    UTNOX_EQUALS(noxtls_ecc_key_import_private(&key, NOXTLS_ECC_SECP384R1, d4, 48U), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_efr32_se_ecdsa_sign(48U, d4, h4, r4, s4), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(g_ut.se_last_params[0], 0x8000402FU);
    UTNOX_EQUALS(noxtls_efr32_se_ecdsa_verify(48U, key.Q.x, key.Q.y, h4, r4, s4), NOXTLS_RETURN_SUCCESS);
    (void)noxtls_ecc_key_free(&key);
    /* Argument and state errors. */
    UTNOX_EQUALS(noxtls_efr32_se_ecdsa_sign(32U, NULL, h, r, s), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_efr32_se_ecdsa_sign(32U, d, NULL, r, s), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_efr32_se_ecdsa_sign(32U, d, h, NULL, s), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_efr32_se_ecdsa_sign(32U, d, h, r, NULL), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_efr32_se_ecdsa_sign(31U, d, h, r, s), NOXTLS_RETURN_INVALID_PARAM);
    noxtls_efr32_set_ops_disabled(NOXTLS_EFR32_OP_ECDSA_SIGN);
    UTNOX_EQUALS(noxtls_efr32_se_ecdsa_sign(32U, d, h, r, s), NOXTLS_RETURN_NOT_SUPPORTED);
    noxtls_efr32_set_ops_disabled(0U);
    g_ut.se_force = 1U;
    g_ut.se_force_resp = NOXTLS_EFR32_SE_RESP_INTERNAL;
    (void)memset(r, 0xA5, sizeof(r));
    UTNOX_EQUALS(noxtls_efr32_se_ecdsa_sign(32U, d, h, r, s), NOXTLS_RETURN_FAILED);
    UTNOX_IS_TRUE(noxtls_efr32_is_zero(r, 32U) != 0U);
    UTNOX_IS_TRUE(noxtls_efr32_is_zero(s, 32U) != 0U);
    g_ut.se_force = 0U;
    UTNOX_IS_TRUE(ut_clean() != 0U);
    return 0;
}
