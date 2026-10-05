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
* File:    test_nrf54_hash.c
* Summary: Tests of the BA413 SHA-2 backend and the NoxTLS SHA-2 ports
*
*****************************************************************************/

/**
 * @file test_nrf54_hash.c
 * @brief SHA-224/256/384/512 through the NoxTLS API on the mocked CRACEN
 *        (FIPS 180-4 / NIST CSRC example values), direct and bounced input,
 *        chunking, error paths and software fallback.
 * @ingroup noxtls_nrf54_ut
 */

#include <stdint.h>
#include <string.h>

#include "runner.h"
#include "test_assert.h"

#include "ut_nrf54_mock.h"
#include "ut_nrf54_ref.h"
#include "noxtls_sha.h"
#include "sha256/noxtls_sha256.h"
#include "sha512/noxtls_sha512.h"

/** SHA-256 block port (declared by noxtls_sha256.c, implemented by the nRF54 port). */
noxtls_return_t noxtls_sha256_blocks_accel_port(noxtls_sha_ctx_t *ctx, const uint8_t *input, uint32_t block_count);

/** FIPS 180-4 896-bit example message. */
static const char s_msg896[] =
    "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";

/**
 * @brief SHA-224/256 of a buffer through NoxTLS.
 *
 * @param[in]  algo   NOXTLS_HASH_SHA_224 or _256.
 * @param[in]  data   Data.
 * @param[in]  len    Bytes.
 * @param[in]  split  Bytes of the first update (rest in a second update).
 * @param[out] digest Digest.
 *
 * @return NoxTLS result.
 */
static noxtls_return_t ut_sha256(noxtls_hash_algos_t algo, const uint8_t *data, uint32_t len, uint32_t split,
                                 uint8_t *digest)
{
    noxtls_sha_ctx_t ctx;
    noxtls_return_t rc = noxtls_sha256_init(&ctx, algo);

    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_sha256_update(&ctx, data, split);
    }
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_sha256_update(&ctx, &data[split], len - split);
    }
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_sha256_finish(&ctx, digest);
    }
    return rc;
}

/**
 * @brief SHA-384/512 of a buffer through NoxTLS.
 *
 * @param[in]  algo   NOXTLS_HASH_SHA_384 or _512.
 * @param[in]  data   Data.
 * @param[in]  len    Bytes.
 * @param[in]  split  Bytes of the first update.
 * @param[out] digest Digest.
 *
 * @return NoxTLS result.
 */
static noxtls_return_t ut_sha512(noxtls_hash_algos_t algo, const uint8_t *data, uint32_t len, uint32_t split,
                                 uint8_t *digest)
{
    noxtls_sha512_ctx_t ctx;
    noxtls_return_t rc = noxtls_sha512_init(&ctx, algo);

    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_sha512_update(&ctx, data, split);
    }
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_sha512_update(&ctx, &data[split], len - split);
    }
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_sha512_finish(&ctx, digest);
    }
    return rc;
}

REGISTER_TEST(test_hash_fips_vectors)
{
    uint8_t d[64];
    uint8_t e[64];
    uint8_t chip;

    for (chip = 0U; chip < 2U; chip++) {
        ut_setup(chip);
        /* "abc" (single padded block: the finish runs one hardware block). */
        UTNOX_EQUALS(ut_sha256(NOXTLS_HASH_SHA_256, (const uint8_t *)"abc", 3U, 1U, d), NOXTLS_RETURN_SUCCESS);
        (void)ut_hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", e, 32U);
        UTNOX_EQUALS(memcmp(d, e, 32U), 0);
        UTNOX_GREATER_THAN(noxtls_nrf54_cracen_stats()->cm_jobs, 0U);
        UTNOX_EQUALS(ut_sha256(NOXTLS_HASH_SHA_224, (const uint8_t *)"abc", 3U, 3U, d), NOXTLS_RETURN_SUCCESS);
        (void)ut_hex("23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7", e, 28U);
        UTNOX_EQUALS(memcmp(d, e, 28U), 0);
        UTNOX_EQUALS(ut_sha512(NOXTLS_HASH_SHA_512, (const uint8_t *)s_msg896, 112U, 50U, d), NOXTLS_RETURN_SUCCESS);
        (void)ut_hex("8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
                     "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909", e, 64U);
        UTNOX_EQUALS(memcmp(d, e, 64U), 0);
        UTNOX_EQUALS(ut_sha512(NOXTLS_HASH_SHA_384, (const uint8_t *)"abc", 3U, 0U, d), NOXTLS_RETURN_SUCCESS);
        (void)ut_hex("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
                     "8086072ba1e7cc2358baeca134c825a7", e, 48U);
        UTNOX_EQUALS(memcmp(d, e, 48U), 0);
        UTNOX_EQUALS(g_ut.err[0], 0);
    }
    return 0;
}

REGISTER_TEST(test_hash_long_direct_and_bounced)
{
    static uint8_t far_buf[1500];
    uint8_t d[64];
    uint8_t e[64];
    uint32_t i;
    uint32_t jobs;

    ut_setup(0U);
    for (i = 0U; i < sizeof(far_buf); i++) {
        far_buf[i] = (uint8_t)(i * 7U);
        g_ut_ram.in[i] = far_buf[i];
    }
    /* In the DMA window: whole blocks in chunks of NOXTLS_NRF54_CONFIG_MAX_CHUNK. */
    ut_sha(256U, far_buf, sizeof(far_buf), e);
    UTNOX_EQUALS(ut_sha256(NOXTLS_HASH_SHA_256, g_ut_ram.in, sizeof(far_buf), 0U, d), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(memcmp(d, e, 32U), 0);
    jobs = noxtls_nrf54_cracen_stats()->cm_jobs;
    UTNOX_GREATER_THAN(jobs, 5U);
    /* Outside the window: bounced in NOXTLS_NRF54_CONFIG_BOUNCE_SIZE pieces. */
    UTNOX_EQUALS(ut_sha256(NOXTLS_HASH_SHA_256, far_buf, sizeof(far_buf), 1U, d), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(memcmp(d, e, 32U), 0);
    UTNOX_GREATER_THAN(noxtls_nrf54_cracen_stats()->cm_jobs - jobs, 10U);
    ut_sha(512U, far_buf, sizeof(far_buf), e);
    UTNOX_EQUALS(ut_sha512(NOXTLS_HASH_SHA_512, far_buf, sizeof(far_buf), 130U, d), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(memcmp(d, e, 64U), 0);
    /* Interrupt-driven waits give the same result (jobs take a few polls: the task sleeps). */
    ut_port_irq();
    g_ut.delay_reads = 2U;
    UTNOX_EQUALS(ut_sha512(NOXTLS_HASH_SHA_512, g_ut_ram.in, sizeof(far_buf), 0U, d), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(memcmp(d, e, 64U), 0);
    UTNOX_GREATER_THAN(noxtls_nrf54_cracen_stats()->irq_cm, 0U);
    UTNOX_EQUALS(g_ut.err[0], 0);
    return 0;
}

REGISTER_TEST(test_hash_errors_and_fallback)
{
    uint8_t st[64];
    uint8_t ref[64];
    uint8_t d[64];
    uint8_t e[64];

    ut_setup(1U);
    (void)ut_sha_iv(256U, st);
    UTNOX_EQUALS(noxtls_nrf54_hash_blocks(NOXTLS_NRF54_SHA256, NULL, g_ut_ram.in, 1U), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_nrf54_hash_blocks(NOXTLS_NRF54_SHA256, st, NULL, 1U), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_nrf54_hash_blocks((noxtls_nrf54_sha_t)7, st, g_ut_ram.in, 1U), NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_EQUALS(noxtls_nrf54_hash_blocks(NOXTLS_NRF54_SHA256, st, NULL, 0U), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_nrf54_cracen_stats()->acquires, 0U);
    /* Engine without SHA-512: not supported, state untouched. */
    g_ut.core[UT_IDX(NOXTLS_NRF54_HW_BA413_CFG)] = NOXTLS_NRF54_HASH_ALGO_SHA256;
    (void)ut_sha_iv(512U, st);
    (void)memcpy(ref, st, 64U);
    UTNOX_EQUALS(noxtls_nrf54_hash_blocks(NOXTLS_NRF54_SHA512, st, g_ut_ram.in, 1U), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(memcmp(st, ref, 64U), 0);
    /* NoxTLS falls back to software and still gets the right digest. */
    UTNOX_EQUALS(ut_sha512(NOXTLS_HASH_SHA_512, (const uint8_t *)"abc", 3U, 0U, d), NOXTLS_RETURN_SUCCESS);
    ut_sha(512U, (const uint8_t *)"abc", 3U, e);
    UTNOX_EQUALS(memcmp(d, e, 64U), 0);
    /* Busy: not supported. */
    ut_setup(1U);
    (void)ut_sha_iv(256U, st);
    UTNOX_EQUALS(noxtls_nordic_crypto_try_acquire(), 1);
    UTNOX_EQUALS(noxtls_nrf54_hash_blocks(NOXTLS_NRF54_SHA256, st, g_ut_ram.in, 1U), NOXTLS_RETURN_NOT_SUPPORTED);
    noxtls_nordic_crypto_release();
    /* Job failure: error, state untouched; NoxTLS recomputes the update in software. */
    (void)memcpy(ref, st, 32U);
    g_ut.delay_reads = 0U;
    g_ut.inject_error = 1U;
    UTNOX_EQUALS(noxtls_nrf54_hash_blocks(NOXTLS_NRF54_SHA256, st, g_ut_ram.in, 8U), NOXTLS_RETURN_FAILED);
    UTNOX_EQUALS(memcmp(st, ref, 32U), 0);
    g_ut.inject_error = 1U;
    (void)memset(g_ut_ram.in, 0x33, 640U);
    UTNOX_EQUALS(ut_sha256(NOXTLS_HASH_SHA_256, g_ut_ram.in, 640U, 0U, d), NOXTLS_RETURN_SUCCESS);
    ut_sha(256U, g_ut_ram.in, 640U, e);
    UTNOX_EQUALS(memcmp(d, e, 32U), 0);
    /* Disabled at run time: pure software. */
    noxtls_nrf54_cracen_set_enabled(0U);
    noxtls_nrf54_cracen_reset_stats();
    UTNOX_EQUALS(ut_sha256(NOXTLS_HASH_SHA_256, g_ut_ram.in, 640U, 0U, d), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(memcmp(d, e, 32U), 0);
    UTNOX_EQUALS(noxtls_nrf54_cracen_stats()->cm_jobs, 0U);
    noxtls_nrf54_cracen_set_enabled(1U);
    /* Port argument checks. */
    UTNOX_EQUALS(noxtls_sha256_blocks_accel_port(NULL, g_ut_ram.in, 1U), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_sha512_blocks_accel_port(NULL, g_ut_ram.in, 1U), NOXTLS_RETURN_NOT_SUPPORTED);
    {
        noxtls_sha_ctx_t c256;
        noxtls_sha512_ctx_t c512;

        (void)noxtls_sha256_init(&c256, NOXTLS_HASH_SHA_256);
        (void)noxtls_sha512_init(&c512, NOXTLS_HASH_SHA_512);
        UTNOX_EQUALS(noxtls_sha256_blocks_accel_port(&c256, NULL, 1U), NOXTLS_RETURN_NOT_SUPPORTED);
        UTNOX_EQUALS(noxtls_sha256_blocks_accel_port(&c256, g_ut_ram.in, 0U), NOXTLS_RETURN_NOT_SUPPORTED);
        UTNOX_EQUALS(noxtls_sha512_blocks_accel_port(&c512, NULL, 1U), NOXTLS_RETURN_NOT_SUPPORTED);
        UTNOX_EQUALS(noxtls_sha512_blocks_accel_port(&c512, g_ut_ram.in, 0U), NOXTLS_RETURN_NOT_SUPPORTED);
    }
    return 0;
}
