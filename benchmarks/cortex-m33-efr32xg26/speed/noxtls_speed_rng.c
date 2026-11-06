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
* File:    noxtls_speed_rng.c
* Summary: TRNG and DRBG cases of the EFR32xG26 NoxTLS speed benchmark
*
*****************************************************************************/

/**
 * @file noxtls_speed_rng.c
 * @brief Secure Engine TRNG throughput and CTR-DRBG generation, software versus hardware AES.
 * @ingroup noxtls_speed
 *
 * The TRNG has no software equivalent, so its row has no software column; it is
 * checked for sanity (monobit balance, not stuck, two draws differ). The CTR-DRBG
 * is seeded with a fixed entropy input in both backends, so its output is
 * deterministic and compared byte for byte; only its AES block calls change.
 */

#include <stddef.h>
#include <string.h>

#include "drbg/noxtls_drbg.h"
#include "noxtls_efr32_accel.h"

#include "noxtls_speed_bench.h"
#include "noxtls_speed_config.h"
#include "noxtls_speed_timer.h"

/** @brief Multiplier of the DRBG entropy pattern. */
#define SPEED_ENTROPY_MUL       13U
/** @brief Offset of the DRBG entropy pattern. */
#define SPEED_ENTROPY_ADD       1U

/** @brief First TRNG draw. */
static uint8_t s_draw_a[NOXTLS_SPEED_RNG_BYTES];
/** @brief Second TRNG draw. */
static uint8_t s_draw_b[NOXTLS_SPEED_RNG_BYTES];
/** @brief DRBG output of the software backend. */
static uint8_t s_gen_sw[NOXTLS_SPEED_RNG_BYTES];
/** @brief DRBG output of the hardware backend. */
static uint8_t s_gen_hw[NOXTLS_SPEED_RNG_BYTES];
/** @brief DRBG state. */
static drbg_state_t s_drbg;

/**
 * @brief Ones in a buffer.
 * @internal
 *
 * @param[in] buf Buffer.
 * @param[in] len Bytes.
 *
 * @return Number of set bits.
 */
static uint32_t speed_popcount(const uint8_t *buf, uint32_t len)
{
    uint32_t ones = 0U;
    uint32_t i;
    uint32_t b;

    for (i = 0U; i < len; i++) {
        for (b = 0U; b < NOXTLS_SPEED_BITS_PER_BYTE; b++) {
            ones += (uint32_t)((buf[i] >> b) & 1U);
        }
    }
    return ones;
}

/**
 * @brief Whether a draw looks like a working noise source.
 * @internal
 *
 * @param[in] buf Draw.
 * @param[in] len Bytes.
 *
 * @return 1 when the ones count is within the tolerance of half the bits and the bytes are not all equal.
 */
static uint8_t speed_draw_sane(const uint8_t *buf, uint32_t len)
{
    const uint32_t half = (len * NOXTLS_SPEED_BITS_PER_BYTE) / 2U;
    const uint32_t ones = speed_popcount(buf, len);
    uint32_t i;
    uint8_t varies = 0U;
    uint8_t within;

    for (i = 1U; i < len; i++) {
        if (buf[i] != buf[0]) {
            varies = 1U;
        }
    }
    within = ((ones + NOXTLS_SPEED_TRNG_MONOBIT_TOL >= half) && (ones <= half + NOXTLS_SPEED_TRNG_MONOBIT_TOL)) ? 1U : 0U;
    return ((within != 0U) && (varies != 0U)) ? 1U : 0U;
}

/**
 * @brief Time the Secure Engine TRNG (hardware only).
 * @internal
 */
static void speed_case_trng(void)
{
    noxtls_speed_row_t *row = noxtls_speed_row_begin("trng_fill", NOXTLS_SPEED_RNG_BYTES, 1U);
    uint8_t ok = 1U;
    uint32_t start;
    uint32_t activity;
    uint32_t i;

    row->has_sw = 0U;
    noxtls_speed_backend_set(NOXTLS_SPEED_BACKEND_HW);
    ok &= (noxtls_drbg_entropy_accel_port(s_draw_a, NOXTLS_SPEED_RNG_BYTES) == NOXTLS_RETURN_SUCCESS) ? 1U : 0U;
    activity = noxtls_speed_hw_activity();
    start = noxtls_speed_timer_cycles();
    for (i = 0U; i < NOXTLS_SPEED_ITERS_RNG; i++) {
        ok &= (noxtls_drbg_entropy_accel_port(s_draw_b, NOXTLS_SPEED_RNG_BYTES) == NOXTLS_RETURN_SUCCESS) ? 1U : 0U;
    }
    row->hw_cycles = noxtls_speed_avg(start, NOXTLS_SPEED_ITERS_RNG);
    row->hw_used = (noxtls_speed_hw_activity() != activity) ? 1U : 0U;

    row->run_ok = ok;
    row->match = ((speed_draw_sane(s_draw_a, NOXTLS_SPEED_RNG_BYTES) != 0U) &&
                  (speed_draw_sane(s_draw_b, NOXTLS_SPEED_RNG_BYTES) != 0U) &&
                  (memcmp(s_draw_a, s_draw_b, NOXTLS_SPEED_RNG_BYTES) != 0)) ? 1U : 0U;
    noxtls_speed_row_end(row);
}

/**
 * @brief Seed the DRBG with the fixed entropy input and generate one request.
 * @internal
 *
 * @param[out] out Output (NOXTLS_SPEED_RNG_BYTES).
 *
 * @return Library result.
 */
static noxtls_return_t speed_drbg_first(uint8_t *out)
{
    uint8_t entropy[NOXTLS_SPEED_DRBG_ENTROPY_BYTES];
    noxtls_return_t rc;
    uint32_t i;

    for (i = 0U; i < NOXTLS_SPEED_DRBG_ENTROPY_BYTES; i++) {
        entropy[i] = (uint8_t)((i * SPEED_ENTROPY_MUL) + SPEED_ENTROPY_ADD);
    }
    rc = drbg_instantiate(&s_drbg, DRBG_AES128, entropy, NOXTLS_SPEED_DRBG_ENTROPY_BYTES, NULL, 0U, NULL, 0U);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = drbg_generate(&s_drbg, out, NOXTLS_SPEED_RNG_BYTES * NOXTLS_SPEED_BITS_PER_BYTE, NULL, 0U);
    }
    return rc;
}

/**
 * @brief Time CTR-DRBG generation on both backends and compare the (deterministic) output.
 * @internal
 */
static void speed_case_drbg(void)
{
    noxtls_speed_row_t *row = noxtls_speed_row_begin("ctr_drbg_gen", NOXTLS_SPEED_RNG_BYTES, 1U);
    uint8_t ok = 1U;
    uint32_t start;
    uint32_t activity;
    uint32_t i;

    noxtls_speed_backend_set(NOXTLS_SPEED_BACKEND_SW);
    ok &= (speed_drbg_first(s_gen_sw) == NOXTLS_RETURN_SUCCESS) ? 1U : 0U;
    start = noxtls_speed_timer_cycles();
    for (i = 0U; i < NOXTLS_SPEED_ITERS_RNG; i++) {
        ok &= (drbg_generate(&s_drbg, s_draw_a, NOXTLS_SPEED_RNG_BYTES * NOXTLS_SPEED_BITS_PER_BYTE, NULL, 0U) ==
               NOXTLS_RETURN_SUCCESS) ? 1U : 0U;
    }
    row->sw_cycles = noxtls_speed_avg(start, NOXTLS_SPEED_ITERS_RNG);

    noxtls_speed_backend_set(NOXTLS_SPEED_BACKEND_HW);
    ok &= (speed_drbg_first(s_gen_hw) == NOXTLS_RETURN_SUCCESS) ? 1U : 0U;
    activity = noxtls_speed_hw_activity();
    start = noxtls_speed_timer_cycles();
    for (i = 0U; i < NOXTLS_SPEED_ITERS_RNG; i++) {
        ok &= (drbg_generate(&s_drbg, s_draw_b, NOXTLS_SPEED_RNG_BYTES * NOXTLS_SPEED_BITS_PER_BYTE, NULL, 0U) ==
               NOXTLS_RETURN_SUCCESS) ? 1U : 0U;
    }
    row->hw_cycles = noxtls_speed_avg(start, NOXTLS_SPEED_ITERS_RNG);
    row->hw_used = (noxtls_speed_hw_activity() != activity) ? 1U : 0U;

    /* Same seed and the same number of requests: the streams must be identical. */
    row->run_ok = ok;
    row->match = ((memcmp(s_gen_sw, s_gen_hw, NOXTLS_SPEED_RNG_BYTES) == 0) &&
                  (memcmp(s_draw_a, s_draw_b, NOXTLS_SPEED_RNG_BYTES) == 0)) ? 1U : 0U;
    (void)noxtls_drbg_uninstantiate(&s_drbg);
    noxtls_speed_row_end(row);
}

void noxtls_speed_run_rng(void)
{
    speed_case_trng();
    speed_case_drbg();
}
