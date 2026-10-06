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
* File:    cc13xx_p256_ut.c
* Summary: Actual-domain CC13xx P-256 accelerator boundary tests
*
*
*****************************************************************************/

/** @file cc13xx_p256_ut.c
 * @brief Actual P-256 validation with synchronous hardware-boundary injection.
 * @ingroup noxtls_cc13xx_ecc
 * @note Inclusion exposes only diagnostic counters for UINT32_MAX saturation.
 * Built for the umbrella, the P-256-only switch and both disabled variants.
 */
#include "pkc/ecc/noxtls_ecc_accel_cc13xx_port.c"
#include "runner.h"
#include "test_assert.h"

#if NOXTLS_CC13XX_P256_ACCEL_ENABLED
static ecc_curve_params_t s_curve;
static ecc_point_t s_result;
static uint8_t s_scalar[NOXTLS_CC13XX_P256_BYTES];
static uint8_t s_expected_scalar[NOXTLS_CC13XX_P256_BYTES];
static unsigned s_calls;
static unsigned s_output_mode;
static bool s_bytes_match;
static bool s_nested;
static noxtls_return_t s_callback_rc;
static noxtls_return_t s_nested_rc;
static noxtls_return_t s_rebind_rc;
static const uint8_t s_twice_x[32U] = {
    0x7c, 0xf2, 0x7b, 0x18, 0x8d, 0x03, 0x4f, 0x7e, 0x8a, 0x52, 0x38, 0x03, 0x04, 0xb5, 0x1a, 0xc3,
    0xc0, 0x89, 0x69, 0xe2, 0x77, 0xf2, 0x1b, 0x35, 0xa6, 0x0b, 0x48, 0xfc, 0x47, 0x66, 0x99, 0x78};
static const uint8_t s_twice_y[32U] = {
    0x07, 0x77, 0x55, 0x10, 0xdb, 0x8e, 0xd0, 0x40, 0x29, 0x3d, 0x9a, 0xc6, 0x9f, 0x74, 0x30, 0xdb,
    0xba, 0x7d, 0xad, 0xe6, 0x3c, 0xe9, 0x82, 0x29, 0x9e, 0x04, 0xb7, 0x9d, 0x22, 0x78, 0x73, 0xd1};

/** @brief Model actual fixed-width BE callback result and optional reentry.
 *
 * @param[in] context Unused fixture context.
 * @param[in] scalar Exact scalar bytes.
 * @param[in] x Exact public x bytes.
 * @param[in] y Exact public y bytes.
 * @param[out] out_x Modeled hardware x.
 * @param[out] out_y Modeled hardware y.
 *
 * @return Injected actual callback status. */
static noxtls_return_t multiply(void *context, const uint8_t scalar[32], const uint8_t x[32],
                                const uint8_t y[32], uint8_t out_x[32], uint8_t out_y[32])
{
    (void)context;
    ++s_calls;
    s_bytes_match = memcmp(scalar, s_expected_scalar, sizeof(s_expected_scalar)) == 0 &&
                    memcmp(x, s_curve.G.x, sizeof(s_expected_scalar)) == 0 &&
                    memcmp(y, s_curve.G.y, sizeof(s_expected_scalar)) == 0;
    memcpy(out_x, s_twice_x, sizeof(s_twice_x));
    memcpy(out_y, s_twice_y, sizeof(s_twice_y));
    if (s_output_mode == 1U) {
        memset(out_x, 0, sizeof(s_twice_x));
        memset(out_y, 0, sizeof(s_twice_y));
    } else if (s_output_mode == 2U) {
        memcpy(out_x, s_curve.p, sizeof(s_twice_x));
    } else if (s_output_mode == 3U) {
        memset(out_x, 0, sizeof(s_twice_x));
        memset(out_y, 0, sizeof(s_twice_y));
        out_x[sizeof(s_twice_x) - 1U] = 1U;
        out_y[sizeof(s_twice_y) - 1U] = 1U;
    }

    if (s_nested) {
        ecc_point_t nested_result;
        s_nested = false;
        s_nested_rc =
            noxtls_ecc_point_multiply_accel_port(&nested_result, scalar, &s_curve.G, &s_curve);
        s_rebind_rc = noxtls_cc13xx_crypto_bind(NULL);
    }

    return s_callback_rc;
}

/** @brief Initialize actual secp256r1 domain and isolated idle binding.
 *
 * @return Actual domain/binding initialization result. */
static noxtls_return_t setup(void)
{
    const noxtls_cc13xx_crypto_binding_t binding = {NULL, NULL, multiply};
    noxtls_return_t rc;
    memset(&s_curve, 0, sizeof(s_curve));
    memset(&s_result, 0xA5, sizeof(s_result));
    memset(s_scalar, 0, sizeof(s_scalar));
    s_scalar[sizeof(s_scalar) - 1U] = 2U;
    memcpy(s_expected_scalar, s_scalar, sizeof(s_scalar));
    s_calls = 0U;
    s_output_mode = 0U;
    s_bytes_match = false;
    s_nested = false;
    s_callback_rc = NOXTLS_RETURN_SUCCESS;
    s_nested_rc = NOXTLS_RETURN_SUCCESS;
    s_rebind_rc = NOXTLS_RETURN_SUCCESS;
    noxtls_cc13xx_counter_store(&s_operations, 0U);
    noxtls_cc13xx_counter_store(&s_fallbacks, 0U);
    rc = noxtls_ecc_curve_init(&s_curve, NOXTLS_ECC_SECP256R1);
    return rc == NOXTLS_RETURN_SUCCESS ? noxtls_cc13xx_crypto_bind(&binding) : rc;
}

/** @brief Check full cleared result, including bytes beyond the P-256 extent.
 *
 * @param[in] result Owned result storage.
 *
 * @return True only after complete failure erasure. */
static bool cleared(const ecc_point_t *result)
{
    size_t index;
    for (index = 0U; index < sizeof(result->x); ++index) {
        if (result->x[index] != 0U || result->y[index] != 0U) {
            return false;
        }
    }

    return result->size == 0U;
}

/** @brief Successful result preserves BE bytes and exposes no secret telemetry.
 *
 * @return Zero after exact byte and diagnostic assertions. */
REGISTER_TEST(test_cc13xx_p256_success_bytes_and_reentry)
{
    ecc_point_t alias;
    UTNOX_EQUALS(setup(), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_ecc_accel_is_ready(), 1);
    s_nested = true;
    UTNOX_EQUALS(noxtls_ecc_point_multiply_accel_port(&s_result, s_scalar, &s_curve.G, &s_curve),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_IS_TRUE(s_bytes_match);
    UTNOX_EQUALS(memcmp(s_result.x, s_twice_x, sizeof(s_twice_x)), 0);
    UTNOX_EQUALS(memcmp(s_result.y, s_twice_y, sizeof(s_twice_y)), 0);
    UTNOX_EQUALS(s_result.size, 32U);
    UTNOX_EQUALS(s_nested_rc, NOXTLS_RETURN_NOT_SUPPORTED); /* Busy PKA: software fallback. */
    UTNOX_EQUALS(s_rebind_rc, NOXTLS_RETURN_NOT_INITIALIZED);
    UTNOX_EQUALS(s_calls, 1U);
    UTNOX_EQUALS(noxtls_ecc_accel_operation_count(), 1U);
    UTNOX_EQUALS(noxtls_ecc_accel_last_rc(), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_ecc_accel_last_status(), 0U);
    UTNOX_EQUALS(noxtls_ecc_accel_last_stage(), 0U);
    UTNOX_EQUALS(noxtls_ecc_accel_input_echo_ok(), 0);
    noxtls_ecc_accel_note_fallback();
    UTNOX_EQUALS(noxtls_ecc_accel_fallback_count(), 1U);
    noxtls_cc13xx_counter_store(&s_operations, UINT32_MAX);
    noxtls_cc13xx_counter_store(&s_fallbacks, UINT32_MAX);
    UTNOX_EQUALS(noxtls_ecc_point_multiply_accel_port(&s_result, s_scalar, &s_curve.G, &s_curve),
                 NOXTLS_RETURN_SUCCESS);
    noxtls_ecc_accel_note_fallback();
    UTNOX_EQUALS(noxtls_ecc_accel_operation_count(), UINT32_MAX);
    UTNOX_EQUALS(noxtls_ecc_accel_fallback_count(), UINT32_MAX);
    alias = s_curve.G;
    UTNOX_EQUALS(noxtls_ecc_point_multiply_accel_port(&alias, s_scalar,
        &alias, &s_curve), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(memcmp(alias.x, s_twice_x, sizeof(s_twice_x)), 0);
    UTNOX_EQUALS(memcmp(alias.y, s_twice_y, sizeof(s_twice_y)), 0);
    UTNOX_EQUALS(noxtls_ecc_curve_free(&s_curve), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_cc13xx_crypto_bind(NULL), NOXTLS_RETURN_SUCCESS);
    return 0;
}

/** @brief Every malformed pointer/domain is rejected before any hardware call.
 *
 * @return Zero after each null and domain-shape boundary assertion. */
REGISTER_TEST(test_cc13xx_p256_pointers_and_exact_domain)
{
    uint8_t *saved;
    uint8_t *parameters[4U];
    size_t index;
    UTNOX_EQUALS(setup(), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_ecc_point_multiply_accel_port(NULL, s_scalar, &s_curve.G, &s_curve),
                 NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_ecc_point_multiply_accel_port(&s_result, NULL, &s_curve.G, &s_curve),
                 NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_ecc_point_multiply_accel_port(&s_result, s_scalar, NULL, &s_curve),
                 NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_ecc_point_multiply_accel_port(&s_result, s_scalar, &s_curve.G, NULL),
                 NOXTLS_RETURN_NULL);
    saved = s_curve.p;
    s_curve.p = NULL;
    UTNOX_EQUALS(noxtls_ecc_point_multiply_accel_port(&s_result, s_scalar, &s_curve.G, &s_curve),
                 NOXTLS_RETURN_INVALID_PARAM);
    s_curve.p = saved;
    saved = s_curve.a;
    s_curve.a = NULL;
    UTNOX_EQUALS(noxtls_ecc_point_multiply_accel_port(&s_result, s_scalar, &s_curve.G, &s_curve),
                 NOXTLS_RETURN_INVALID_PARAM);
    s_curve.a = saved;
    saved = s_curve.b;
    s_curve.b = NULL;
    UTNOX_EQUALS(noxtls_ecc_point_multiply_accel_port(&s_result, s_scalar, &s_curve.G, &s_curve),
                 NOXTLS_RETURN_INVALID_PARAM);
    s_curve.b = saved;
    saved = s_curve.n;
    s_curve.n = NULL;
    UTNOX_EQUALS(noxtls_ecc_point_multiply_accel_port(&s_result, s_scalar, &s_curve.G, &s_curve),
                 NOXTLS_RETURN_INVALID_PARAM);
    s_curve.n = saved;
    s_curve.size = UINT32_MAX;
    UTNOX_EQUALS(noxtls_ecc_point_multiply_accel_port(&s_result, s_scalar, &s_curve.G, &s_curve),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    s_curve.size = 32U;
    s_curve.G.size = 31U;
    UTNOX_EQUALS(noxtls_ecc_point_multiply_accel_port(&s_result, s_scalar, &s_curve.G, &s_curve),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    s_curve.G.size = 32U;
    parameters[0] = s_curve.p;
    parameters[1] = s_curve.a;
    parameters[2] = s_curve.b;
    parameters[3] = s_curve.n;
    for (index = 0U; index < sizeof(parameters) / sizeof(parameters[0]); ++index) {
        parameters[index][0] ^= 1U;
        UTNOX_EQUALS(
            noxtls_ecc_point_multiply_accel_port(&s_result, s_scalar, &s_curve.G, &s_curve),
            NOXTLS_RETURN_NOT_SUPPORTED);
        parameters[index][0] ^= 1U;
    }

    s_curve.G.x[0] ^= 1U;
    UTNOX_EQUALS(noxtls_ecc_point_multiply_accel_port(&s_result, s_scalar, &s_curve.G, &s_curve),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    s_curve.G.x[0] ^= 1U;
    s_curve.G.y[0] ^= 1U;
    UTNOX_EQUALS(noxtls_ecc_point_multiply_accel_port(&s_result, s_scalar, &s_curve.G, &s_curve),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    s_curve.G.y[0] ^= 1U;
    UTNOX_IS_TRUE(cleared(&s_result));
    UTNOX_EQUALS(s_calls, 0U);
    UTNOX_EQUALS(noxtls_ecc_curve_free(&s_curve), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_cc13xx_crypto_bind(NULL), NOXTLS_RETURN_SUCCESS);
    return 0;
}

/** @brief Fixed-width scalar/point boundaries never reach invalid hardware.
 *
 * @return Zero after scalar range, infinity, field bounds and equation checks. */
REGISTER_TEST(test_cc13xx_p256_scalar_and_point_boundaries)
{
    ecc_point_t point;
    UTNOX_EQUALS(setup(), NOXTLS_RETURN_SUCCESS);
    memset(s_scalar, 0, sizeof(s_scalar));
    UTNOX_EQUALS(noxtls_ecc_point_multiply_accel_port(&s_result, s_scalar, &s_curve.G, &s_curve),
                 NOXTLS_RETURN_INVALID_PARAM);
    memcpy(s_scalar, s_curve.n, sizeof(s_scalar));
    UTNOX_EQUALS(noxtls_ecc_point_multiply_accel_port(&s_result, s_scalar, &s_curve.G, &s_curve),
                 NOXTLS_RETURN_INVALID_PARAM);
    memset(s_scalar, 0xFF, sizeof(s_scalar));
    UTNOX_EQUALS(noxtls_ecc_point_multiply_accel_port(&s_result, s_scalar, &s_curve.G, &s_curve),
                 NOXTLS_RETURN_INVALID_PARAM);
    memcpy(s_scalar, s_curve.n, sizeof(s_scalar));
    --s_scalar[sizeof(s_scalar) - 1U];
    memcpy(s_expected_scalar, s_scalar, sizeof(s_scalar));
    UTNOX_EQUALS(noxtls_ecc_point_multiply_accel_port(&s_result, s_scalar, &s_curve.G, &s_curve),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_IS_TRUE(s_bytes_match);
    memset(s_scalar, 0, sizeof(s_scalar));
    s_scalar[sizeof(s_scalar) - 1U] = 1U;
    memcpy(s_expected_scalar, s_scalar, sizeof(s_scalar));
    UTNOX_EQUALS(noxtls_ecc_point_multiply_accel_port(&s_result, s_scalar, &s_curve.G, &s_curve),
                 NOXTLS_RETURN_SUCCESS);
    point = s_curve.G;
    point.size = 33U;
    UTNOX_EQUALS(noxtls_ecc_point_multiply_accel_port(&s_result, s_scalar, &point, &s_curve),
                 NOXTLS_RETURN_BAD_DATA);
    point.size = 32U;
    memset(point.x, 0, sizeof(point.x));
    memset(point.y, 0, sizeof(point.y));
    UTNOX_EQUALS(noxtls_ecc_point_multiply_accel_port(&s_result, s_scalar, &point, &s_curve),
                 NOXTLS_RETURN_BAD_DATA);
    point = s_curve.G;
    memset(point.x, 0, sizeof(point.x));
    UTNOX_EQUALS(noxtls_ecc_point_multiply_accel_port(&s_result, s_scalar, &point, &s_curve),
                 NOXTLS_RETURN_BAD_DATA);
    point = s_curve.G;
    memcpy(point.x, s_curve.p, sizeof(s_scalar));
    UTNOX_EQUALS(noxtls_ecc_point_multiply_accel_port(&s_result, s_scalar, &point, &s_curve),
                 NOXTLS_RETURN_BAD_DATA);
    point = s_curve.G;
    memcpy(point.y, s_curve.p, sizeof(s_scalar));
    UTNOX_EQUALS(noxtls_ecc_point_multiply_accel_port(&s_result, s_scalar, &point, &s_curve),
                 NOXTLS_RETURN_BAD_DATA);
    point = s_curve.G;
    point.x[0] ^= 1U;
    UTNOX_EQUALS(noxtls_ecc_point_multiply_accel_port(&s_result, s_scalar, &point, &s_curve),
                 NOXTLS_RETURN_BAD_DATA);
    UTNOX_IS_TRUE(cleared(&s_result));
    UTNOX_EQUALS(s_calls, 2U);
    UTNOX_EQUALS(noxtls_ecc_curve_free(&s_curve), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_cc13xx_crypto_bind(NULL), NOXTLS_RETURN_SUCCESS);
    return 0;
}

/** @brief Actual failures, malformed output and absence remain explicit.
 *
 * @return Zero after every checked callback/failure result is preserved. */
REGISTER_TEST(test_cc13xx_p256_failures_and_output_validation)
{
    const noxtls_return_t errors[] = {NOXTLS_RETURN_TIMEOUT, NOXTLS_RETURN_FAILED,
                                      NOXTLS_RETURN_NOT_INITIALIZED, NOXTLS_RETURN_BAD_DATA,
                                      NOXTLS_RETURN_NOT_SUPPORTED};
    size_t index;
    UTNOX_EQUALS(setup(), NOXTLS_RETURN_SUCCESS);
    for (index = 0U; index < sizeof(errors) / sizeof(errors[0]); ++index) {
        s_callback_rc = errors[index];
        UTNOX_EQUALS(
            noxtls_ecc_point_multiply_accel_port(&s_result, s_scalar, &s_curve.G, &s_curve),
            s_callback_rc);
        UTNOX_IS_TRUE(cleared(&s_result));
    }

    s_callback_rc = NOXTLS_RETURN_SUCCESS;
    for (s_output_mode = 1U; s_output_mode <= 3U; ++s_output_mode) {
        UTNOX_EQUALS(
            noxtls_ecc_point_multiply_accel_port(&s_result, s_scalar, &s_curve.G, &s_curve),
            NOXTLS_RETURN_BAD_DATA);
        UTNOX_IS_TRUE(cleared(&s_result));
    }

    UTNOX_EQUALS(noxtls_ecc_accel_operation_count(), 0U);
    UTNOX_EQUALS(noxtls_cc13xx_crypto_bind(NULL), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_ecc_accel_is_ready(), 0);
    UTNOX_EQUALS(noxtls_ecc_point_multiply_accel_port(&s_result, s_scalar, &s_curve.G, &s_curve),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_IS_TRUE(cleared(&s_result));
    UTNOX_EQUALS(noxtls_ecc_curve_free(&s_curve), NOXTLS_RETURN_SUCCESS);
    return 0;
}
#else
/** @brief Disabled source refuses even an otherwise configured backend.
 *
 * @return Zero after no-capability and scalar-only diagnostic assertions. */
REGISTER_TEST(test_cc13xx_p256_disabled_default)
{
    ecc_point_t result;
    memset(&result, 0xA5, sizeof(result));
    UTNOX_EQUALS(noxtls_ecc_point_multiply_accel_port(&result, NULL, NULL, NULL),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_ecc_accel_is_ready(), 0);
    UTNOX_EQUALS(noxtls_ecc_accel_operation_count(), 0U);
    UTNOX_EQUALS(noxtls_ecc_accel_last_rc(), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_ecc_accel_last_status(), 0U);
    UTNOX_EQUALS(noxtls_ecc_accel_last_stage(), 0U);
    UTNOX_EQUALS(noxtls_ecc_accel_input_echo_ok(), 0);
    noxtls_ecc_accel_note_fallback();
    UTNOX_EQUALS(noxtls_ecc_accel_fallback_count(), 1U);
    return 0;
}
#endif

#if defined(_MSC_VER) && !defined(__cplusplus)
/** @brief Register exactly the enabled fixture for MSVC-compatible C builds.
 *
 * @return None. */
void utnox_register_tests(void)
{
#if NOXTLS_CC13XX_P256_ACCEL_ENABLED
    register_test("test_cc13xx_p256_success_bytes_and_reentry",
        test_cc13xx_p256_success_bytes_and_reentry);
    register_test("test_cc13xx_p256_pointers_and_exact_domain",
        test_cc13xx_p256_pointers_and_exact_domain);
    register_test("test_cc13xx_p256_scalar_and_point_boundaries",
        test_cc13xx_p256_scalar_and_point_boundaries);
    register_test("test_cc13xx_p256_failures_and_output_validation",
        test_cc13xx_p256_failures_and_output_validation);
#else
    register_test("test_cc13xx_p256_disabled_default", test_cc13xx_p256_disabled_default);
#endif
}
#endif
