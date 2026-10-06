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
* File:    ecc_accel_errors_ut.c
* Summary: ECC accelerator failure propagation regression tests
*
*
*****************************************************************************/

/** @file ecc_accel_errors_ut.c
 * @brief Actual dispatcher/math with platform accelerator result injection.
 * @defgroup noxtls_ecc_errors ECC accelerator failure isolation
 * @brief Default and Nordic-equivalent callback error regression evidence.
 */
#include "pkc/ecc/noxtls_ecc.h"
#include "runner.h"
#include "test_assert.h"
#include <string.h>

static ecc_curve_params_t s_curve;
static ecc_point_t s_result;
static uint8_t s_scalar[32U];
static noxtls_return_t s_rc;
static unsigned s_calls;
static unsigned s_fallbacks;
static const uint8_t s_twice_x[32U] = {
    0x7c, 0xf2, 0x7b, 0x18, 0x8d, 0x03, 0x4f, 0x7e, 0x8a, 0x52, 0x38, 0x03, 0x04, 0xb5, 0x1a, 0xc3,
    0xc0, 0x89, 0x69, 0xe2, 0x77, 0xf2, 0x1b, 0x35, 0xa6, 0x0b, 0x48, 0xfc, 0x47, 0x66, 0x99, 0x78};
static const uint8_t s_twice_y[32U] = {
    0x07, 0x77, 0x55, 0x10, 0xdb, 0x8e, 0xd0, 0x40, 0x29, 0x3d, 0x9a, 0xc6, 0x9f, 0x74, 0x30, 0xdb,
    0xba, 0x7d, 0xad, 0xe6, 0x3c, 0xe9, 0x82, 0x29, 0x9e, 0x04, 0xb7, 0x9d, 0x22, 0x78, 0x73, 0xd1};

/** @brief Inject real backend status and partial output, not software failure.
 *
 * @param[out] result Caller-owned output.
 * @param[in] scalar Complete input scalar.
 * @param[in] point Complete public input point.
 * @param[in] curve Validated test domain.
 *
 * @return Actual injected platform result. */
noxtls_return_t noxtls_ecc_point_multiply_accel_port(ecc_point_t *result, const uint8_t *scalar,
                                                     const ecc_point_t *point,
                                                     const ecc_curve_params_t *curve)
{
    (void)scalar;
    (void)point;
    (void)curve;
    ++s_calls;
    memset(result, 0xA5, sizeof(*result));
    if (s_rc == NOXTLS_RETURN_SUCCESS) {
        memcpy(result->x, s_twice_x, sizeof(s_twice_x));
        memcpy(result->y, s_twice_y, sizeof(s_twice_y));
        result->size = sizeof(s_twice_x);
    }

    return s_rc;
}

/** @brief Record only actual NOT_SUPPORTED software continuation.
 *
 * @return None. */
void noxtls_ecc_accel_note_fallback(void)
{
    ++s_fallbacks;
}

/** @brief Build an actual secp256r1 domain for known 2G and failure tests.
 *
 * @return Actual curve initialization status. */
static noxtls_return_t setup(void)
{
    memset(&s_curve, 0, sizeof(s_curve));
    memset(&s_result, 0x39, sizeof(s_result));
    memset(s_scalar, 0, sizeof(s_scalar));
    s_scalar[sizeof(s_scalar) - 1U] = 2U;
    s_calls = 0U;
    s_fallbacks = 0U;
    return noxtls_ecc_curve_init(&s_curve, NOXTLS_ECC_SECP256R1);
}

/** @brief All communicated runtime errors propagate and erase partial outputs.
 *
 * @return Zero after exact error/cleared-output/no-fallback assertions. */
REGISTER_TEST(test_ecc_actual_backend_errors_do_not_fallback)
{
    const noxtls_return_t errors[] = {NOXTLS_RETURN_FAILED,           NOXTLS_RETURN_TIMEOUT,
                                      NOXTLS_RETURN_NOT_INITIALIZED,  NOXTLS_RETURN_INVALID_PARAM,
                                      NOXTLS_RETURN_BAD_DATA,         NOXTLS_RETURN_NULL,
                                      NOXTLS_RETURN_NOT_ENOUGH_MEMORY};
    size_t index;
    size_t byte;
    UTNOX_EQUALS(setup(), NOXTLS_RETURN_SUCCESS);
    for (index = 0U; index < sizeof(errors) / sizeof(errors[0]); ++index) {
        s_rc = errors[index];
        UTNOX_EQUALS(noxtls_ecc_point_multiply(&s_result, s_scalar, &s_curve.G, &s_curve), s_rc);
        UTNOX_EQUALS(s_result.size, 0U);
        for (byte = 0U; byte < sizeof(s_result.x); ++byte) {
            UTNOX_EQUALS(s_result.x[byte], 0U);
            UTNOX_EQUALS(s_result.y[byte], 0U);
        }
    }

    UTNOX_EQUALS(s_calls, sizeof(errors) / sizeof(errors[0]));
    UTNOX_EQUALS(s_fallbacks, 0U);
    UTNOX_EQUALS(noxtls_ecc_curve_free(&s_curve), NOXTLS_RETURN_SUCCESS);
    return 0;
}

/** @brief Unavailable/default capability still computes the correct software 2G.
 *
 * @return Zero after known-point and exact fallback-count assertions. */
REGISTER_TEST(test_ecc_software_default_not_supported_fallback)
{
    UTNOX_EQUALS(setup(), NOXTLS_RETURN_SUCCESS);
    s_rc = NOXTLS_RETURN_NOT_SUPPORTED;
    UTNOX_EQUALS(noxtls_ecc_point_multiply(&s_result, s_scalar, &s_curve.G, &s_curve),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(memcmp(s_result.x, s_twice_x, sizeof(s_twice_x)), 0);
    UTNOX_EQUALS(memcmp(s_result.y, s_twice_y, sizeof(s_twice_y)), 0);
    UTNOX_EQUALS(s_result.size, sizeof(s_twice_x));
    UTNOX_EQUALS(s_calls, 1U);
    UTNOX_EQUALS(s_fallbacks, 1U);
    UTNOX_EQUALS(noxtls_ecc_curve_free(&s_curve), NOXTLS_RETURN_SUCCESS);
    return 0;
}

/** @brief Successful hardware result is preserved, including scalar shortcuts.
 *
 * @return Zero after success/no-fallback and unchanged zero/one behavior. */
REGISTER_TEST(test_ecc_success_and_scalar_shortcuts_are_preserved)
{
    UTNOX_EQUALS(setup(), NOXTLS_RETURN_SUCCESS);
    s_rc = NOXTLS_RETURN_SUCCESS;
    UTNOX_EQUALS(noxtls_ecc_point_multiply(&s_result, s_scalar, &s_curve.G, &s_curve),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(memcmp(s_result.x, s_twice_x, sizeof(s_twice_x)), 0);
    UTNOX_EQUALS(s_fallbacks, 0U);
    s_scalar[sizeof(s_scalar) - 1U] = 1U;
    UTNOX_EQUALS(noxtls_ecc_point_multiply(&s_result, s_scalar, &s_curve.G, &s_curve),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(memcmp(s_result.x, s_curve.G.x, sizeof(s_twice_x)), 0);
    s_scalar[sizeof(s_scalar) - 1U] = 0U;
    UTNOX_EQUALS(noxtls_ecc_point_multiply(&s_result, s_scalar, &s_curve.G, &s_curve),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(s_calls, 1U);
    UTNOX_EQUALS(noxtls_ecc_curve_free(&s_curve), NOXTLS_RETURN_SUCCESS);
    return 0;
}

#if defined(_MSC_VER) && !defined(__cplusplus)
/** @brief Register the C fixture with the MSVC-compatible UTNox runner.
 *
 * @return None. */
void utnox_register_tests(void)
{
    register_test("test_ecc_actual_backend_errors_do_not_fallback",
        test_ecc_actual_backend_errors_do_not_fallback);
    register_test("test_ecc_software_default_not_supported_fallback",
        test_ecc_software_default_not_supported_fallback);
    register_test("test_ecc_success_and_scalar_shortcuts_are_preserved",
        test_ecc_success_and_scalar_shortcuts_are_preserved);
}
#endif
