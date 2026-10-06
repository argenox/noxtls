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
* File:    cc13xx_engines_ut.c
* Summary: Independent CC13xx AES/PKA engines through the AES and ECC cores
*
*
*****************************************************************************/

/** @file cc13xx_engines_ut.c
 * @brief Cross-engine concurrency, fallback and known answers via public APIs.
 * @ingroup noxtls_cc13xx_crypto
 *
 * Built once per selection: umbrella, both per-engine switches, AES only,
 * P-256 only and none. The "hardware" callbacks model a yielding driver by
 * calling back into NoxTLS while their engine is held: a nested request for
 * the same engine must fall back to software, a request for the other engine
 * may use it, and every result is checked against a known answer.
 * Vectors: FIPS 197 (2023) Appendix C.1 (AES-128); SEC 2 v2.0 section 2.4.2
 * (secp256r1 G), with 2G and (n-1)G = -G = (Gx, p - Gy).
 */
#include "noxtls_config.h"
#include "noxtls_cc13xx_crypto.h"
#include "noxtls_aes.h"
#include "pkc/ecc/noxtls_ecc.h"
#include "runner.h"
#include "test_assert.h"
#include <string.h>

/** True when this image compiles the CC13xx AES port. */
#define UT_AES_PORT ((NOXTLS_CC13XX_AES_ACCEL_ENABLED) ? 1U : 0U)
/** True when this image compiles the CC13xx P-256 port. */
#define UT_P256_PORT ((NOXTLS_CC13XX_P256_ACCEL_ENABLED) ? 1U : 0U)
/** True when the shared binding is linked. */
#define UT_BINDING ((NOXTLS_CC13XX_AES_ACCEL_ENABLED) || (NOXTLS_CC13XX_P256_ACCEL_ENABLED))
/** secp256r1 scalar and coordinate width. */
#define UT_P256_BYTES 32U
/** One AES block. */
#define UT_AES_BLOCK 16U

/** FIPS 197 (2023) Appendix C.1 AES-128 key. */
static const uint8_t s_kat_key[UT_AES_BLOCK] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
/** FIPS 197 (2023) Appendix C.1 plaintext. */
static const uint8_t s_kat_pt[UT_AES_BLOCK] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
/** FIPS 197 (2023) Appendix C.1 ciphertext. */
static const uint8_t s_kat_ct[UT_AES_BLOCK] = {
    0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a};
/** x(2G) for secp256r1. */
static const uint8_t s_twice_x[UT_P256_BYTES] = {
    0x7c, 0xf2, 0x7b, 0x18, 0x8d, 0x03, 0x4f, 0x7e, 0x8a, 0x52, 0x38, 0x03, 0x04, 0xb5, 0x1a, 0xc3,
    0xc0, 0x89, 0x69, 0xe2, 0x77, 0xf2, 0x1b, 0x35, 0xa6, 0x0b, 0x48, 0xfc, 0x47, 0x66, 0x99, 0x78};
/** y(2G) for secp256r1. */
static const uint8_t s_twice_y[UT_P256_BYTES] = {
    0x07, 0x77, 0x55, 0x10, 0xdb, 0x8e, 0xd0, 0x40, 0x29, 0x3d, 0x9a, 0xc6, 0x9f, 0x74, 0x30, 0xdb,
    0xba, 0x7d, 0xad, 0xe6, 0x3c, 0xe9, 0x82, 0x29, 0x9e, 0x04, 0xb7, 0x9d, 0x22, 0x78, 0x73, 0xd1};
/** y(-G) = p - Gy for secp256r1. */
static const uint8_t s_neg_gy[UT_P256_BYTES] = {
    0xb0, 0x1c, 0xbd, 0x1c, 0x01, 0xe5, 0x80, 0x65, 0x71, 0x18, 0x14, 0xb5, 0x83, 0xf0, 0x61, 0xe9,
    0xd4, 0x31, 0xcc, 0xa9, 0x94, 0xce, 0xa1, 0x31, 0x34, 0x49, 0xbf, 0x97, 0xc8, 0x40, 0xae, 0x0a};

static ecc_curve_params_t s_curve;
static uint32_t s_aes_calls;
static uint32_t s_p256_calls;
static noxtls_return_t s_aes_fail;
static noxtls_return_t s_p256_fail;
static bool s_probe_aes;
static bool s_probe_bind;
static noxtls_return_t s_inner_aes_rc;
static noxtls_return_t s_during_aes_rc;
static noxtls_return_t s_nested_p256_rc;
static noxtls_return_t s_bind_rc;
static uint8_t s_during_aes_out[UT_AES_BLOCK];

/**
 * @brief Run the AES-128 known answer through the public ECB API.
 * @internal
 *
 * @param[out] output One output block.
 *
 * @return ECB status.
 */
static noxtls_return_t aes_kat(uint8_t output[UT_AES_BLOCK])
{
    return noxtls_aes_encrypt_ecb(s_kat_key, s_kat_pt, UT_AES_BLOCK, NULL, output, NOXTLS_AES_128_BIT);
}

/**
 * @brief Multiply G by a small or (n-1) scalar through the public ECC API.
 * @internal
 *
 * @param[out] result Result point.
 * @param[in] minus_one True for n-1, false for 2.
 *
 * @return Point multiplication status.
 */
static noxtls_return_t multiply_g(ecc_point_t *result, bool minus_one)
{
    uint8_t scalar[UT_P256_BYTES] = {0};
    if (minus_one) {
        memcpy(scalar, s_curve.n, sizeof(scalar));
        --scalar[UT_P256_BYTES - 1U];
    } else {
        scalar[UT_P256_BYTES - 1U] = 2U;
    }

    return noxtls_ecc_point_multiply(result, scalar, &s_curve.G, &s_curve);
}

/**
 * @brief Check a result point against 2G or -G.
 * @internal
 *
 * @param[in] point Result point.
 * @param[in] minus_one True for -G.
 *
 * @return True on an exact match.
 */
static bool point_is(const ecc_point_t *point, bool minus_one)
{
    if (minus_one) {
        return (memcmp(point->x, s_curve.G.x, UT_P256_BYTES) == 0) &&
            (memcmp(point->y, s_neg_gy, UT_P256_BYTES) == 0);
    }

    return (memcmp(point->x, s_twice_x, UT_P256_BYTES) == 0) &&
        (memcmp(point->y, s_twice_y, UT_P256_BYTES) == 0);
}

#if UT_BINDING
/**
 * @brief AES "hardware": holds the AES engine and computes through NoxTLS.
 * @internal
 *
 * The nested ECB call finds the AES engine busy, so it must use software.
 *
 * @param[in] context Unused.
 * @param[in] decrypt True for decryption.
 * @param[in] key Key bytes.
 * @param[in] key_length 16, 24 or 32.
 * @param[in] input One block.
 * @param[out] output One block.
 *
 * @return Injected failure or nested status.
 */
static noxtls_return_t hw_aes(void *context, bool decrypt, const uint8_t *key,
    uint32_t key_length, const uint8_t input[UT_AES_BLOCK], uint8_t output[UT_AES_BLOCK])
{
    const noxtls_aes_type_t type = (key_length == 16U) ? NOXTLS_AES_128_BIT :
        ((key_length == 24U) ? NOXTLS_AES_192_BIT : NOXTLS_AES_256_BIT);
    (void)context;
    ++s_aes_calls;
    if (s_aes_fail != NOXTLS_RETURN_SUCCESS) {
        return s_aes_fail;
    }

    if (s_probe_bind) {
        s_bind_rc = noxtls_cc13xx_crypto_bind(NULL);
    }

    s_inner_aes_rc = decrypt ? noxtls_aes_decrypt_ecb(key, input, UT_AES_BLOCK, NULL, output, type) :
        noxtls_aes_encrypt_ecb(key, input, UT_AES_BLOCK, NULL, output, type);
    return s_inner_aes_rc;
}

/**
 * @brief PKA "hardware": holds the PKA, may run AES, and computes through NoxTLS.
 * @internal
 *
 * Models a driver that yields while the PKA works: an AES request made here
 * is a request made while the multiply is in progress. The nested multiply
 * finds the PKA busy, so it must use software.
 *
 * @param[in] context Unused.
 * @param[in] scalar Big-endian scalar.
 * @param[in] x Input x.
 * @param[in] y Input y.
 * @param[out] result_x Output x.
 * @param[out] result_y Output y.
 *
 * @return Injected failure or nested status.
 */
static noxtls_return_t hw_p256(void *context, const uint8_t scalar[UT_P256_BYTES],
    const uint8_t x[UT_P256_BYTES], const uint8_t y[UT_P256_BYTES],
    uint8_t result_x[UT_P256_BYTES], uint8_t result_y[UT_P256_BYTES])
{
    ecc_point_t point;
    ecc_point_t nested;
    (void)context;
    ++s_p256_calls;
    if (s_p256_fail != NOXTLS_RETURN_SUCCESS) {
        return s_p256_fail;
    }

    if (s_probe_bind) {
        s_bind_rc = noxtls_cc13xx_crypto_bind(NULL);
    }

    if (s_probe_aes) {
        s_during_aes_rc = aes_kat(s_during_aes_out);
    }

    memset(&point, 0, sizeof(point));
    memcpy(point.x, x, UT_P256_BYTES);
    memcpy(point.y, y, UT_P256_BYTES);
    point.size = UT_P256_BYTES;
    s_nested_p256_rc = noxtls_ecc_point_multiply(&nested, scalar, &point, &s_curve);
    memcpy(result_x, nested.x, UT_P256_BYTES);
    memcpy(result_y, nested.y, UT_P256_BYTES);
    return s_nested_p256_rc;
}

/**
 * @brief Bind the selected model callbacks.
 * @internal
 *
 * @param[in] aes Bind the AES callback.
 * @param[in] p256 Bind the P-256 callback.
 *
 * @return Bind status.
 */
static noxtls_return_t bind_models(bool aes, bool p256)
{
    noxtls_cc13xx_crypto_binding_t binding;
    memset(&binding, 0, sizeof(binding));
    binding.aes_block = aes ? hw_aes : NULL;
    binding.p256_multiply = p256 ? hw_p256 : NULL;
    return noxtls_cc13xx_crypto_bind((aes || p256) ? &binding : NULL);
}
#endif

/**
 * @brief Reset fixture state and the secp256r1 domain.
 * @internal
 *
 * @return Curve initialization status.
 */
static noxtls_return_t setup(void)
{
    s_aes_calls = 0U;
    s_p256_calls = 0U;
    s_aes_fail = NOXTLS_RETURN_SUCCESS;
    s_p256_fail = NOXTLS_RETURN_SUCCESS;
    s_probe_aes = false;
    s_probe_bind = false;
    s_inner_aes_rc = NOXTLS_RETURN_FAILED;
    s_during_aes_rc = NOXTLS_RETURN_FAILED;
    s_nested_p256_rc = NOXTLS_RETURN_FAILED;
    s_bind_rc = NOXTLS_RETURN_FAILED;
    memset(s_during_aes_out, 0, sizeof(s_during_aes_out));
    (void)noxtls_ecc_curve_free(&s_curve);
    memset(&s_curve, 0, sizeof(s_curve));
    return noxtls_ecc_curve_init(&s_curve, NOXTLS_ECC_SECP256R1);
}

/** @brief Software-only paths stay correct in every selection. */
REGISTER_TEST(test_engines_unbound_use_software)
{
    uint8_t out[UT_AES_BLOCK];
    ecc_point_t result;
    uint32_t fallbacks;
    UTNOX_EQUALS(setup(), NOXTLS_RETURN_SUCCESS);
#if UT_BINDING
    UTNOX_EQUALS(bind_models(false, false), NOXTLS_RETURN_SUCCESS);
#endif
    fallbacks = noxtls_ecc_accel_fallback_count();
    UTNOX_EQUALS(aes_kat(out), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(memcmp(out, s_kat_ct, sizeof(out)), 0);
    UTNOX_EQUALS(multiply_g(&result, false), NOXTLS_RETURN_SUCCESS);
    UTNOX_IS_TRUE(point_is(&result, false));
    UTNOX_EQUALS(noxtls_ecc_accel_fallback_count(), fallbacks + 1U);
    UTNOX_EQUALS(noxtls_ecc_accel_is_ready(), 0);
    UTNOX_EQUALS(s_aes_calls, 0U);
    UTNOX_EQUALS(s_p256_calls, 0U);
    return 0;
}

#if UT_BINDING
/** @brief AES during an active, yielding P-256 multiply succeeds with the KAT. */
REGISTER_TEST(test_engines_aes_kat_while_p256_multiply_active)
{
    ecc_point_t result;
    uint32_t fallbacks;
    uint32_t operations;
    UTNOX_EQUALS(setup(), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(bind_models(true, true), NOXTLS_RETURN_SUCCESS);
    s_probe_aes = true;
    fallbacks = noxtls_ecc_accel_fallback_count();
    operations = noxtls_ecc_accel_operation_count();
    UTNOX_EQUALS(multiply_g(&result, false), NOXTLS_RETURN_SUCCESS);
    UTNOX_IS_TRUE(point_is(&result, false));
    UTNOX_EQUALS(s_p256_calls, UT_P256_PORT);
    if (UT_P256_PORT != 0U) {
        /* The AES engine was free while the PKA was held. */
        UTNOX_EQUALS(s_during_aes_rc, NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(memcmp(s_during_aes_out, s_kat_ct, UT_AES_BLOCK), 0);
        UTNOX_EQUALS(s_aes_calls, UT_AES_PORT);
        if (UT_AES_PORT != 0U) {
            UTNOX_EQUALS(s_inner_aes_rc, NOXTLS_RETURN_SUCCESS); /* Busy AES: software. */
        }

        UTNOX_EQUALS(s_nested_p256_rc, NOXTLS_RETURN_SUCCESS); /* Busy PKA: software. */
        UTNOX_EQUALS(noxtls_ecc_accel_operation_count(), operations + 1U);
    }

    /* Exactly one software multiply in both cases: nested, or the whole request. */
    UTNOX_EQUALS(noxtls_ecc_accel_fallback_count(), fallbacks + 1U);
    /* Same request with no AES callback bound: AES is computed in software. */
    UTNOX_EQUALS(setup(), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(bind_models(false, true), NOXTLS_RETURN_SUCCESS);
    s_probe_aes = true;
    UTNOX_EQUALS(multiply_g(&result, true), NOXTLS_RETURN_SUCCESS);
    UTNOX_IS_TRUE(point_is(&result, true));
    if (UT_P256_PORT != 0U) {
        UTNOX_EQUALS(s_during_aes_rc, NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(memcmp(s_during_aes_out, s_kat_ct, UT_AES_BLOCK), 0);
    }

    UTNOX_EQUALS(s_aes_calls, 0U);
    UTNOX_EQUALS(bind_models(false, false), NOXTLS_RETURN_SUCCESS);
    return 0;
}

/** @brief A second multiply during an active one falls back and is correct. */
REGISTER_TEST(test_engines_nested_p256_falls_back_with_correct_point)
{
    ecc_point_t result;
    uint32_t fallbacks;
    uint32_t operations;
    UTNOX_EQUALS(setup(), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(bind_models(false, true), NOXTLS_RETURN_SUCCESS);
    fallbacks = noxtls_ecc_accel_fallback_count();
    operations = noxtls_ecc_accel_operation_count();
    UTNOX_EQUALS(multiply_g(&result, true), NOXTLS_RETURN_SUCCESS);
    UTNOX_IS_TRUE(point_is(&result, true));
    UTNOX_EQUALS(multiply_g(&result, false), NOXTLS_RETURN_SUCCESS);
    UTNOX_IS_TRUE(point_is(&result, false));
    UTNOX_EQUALS(s_p256_calls, 2U * UT_P256_PORT); /* Never reentered. */
    UTNOX_EQUALS(noxtls_ecc_accel_fallback_count(), fallbacks + 2U);
    UTNOX_EQUALS(noxtls_ecc_accel_operation_count(), operations + (2U * UT_P256_PORT));
    UTNOX_EQUALS(noxtls_ecc_accel_is_ready(), (int)UT_P256_PORT);
    UTNOX_EQUALS(bind_models(false, false), NOXTLS_RETURN_SUCCESS);
    return 0;
}

/** @brief Each engine bound alone serves its own requests only. */
REGISTER_TEST(test_engines_single_engine_bound)
{
    uint8_t out[UT_AES_BLOCK];
    ecc_point_t result;
    UTNOX_EQUALS(setup(), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(bind_models(true, false), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(aes_kat(out), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(memcmp(out, s_kat_ct, sizeof(out)), 0);
    UTNOX_EQUALS(s_aes_calls, UT_AES_PORT);
    UTNOX_EQUALS(multiply_g(&result, false), NOXTLS_RETURN_SUCCESS);
    UTNOX_IS_TRUE(point_is(&result, false));
    UTNOX_EQUALS(s_p256_calls, 0U);
    UTNOX_EQUALS(noxtls_ecc_accel_is_ready(), 0);
    UTNOX_EQUALS(setup(), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(bind_models(false, true), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(aes_kat(out), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(memcmp(out, s_kat_ct, sizeof(out)), 0);
    UTNOX_EQUALS(s_aes_calls, 0U);
    UTNOX_EQUALS(multiply_g(&result, false), NOXTLS_RETURN_SUCCESS);
    UTNOX_IS_TRUE(point_is(&result, false));
    UTNOX_EQUALS(s_p256_calls, UT_P256_PORT);
    UTNOX_EQUALS(bind_models(false, false), NOXTLS_RETURN_SUCCESS);
    return 0;
}

/** @brief Genuine accelerator errors still fail the request; no software result. */
REGISTER_TEST(test_engines_callback_errors_propagate)
{
    uint8_t out[UT_AES_BLOCK];
    ecc_point_t result;
    UTNOX_EQUALS(setup(), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(bind_models(true, true), NOXTLS_RETURN_SUCCESS);
    s_aes_fail = NOXTLS_RETURN_TIMEOUT;
    s_p256_fail = NOXTLS_RETURN_TIMEOUT;
    memset(out, 0xA5, sizeof(out));
    UTNOX_EQUALS(aes_kat(out), (UT_AES_PORT != 0U) ? NOXTLS_RETURN_TIMEOUT : NOXTLS_RETURN_SUCCESS);
    if (UT_AES_PORT == 0U) {
        UTNOX_EQUALS(memcmp(out, s_kat_ct, sizeof(out)), 0);
    }

    UTNOX_EQUALS(multiply_g(&result, false),
        (UT_P256_PORT != 0U) ? NOXTLS_RETURN_TIMEOUT : NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_ecc_accel_last_rc(),
        (UT_P256_PORT != 0U) ? NOXTLS_RETURN_TIMEOUT : NOXTLS_RETURN_NOT_SUPPORTED);
    /* Guards were released after the failures. */
    s_aes_fail = NOXTLS_RETURN_SUCCESS;
    s_p256_fail = NOXTLS_RETURN_SUCCESS;
    UTNOX_EQUALS(aes_kat(out), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(memcmp(out, s_kat_ct, sizeof(out)), 0);
    UTNOX_EQUALS(multiply_g(&result, false), NOXTLS_RETURN_SUCCESS);
    UTNOX_IS_TRUE(point_is(&result, false));
    UTNOX_EQUALS(bind_models(false, false), NOXTLS_RETURN_SUCCESS);
    return 0;
}

/** @brief Bind is refused while either engine is active, then succeeds. */
REGISTER_TEST(test_engines_bind_refused_while_active)
{
    uint8_t out[UT_AES_BLOCK];
    ecc_point_t result;
    UTNOX_EQUALS(setup(), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(bind_models(true, true), NOXTLS_RETURN_SUCCESS);
    s_probe_bind = true;
    UTNOX_EQUALS(aes_kat(out), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(memcmp(out, s_kat_ct, sizeof(out)), 0);
    if (UT_AES_PORT != 0U) {
        UTNOX_EQUALS(s_bind_rc, NOXTLS_RETURN_NOT_INITIALIZED);
    }

    s_bind_rc = NOXTLS_RETURN_FAILED;
    UTNOX_EQUALS(multiply_g(&result, false), NOXTLS_RETURN_SUCCESS);
    UTNOX_IS_TRUE(point_is(&result, false));
    if (UT_P256_PORT != 0U) {
        UTNOX_EQUALS(s_bind_rc, NOXTLS_RETURN_NOT_INITIALIZED);
        UTNOX_EQUALS(noxtls_cc13xx_crypto_has_p256(), true);
    }

    UTNOX_EQUALS(bind_models(false, false), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_cc13xx_crypto_has_p256(), false);
    return 0;
}
#endif

#if defined(_MSC_VER) && !defined(__cplusplus)
/** @brief Register the selection's fixtures for MSVC-compatible C builds. */
void utnox_register_tests(void)
{
    register_test("test_engines_unbound_use_software", test_engines_unbound_use_software);
#if UT_BINDING
    register_test("test_engines_aes_kat_while_p256_multiply_active",
        test_engines_aes_kat_while_p256_multiply_active);
    register_test("test_engines_nested_p256_falls_back_with_correct_point",
        test_engines_nested_p256_falls_back_with_correct_point);
    register_test("test_engines_single_engine_bound", test_engines_single_engine_bound);
    register_test("test_engines_callback_errors_propagate", test_engines_callback_errors_propagate);
    register_test("test_engines_bind_refused_while_active", test_engines_bind_refused_while_active);
#endif
}
#endif
