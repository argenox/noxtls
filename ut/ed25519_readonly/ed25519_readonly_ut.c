/* Copyright (c) 2026 Argenox Technologies LLC. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
 * File: ed25519_readonly_ut.c
 * Summary: Compare complete generated tables and independent scalar ladders.
 */
/** @file ed25519_readonly_ut.c
 * @brief Exercise actual group arithmetic under lazy and read-only profiles.
 */
#include <stdbool.h>
#include "runner.h"
#include "test_assert.h"
#include "ed25519_readonly_test_config.h"
/* Include the production translation unit to inspect private tables without
 * exporting a test API or adding any production workspace. */
#include "../../noxtls-lib/pkc/ed25519/noxtls_ed25519_ge.c"

/** RFC 8032 base point for the independent binary-ladder oracle. */
static const uint8_t s_test_base_point[ED_READONLY_TEST_SCALAR_BYTES] =
    ED_READONLY_TEST_BASE_POINT;

/** @brief Independent binary double/add ladder, without either base table.
 * @param[out] result Result point.
 * @param[in] point Arbitrary base point.
 * @param[in] scalar Full little-endian scalar.
 */
static void test_binary_multiply(ge25519_n_t *result,
    const ge25519_n_t *point, const uint8_t *scalar)
{
    int32_t bit;
    ge25519_n_zero(result);
    for(bit = (int32_t)NOXTLS_ED25519_SCALAR_BIT_LENGTH - 1; bit >= 0; bit--) {
        ge25519_n_dbl(result, result);
        if(((scalar[(uint32_t)bit / ED_READONLY_TEST_BYTE_BITS] >>
             ((uint32_t)bit % ED_READONLY_TEST_BYTE_BITS)) & 1U) != 0U) {
            ge25519_n_add(result, result, point);
        }
    }
}

/** @brief Fill a public deterministic scalar, not a key-generation RNG.
 * @param[out] scalar Scalar bytes.
 * @param[in,out] state Deterministic test state.
 */
static void test_scalar(uint8_t *scalar, uint32_t *state)
{
    uint32_t i;
    for(i = 0U; i < ED_READONLY_TEST_SCALAR_BYTES; i++) {
        *state = *state * ED_READONLY_TEST_LCG_MULTIPLIER + ED_READONLY_TEST_LCG_INCREMENT;
        scalar[i] = (uint8_t)(*state >> ED_READONLY_TEST_TOP_SHIFT);
    }
}

/** @brief Every native limb matches a freshly generated in-house table.
 * @return Zero on success.
 */
REGISTER_TEST(ed25519_readonly_all_generated_entries)
{
    ge25519_pt_t decoded;
    ge25519_n_t base, twice, odd;
    ge25519_n_t compact[NOXTLS_ED25519_SCALAR_TABLE_ENTRIES];
    ge25519_precomp_t expected;
    uint32_t i;
    UTNOX_EQUALS(ge25519_decode(&decoded, s_test_base_point), NOXTLS_RETURN_SUCCESS);
    ge25519_n_from_pt(&base, &decoded);
    ge25519_n_precompute_table(compact, &base);
    UTNOX_EQUALS(ge25519_base_table_small_init(), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(ge25519_base_odd_init(), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(memcmp(compact, g_base_table_small, sizeof(compact)), 0);
    ge25519_n_to_affine(&base);
    ge25519_n_dbl(&twice, &base);
    ge25519_n_to_affine(&twice);
    odd = base;
    for(i = 0U; i < NOXTLS_ED25519_SLIDE_ODD_COUNT; i++) {
        ge25519_n_to_affine(&odd);
        ge25519_n_to_precomp(&expected, &odd);
        UTNOX_EQUALS(memcmp(&expected, &g_base_odd[i], sizeof(expected)), 0);
        if(i + 1U < NOXTLS_ED25519_SLIDE_ODD_COUNT) {
            ge25519_n_add(&odd, &odd, &twice);
        }
    }

    return 0;
}

/** @brief Zero, maximum and deterministic full-width scalars match a binary ladder.
 * @return Zero on success.
 */
REGISTER_TEST(ed25519_readonly_full_width_fixed_base)
{
    uint8_t scalar[ED_READONLY_TEST_SCALAR_BYTES];
    uint8_t actual_bytes[ED_READONLY_TEST_SCALAR_BYTES];
    uint8_t expected_bytes[ED_READONLY_TEST_SCALAR_BYTES];
    ge25519_pt_t decoded;
    ge25519_n_t base, actual, expected;
    uint32_t seed = ED_READONLY_TEST_SEED, i;
    UTNOX_EQUALS(ge25519_decode(&decoded, s_test_base_point), NOXTLS_RETURN_SUCCESS);
    ge25519_n_from_pt(&base, &decoded);
    for(i = 0U; i < ED_READONLY_TEST_CASES; i++) {
        test_scalar(scalar, &seed);
        if(i < 2U) {
            (void)memset(scalar, i == 0U ? 0 : 0xff, sizeof(scalar));
        }

        ge25519_scalarmult_base_n(&actual, scalar);
        test_binary_multiply(&expected, &base, scalar);
        ge25519_encode_n(actual_bytes, &actual);
        ge25519_encode_n(expected_bytes, &expected);
        UTNOX_EQUALS(memcmp(actual_bytes, expected_bytes, sizeof(actual_bytes)), 0);
    }

    return 0;
}

/** @brief Verify's signed sliding-window path matches independent additions.
 * @return Zero on success.
 */
REGISTER_TEST(ed25519_readonly_double_scalar_verify_path)
{
    uint8_t a[ED_READONLY_TEST_SCALAR_BYTES], b[ED_READONLY_TEST_SCALAR_BYTES];
    uint8_t actual_bytes[ED_READONLY_TEST_SCALAR_BYTES], expected_bytes[ED_READONLY_TEST_SCALAR_BYTES];
    ge25519_pt_t decoded;
    ge25519_n_t base, variable, actual, left, right, expected;
    uint32_t seed = ED_READONLY_TEST_SEED, i;
    UTNOX_EQUALS(ge25519_decode(&decoded, s_test_base_point), NOXTLS_RETURN_SUCCESS);
    ge25519_n_from_pt(&base, &decoded);
    test_scalar(a, &seed);
    test_binary_multiply(&variable, &base, a);
    for(i = 0U; i < ED_READONLY_TEST_CASES; i++) {
        test_scalar(a, &seed);
        test_scalar(b, &seed);
        a[ED_READONLY_TEST_SCALAR_BYTES - 1U] &= ED_READONLY_TEST_CANONICAL_TOP_MASK;
        b[ED_READONLY_TEST_SCALAR_BYTES - 1U] &= ED_READONLY_TEST_CANONICAL_TOP_MASK;
        if(i == 0U) {
            (void)memset(a, 0, sizeof(a));
            (void)memset(b, 0, sizeof(b));
        }

        ge25519_double_scalarmult_n(&actual, a, &variable, b);
        test_binary_multiply(&left, &variable, a);
        test_binary_multiply(&right, &base, b);
        ge25519_n_add(&expected, &left, &right);
        ge25519_encode_n(actual_bytes, &actual);
        ge25519_encode_n(expected_bytes, &expected);
        UTNOX_EQUALS(memcmp(actual_bytes, expected_bytes, sizeof(actual_bytes)), 0);
    }

    return 0;
}

/** @brief Preserve public point ABI and malformed-encoding rejection.
 * @return Zero on success.
 */
REGISTER_TEST(ed25519_readonly_public_abi_and_rejection)
{
    ge25519_pt_t base, fixed, variable, combined;
    ge25519_n_t native;
    const uint8_t scalar[ED_READONLY_TEST_SCALAR_BYTES] = {1U};
    const uint8_t zero[ED_READONLY_TEST_SCALAR_BYTES] = {0U};
    uint8_t fixed_bytes[ED_READONLY_TEST_SCALAR_BYTES];
    uint8_t variable_bytes[ED_READONLY_TEST_SCALAR_BYTES];
    uint8_t invalid[ED_READONLY_TEST_SCALAR_BYTES];
    UTNOX_EQUALS(ge25519_decode(&base, s_test_base_point), NOXTLS_RETURN_SUCCESS);
    ge25519_scalarmult_base(&fixed, scalar);
    UTNOX_EQUALS(ge25519_scalar_mult(&variable, scalar, &base), NOXTLS_RETURN_SUCCESS);
    ge25519_encode(fixed_bytes, &fixed);
    ge25519_encode(variable_bytes, &variable);
    UTNOX_EQUALS(memcmp(fixed_bytes, variable_bytes, sizeof(fixed_bytes)), 0);
    ge25519_double_scalarmult(&combined, scalar, &base, zero);
    ge25519_encode(variable_bytes, &combined);
    UTNOX_EQUALS(memcmp(fixed_bytes, variable_bytes, sizeof(fixed_bytes)), 0);
    UTNOX_EQUALS(ge25519_decode(NULL, s_test_base_point), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(ge25519_decode(&base, NULL), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(ge25519_decode_n(NULL, s_test_base_point), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(ge25519_decode_n(&native, NULL), NOXTLS_RETURN_NULL);
    (void)memset(invalid, 0xff, sizeof(invalid));
    UTNOX_EQUALS(ge25519_decode(&base, invalid), NOXTLS_RETURN_FAILED);
    (void)memset(invalid, 0, sizeof(invalid));
    invalid[0] = 1U;
    invalid[ED_READONLY_TEST_SCALAR_BYTES - 1U] = 0x80U;
    UTNOX_EQUALS(ge25519_decode(&base, invalid), NOXTLS_RETURN_FAILED);
    return 0;
}

#if defined(_MSC_VER) && !defined(__cplusplus)
/**
 * @brief Register all cases when the MSVC C runner has no constructors.
 * @ingroup noxtls_ed25519
 * @internal
 */
void utnox_register_tests(void)
{
    register_test("ed25519_readonly_all_generated_entries",
        ed25519_readonly_all_generated_entries);
    register_test("ed25519_readonly_full_width_fixed_base",
        ed25519_readonly_full_width_fixed_base);
    register_test("ed25519_readonly_double_scalar_verify_path",
        ed25519_readonly_double_scalar_verify_path);
    register_test("ed25519_readonly_public_abi_and_rejection",
        ed25519_readonly_public_abi_and_rejection);
}
#endif
