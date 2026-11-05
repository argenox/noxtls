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
* File:    test_efr32_selftest.c
* Summary: Tests of the known-answer self-test
*
*****************************************************************************/

/**
 * @file test_efr32_selftest.c
 * @brief The hardware self-test passes on a healthy part, reports skipped units, detects a
 *        faulty engine per operation and disables failing operations on request.
 * @ingroup noxtls_efr32_ut
 */

#include <stdint.h>
#include <string.h>

#include "runner.h"
#include "test_assert.h"

#include "ut_efr32_mock.h"

REGISTER_TEST(test_selftest_passes_on_a_healthy_part)
{
    noxtls_efr32_selftest_t res;

    ut_setup();
    UTNOX_EQUALS(noxtls_efr32_selftest(&res, 1U), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(res.ran, NOXTLS_EFR32_ST_ALL);
    UTNOX_EQUALS(res.passed, NOXTLS_EFR32_ST_ALL);
    UTNOX_EQUALS(res.skipped, 0U);
    UTNOX_EQUALS(noxtls_efr32_op_allowed(NOXTLS_EFR32_OP_SHA256), 1U);
    UTNOX_IS_TRUE(ut_clean() != 0U);
    UTNOX_EQUALS(noxtls_efr32_selftest(NULL, 0U), NOXTLS_RETURN_NULL);
    return 0;
}

REGISTER_TEST(test_selftest_reports_unavailable_units_as_skipped)
{
    noxtls_efr32_selftest_t res;

    ut_setup();
    noxtls_efr32_set_enabled(NOXTLS_EFR32_UNIT_AES, 0U);
    UTNOX_EQUALS(noxtls_efr32_selftest(&res, 0U), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(res.skipped, NOXTLS_EFR32_ST_AES128_ECB | NOXTLS_EFR32_ST_AES256_ECB | NOXTLS_EFR32_ST_AES_CBC | NOXTLS_EFR32_ST_AES_CTR |
                              NOXTLS_EFR32_ST_AES_CCM);
    UTNOX_EQUALS(res.ran, NOXTLS_EFR32_ST_ALL & ~res.skipped);
    UTNOX_EQUALS(res.passed, res.ran);
    noxtls_efr32_set_enabled(NOXTLS_EFR32_UNIT_ALL, 0U);
    UTNOX_EQUALS(noxtls_efr32_selftest(&res, 0U), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(res.ran, 0U);
    UTNOX_EQUALS(res.skipped, NOXTLS_EFR32_ST_ALL);
    noxtls_efr32_set_enabled(NOXTLS_EFR32_UNIT_ALL, 1U);
    /* A part without CBC: that test is skipped, the others pass. */
    ut_set_caps(NOXTLS_EFR32_INCL_AES, 0x05010125U, 0x80U);
    UTNOX_EQUALS(noxtls_efr32_selftest(&res, 0U), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(res.skipped, NOXTLS_EFR32_ST_AES_CBC);
    return 0;
}

REGISTER_TEST(test_selftest_detects_a_faulty_aes_engine_and_disables_it)
{
    noxtls_efr32_selftest_t res;

    ut_setup();
    g_ut.aes_bus_error = 1U;
    UTNOX_EQUALS(noxtls_efr32_selftest(&res, 0U), NOXTLS_RETURN_FAILED);
    UTNOX_EQUALS(res.passed & (NOXTLS_EFR32_ST_AES128_ECB | NOXTLS_EFR32_ST_AES256_ECB | NOXTLS_EFR32_ST_AES_CBC | NOXTLS_EFR32_ST_AES_CTR |
                               NOXTLS_EFR32_ST_AES_CCM), 0U);
    /* Without disable_failed the engine stays usable (and keeps failing here). */
    g_ut.aes_bus_error = 0U;
    (void)memset(g_ut_ram.aux, 0, 16U);
    UTNOX_EQUALS(noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_ECB, 0U, g_ut_ram.aux, 16U, NULL, g_ut_ram.in, g_ut_ram.out, 16U), NOXTLS_RETURN_SUCCESS);
    g_ut.aes_bus_error = 1U;
    UTNOX_EQUALS(noxtls_efr32_selftest(&res, 1U), NOXTLS_RETURN_FAILED);
    g_ut.aes_bus_error = 0U;
    UTNOX_EQUALS(noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_ECB, 0U, g_ut_ram.aux, 16U, NULL, g_ut_ram.in, g_ut_ram.out, 16U),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_CBC, 0U, g_ut_ram.aux, 16U, g_ut_ram.aux2, g_ut_ram.in, g_ut_ram.out, 16U),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_CTR, 0U, g_ut_ram.aux, 16U, g_ut_ram.aux2, g_ut_ram.in, g_ut_ram.out, 16U),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_efr32_aes_ccm(0U, g_ut_ram.aux, 16U, g_ut_ram.aux2, 12U, NULL, 0U, g_ut_ram.in, g_ut_ram.out, 16U, &g_ut_ram.aux2[64], 8U),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    return 0;
}

REGISTER_TEST(test_selftest_detects_wrong_answers_per_operation)
{
    noxtls_efr32_selftest_t res;

    ut_setup();
    /* A point multiplication that returns a wrong point fails only the ECC test. */
    g_ut.se_wrong_mul = 1U;
    UTNOX_EQUALS(noxtls_efr32_selftest(&res, 1U), NOXTLS_RETURN_FAILED);
    UTNOX_EQUALS(res.ran & ~res.passed, NOXTLS_EFR32_ST_ECC_MUL);
    UTNOX_EQUALS(noxtls_efr32_op_allowed(NOXTLS_EFR32_OP_ECC_MUL), 0U);
    UTNOX_EQUALS(noxtls_efr32_op_allowed(NOXTLS_EFR32_OP_SHA256), 1U);
    g_ut.se_wrong_mul = 0U;
    /* A TRNG that returns zeros fails only the TRNG test. */
    ut_setup();
    g_ut.se_trng_zero = 1U;
    UTNOX_EQUALS(noxtls_efr32_selftest(&res, 1U), NOXTLS_RETURN_FAILED);
    UTNOX_EQUALS(res.ran & ~res.passed, NOXTLS_EFR32_ST_TRNG);
    UTNOX_EQUALS(noxtls_efr32_op_allowed(NOXTLS_EFR32_OP_TRNG), 0U);
    return 0;
}

REGISTER_TEST(test_selftest_disables_every_failing_secure_engine_operation)
{
    noxtls_efr32_selftest_t res;

    ut_setup();
    g_ut.se_force = 1U;
    g_ut.se_force_resp = NOXTLS_EFR32_SE_RESP_INTERNAL;
    UTNOX_EQUALS(noxtls_efr32_selftest(&res, 1U), NOXTLS_RETURN_FAILED);
    UTNOX_EQUALS(res.ran & ~res.passed, NOXTLS_EFR32_ST_SHA256 | NOXTLS_EFR32_ST_SHA512 | NOXTLS_EFR32_ST_TRNG | NOXTLS_EFR32_ST_ECC_MUL |
                                        NOXTLS_EFR32_ST_ECDSA_VERIFY | NOXTLS_EFR32_ST_ECDSA_SIGN);
    UTNOX_EQUALS(noxtls_efr32_op_allowed(NOXTLS_EFR32_OP_SHA256), 0U);
    UTNOX_EQUALS(noxtls_efr32_op_allowed(NOXTLS_EFR32_OP_SHA512), 0U);
    UTNOX_EQUALS(noxtls_efr32_op_allowed(NOXTLS_EFR32_OP_TRNG), 0U);
    UTNOX_EQUALS(noxtls_efr32_op_allowed(NOXTLS_EFR32_OP_ECC_MUL), 0U);
    UTNOX_EQUALS(noxtls_efr32_op_allowed(NOXTLS_EFR32_OP_ECDSA_SIGN), 0U);
    UTNOX_EQUALS(noxtls_efr32_op_allowed(NOXTLS_EFR32_OP_ECDSA_VERIFY), 0U);
    /* AES was healthy. */
    UTNOX_EQUALS(res.passed & NOXTLS_EFR32_ST_AES_CCM, NOXTLS_EFR32_ST_AES_CCM);
    g_ut.se_force = 0U;
    ut_setup();
    return 0;
}

REGISTER_TEST(test_selftest_unsupported_se_commands_are_skipped)
{
    noxtls_efr32_selftest_t res;

    ut_setup();
    /* An SE without the Vault feature set answers "invalid command" to SHA-512 and P-384 type commands: skipped, not failed. */
    g_ut.se_force = 1U;
    g_ut.se_force_resp = NOXTLS_EFR32_SE_RESP_INVALID_CMD;
    UTNOX_EQUALS(noxtls_efr32_selftest(&res, 1U), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(res.skipped, NOXTLS_EFR32_ST_SHA256 | NOXTLS_EFR32_ST_SHA512 | NOXTLS_EFR32_ST_TRNG | NOXTLS_EFR32_ST_ECC_MUL |
                              NOXTLS_EFR32_ST_ECDSA_VERIFY | NOXTLS_EFR32_ST_ECDSA_SIGN);
    g_ut.se_force = 0U;
    return 0;
}
