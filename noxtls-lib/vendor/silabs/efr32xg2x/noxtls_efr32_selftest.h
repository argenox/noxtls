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
* File:    noxtls_efr32_selftest.h
* Summary: Known-answer self-test of the EFR32xG2x hardware path
*
*****************************************************************************/

/**
 * @file noxtls_efr32_selftest.h
 * @brief Known-answer tests that run the published vectors through the RADIOAES and
 *        Secure Engine drivers (not through the software fallback).
 * @ingroup noxtls_efr32
 *
 * Intended for bench bring-up and for a power-on check: noxtls_efr32_selftest()
 * reports per operation whether the hardware produced the vector, and can
 * switch failing operations off so NoxTLS uses its software implementation for
 * them. Vectors: FIPS 197 Appendix C.1 / C.3 (AES), NIST SP 800-38A F.2.1 / F.5.1
 * (CBC, CTR), NIST SP 800-38C Appendix C Example 1 (CCM), FIPS 180-4 (SHA-256
 * and SHA-512 of "abc"), SEC 1 / SP 800-186 (2 * G on P-256 for point
 * multiplication and ECDH) and RFC 6979 §A.2.5 (ECDSA P-256 verify, sign +
 * verify round trip).
 */
#ifndef NOXTLS_EFR32_SELFTEST_H
#define NOXTLS_EFR32_SELFTEST_H

#include <stdint.h>

#include "noxtls_efr32_aes_engine.h"
#include "noxtls_efr32_se_ops.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Test bit: AES-128 ECB (FIPS 197 C.1). */
#define NOXTLS_EFR32_ST_AES128_ECB      0x00000001UL
/** @brief Test bit: AES-256 ECB (FIPS 197 C.3). */
#define NOXTLS_EFR32_ST_AES256_ECB      0x00000002UL
/** @brief Test bit: AES-128 CBC encrypt and decrypt (SP 800-38A F.2.1). */
#define NOXTLS_EFR32_ST_AES_CBC         0x00000004UL
/** @brief Test bit: AES-128 CTR (SP 800-38A F.5.1). */
#define NOXTLS_EFR32_ST_AES_CTR         0x00000008UL
/** @brief Test bit: AES-128 CCM encrypt and decrypt (SP 800-38C C.1). */
#define NOXTLS_EFR32_ST_AES_CCM         0x00000010UL
/** @brief Test bit: SE SHA-256 compression ("abc"). */
#define NOXTLS_EFR32_ST_SHA256          0x00000020UL
/** @brief Test bit: SE SHA-512 compression ("abc"). */
#define NOXTLS_EFR32_ST_SHA512          0x00000040UL
/** @brief Test bit: SE TRNG (two non-zero, different draws). */
#define NOXTLS_EFR32_ST_TRNG            0x00000080UL
/** @brief Test bit: SE P-256 point multiplication (2 * G) and ECDH agreement. */
#define NOXTLS_EFR32_ST_ECC_MUL         0x00000100UL
/** @brief Test bit: SE ECDSA P-256 verify (RFC 6979 A.2.5 accept and reject). */
#define NOXTLS_EFR32_ST_ECDSA_VERIFY    0x00000200UL
/** @brief Test bit: SE ECDSA P-256 sign (round trip through verify). */
#define NOXTLS_EFR32_ST_ECDSA_SIGN      0x00000400UL
/** @brief All tests. */
#define NOXTLS_EFR32_ST_ALL             0x000007FFUL

/** Result of noxtls_efr32_selftest(). */
typedef struct {
    uint32_t ran;      /**< Tests that ran (the unit was available). */
    uint32_t passed;   /**< Tests whose result matched the vector. */
    uint32_t skipped;  /**< Tests that could not run (unit disabled, busy or not implemented by the part). */
} noxtls_efr32_selftest_t;

/**
 * @brief Run the known-answer tests through the hardware drivers.
 *
 * @param[out] result         Receives the per-test masks (NOXTLS_EFR32_ST_*).
 * @param[in]  disable_failed Non-zero: operations that ran and failed are disabled so NoxTLS uses software for them.
 *
 * @return NOXTLS_RETURN_SUCCESS when every test that ran passed, NOXTLS_RETURN_FAILED when one failed,
 *         NOXTLS_RETURN_NULL for a NULL @p result.
 */
noxtls_return_t noxtls_efr32_selftest(noxtls_efr32_selftest_t *result, uint8_t disable_failed);

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_EFR32_SELFTEST_H */
