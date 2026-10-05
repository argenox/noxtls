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
* File:    noxtls_nrf54_port_ed25519.c
* Summary: NoxTLS Ed25519 verification port on the nRF54L CRACEN BA414EP
*
*****************************************************************************/

/**
 * @file noxtls_nrf54_port_ed25519.c
 * @brief noxtls_ed25519_verify_accel_port() served by the CRACEN BA414EP
 *        (RFC 8032 §5.1.7 verification from k = SHA-512(dom || R || A || M)).
 * @ingroup noxtls_nrf54
 *
 * A hardware rejection is final (FAILED); any other hardware error falls back
 * to the NoxTLS software verifier. NoxTLS compares encode([S]B - [k]A) with
 * the R octets, so a non-canonical R (y >= p) can never verify: it is
 * rejected here without using the engine, which decompresses R and could
 * otherwise accept the reduced value. A non-canonical A is left to the
 * software decoder so both paths treat public keys identically.
 */

#include <stddef.h>

#include "noxtls_ed25519.h"
#include "noxtls_nrf54_pke.h"

/** @brief Byte holding the x-parity bit of an encoded Edwards point. */
#define NOXTLS_NRF54_PORT_ED_TOP        31U
/** @brief Mask clearing the x-parity bit. */
#define NOXTLS_NRF54_PORT_ED_Y_MSK      0x7FU
/** @brief Least significant byte of p = 2^255 - 19 (little-endian). */
#define NOXTLS_NRF54_PORT_ED_P_LOW      0xEDU
/** @brief Middle bytes of p. */
#define NOXTLS_NRF54_PORT_ED_P_MID      0xFFU

/**
 * @brief Whether an encoded Edwards25519 y-coordinate is >= p = 2^255 - 19 (non-canonical).
 * @internal
 *
 * @param[in] enc Encoded point (32 bytes, little-endian).
 *
 * @return 1 when non-canonical.
 */
static uint8_t noxtls_nrf54_port_ed_noncanonical(const uint8_t *enc)
{
    uint8_t high = 1U;
    uint32_t i;

    /* y >= p  <=>  y in [2^255 - 19, 2^255 - 1]: top byte 0x7F, middle bytes 0xFF, low byte >= 0xED. */
    if ((enc[NOXTLS_NRF54_PORT_ED_TOP] & NOXTLS_NRF54_PORT_ED_Y_MSK) != NOXTLS_NRF54_PORT_ED_Y_MSK) {
        high = 0U;
    }
    for (i = 1U; (i < NOXTLS_NRF54_PORT_ED_TOP) && (high != 0U); i++) {
        if (enc[i] != NOXTLS_NRF54_PORT_ED_P_MID) {
            high = 0U;
        }
    }
    return ((high != 0U) && (enc[0] >= NOXTLS_NRF54_PORT_ED_P_LOW)) ? 1U : 0U;
}

noxtls_return_t noxtls_ed25519_verify_accel_port(const uint8_t public_key[NOXTLS_ED25519_PUBLIC_KEY_SIZE],
                                                 const uint8_t signature[NOXTLS_ED25519_SIGNATURE_SIZE],
                                                 const uint8_t k_digest[NOXTLS_ED25519_SHA512_DIGEST_BYTES])
{
    noxtls_return_t rc = NOXTLS_RETURN_NOT_SUPPORTED;

    if ((public_key == NULL) || (signature == NULL) || (k_digest == NULL) ||
        (noxtls_nrf54_port_ed_noncanonical(public_key) != 0U)) {
        /* Non-canonical A: the software decoder decides. */
    } else if (noxtls_nrf54_port_ed_noncanonical(signature) != 0U) {
        /* NoxTLS compares encode([S]B - [k]A) with R: a non-canonical R never matches. */
        rc = NOXTLS_RETURN_FAILED;
    } else {
        rc = noxtls_nrf54_pke_ed25519_verify(public_key, signature, k_digest);
        if ((rc != NOXTLS_RETURN_SUCCESS) && (rc != NOXTLS_RETURN_FAILED)) {
            rc = NOXTLS_RETURN_NOT_SUPPORTED;
        }
    }
    return rc;
}
