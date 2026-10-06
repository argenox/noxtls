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
* File:    noxtls_spake2p_matter.c
* Summary: SPAKE2+ draft-01 key schedule used by Matter PASE
*
*
*****************************************************************************/

/**
 * @file noxtls_spake2p_matter.c
 * @brief draft-bar-cfrg-spake2plus-01 section 3.4 key schedule (Matter PASE profile).
 * @ingroup noxtls_spake2p
 *
 * Matter Core specification 1.x section 3.10 (Crypto_P2/Crypto_P3)
 * references draft-bar-cfrg-spake2plus-01 rather than RFC 9383:
 *
 * Ka || Ke = Hash(TT)                        (16 + 16 bytes)
 * KcA || KcB = KDF(nil, Ka, "ConfirmationKeys")  (16 + 16 bytes)
 * cA = HMAC(KcA, Y), cB = HMAC(KcB, X)
 * Shared secret = Ke
 *
 * This is NOT RFC 9383; it exists only for Matter interoperability.
 * Validated against the draft-bar-cfrg-spake2plus-01 test vector used by
 * connectedhomeip.
 */

#include <stdint.h>
#include <string.h>

#include "noxtls_spake2p_internal.h"
#include "common/noxtls_ct.h"

#if NOXTLS_FEATURE_SPAKE2P_MATTER

/** @brief Length of the "ConfirmationKeys" label without the terminator. */
#define NOXTLS_SPAKE2P_MATTER_CONFIRM_LABEL_LEN ((uint32_t)(sizeof(NOXTLS_SPAKE2P_LABEL_CONFIRMATION_KEYS) - 1U))

noxtls_return_t noxtls_spake2p_matter_derive_keys(noxtls_spake2p_ctx_t *ctx,
                                                  const uint8_t ka_ke[NOXTLS_SPAKE2P_HASH_SIZE])
{
    uint8_t confirm_keys[NOXTLS_SPAKE2P_MATTER_CONFIRM_KEY_SIZE * 2U];
    noxtls_return_t rc;

    if ((ctx == NULL) || (ka_ke == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    /* KcA || KcB = KDF(nil, Ka, "ConfirmationKeys"), Ka = first half of Hash(TT). */
    rc = noxtls_spake2p_kdf(ka_ke, NOXTLS_SPAKE2P_MATTER_KA_SIZE,
                            (const uint8_t *)NOXTLS_SPAKE2P_LABEL_CONFIRMATION_KEYS,
                            NOXTLS_SPAKE2P_MATTER_CONFIRM_LABEL_LEN,
                            confirm_keys, (uint32_t)sizeof(confirm_keys));
    if (rc == NOXTLS_RETURN_SUCCESS) {
        memcpy(ctx->confirm_key_prover, confirm_keys, NOXTLS_SPAKE2P_MATTER_CONFIRM_KEY_SIZE);
        memcpy(ctx->confirm_key_verifier, &confirm_keys[NOXTLS_SPAKE2P_MATTER_CONFIRM_KEY_SIZE],
               NOXTLS_SPAKE2P_MATTER_CONFIRM_KEY_SIZE);
        ctx->confirm_key_len = NOXTLS_SPAKE2P_MATTER_CONFIRM_KEY_SIZE;

        /* Ke = second half of Hash(TT). */
        memcpy(ctx->shared_key, &ka_ke[NOXTLS_SPAKE2P_MATTER_KA_SIZE], NOXTLS_SPAKE2P_MATTER_SHARED_KEY_SIZE);
        ctx->shared_key_len = NOXTLS_SPAKE2P_MATTER_SHARED_KEY_SIZE;
    }

    noxtls_secure_zero(confirm_keys, sizeof(confirm_keys));
    return rc;
}

#endif /* NOXTLS_FEATURE_SPAKE2P_MATTER */
