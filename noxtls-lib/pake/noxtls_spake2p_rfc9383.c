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
* File:    noxtls_spake2p_rfc9383.c
* Summary: SPAKE2+ RFC 9383 key schedule (standard profile)
*
*
*****************************************************************************/

/**
 * @file noxtls_spake2p_rfc9383.c
 * @brief RFC 9383 section 3.4 key schedule for P256-SHA256-HKDF-SHA256-HMAC-SHA256.
 * @ingroup noxtls_spake2p
 *
 * K_main = Hash(TT)
 * K_confirmP || K_confirmV = KDF(nil, K_main, "ConfirmationKeys")
 * K_shared = KDF(nil, K_main, "SharedKey")
 * confirmP = MAC(K_confirmP, shareV), confirmV = MAC(K_confirmV, shareP)
 *
 * Validated against RFC 9383 Appendix C.
 */

#include <stdint.h>
#include <string.h>

#include "noxtls_spake2p_internal.h"
#include "common/noxtls_ct.h"

#if NOXTLS_FEATURE_SPAKE2P_RFC9383

/** @brief Length of the "ConfirmationKeys" label without the terminator. */
#define NOXTLS_SPAKE2P_RFC9383_CONFIRM_LABEL_LEN ((uint32_t)(sizeof(NOXTLS_SPAKE2P_LABEL_CONFIRMATION_KEYS) - 1U))
/** @brief Length of the "SharedKey" label without the terminator. */
#define NOXTLS_SPAKE2P_RFC9383_SHARED_LABEL_LEN ((uint32_t)(sizeof(NOXTLS_SPAKE2P_LABEL_SHARED_KEY) - 1U))

noxtls_return_t noxtls_spake2p_rfc9383_derive_keys(noxtls_spake2p_ctx_t *ctx,
                                                   const uint8_t k_main[NOXTLS_SPAKE2P_HASH_SIZE])
{
    uint8_t confirm_keys[NOXTLS_SPAKE2P_RFC9383_CONFIRM_KEY_SIZE * 2U];
    noxtls_return_t rc;

    if ((ctx == NULL) || (k_main == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    rc = noxtls_spake2p_kdf(k_main, NOXTLS_SPAKE2P_HASH_SIZE,
                            (const uint8_t *)NOXTLS_SPAKE2P_LABEL_CONFIRMATION_KEYS,
                            NOXTLS_SPAKE2P_RFC9383_CONFIRM_LABEL_LEN,
                            confirm_keys, (uint32_t)sizeof(confirm_keys));
    if (rc == NOXTLS_RETURN_SUCCESS) {
        memcpy(ctx->confirm_key_prover, confirm_keys, NOXTLS_SPAKE2P_RFC9383_CONFIRM_KEY_SIZE);
        memcpy(ctx->confirm_key_verifier, &confirm_keys[NOXTLS_SPAKE2P_RFC9383_CONFIRM_KEY_SIZE],
               NOXTLS_SPAKE2P_RFC9383_CONFIRM_KEY_SIZE);
        ctx->confirm_key_len = NOXTLS_SPAKE2P_RFC9383_CONFIRM_KEY_SIZE;
        rc = noxtls_spake2p_kdf(k_main, NOXTLS_SPAKE2P_HASH_SIZE,
                                (const uint8_t *)NOXTLS_SPAKE2P_LABEL_SHARED_KEY,
                                NOXTLS_SPAKE2P_RFC9383_SHARED_LABEL_LEN,
                                ctx->shared_key, NOXTLS_SPAKE2P_RFC9383_SHARED_KEY_SIZE);
    }

    if (rc == NOXTLS_RETURN_SUCCESS) {
        ctx->shared_key_len = NOXTLS_SPAKE2P_RFC9383_SHARED_KEY_SIZE;
    }

    noxtls_secure_zero(confirm_keys, sizeof(confirm_keys));
    return rc;
}

#endif /* NOXTLS_FEATURE_SPAKE2P_RFC9383 */
