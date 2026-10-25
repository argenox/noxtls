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
* File:    noxtls_pkc_rng.c
* Summary: Internal CTR-DRBG instance shared by the public-key modules
*
* ECC, ECDSA, RSA, X25519, X448, Ed25519 and Ed448 each used to keep a private
* static drbg_state_t. One state (NOXTLS_PKC_SHARED_DRBG=1) gives the same
* security (every module drew from an independent instance of the same
* CTR-DRBG seeded from the same entropy source) with one state in .bss.
*
*****************************************************************************/

#include <stdint.h>

#include "noxtls_common.h"
#include "common/noxtls_ct.h"
#include "drbg/noxtls_drbg.h"
#include "noxtls_pkc_rng.h"

#if NOXTLS_FEATURE_PKC

#if NOXTLS_FEATURE_AES_256
#define NOXTLS_PKC_RNG_DRBG_TYPE     DRBG_AES256
#else
/* Size-constrained targets without AES-256 (e.g. nRF52 AES-128 ECB backend):
 * 128-bit security strength. */
#define NOXTLS_PKC_RNG_DRBG_TYPE     DRBG_AES128
#endif

#if NOXTLS_PKC_SHARED_DRBG
#define NOXTLS_PKC_RNG_STATES 1U
#else
#define NOXTLS_PKC_RNG_STATES NOXTLS_PKC_RNG_SLOT_COUNT
#endif

static drbg_state_t s_pkc_rng_state[NOXTLS_PKC_RNG_STATES];
static uint8_t s_pkc_rng_ready[NOXTLS_PKC_RNG_STATES];

/* Personalization string (SP 800-90A 8.7.1): separates this DRBG from every
 * other instance seeded from the same entropy source; the last byte is the slot. */
static const uint8_t k_pkc_rng_pers[] = {
    'N', 'o', 'x', 'T', 'L', 'S', ' ', 'P', 'K', 'C', ' ', 'D', 'R', 'B', 'G', 0U
};

noxtls_return_t noxtls_pkc_rng_generate(noxtls_pkc_rng_slot_t slot, uint8_t *out, uint32_t requested_bits)
{
    uint8_t pers[sizeof(k_pkc_rng_pers)];
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    uint32_t idx = 0U;

    if((out == NULL) || (slot >= NOXTLS_PKC_RNG_SLOT_COUNT)) {
        return NOXTLS_RETURN_NULL;
    }
#if !NOXTLS_PKC_SHARED_DRBG
    idx = (uint32_t)slot;
#endif

    if((s_pkc_rng_ready[idx] == 0U) || (s_pkc_rng_state[idx].instantiated == 0U)) {
        /* Entropy input and nonce (3/2 x security strength) come from
         * noxtls_drbg_get_entropy() inside drbg_instantiate(). */
        noxtls_copy_u8(pers, sizeof(pers), k_pkc_rng_pers, sizeof(k_pkc_rng_pers));
        pers[sizeof(pers) - 1U] = (uint8_t)idx;
        rc = drbg_instantiate(&s_pkc_rng_state[idx], NOXTLS_PKC_RNG_DRBG_TYPE,
                              NULL, 0U, NULL, 0U, pers, (uint32_t)sizeof(pers));
        if(rc != NOXTLS_RETURN_SUCCESS) {
            s_pkc_rng_ready[idx] = 0U;
            noxtls_secure_zero(out, (size_t)((requested_bits + 7U) / 8U));
            return rc;
        }
        s_pkc_rng_ready[idx] = 1U;
    }
#if NOXTLS_PKC_RNG_RESEED_INTERVAL > 0
    else if(s_pkc_rng_state[idx].reseed_counter > (uint64_t)NOXTLS_PKC_RNG_RESEED_INTERVAL) {
        /* Long-lived instance: fresh entropy every NOXTLS_PKC_RNG_RESEED_INTERVAL
         * requests (well inside the SP 800-90A limit of 2^48). */
        rc = drbg_reseed(&s_pkc_rng_state[idx], NULL, 0U, NULL, 0U);
    } else {
        /* MISRA 15.7: instance ready, no reseed due */
    }
#endif

    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = drbg_generate(&s_pkc_rng_state[idx], out, requested_bits, NULL, 0U);
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        /* Fail closed for this call. A DRBG error that invalidated the state
         * (AES failure) makes the next call re-instantiate from fresh entropy;
         * an entropy-source failure leaves the state intact and the next call
         * retries the reseed. */
        if(s_pkc_rng_state[idx].instantiated == 0U) {
            (void)noxtls_drbg_uninstantiate(&s_pkc_rng_state[idx]);
            s_pkc_rng_ready[idx] = 0U;
        }
        noxtls_secure_zero(out, (size_t)((requested_bits + 7U) / 8U));
    }
    return rc;
}

#endif /* NOXTLS_FEATURE_PKC */
