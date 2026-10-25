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
* File:    noxtls_pkc_rng.h
* Summary: Internal CTR-DRBG instance shared by the public-key modules
*
*****************************************************************************/

/** @addtogroup noxtls_pkc */
/** @{ */

#ifndef NOXTLS_PKC_RNG_H_
#define NOXTLS_PKC_RNG_H_

#include <stdint.h>
#include "noxtls_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* NOXTLS_PKC_SHARED_DRBG (see noxtls_config.h): 1 = one CTR-DRBG state for all
 * PKC modules (saves ~6 x sizeof(drbg_state_t) of .bss), 0 = one state per
 * module, as in earlier releases. */
#ifndef NOXTLS_PKC_SHARED_DRBG
#define NOXTLS_PKC_SHARED_DRBG 1
#endif

/* NOXTLS_PKC_RNG_RESEED_INTERVAL (see noxtls_config.h): requests between
 * reseeds of the PKC DRBG from the entropy source; 0 = SP 800-90A limit only. */
#ifndef NOXTLS_PKC_RNG_RESEED_INTERVAL
#define NOXTLS_PKC_RNG_RESEED_INTERVAL 1024
#endif

/* Requesting modules. With NOXTLS_PKC_SHARED_DRBG=1 they all map to one state. */
typedef uint32_t noxtls_pkc_rng_slot_t;
#define NOXTLS_PKC_RNG_SLOT_ECC     ((noxtls_pkc_rng_slot_t)0U)
#define NOXTLS_PKC_RNG_SLOT_ECDSA   ((noxtls_pkc_rng_slot_t)1U)
#define NOXTLS_PKC_RNG_SLOT_RSA     ((noxtls_pkc_rng_slot_t)2U)
#define NOXTLS_PKC_RNG_SLOT_X25519  ((noxtls_pkc_rng_slot_t)3U)
#define NOXTLS_PKC_RNG_SLOT_X448    ((noxtls_pkc_rng_slot_t)4U)
#define NOXTLS_PKC_RNG_SLOT_ED25519 ((noxtls_pkc_rng_slot_t)5U)
#define NOXTLS_PKC_RNG_SLOT_ED448   ((noxtls_pkc_rng_slot_t)6U)
#define NOXTLS_PKC_RNG_SLOT_COUNT   7U

/**
 * @brief Fill @p out with @p requested_bits bits from the PKC CTR-DRBG.
 *
 * The DRBG (SP 800-90A CTR_DRBG with derivation function; AES-256 when
 * NOXTLS_FEATURE_AES_256, else AES-128) is instantiated on first use with
 * 3/2 x security strength bits from noxtls_drbg_get_entropy() and a
 * personalization string naming the PKC DRBG (and slot), reseeded from the
 * entropy source every NOXTLS_PKC_RNG_RESEED_INTERVAL requests, and (hosted
 * POSIX, NOXTLS_DRBG_FORK_DETECT) reseeded in a forked child before its first
 * output. When a call fails, @p out is wiped; if the DRBG state was
 * invalidated (AES failure) the next call re-instantiates from fresh entropy,
 * if only the entropy source failed the next call retries the reseed.
 *
 * Not reentrant: like the per-module states it replaces, the state is not
 * locked. With NOXTLS_PKC_SHARED_DRBG=1 callers must serialize ALL PKC random
 * generation (keygen, signing nonces, blinding) across threads; with 0 only
 * calls from the same module must be serialized.
 *
 * @param slot Requesting module (NOXTLS_PKC_RNG_SLOT_*)
 * @param out Output buffer of at least (requested_bits + 7) / 8 bytes
 * @param requested_bits Number of bits (1..DRBG_MAX_BITS_PER_REQUEST)
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL, or the DRBG/entropy error
 */
noxtls_return_t noxtls_pkc_rng_generate(noxtls_pkc_rng_slot_t slot, uint8_t *out, uint32_t requested_bits);

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_PKC_RNG_H_ */

/** @} */
