/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*****************************************************************************/

#ifndef NOXTLS_HMAC_H_
#define NOXTLS_HMAC_H_

#include <stdint.h>

#include "noxtls_common.h"
#include "mdigest/noxtls_hash.h"
#include "mdigest/noxtls_sha.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Largest HMAC chaining value kept in the context (32-bit words / 64-bit words). */
#define NOXTLS_HMAC_MIDSTATE_WORDS (8U)

/**
 * @brief Chaining value of the underlying hash after one key-pad block.
 */
typedef union
{
    uint32_t w32[NOXTLS_HMAC_MIDSTATE_WORDS];  /* MD5 / SHA-1 / SHA-256 */
#if (NOXTLS_FEATURE_SHA384 || NOXTLS_FEATURE_SHA512)
    uint64_t w64[NOXTLS_HMAC_MIDSTATE_WORDS];  /* SHA-384 / SHA-512 */
#endif
} noxtls_hmac_midstate_t;

/**
 * @brief HMAC context (RFC 2104), self-contained: no heap or shared state.
 *
 * noxtls_hmac_init() hashes the K^ipad and K^opad blocks once and keeps only
 * the two resulting chaining values; the key and the pads themselves are not
 * stored. Each MAC then costs no key-pad compressions, and
 * noxtls_hmac_reset() starts a new MAC under the same key without re-keying
 * (HKDF, PBKDF2, TLS PRF and DRBG loops).
 *
 * Fields are private to the implementation. The context holds key-derived
 * secrets until noxtls_hmac_free() wipes it.
 */
typedef struct
{
    noxtls_sha_ctx_t hash;            /* running inner hash (outer hash during final) */
    noxtls_hmac_midstate_t inner_mid; /* H state after K ^ ipad */
    noxtls_hmac_midstate_t outer_mid; /* H state after K ^ opad */
    noxtls_hash_algos_t hash_algo;
    uint8_t state;                    /* 0 unkeyed, 1 accepting data, 2 MAC produced */
} noxtls_hmac_context_t;

/* Backward-compatible type alias. */
typedef noxtls_hmac_context_t hmac_context_t;

/**
 * @brief Key an HMAC context and start the first MAC.
 *
 * Supported digests: MD5 (legacy, for the TLS 1.0/1.1 PRF), SHA-1, SHA-256,
 * SHA-384, SHA-512 (each when enabled). The
 * context is cleared first, so a failed init is still safe to pass to
 * noxtls_hmac_free().
 */
noxtls_return_t noxtls_hmac_init(noxtls_hmac_context_t *ctx, noxtls_hash_algos_t hash_algo, const uint8_t *key, uint32_t key_len);
noxtls_return_t noxtls_hmac_update(noxtls_hmac_context_t *ctx, const uint8_t *data, uint32_t data_len);
/**
 * @brief Produce the MAC. Afterwards update/final fail until noxtls_hmac_reset().
 *
 * On *mac_len smaller than the digest size, *mac_len is set to the digest
 * size and NOXTLS_RETURN_FAILED is returned with the context unchanged.
 */
noxtls_return_t noxtls_hmac_final(noxtls_hmac_context_t *ctx, uint8_t *mac, uint32_t *mac_len);
/**
 * @brief Discard any MAC in progress and start a new one under the same key.
 *
 * Valid after a successful noxtls_hmac_init(), in any later state (also after
 * noxtls_hmac_final()), until noxtls_hmac_free().
 */
noxtls_return_t noxtls_hmac_reset(noxtls_hmac_context_t *ctx);
/** @brief Wipe the whole context (key-derived state included). */
noxtls_return_t noxtls_hmac_free(noxtls_hmac_context_t *ctx);
noxtls_return_t noxtls_hmac_compute(noxtls_hash_algos_t hash_algo, const uint8_t *key, uint32_t key_len,
                                    const uint8_t *data, uint32_t data_len, uint8_t *mac, uint32_t *mac_len);

/* Backward-compatible function alias. */
noxtls_return_t hmac_compute(noxtls_hash_algos_t hash_algo, const uint8_t *key, uint32_t key_len,
                             const uint8_t *data, uint32_t data_len, uint8_t *mac, uint32_t *mac_len);

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_HMAC_H_ */
