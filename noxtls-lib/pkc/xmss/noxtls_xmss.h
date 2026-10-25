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
* File:    noxtls_xmss.h
* Summary: XMSS / XMSS^MT stateful hash-based signatures (RFC 8391, NIST
*          SP 800-208): parameter sets, key generation, stateful signing with
*          fail-closed state persistence, streaming verification.
*
*****************************************************************************/

#ifndef NOXTLS_XMSS_H_
#define NOXTLS_XMSS_H_

#include <stdint.h>
#include "noxtls_common.h"
#include "mdigest/noxtls_sha.h"
#if (NOXTLS_FEATURE_SHA384 || NOXTLS_FEATURE_SHA512)
#include "mdigest/sha512/noxtls_sha512.h"
#endif
#if NOXTLS_FEATURE_SHA3
#include "mdigest/sha3/noxtls_sha3.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Build-time options (noxtls_config.h):
 *   NOXTLS_XMSS_ENABLE_SHA2   SHA-256 sets (n = 32 RFC 8391, n = 24 SP 800-208)
 *   NOXTLS_XMSS_ENABLE_SHAKE  SHAKE sets (SHAKE256 n = 32/24 SP 800-208, RFC 8391 SHAKE128 n = 32),
 *                             effective only with NOXTLS_FEATURE_SHA3
 *   NOXTLS_XMSS_ENABLE_N64    RFC 8391 n = 64 sets (SHA-512 / SHAKE256-512), not SP 800-208 approved;
 *                             the SHA-512 ones need NOXTLS_FEATURE_SHA512
 *   NOXTLS_XMSS_MAX_HEIGHT    largest total tree height h accepted (10..60)
 *   NOXTLS_XMSS_ENABLE_SIGN   0 builds a verification-only module
 *   NOXTLS_XMSS_SIGN_SELF_CHECK verify every signature before it is released
 */
#ifndef NOXTLS_XMSS_ENABLE_SHA2
#define NOXTLS_XMSS_ENABLE_SHA2 1
#endif
#ifndef NOXTLS_XMSS_ENABLE_SHAKE
#define NOXTLS_XMSS_ENABLE_SHAKE 1
#endif
#ifndef NOXTLS_XMSS_ENABLE_N64
#define NOXTLS_XMSS_ENABLE_N64 0
#endif
#ifndef NOXTLS_XMSS_MAX_HEIGHT
#define NOXTLS_XMSS_MAX_HEIGHT 60
#endif
#ifndef NOXTLS_XMSS_ENABLE_SIGN
#define NOXTLS_XMSS_ENABLE_SIGN 1
#endif
#ifndef NOXTLS_XMSS_SIGN_SELF_CHECK
#define NOXTLS_XMSS_SIGN_SELF_CHECK 1
#endif

/* Hash families actually compiled in. */
#define NOXTLS_XMSS_HAVE_SHAKE (NOXTLS_XMSS_ENABLE_SHAKE && NOXTLS_FEATURE_SHA3)
#define NOXTLS_XMSS_HAVE_SHA512 (NOXTLS_XMSS_ENABLE_N64 && NOXTLS_XMSS_ENABLE_SHA2 && NOXTLS_FEATURE_SHA512)

#if NOXTLS_FEATURE_XMSS
#if !NOXTLS_XMSS_ENABLE_SHA2 && !NOXTLS_XMSS_HAVE_SHAKE
#error "NOXTLS_FEATURE_XMSS needs NOXTLS_XMSS_ENABLE_SHA2, or NOXTLS_XMSS_ENABLE_SHAKE with NOXTLS_FEATURE_SHA3."
#endif
#if (NOXTLS_XMSS_MAX_HEIGHT < 10) || (NOXTLS_XMSS_MAX_HEIGHT > 60)
#error "NOXTLS_XMSS_MAX_HEIGHT must be in 10..60."
#endif
#endif

/*
 * Parameter set identifiers.  For XMSS the value is the RFC 8391 / SP 800-208
 * OID (IANA "XMSS Algorithm Types"); for XMSS^MT it is the XMSS^MT OID ORed
 * with NOXTLS_XMSS_PARAM_MT_FLAG (the two OID name spaces overlap).
 */
typedef uint32_t noxtls_xmss_param_t;
#define NOXTLS_XMSS_NONE                    ((noxtls_xmss_param_t)0U)
#define NOXTLS_XMSS_PARAM_MT_FLAG           ((noxtls_xmss_param_t)0x00010000U)

#define NOXTLS_XMSS_SHA2_10_256             ((noxtls_xmss_param_t)0x01U)
#define NOXTLS_XMSS_SHA2_16_256             ((noxtls_xmss_param_t)0x02U)
#define NOXTLS_XMSS_SHA2_20_256             ((noxtls_xmss_param_t)0x03U)
#define NOXTLS_XMSS_SHA2_10_512             ((noxtls_xmss_param_t)0x04U)
#define NOXTLS_XMSS_SHA2_16_512             ((noxtls_xmss_param_t)0x05U)
#define NOXTLS_XMSS_SHA2_20_512             ((noxtls_xmss_param_t)0x06U)
#define NOXTLS_XMSS_SHAKE_10_256            ((noxtls_xmss_param_t)0x07U)
#define NOXTLS_XMSS_SHAKE_16_256            ((noxtls_xmss_param_t)0x08U)
#define NOXTLS_XMSS_SHAKE_20_256            ((noxtls_xmss_param_t)0x09U)
#define NOXTLS_XMSS_SHAKE_10_512            ((noxtls_xmss_param_t)0x0aU)
#define NOXTLS_XMSS_SHAKE_16_512            ((noxtls_xmss_param_t)0x0bU)
#define NOXTLS_XMSS_SHAKE_20_512            ((noxtls_xmss_param_t)0x0cU)
#define NOXTLS_XMSS_SHA2_10_192             ((noxtls_xmss_param_t)0x0dU)
#define NOXTLS_XMSS_SHA2_16_192             ((noxtls_xmss_param_t)0x0eU)
#define NOXTLS_XMSS_SHA2_20_192             ((noxtls_xmss_param_t)0x0fU)
#define NOXTLS_XMSS_SHAKE256_10_256         ((noxtls_xmss_param_t)0x10U)
#define NOXTLS_XMSS_SHAKE256_16_256         ((noxtls_xmss_param_t)0x11U)
#define NOXTLS_XMSS_SHAKE256_20_256         ((noxtls_xmss_param_t)0x12U)
#define NOXTLS_XMSS_SHAKE256_10_192         ((noxtls_xmss_param_t)0x13U)
#define NOXTLS_XMSS_SHAKE256_16_192         ((noxtls_xmss_param_t)0x14U)
#define NOXTLS_XMSS_SHAKE256_20_192         ((noxtls_xmss_param_t)0x15U)

#define NOXTLS_XMSSMT_SHA2_20_2_256         (NOXTLS_XMSS_PARAM_MT_FLAG | (noxtls_xmss_param_t)0x01U)
#define NOXTLS_XMSSMT_SHA2_20_4_256         (NOXTLS_XMSS_PARAM_MT_FLAG | (noxtls_xmss_param_t)0x02U)
#define NOXTLS_XMSSMT_SHA2_40_2_256         (NOXTLS_XMSS_PARAM_MT_FLAG | (noxtls_xmss_param_t)0x03U)
#define NOXTLS_XMSSMT_SHA2_40_4_256         (NOXTLS_XMSS_PARAM_MT_FLAG | (noxtls_xmss_param_t)0x04U)
#define NOXTLS_XMSSMT_SHA2_40_8_256         (NOXTLS_XMSS_PARAM_MT_FLAG | (noxtls_xmss_param_t)0x05U)
#define NOXTLS_XMSSMT_SHA2_60_3_256         (NOXTLS_XMSS_PARAM_MT_FLAG | (noxtls_xmss_param_t)0x06U)
#define NOXTLS_XMSSMT_SHA2_60_6_256         (NOXTLS_XMSS_PARAM_MT_FLAG | (noxtls_xmss_param_t)0x07U)
#define NOXTLS_XMSSMT_SHA2_60_12_256        (NOXTLS_XMSS_PARAM_MT_FLAG | (noxtls_xmss_param_t)0x08U)
#define NOXTLS_XMSSMT_SHA2_20_2_512         (NOXTLS_XMSS_PARAM_MT_FLAG | (noxtls_xmss_param_t)0x09U)
#define NOXTLS_XMSSMT_SHA2_20_4_512         (NOXTLS_XMSS_PARAM_MT_FLAG | (noxtls_xmss_param_t)0x0aU)
#define NOXTLS_XMSSMT_SHA2_40_2_512         (NOXTLS_XMSS_PARAM_MT_FLAG | (noxtls_xmss_param_t)0x0bU)
#define NOXTLS_XMSSMT_SHA2_40_4_512         (NOXTLS_XMSS_PARAM_MT_FLAG | (noxtls_xmss_param_t)0x0cU)
#define NOXTLS_XMSSMT_SHA2_40_8_512         (NOXTLS_XMSS_PARAM_MT_FLAG | (noxtls_xmss_param_t)0x0dU)
#define NOXTLS_XMSSMT_SHA2_60_3_512         (NOXTLS_XMSS_PARAM_MT_FLAG | (noxtls_xmss_param_t)0x0eU)
#define NOXTLS_XMSSMT_SHA2_60_6_512         (NOXTLS_XMSS_PARAM_MT_FLAG | (noxtls_xmss_param_t)0x0fU)
#define NOXTLS_XMSSMT_SHA2_60_12_512        (NOXTLS_XMSS_PARAM_MT_FLAG | (noxtls_xmss_param_t)0x10U)
#define NOXTLS_XMSSMT_SHAKE_20_2_256        (NOXTLS_XMSS_PARAM_MT_FLAG | (noxtls_xmss_param_t)0x11U)
#define NOXTLS_XMSSMT_SHAKE_20_4_256        (NOXTLS_XMSS_PARAM_MT_FLAG | (noxtls_xmss_param_t)0x12U)
#define NOXTLS_XMSSMT_SHAKE_40_2_256        (NOXTLS_XMSS_PARAM_MT_FLAG | (noxtls_xmss_param_t)0x13U)
#define NOXTLS_XMSSMT_SHAKE_40_4_256        (NOXTLS_XMSS_PARAM_MT_FLAG | (noxtls_xmss_param_t)0x14U)
#define NOXTLS_XMSSMT_SHAKE_40_8_256        (NOXTLS_XMSS_PARAM_MT_FLAG | (noxtls_xmss_param_t)0x15U)
#define NOXTLS_XMSSMT_SHAKE_60_3_256        (NOXTLS_XMSS_PARAM_MT_FLAG | (noxtls_xmss_param_t)0x16U)
#define NOXTLS_XMSSMT_SHAKE_60_6_256        (NOXTLS_XMSS_PARAM_MT_FLAG | (noxtls_xmss_param_t)0x17U)
#define NOXTLS_XMSSMT_SHAKE_60_12_256       (NOXTLS_XMSS_PARAM_MT_FLAG | (noxtls_xmss_param_t)0x18U)
#define NOXTLS_XMSSMT_SHAKE_20_2_512        (NOXTLS_XMSS_PARAM_MT_FLAG | (noxtls_xmss_param_t)0x19U)
#define NOXTLS_XMSSMT_SHAKE_20_4_512        (NOXTLS_XMSS_PARAM_MT_FLAG | (noxtls_xmss_param_t)0x1aU)
#define NOXTLS_XMSSMT_SHAKE_40_2_512        (NOXTLS_XMSS_PARAM_MT_FLAG | (noxtls_xmss_param_t)0x1bU)
#define NOXTLS_XMSSMT_SHAKE_40_4_512        (NOXTLS_XMSS_PARAM_MT_FLAG | (noxtls_xmss_param_t)0x1cU)
#define NOXTLS_XMSSMT_SHAKE_40_8_512        (NOXTLS_XMSS_PARAM_MT_FLAG | (noxtls_xmss_param_t)0x1dU)
#define NOXTLS_XMSSMT_SHAKE_60_3_512        (NOXTLS_XMSS_PARAM_MT_FLAG | (noxtls_xmss_param_t)0x1eU)
#define NOXTLS_XMSSMT_SHAKE_60_6_512        (NOXTLS_XMSS_PARAM_MT_FLAG | (noxtls_xmss_param_t)0x1fU)
#define NOXTLS_XMSSMT_SHAKE_60_12_512       (NOXTLS_XMSS_PARAM_MT_FLAG | (noxtls_xmss_param_t)0x20U)
#define NOXTLS_XMSSMT_SHA2_20_2_192         (NOXTLS_XMSS_PARAM_MT_FLAG | (noxtls_xmss_param_t)0x21U)
#define NOXTLS_XMSSMT_SHA2_20_4_192         (NOXTLS_XMSS_PARAM_MT_FLAG | (noxtls_xmss_param_t)0x22U)
#define NOXTLS_XMSSMT_SHA2_40_2_192         (NOXTLS_XMSS_PARAM_MT_FLAG | (noxtls_xmss_param_t)0x23U)
#define NOXTLS_XMSSMT_SHA2_40_4_192         (NOXTLS_XMSS_PARAM_MT_FLAG | (noxtls_xmss_param_t)0x24U)
#define NOXTLS_XMSSMT_SHA2_40_8_192         (NOXTLS_XMSS_PARAM_MT_FLAG | (noxtls_xmss_param_t)0x25U)
#define NOXTLS_XMSSMT_SHA2_60_3_192         (NOXTLS_XMSS_PARAM_MT_FLAG | (noxtls_xmss_param_t)0x26U)
#define NOXTLS_XMSSMT_SHA2_60_6_192         (NOXTLS_XMSS_PARAM_MT_FLAG | (noxtls_xmss_param_t)0x27U)
#define NOXTLS_XMSSMT_SHA2_60_12_192        (NOXTLS_XMSS_PARAM_MT_FLAG | (noxtls_xmss_param_t)0x28U)
#define NOXTLS_XMSSMT_SHAKE256_20_2_256     (NOXTLS_XMSS_PARAM_MT_FLAG | (noxtls_xmss_param_t)0x29U)
#define NOXTLS_XMSSMT_SHAKE256_20_4_256     (NOXTLS_XMSS_PARAM_MT_FLAG | (noxtls_xmss_param_t)0x2aU)
#define NOXTLS_XMSSMT_SHAKE256_40_2_256     (NOXTLS_XMSS_PARAM_MT_FLAG | (noxtls_xmss_param_t)0x2bU)
#define NOXTLS_XMSSMT_SHAKE256_40_4_256     (NOXTLS_XMSS_PARAM_MT_FLAG | (noxtls_xmss_param_t)0x2cU)
#define NOXTLS_XMSSMT_SHAKE256_40_8_256     (NOXTLS_XMSS_PARAM_MT_FLAG | (noxtls_xmss_param_t)0x2dU)
#define NOXTLS_XMSSMT_SHAKE256_60_3_256     (NOXTLS_XMSS_PARAM_MT_FLAG | (noxtls_xmss_param_t)0x2eU)
#define NOXTLS_XMSSMT_SHAKE256_60_6_256     (NOXTLS_XMSS_PARAM_MT_FLAG | (noxtls_xmss_param_t)0x2fU)
#define NOXTLS_XMSSMT_SHAKE256_60_12_256    (NOXTLS_XMSS_PARAM_MT_FLAG | (noxtls_xmss_param_t)0x30U)
#define NOXTLS_XMSSMT_SHAKE256_20_2_192     (NOXTLS_XMSS_PARAM_MT_FLAG | (noxtls_xmss_param_t)0x31U)
#define NOXTLS_XMSSMT_SHAKE256_20_4_192     (NOXTLS_XMSS_PARAM_MT_FLAG | (noxtls_xmss_param_t)0x32U)
#define NOXTLS_XMSSMT_SHAKE256_40_2_192     (NOXTLS_XMSS_PARAM_MT_FLAG | (noxtls_xmss_param_t)0x33U)
#define NOXTLS_XMSSMT_SHAKE256_40_4_192     (NOXTLS_XMSS_PARAM_MT_FLAG | (noxtls_xmss_param_t)0x34U)
#define NOXTLS_XMSSMT_SHAKE256_40_8_192     (NOXTLS_XMSS_PARAM_MT_FLAG | (noxtls_xmss_param_t)0x35U)
#define NOXTLS_XMSSMT_SHAKE256_60_3_192     (NOXTLS_XMSS_PARAM_MT_FLAG | (noxtls_xmss_param_t)0x36U)
#define NOXTLS_XMSSMT_SHAKE256_60_6_192     (NOXTLS_XMSS_PARAM_MT_FLAG | (noxtls_xmss_param_t)0x37U)
#define NOXTLS_XMSSMT_SHAKE256_60_12_192    (NOXTLS_XMSS_PARAM_MT_FLAG | (noxtls_xmss_param_t)0x38U)

/* Hash functions (noxtls_xmss_param_info_t::hash). */
#define NOXTLS_XMSS_HASH_SHA256   1U
#define NOXTLS_XMSS_HASH_SHA512   2U
#define NOXTLS_XMSS_HASH_SHAKE128 3U
#define NOXTLS_XMSS_HASH_SHAKE256 4U

/* Largest hash output n of the enabled parameter sets. */
#if NOXTLS_XMSS_ENABLE_N64
#define NOXTLS_XMSS_MAX_N 64U
#else
#define NOXTLS_XMSS_MAX_N 32U
#endif

/*
 * Largest encodings over the enabled parameter sets:
 *   public key  = u32 OID || root[n] || PUB_SEED[n]
 *   secret key  = u32 OID || idx[idx_len] || SK_SEED[n] || SK_PRF[n] || root[n] || PUB_SEED[n]
 *                 (layout of the XMSS reference implementation, idx_len = 4 for
 *                 XMSS and ceil(h / 8) for XMSS^MT, big-endian)
 *   signature   = idx[idx_len] || r[n] || d x (WOTS+ sig[len * n] || auth[(h / d) * n])
 */
#if NOXTLS_XMSS_ENABLE_N64
#define NOXTLS_XMSS_MAX_PUBLIC_KEY_LEN 132U
#define NOXTLS_XMSS_MAX_SECRET_KEY_LEN 268U
#if NOXTLS_XMSS_MAX_HEIGHT <= 15
#define NOXTLS_XMSS_MAX_SIGNATURE_LEN 9092U
#elif NOXTLS_XMSS_MAX_HEIGHT <= 19
#define NOXTLS_XMSS_MAX_SIGNATURE_LEN 9476U
#elif NOXTLS_XMSS_MAX_HEIGHT <= 39
#define NOXTLS_XMSS_MAX_SIGNATURE_LEN 34883U
#elif NOXTLS_XMSS_MAX_HEIGHT <= 59
#define NOXTLS_XMSS_MAX_SIGNATURE_LEN 69701U
#else
#define NOXTLS_XMSS_MAX_SIGNATURE_LEN 104520U
#endif
#else
#define NOXTLS_XMSS_MAX_PUBLIC_KEY_LEN 68U
#define NOXTLS_XMSS_MAX_SECRET_KEY_LEN 140U
#if NOXTLS_XMSS_MAX_HEIGHT <= 15
#define NOXTLS_XMSS_MAX_SIGNATURE_LEN 2500U
#elif NOXTLS_XMSS_MAX_HEIGHT <= 19
#define NOXTLS_XMSS_MAX_SIGNATURE_LEN 2692U
#elif NOXTLS_XMSS_MAX_HEIGHT <= 39
#define NOXTLS_XMSS_MAX_SIGNATURE_LEN 9251U
#elif NOXTLS_XMSS_MAX_HEIGHT <= 59
#define NOXTLS_XMSS_MAX_SIGNATURE_LEN 18469U
#else
#define NOXTLS_XMSS_MAX_SIGNATURE_LEN 27688U
#endif
#endif

/** Description of one parameter set (noxtls_xmss_get_param_info()). */
typedef struct
{
    uint32_t oid;            /**< RFC 8391 / SP 800-208 OID (u32 prefix of keys) */
    uint32_t public_key_len;
    uint32_t secret_key_len;
    uint32_t signature_len;
    uint8_t is_mt;           /**< 1 for XMSS^MT */
    uint8_t hash;            /**< NOXTLS_XMSS_HASH_* */
    uint8_t n;               /**< hash output / node size in bytes */
    uint8_t w;               /**< Winternitz parameter (16) */
    uint8_t wots_len;        /**< WOTS+ chains */
    uint8_t height;          /**< total tree height h */
    uint8_t layers;          /**< d (1 for XMSS) */
    uint8_t tree_height;     /**< h / d */
    uint8_t index_len;       /**< bytes of idx in signatures and secret keys */
    uint8_t sp800_208;       /**< 1 when approved by NIST SP 800-208 */
} noxtls_xmss_param_info_t;

#if NOXTLS_FEATURE_XMSS

/** Hash state used by the streaming verifier (private). */
typedef struct
{
    union
    {
        noxtls_sha_ctx_t sha2;
#if NOXTLS_XMSS_HAVE_SHA512
        noxtls_sha512_ctx_t sha512;
#endif
#if NOXTLS_FEATURE_SHA3
        noxtls_sha3_ctx_t shake;
#endif
    } u;
    uint8_t hash;
} noxtls_xmss_hash_state_t;

/**
 * Streaming verification context (no heap; fields are private).
 * About 250 bytes plus the largest enabled hash context.
 */
typedef struct
{
    noxtls_xmss_param_t param;
    uint32_t state;
    uint64_t idx;
    uint8_t root[NOXTLS_XMSS_MAX_N];
    uint8_t pub_seed[NOXTLS_XMSS_MAX_N];
    uint8_t r[NOXTLS_XMSS_MAX_N];
    noxtls_xmss_hash_state_t hash;
} noxtls_xmss_verify_ctx_t;

/**
 * Persistence callback for the private key state.  It must durably store
 * secret_key_len bytes of secret_key (the complete serialized private key,
 * whose index field already holds the next index that may be used after a
 * restart) and return NOXTLS_RETURN_SUCCESS only once the data is committed
 * to non-volatile storage.  Any other return value makes the signer fail
 * closed: no signature is produced.
 */
typedef noxtls_return_t (*noxtls_xmss_persist_cb_t)(void *user, const uint8_t *secret_key, uint32_t secret_key_len);

/**
 * Stateful signer (fields are private; use the noxtls_xmss_signer_* API).
 * The serialized private key stays in the caller's buffer and is updated in
 * place; the optional traversal (BDS) state lives in a caller buffer too.
 */
typedef struct
{
    noxtls_xmss_param_t param;
    uint8_t *secret_key;
    uint32_t secret_key_len;
    noxtls_xmss_persist_cb_t persist;
    void *persist_user;
    uint32_t reserve;
    uint64_t reserved_end;
    uint8_t *traversal;
    uint32_t traversal_len;
    uint32_t bds_k;
    uint32_t magic;
} noxtls_xmss_signer_t;

/* ---- parameter queries ------------------------------------------------- */

/** @return public key length in bytes (u32 OID || root || PUB_SEED), 0 if unsupported. */
uint32_t noxtls_xmss_public_key_len(noxtls_xmss_param_t param);
/** @return serialized private key length in bytes, 0 if unsupported. */
uint32_t noxtls_xmss_secret_key_len(noxtls_xmss_param_t param);
/** @return signature length in bytes, 0 if unsupported. */
uint32_t noxtls_xmss_signature_len(noxtls_xmss_param_t param);
/**
 * @return number of signatures of a fresh key, 0 if unsupported: 2^h, except
 *         2^h - 1 for the XMSS^MT h = 40 sets, whose 5-byte index field cannot
 *         hold the exhausted marker 2^h (the all-0xff index marks exhaustion).
 */
uint64_t noxtls_xmss_max_signatures(noxtls_xmss_param_t param);
noxtls_return_t noxtls_xmss_get_param_info(noxtls_xmss_param_t param, noxtls_xmss_param_info_t *info);
/** Map an OID (from a key prefix) to a parameter set enabled in this build. */
noxtls_return_t noxtls_xmss_param_from_oid(uint32_t oid, uint8_t is_mt, noxtls_xmss_param_t *param);

/* ---- verification (stateless) ------------------------------------------ */

/**
 * Verify an XMSS / XMSS^MT signature.  public_key is the 4-byte OID-prefixed
 * RFC 8391 encoding; its OID must match param and signature_len must equal
 * noxtls_xmss_signature_len(param) exactly.
 * @return NOXTLS_RETURN_SUCCESS for a valid signature, NOXTLS_RETURN_FAILED for
 *         an invalid one, NOXTLS_RETURN_BAD_DATA / INVALID_PARAM / NULL /
 *         NOT_SUPPORTED for malformed input.
 */
noxtls_return_t noxtls_xmss_verify(noxtls_xmss_param_t param,
                                   const uint8_t *public_key,
                                   const uint8_t *message,
                                   uint32_t message_len,
                                   const uint8_t *signature,
                                   uint32_t signature_len);

/**
 * Streaming verification: init() parses the public key and the signature
 * header (idx || r), update() absorbs the message in any number of chunks,
 * final() checks the rest of the signature.  The signature passed to final()
 * must be the one passed to init() (its header is re-checked).  No heap; the
 * context may live anywhere and holds no secrets.
 */
noxtls_return_t noxtls_xmss_verify_init(noxtls_xmss_verify_ctx_t *ctx,
                                        noxtls_xmss_param_t param,
                                        const uint8_t *public_key,
                                        uint32_t public_key_len,
                                        const uint8_t *signature,
                                        uint32_t signature_len);
noxtls_return_t noxtls_xmss_verify_update(noxtls_xmss_verify_ctx_t *ctx, const uint8_t *data, uint32_t data_len);
noxtls_return_t noxtls_xmss_verify_final(noxtls_xmss_verify_ctx_t *ctx, const uint8_t *signature, uint32_t signature_len);

/* ---- key generation ---------------------------------------------------- */

/**
 * Generate a key pair from DRBG seeds.  secret_key receives the serialized
 * private key with index 0; it must be persisted before the first signature.
 * Cost: one tree of 2^(h/d) leaves.
 */
noxtls_return_t noxtls_xmss_keygen(noxtls_xmss_param_t param,
                                   uint8_t *public_key,
                                   uint32_t public_key_len,
                                   uint8_t *secret_key,
                                   uint32_t secret_key_len);

/**
 * Deterministic key generation (KATs): seed = SK_SEED || SK_PRF || PUB_SEED,
 * each n bytes (seed_len = 3n), as in the XMSS reference implementation.
 */
noxtls_return_t noxtls_xmss_keygen_from_seed(noxtls_xmss_param_t param,
                                             const uint8_t *seed,
                                             uint32_t seed_len,
                                             uint8_t *public_key,
                                             uint32_t public_key_len,
                                             uint8_t *secret_key,
                                             uint32_t secret_key_len);

/** Extract the public key (OID || root || PUB_SEED) from a serialized private key. */
noxtls_return_t noxtls_xmss_public_key_from_secret(noxtls_xmss_param_t param,
                                                   const uint8_t *secret_key,
                                                   uint32_t secret_key_len,
                                                   uint8_t *public_key,
                                                   uint32_t public_key_len);

/** Number of signatures a serialized private key can still produce (0 when exhausted). */
noxtls_return_t noxtls_xmss_secret_key_remaining(noxtls_xmss_param_t param,
                                                 const uint8_t *secret_key,
                                                 uint32_t secret_key_len,
                                                 uint64_t *remaining);

/* ---- stateful signing (SP 800-208 Section 8) --------------------------- */

/**
 * Legacy one-shot API.  A const private key cannot be advanced, so signing
 * through it would reuse one-time keys: always returns
 * NOXTLS_RETURN_NOT_SUPPORTED.  Use noxtls_xmss_signer_init() and
 * noxtls_xmss_sign_stateful().
 */
noxtls_return_t noxtls_xmss_sign(noxtls_xmss_param_t param,
                                 const uint8_t *secret_key,
                                 const uint8_t *message,
                                 uint32_t message_len,
                                 uint8_t *signature,
                                 uint32_t *signature_len);

/**
 * Bind a signer to a serialized private key held in the caller's buffer.
 *
 * State-management contract:
 *  - persist is mandatory.  Before a signature with index i is computed the
 *    signer stores an image of the private key whose index field is at least
 *    i + 1 (i + reserve, capped at 2^h) through persist; only after persist
 *    returns NOXTLS_RETURN_SUCCESS is the signature computed and released.
 *    If persist fails, nothing is released, the index is not consumed and
 *    the callback's error code is returned (fail closed; retrying is safe).
 *  - reserve >= 1 batches persistence: one persist call covers the next
 *    `reserve` indices; after a crash up to reserve - 1 indices are skipped,
 *    never reused.
 *  - The in-RAM key (secret_key) always holds the next unused index.  When the
 *    last index has been used the seeds are wiped, the index is set to 2^h and
 *    the wiped image is persisted (2^h - 1 for XMSS^MT h = 40, see
 *    noxtls_xmss_max_signatures()); later calls fail with
 *    NOXTLS_RETURN_KEY_EXHAUSTED.
 *  - The caller must not use the same private key from two signers, copy it
 *    back from a backup, or sign while a previous persist is in flight.
 * The secret_key buffer must stay valid for the signer's lifetime.
 */
noxtls_return_t noxtls_xmss_signer_init(noxtls_xmss_signer_t *signer,
                                        noxtls_xmss_param_t param,
                                        uint8_t *secret_key,
                                        uint32_t secret_key_len,
                                        noxtls_xmss_persist_cb_t persist,
                                        void *persist_user,
                                        uint32_t reserve);

/**
 * Size of the optional BDS traversal state for (param, bds_k), 0 when the
 * combination is invalid.  bds_k trades memory for speed: (h/d - bds_k) must
 * be even and 0 <= bds_k <= h/d.  Larger k keeps more nodes (2^k - k - 1 per
 * tree) and does fewer leaf computations per signature ((h/d - k)/2).
 */
uint32_t noxtls_xmss_traversal_state_len(noxtls_xmss_param_t param, uint32_t bds_k);

/**
 * Attach a caller buffer as BDS traversal state and build it for the key's
 * current index (cost about (2d - 1) * 2^(h/d) leaf computations, i.e.
 * roughly one key generation).  Afterwards each signature costs about
 * (h/d - bds_k)/2 + d leaf computations instead of d * 2^(h/d).  The state
 * holds only public tree nodes; it is a cache that is rebuilt on attach.
 */
noxtls_return_t noxtls_xmss_signer_attach_traversal(noxtls_xmss_signer_t *signer,
                                                    uint8_t *state,
                                                    uint32_t state_len,
                                                    uint32_t bds_k);

/**
 * Sign message with the next one-time key.  *signature_len is the capacity
 * of signature on input and the signature length on output.  The output
 * never holds signature material on error: once an index has been reserved,
 * any later failure wipes the buffer; argument errors (capacity too small,
 * NULL message), an exhausted or corrupt key return before the buffer is
 * touched.
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_KEY_EXHAUSTED, the persistence
 *         callback's error code, NOXTLS_RETURN_INVALID_BLOCK_SIZE (capacity
 *         too small) or another parameter error.
 */
noxtls_return_t noxtls_xmss_sign_stateful(noxtls_xmss_signer_t *signer,
                                          const uint8_t *message,
                                          uint32_t message_len,
                                          uint8_t *signature,
                                          uint32_t *signature_len);

/** Signatures left for this signer (counts reserved-but-unused indices as available). */
noxtls_return_t noxtls_xmss_signer_remaining(const noxtls_xmss_signer_t *signer, uint64_t *remaining);

/** Detach and wipe the traversal state and the signer (the caller's key buffer is not touched). */
void noxtls_xmss_signer_free(noxtls_xmss_signer_t *signer);

#endif /* NOXTLS_FEATURE_XMSS */

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_XMSS_H_ */
