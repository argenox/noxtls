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
* File:    noxtls_tls_kdf.c
* Summary: TLS Key Derivation Functions (PRF, HKDF) Implementation
*
*
*****************************************************************************/

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "common/noxtls_memory_compat.h"
#include "noxtls_tls_kdf.h"
#include "common/noxtls_memory.h"
#include "mac/noxtls_hmac.h"
#include "kdf/noxtls_hkdf.h"
#include "mdigest/md5/noxtls_md5.h"
#include "mdigest/sha1/noxtls_sha1.h"
#include "mdigest/sha256/noxtls_sha256.h"
#include "mdigest/sha512/noxtls_sha512.h"
#include "noxtls_ct.h"

static uint32_t get_hash_output_size(noxtls_hash_algos_t hash_algo)
{
    switch(hash_algo) {
        case NOXTLS_HASH_MD5: return 16U;
        case NOXTLS_HASH_SHA1: return 20U;
        case NOXTLS_HASH_SHA_224: return 28U;
        case NOXTLS_HASH_SHA_256: return 32U;
        case NOXTLS_HASH_SHA_384: return 48U;
        case NOXTLS_HASH_SHA_512: return 64U;
        case NOXTLS_HASH_SHA_512_224: return 28U;
        case NOXTLS_HASH_SHA_512_256: return 32U;
        case NOXTLS_HASH_SHA3_224: return 28U;
        case NOXTLS_HASH_SHA3_256: return 32U;
        case NOXTLS_HASH_SHA3_384: return 48U;
        case NOXTLS_HASH_SHA3_512: return 64U;
        default: return 0U;
    }
}

/*
 * TLS P_hash (RFC 5246 section 5, RFC 2246 section 5):
 *   A(0) = label || seed, A(i) = HMAC(secret, A(i-1)),
 *   P_hash = HMAC(secret, A(1) || label || seed) || HMAC(secret, A(2) || label || seed) || ...
 * The secret is keyed into one HMAC context once and every HMAC restarts from
 * its key-pad midstates (noxtls_hmac_reset), label and seed are streamed as
 * separate parts, so nothing is allocated and nothing is concatenated.
 * With xor_into != 0 the stream is XORed into output (TLS 1.0/1.1 PRF halves).
 */
static noxtls_return_t p_hash(noxtls_hash_algos_t hash_algo,
                              const uint8_t *secret, uint32_t secret_len,
                              const uint8_t *label, uint32_t label_len,
                              const uint8_t *seed, uint32_t seed_len,
                              uint8_t *output, uint32_t output_len, uint8_t xor_into)
{
    uint32_t hash_len = get_hash_output_size(hash_algo);
    noxtls_hmac_context_t hmac;
    uint8_t A[64];
    uint8_t chunk[64];
    uint32_t produced = 0U;
    uint32_t tmp_len = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if((secret == NULL) || (seed == NULL) || (output == NULL) || ((label == NULL) && (label_len != 0U))) {
        return NOXTLS_RETURN_NULL;
    }
    if((hash_len == 0U) || ((size_t)hash_len > sizeof(A))) {
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }

    /* A(1) = HMAC(secret, label || seed) */
    rc = noxtls_hmac_init(&hmac, hash_algo, secret, secret_len);
    if((rc == NOXTLS_RETURN_SUCCESS) && (label_len > 0U)) {
        rc = noxtls_hmac_update(&hmac, label, label_len);
    }
    if((rc == NOXTLS_RETURN_SUCCESS) && (seed_len > 0U)) {
        rc = noxtls_hmac_update(&hmac, seed, seed_len);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        tmp_len = hash_len;
        rc = noxtls_hmac_final(&hmac, A, &tmp_len);
    }

    while((rc == NOXTLS_RETURN_SUCCESS) && (produced < output_len)) {
        uint32_t copy_len = 0U;
        uint32_t i = 0U;

        /* HMAC(secret, A(i) || label || seed) */
        rc = noxtls_hmac_reset(&hmac);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = noxtls_hmac_update(&hmac, A, hash_len);
        }
        if((rc == NOXTLS_RETURN_SUCCESS) && (label_len > 0U)) {
            rc = noxtls_hmac_update(&hmac, label, label_len);
        }
        if((rc == NOXTLS_RETURN_SUCCESS) && (seed_len > 0U)) {
            rc = noxtls_hmac_update(&hmac, seed, seed_len);
        }
        if(rc == NOXTLS_RETURN_SUCCESS) {
            tmp_len = hash_len;
            rc = noxtls_hmac_final(&hmac, chunk, &tmp_len);
        }
        if(rc != NOXTLS_RETURN_SUCCESS) {
            break;
        }

        copy_len = ((output_len - produced) < hash_len) ? (output_len - produced) : hash_len;
        if(xor_into != 0U) {
            for(i = 0U; i < copy_len; i += 1U) {
                output[produced + i] = (uint8_t)(output[produced + i] ^ chunk[i]);
            }
        } else {
            noxtls_copy_u8(&output[produced], (size_t)output_len - (size_t)produced, chunk, (size_t)copy_len);
        }
        produced += copy_len;

        if(produced < output_len) {
            /* A(i+1) = HMAC(secret, A(i)); final reads A before overwriting it. */
            rc = noxtls_hmac_reset(&hmac);
            if(rc == NOXTLS_RETURN_SUCCESS) {
                rc = noxtls_hmac_update(&hmac, A, hash_len);
            }
            if(rc == NOXTLS_RETURN_SUCCESS) {
                tmp_len = hash_len;
                rc = noxtls_hmac_final(&hmac, A, &tmp_len);
            }
        }
    }

    (void)noxtls_hmac_free(&hmac);
    noxtls_secure_zero(A, sizeof(A));
    noxtls_secure_zero(chunk, sizeof(chunk));
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(output, (size_t)output_len);
        return NOXTLS_RETURN_FAILED;
    }
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t tls12_prf(const uint8_t *secret, uint32_t secret_len,
                          const uint8_t *label, uint32_t label_len,
                          const uint8_t *seed, uint32_t seed_len,
                          uint8_t *output, uint32_t output_len,
                          noxtls_hash_algos_t hash_algo)
{
    if((secret == NULL) || (label == NULL) || (seed == NULL) || (output == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    return p_hash(hash_algo, secret, secret_len, label, label_len, seed, seed_len,
                  output, output_len, 0U);
}

noxtls_return_t tls10_prf(const uint8_t *secret, uint32_t secret_len,
                          const uint8_t *label, uint32_t label_len,
                          const uint8_t *seed, uint32_t seed_len,
                          uint8_t *output, uint32_t output_len)
{
#if NOXTLS_FEATURE_MD5 && NOXTLS_FEATURE_SHA1
    uint32_t half_len = 0U;
    const uint8_t *s1 = NULL;
    const uint8_t *s2 = NULL;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if((secret == NULL) || (label == NULL) || (seed == NULL) || (output == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if(secret_len == 0U) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    /* PRF = P_MD5(S1, label || seed) XOR P_SHA-1(S2, label || seed); the halves
     * overlap by one byte for odd secret lengths (RFC 2246 section 5). */
    half_len = (secret_len + 1U) / 2U;
    s1 = secret;
    s2 = &secret[secret_len - half_len];

    rc = p_hash(NOXTLS_HASH_MD5, s1, half_len, label, label_len, seed, seed_len, output, output_len, 0U);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = p_hash(NOXTLS_HASH_SHA1, s2, half_len, label, label_len, seed, seed_len, output, output_len, 1U);
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(output, (size_t)output_len);
        return NOXTLS_RETURN_FAILED;
    }
    return NOXTLS_RETURN_SUCCESS;
#else
    (void)secret;
    (void)secret_len;
    (void)label;
    (void)label_len;
    (void)seed;
    (void)seed_len;
    (void)output;
    (void)output_len;
    return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
}

/*
 * HKDF-Expand-Label (RFC 8446 section 7.1, RFC 9147 section 5.9):
 *   info = uint16 length || uint8 len(prefix || label) || prefix || label ||
 *          uint8 len(context) || context
 * The HkdfLabel structure is streamed into HKDF-Expand as six parts instead of
 * being assembled in a stack buffer, so the protocol maximum (255-byte label
 * and 255-byte context, 514-byte HkdfLabel) is supported without any copy.
 */
static noxtls_return_t hkdf_expand_label_with_prefix(noxtls_hash_algos_t hash_algo,
                                                     const uint8_t *prefix,
                                                     const uint8_t *secret, uint32_t secret_len,
                                                     const uint8_t *label, uint32_t label_len,
                                                     const uint8_t *context, uint32_t context_len,
                                                     uint8_t *output, uint32_t output_len)
{
    uint8_t head[3];
    uint8_t ctx_len_byte;
    noxtls_hkdf_info_part_t parts[5];
    uint32_t prefix_len = (uint32_t)noxtls_u8_strlen(prefix);
    uint32_t full_label_len = 0U;

    /* Bound label_len before adding the prefix so the sum cannot wrap (HkdfLabel.label is
     * opaque<7..255>, RFC 8446 7.1). */
    if((secret == NULL) || (label == NULL) || (output == NULL) || (prefix_len > 255U) ||
       (label_len > (255U - prefix_len)) || (context_len > 255U) || (output_len > 0xFFFFU)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    full_label_len = prefix_len + label_len;
    if((context == NULL) && (context_len != 0U)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    head[0] = (uint8_t)((output_len >> 8U) & 0xFFU);
    head[1] = (uint8_t)(output_len & 0xFFU);
    head[2] = (uint8_t)full_label_len;
    ctx_len_byte = (uint8_t)context_len;

    parts[0].data = head;
    parts[0].len = (uint32_t)sizeof(head);
    parts[1].data = prefix;
    parts[1].len = prefix_len;
    parts[2].data = label;
    parts[2].len = label_len;
    parts[3].data = &ctx_len_byte;
    parts[3].len = 1U;
    parts[4].data = context;
    parts[4].len = context_len;

    return noxtls_hkdf_expand_parts(hash_algo, secret, secret_len, parts, 5U, output, output_len);
}

noxtls_return_t tls13_hkdf_expand_label(noxtls_hash_algos_t hash_algo,
                                        const uint8_t *secret, uint32_t secret_len,
                                        const uint8_t *label, uint32_t label_len,
                                        const uint8_t *context, uint32_t context_len,
                                        uint8_t *output, uint32_t output_len)
{
    return hkdf_expand_label_with_prefix(hash_algo, (const uint8_t[]){ (uint8_t)'t', (uint8_t)'l', (uint8_t)'s', (uint8_t)'1', (uint8_t)'3', (uint8_t)' ', 0 }, secret, secret_len,
                                         label, label_len, context, context_len,
                                         output, output_len);
}

noxtls_return_t dtls13_hkdf_expand_label(noxtls_hash_algos_t hash_algo,
                                         const uint8_t *secret, uint32_t secret_len,
                                         const uint8_t *label, uint32_t label_len,
                                         const uint8_t *context, uint32_t context_len,
                                         uint8_t *output, uint32_t output_len)
{
    return hkdf_expand_label_with_prefix(hash_algo, (const uint8_t[]){ (uint8_t)'d', (uint8_t)'t', (uint8_t)'l', (uint8_t)'s', (uint8_t)'1', (uint8_t)'3', 0 }, secret, secret_len,
                                         label, label_len, context, context_len,
                                         output, output_len);
}

static noxtls_return_t hash_message_sha256(const uint8_t *messages, uint32_t messages_len,
                                           uint8_t *out_digest, uint32_t out_len)
{
    noxtls_sha_ctx_t ctx;

    if(out_len < 32U) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(noxtls_sha256_init(&ctx, NOXTLS_HASH_SHA_256) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    if((messages != NULL) && (messages_len > 0U)) {
        if(noxtls_sha256_update(&ctx, messages, messages_len) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
    }
    return noxtls_sha256_finish(&ctx, out_digest);
}

#if NOXTLS_FEATURE_SHA384 || NOXTLS_FEATURE_SHA512
static noxtls_return_t hash_message_sha512(noxtls_hash_algos_t hash_algo,
                                           const uint8_t *messages, uint32_t messages_len,
                                           uint8_t *out_digest, uint32_t out_len)
{
    noxtls_sha512_ctx_t ctx;
    uint32_t need = (hash_algo == NOXTLS_HASH_SHA_384) ? 48U : 64U;

#if !NOXTLS_FEATURE_SHA384
    if(hash_algo == NOXTLS_HASH_SHA_384) {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }
#endif
#if !NOXTLS_FEATURE_SHA512
    if(hash_algo == NOXTLS_HASH_SHA_512) {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }
#endif

    if(out_len < need) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(noxtls_sha512_init(&ctx, hash_algo) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    if((messages != NULL) && (messages_len > 0U)) {
        if(noxtls_sha512_update(&ctx, messages, messages_len) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
    }
    return noxtls_sha512_finish(&ctx, out_digest);
}
#endif /* NOXTLS_FEATURE_SHA384 || NOXTLS_FEATURE_SHA512 */

#if NOXTLS_FEATURE_SHA1
static noxtls_return_t hash_message_sha1(const uint8_t *messages, uint32_t messages_len,
                                         uint8_t *out_digest, uint32_t out_len)
{
    noxtls_sha_ctx_t ctx;

    if(out_len < 20U) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(noxtls_sha1_init(&ctx, NOXTLS_HASH_SHA1) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    if((messages != NULL) && (messages_len > 0U)) {
        if(noxtls_sha1_update(&ctx, messages, messages_len) != NOXTLS_RETURN_SUCCESS) {
            return NOXTLS_RETURN_FAILED;
        }
    }
    return noxtls_sha1_finish(&ctx, out_digest);
}
#endif /* NOXTLS_FEATURE_SHA1 */

static noxtls_return_t hash_message(noxtls_hash_algos_t hash_algo,
                                    const uint8_t *messages, uint32_t messages_len,
                                    uint8_t *out_digest, uint32_t out_len)
{
    if((messages == NULL) || (out_digest == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    if(hash_algo == NOXTLS_HASH_SHA_256) {
        return hash_message_sha256(messages, messages_len, out_digest, out_len);
    }
#if NOXTLS_FEATURE_SHA384 || NOXTLS_FEATURE_SHA512
    if((hash_algo == NOXTLS_HASH_SHA_384) || (hash_algo == NOXTLS_HASH_SHA_512)) {
        return hash_message_sha512(hash_algo, messages, messages_len, out_digest, out_len);
    }
#endif
#if NOXTLS_FEATURE_SHA1
    if(hash_algo == NOXTLS_HASH_SHA1) {
        return hash_message_sha1(messages, messages_len, out_digest, out_len);
    }
#endif

    return NOXTLS_RETURN_INVALID_ALGORITHM;
}

static noxtls_return_t hash_empty_message(noxtls_hash_algos_t hash_algo,
                                          uint8_t *out_digest, uint32_t out_len)
{
    if(out_digest == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    if(hash_algo == NOXTLS_HASH_SHA_256) {
        return hash_message_sha256(NULL, 0U, out_digest, out_len);
    }
#if NOXTLS_FEATURE_SHA384 || NOXTLS_FEATURE_SHA512
    if((hash_algo == NOXTLS_HASH_SHA_384) || (hash_algo == NOXTLS_HASH_SHA_512)) {
        return hash_message_sha512(hash_algo, NULL, 0U, out_digest, out_len);
    }
#endif
#if NOXTLS_FEATURE_SHA1
    if(hash_algo == NOXTLS_HASH_SHA1) {
        return hash_message_sha1(NULL, 0U, out_digest, out_len);
    }
#endif

    return NOXTLS_RETURN_INVALID_ALGORITHM;
}

noxtls_return_t tls13_derive_secret(noxtls_hash_algos_t hash_algo,
                                    const uint8_t *secret, uint32_t secret_len,
                                    const uint8_t *label, uint32_t label_len,
                                    const uint8_t *messages, uint32_t messages_len,
                                    uint8_t *output, uint32_t output_len)
{
    uint32_t hash_len = get_hash_output_size(hash_algo);
    uint8_t transcript_hash[64];
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if((secret == NULL) || (label == NULL) || (output == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if((hash_len == 0U) || ((size_t)(hash_len) > sizeof(transcript_hash))) {
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }
    if(output_len < hash_len) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    if((messages != NULL) && (messages_len > 0U)) {
        rc = hash_message(hash_algo, messages, messages_len, transcript_hash, sizeof(transcript_hash));
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    } else {
        /* MISRA 15.7: final else path */
        rc = hash_empty_message(hash_algo, transcript_hash, sizeof(transcript_hash));
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }

    return tls13_hkdf_expand_label(hash_algo, secret, secret_len, label, label_len,
                                   transcript_hash, hash_len, output, hash_len);
}

noxtls_return_t dtls13_derive_secret(noxtls_hash_algos_t hash_algo,
                                     const uint8_t *secret, uint32_t secret_len,
                                     const uint8_t *label, uint32_t label_len,
                                     const uint8_t *messages, uint32_t messages_len,
                                     uint8_t *output, uint32_t output_len)
{
    uint32_t hash_len = get_hash_output_size(hash_algo);
    uint8_t transcript_hash[64];
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if((secret == NULL) || (label == NULL) || (output == NULL)) {
        return NOXTLS_RETURN_NULL;
    }
    if((hash_len == 0U) || ((size_t)(hash_len) > sizeof(transcript_hash))) {
        return NOXTLS_RETURN_INVALID_ALGORITHM;
    }
    if(output_len < hash_len) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    if((messages != NULL) && (messages_len > 0U)) {
        rc = hash_message(hash_algo, messages, messages_len, transcript_hash, sizeof(transcript_hash));
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    } else {
        /* MISRA 15.7: final else path */
        rc = hash_empty_message(hash_algo, transcript_hash, sizeof(transcript_hash));
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }

    return dtls13_hkdf_expand_label(hash_algo, secret, secret_len, label, label_len,
                                    transcript_hash, hash_len, output, hash_len);
}
