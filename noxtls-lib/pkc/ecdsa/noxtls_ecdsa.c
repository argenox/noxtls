/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
* This file is part of the NoxTLS Library.
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 2 of the License, or
* (at your option) any later version.
*
* Alternatively, this file may be used under the terms of a
* commercial license from Argenox Technologies LLC.
*
* See the LICENSE file in the project root for full details.
* CONTACT: info@argenox.com
* 
*
* File:    noxtls_ecdsa.c
* Summary: Elliptic Curve Digital Signature Algorithm (ECDSA) Implementation
*
*/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/noxtls_memory.h"
#include "common/noxtls_memory_compat.h"
#include "noxtls_ecdsa.h"
#include "pkc/ecc/noxtls_ecc.h"
#include "pkc/rsa/noxtls_bignum.h"
#include "mdigest/md5/noxtls_md5.h"
#include "mdigest/sha1/noxtls_sha1.h"
#include "mdigest/sha256/noxtls_sha256.h"
#include "mdigest/sha512/noxtls_sha512.h"
#include "drbg/noxtls_drbg.h"

#if defined(NOXTLS_ECDSA_VERIFY_DEBUG)
static void ecdsa_debug_hex(const char *label, const uint8_t *buf, uint32_t len)
{
    uint32_t i;
    printf("[ecdsa_verify] %s (%u bytes): ", label, (unsigned)len);
    if (buf) {
        for (i = 0; i < len; i++) printf("%02X", buf[i]);
    } else {
        printf("(null)");
    }
    printf("\n");
    fflush(stdout);
}
#endif

/**
 * @brief Helper function to hash a message
 * 
 * @param hash Output hash
 * @param hash_len Length of the hash
 * @param message Message to hash
 * @param message_len Length of the message
 * @param hash_algo Hash algorithm
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if hash is NULL
 */
static noxtls_return_t ecdsa_hash_message(uint8_t *hash, uint32_t *hash_len, const uint8_t *message, uint32_t message_len, noxtls_hash_algos_t hash_algo)
{
    noxtls_sha_ctx_t ctx;
    noxtls_sha512_ctx_t ctx512;
    
    if(hash == NULL || hash_len == NULL || message == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    switch(hash_algo) {
        case NOXTLS_HASH_MD5:
            if(noxtls_md5_init(&ctx) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
            if(noxtls_md5_update(&ctx, (uint8_t*)message, message_len) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
            if(noxtls_md5_finish(&ctx, hash) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
            *hash_len = 16;
            break;
        case NOXTLS_HASH_SHA1:
            if(noxtls_sha1_init(&ctx, hash_algo) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
            if(noxtls_sha1_update(&ctx, (uint8_t*)message, message_len) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
            if(noxtls_sha1_finish(&ctx, hash) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
            *hash_len = 20;
            break;
        case NOXTLS_HASH_SHA_224:
            if(noxtls_sha256_init(&ctx, hash_algo) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
            if(noxtls_sha256_update(&ctx, (uint8_t*)message, message_len) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
            if(noxtls_sha256_finish(&ctx, hash) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
            *hash_len = 28;
            break;
        case NOXTLS_HASH_SHA_256:
            if(noxtls_sha256_init(&ctx, hash_algo) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
            if(noxtls_sha256_update(&ctx, (uint8_t*)message, message_len) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
            if(noxtls_sha256_finish(&ctx, hash) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
            *hash_len = 32;
            break;
        case NOXTLS_HASH_SHA_384:
        case NOXTLS_HASH_SHA_512:
            if(noxtls_sha512_init(&ctx512, hash_algo) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
            if(noxtls_sha512_update(&ctx512, (uint8_t*)message, message_len) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
            if(noxtls_sha512_finish(&ctx512, hash) != NOXTLS_RETURN_SUCCESS) return NOXTLS_RETURN_FAILED;
            *hash_len = (hash_algo == NOXTLS_HASH_SHA_384) ? 48 : 64;
            break;
        case NOXTLS_HASH_MD4:
        case NOXTLS_HASH_SHA_512_224:
        case NOXTLS_HASH_SHA_512_256:
        case NOXTLS_HASH_SHA3_224:
        case NOXTLS_HASH_SHA3_256:
        case NOXTLS_HASH_SHA3_384:
        case NOXTLS_HASH_SHA3_512:
            return NOXTLS_RETURN_NOT_SUPPORTED;
        default:
            return NOXTLS_RETURN_INVALID_ALGORITHM;
    }
    
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Modular inverse for prime modulus using Fermat: a^(p-2) mod p
 * 
 * @param result Result of the modular inverse
 * @param a Value to invert
 * @param mod Modulus
 * @param size Size of the modulus
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if result is NULL
 */
static noxtls_return_t ecdsa_mod_inv_prime(uint8_t *result,
                                           const uint8_t *a,
                                           const uint8_t *mod,
                                           uint32_t size)
{
    if(result == NULL || a == NULL || mod == NULL || size == 0) {
        return NOXTLS_RETURN_NULL;
    }

    uint8_t *mod_minus_2 = (uint8_t*)calloc(size, 1);
    uint8_t *two = (uint8_t*)calloc(size, 1);
    uint8_t *a_mod = (uint8_t*)calloc(size, 1);
    if(!mod_minus_2 || !two || !a_mod) {
        if(mod_minus_2) free(mod_minus_2);
        if(two) free(two);
        if(a_mod) free(a_mod);
        return NOXTLS_RETURN_FAILED;
    }

    /* a_mod = a mod p */
    noxtls_bn_mod(a_mod, a, size, mod, size);
    if(noxtls_bn_is_zero(a_mod, size)) {
        free(mod_minus_2);
        free(two);
        free(a_mod);
        return NOXTLS_RETURN_FAILED;
    }

    /* mod_minus_2 = p - 2 */
    two[size - 1] = 0x02;
    noxtls_bn_copy(mod_minus_2, mod, size);
    noxtls_bn_sub(mod_minus_2, mod_minus_2, two, size);

    noxtls_bn_mod_exp(result, a_mod, mod_minus_2, size, mod, size);

    free(mod_minus_2);
    free(two);
    free(a_mod);
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Initialize ECDSA signature structure
 * 
 * @param sig ECDSA signature structure
 * @param size Size of the signature
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if sig is NULL
 */
noxtls_return_t noxtls_ecdsa_signature_init(ecdsa_signature_t *sig, uint32_t size)
{
    if(sig == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    /* Clear only defined fields to avoid C/C++ ABI mismatch (caller may be C++ with different struct layout). */
    memset(sig->r, 0, ECC_MAX_KEY_SIZE);
    memset(sig->s, 0, ECC_MAX_KEY_SIZE);
    sig->size = size;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Free ECDSA signature structure
 * 
 * @param sig ECDSA signature structure
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if sig is NULL
 */
noxtls_return_t noxtls_ecdsa_signature_free(ecdsa_signature_t *sig)
{
    if(sig == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    /* Clear only defined fields to avoid C/C++ ABI mismatch (caller may be C++ with different struct layout). */
    memset(sig->r, 0, ECC_MAX_KEY_SIZE);
    memset(sig->s, 0, ECC_MAX_KEY_SIZE);
    sig->size = 0;
    return NOXTLS_RETURN_SUCCESS;
}

/* Minimal DER helpers for noxtls_ecdsa_signature_parse_der (no cert dependency) */
static uint32_t ecdsa_der_get_length(const uint8_t **p, const uint8_t *e)
{
    const uint8_t *q = *p;
    uint32_t len = 0;
    if(q >= e) return 0;
    if(*q & 0x80) {
        uint8_t n = *q & 0x7F;
        q++;
        if(n == 0 || n > 4 || q + n > e) return 0;
        for(; n; n--) len = (len << 8) | *q++;
    } else {
        len = *q & 0x7F;
        q++;
    }
    *p = q;
    return len;
}

static int ecdsa_der_get_tag(const uint8_t **p, const uint8_t *e, uint8_t expect)
{
    if(*p >= e || **p != expect) return -1;
    (*p)++;
    return 0;
}

static int ecdsa_der_get_integer(const uint8_t **p, const uint8_t *e, uint8_t *buf, uint32_t buf_size, uint32_t *out_len)
{
    if(*p >= e || *(*p)++ != 0x02) return -1;
    uint32_t len = ecdsa_der_get_length(p, e);
    if(len == 0 || *p + len > e || len > buf_size) return -1;
    *out_len = len;
    memcpy(buf, *p, len);
    *p += len;
    return 0;
}

/**
 * @brief Parse DER-encoded ECDSA signature (SEQUENCE of two INTEGERs r, s) into ecdsa_signature_t
 */
noxtls_return_t noxtls_ecdsa_signature_parse_der(const uint8_t *der, uint32_t der_len, ecdsa_signature_t *out, uint32_t coord_size)
{
    const uint8_t *ptr = der;
    const uint8_t *end = der + der_len;
    uint32_t seq_len, r_len, s_len;
    uint8_t r[ECC_MAX_KEY_SIZE], s[ECC_MAX_KEY_SIZE];

    if(der == NULL || out == NULL || coord_size == 0 || coord_size > ECC_MAX_KEY_SIZE) {
        return NOXTLS_RETURN_NULL;
    }

    if(ptr >= end || ecdsa_der_get_tag(&ptr, end, 0x30) != 0) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    seq_len = ecdsa_der_get_length(&ptr, end);
    if(seq_len == 0 || ptr + seq_len > end) {
        return NOXTLS_RETURN_BAD_DATA;
    }

    {
        const uint8_t *seq_end = ptr + seq_len;
        if(ecdsa_der_get_integer(&ptr, seq_end, r, sizeof(r), &r_len) != 0) {
            return NOXTLS_RETURN_BAD_DATA;
        }
        if(ecdsa_der_get_integer(&ptr, seq_end, s, sizeof(s), &s_len) != 0) {
            return NOXTLS_RETURN_BAD_DATA;
        }
    }

    memset(out, 0, sizeof(ecdsa_signature_t));
    out->size = coord_size;

    if(r_len <= coord_size) {
        memcpy(out->r + coord_size - r_len, r, r_len);
    } else {
        uint32_t skip = r_len - coord_size;
        uint32_t i;
        for(i = 0; i < skip; i++) {
            if(r[i] != 0) {
                return NOXTLS_RETURN_BAD_DATA;
            }
        }
        memcpy(out->r, r + skip, coord_size);
    }
    if(s_len <= coord_size) {
        memcpy(out->s + coord_size - s_len, s, s_len);
    } else {
        uint32_t skip = s_len - coord_size;
        uint32_t i;
        for(i = 0; i < skip; i++) {
            if(s[i] != 0) {
                return NOXTLS_RETURN_BAD_DATA;
            }
        }
        memcpy(out->s, s + skip, coord_size);
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief ECDSA Signature Generation
 * 
 * Algorithm:
 * 1. Hash the message: h = HASH(message)
 * 2. Generate random nonce k in [1, n-1]
 * 3. Compute (x, y) = k * G
 * 4. r = x mod n (if r == 0, go to step 2)
 * 5. s = k^-1 * (h + r * d) mod n (if s == 0, go to step 2)
 * 6. Signature is (r, s)
 *
 * @param key ECC key
 * @param message Message to sign
 * @param message_len Length of the message
 * @param signature ECDSA signature structure
 * @param hash_algo Hash algorithm
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if key is NULL
 */
noxtls_return_t noxtls_ecdsa_sign(ecc_key_t *key, const uint8_t *message, uint32_t message_len, ecdsa_signature_t *signature, noxtls_hash_algos_t hash_algo)
{
    uint8_t *hash = NULL;
    uint8_t *k = NULL;
    uint8_t *k_inv = NULL;
    uint8_t *h = NULL;
    uint8_t *r_times_d = NULL;
    uint8_t *h_plus_rd = NULL;
    uint8_t *s_product = NULL;  /* k_inv * h_plus_rd is 2*size bytes; must not write into signature->s */
    uint8_t *random_bytes = NULL;
    ecc_point_t kG;
    drbg_state_t drbg_state;
    uint32_t size;
    uint32_t hash_len;
    uint32_t bits;
    uint32_t max_attempts = 100;
    uint32_t attempt;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    
    if(key == NULL || message == NULL || signature == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(key->curve == NULL || key->d == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    
    size = key->curve->size;
    bits = size * 8;
    
    /* Allocate buffers */
    hash = (uint8_t*)calloc(64, 1);  /* Max hash size (SHA-512) */
    k = (uint8_t*)calloc(size, 1);
    k_inv = (uint8_t*)calloc(size, 1);
    h = (uint8_t*)calloc(size, 1);
    r_times_d = (uint8_t*)calloc(size * 2, 1);
    /* h + r*d can be up to 2n-2, so we need size+1 bytes to avoid dropping carry in add */
    h_plus_rd = (uint8_t*)calloc(size + 1, 1);
    s_product = (uint8_t*)calloc(size * 2, 1);
    random_bytes = (uint8_t*)calloc(size, 1);
    
    if(!hash || !k || !k_inv || !h || !r_times_d || !h_plus_rd || !s_product || !random_bytes) {
        rc = NOXTLS_RETURN_FAILED;
        goto cleanup;
    }

    /* Initialize signature structure */
    noxtls_ecc_point_init(&kG, size);

    /* Step 1: Hash the message */
    rc = ecdsa_hash_message(hash, &hash_len, message, message_len, hash_algo);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }

    /* Truncate or pad hash to curve size (leftmost bits) */
    if(hash_len >= size) {
        memcpy(h, hash, size);
    } else {
        memcpy(h, hash, hash_len);
    }

    /* Reduce h mod n if h >= n */
    if(noxtls_bn_cmp(h, key->curve->n, size) >= 0) {
        noxtls_bn_mod(h, h, size, key->curve->n, size);
    }

    /* Initialize DRBG */
    rc = drbg_instantiate(&drbg_state, DRBG_AES256, NULL, 0, NULL, 0, NULL, 0);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup;
    }

    /* Step 2-5: Generate signature with retry if r or s is zero */
    for(attempt = 0; attempt < max_attempts; attempt++) {
        /* Step 2: Generate random nonce k in [1, n-1] */
        do {
            rc = drbg_generate(&drbg_state, random_bytes, bits, NULL, 0);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                goto cleanup;
            }

            /* Reduce mod n */
            noxtls_bn_mod(k, random_bytes, size, key->curve->n, size);

            /* Ensure k is not zero */
        } while(noxtls_bn_is_zero(k, size));

        /* Step 3: Compute (x, y) = k * G */
        rc = noxtls_ecc_point_multiply(&kG, k, &key->curve->G, key->curve);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            goto cleanup;
        }
            
        /* Step 4: r = x mod n */
        noxtls_bn_mod(signature->r, kG.x, size, key->curve->n, size);

        /* If r == 0, retry */
        if(noxtls_bn_is_zero(signature->r, size)) {
            continue;
        }

        /* Step 5: s = k^-1 * (h + r * d) mod n */
        /* Compute k^-1 mod n */
        rc = ecdsa_mod_inv_prime(k_inv, k, key->curve->n, size);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            continue;
        }

        /* Compute r * d */
        noxtls_bn_mul(r_times_d, signature->r, size, key->d, size);
        noxtls_bn_mod(r_times_d, r_times_d, size * 2, key->curve->n, size);

        /* Compute h + r * d with carry (can be size+1 bytes); then reduce mod n */
        {
            uint16_t carry = 0;
            uint32_t i;
            for(i = 0; i < size; i++) {
                uint32_t idx = size - 1 - i;
                uint16_t sum = (uint16_t)h[idx] + (uint16_t)r_times_d[idx] + carry;
                h_plus_rd[idx + 1] = (uint8_t)(sum & 0xFF);
                carry = sum >> 8;
            }
            h_plus_rd[0] = (uint8_t)carry;
            {
                uint32_t len = carry ? (size + 1) : size;
                const uint8_t *src = carry ? h_plus_rd : (h_plus_rd + 1);
                noxtls_bn_mod(h_plus_rd, src, len, key->curve->n, size);
            }
        }

        /* Compute s = k^-1 * (h + r * d) mod n (product is 2*size bytes; use temp to avoid overwriting sig->size) */
        noxtls_bn_mul(s_product, k_inv, size, h_plus_rd, size);
        noxtls_bn_mod(signature->s, s_product, size * 2, key->curve->n, size);

        /* If s == 0, retry */
        if(noxtls_bn_is_zero(signature->s, size)) {
            continue;
        }

        /* Success! */
        rc = NOXTLS_RETURN_SUCCESS;
        goto cleanup;
    }

    if(rc != NOXTLS_RETURN_SUCCESS) {
        /* Failed after max attempts */
        rc = NOXTLS_RETURN_FAILED;
    }

cleanup:
    if(hash) free(hash);
    if(k) free(k);
    if(k_inv) free(k_inv);
    if(h) free(h);
    if(r_times_d) free(r_times_d);
    if(h_plus_rd) free(h_plus_rd);
    if(s_product) free(s_product);
    if(random_bytes) free(random_bytes);
    
    return rc;
}

/**
 * @brief ECDSA Signature Verification
 * 
 * Algorithm:
 * 1. Verify r and s are in [1, n-1]
 * 2. Hash the message: h = HASH(message)
 * 3. u1 = s^-1 * h mod n
 * 4. u2 = s^-1 * r mod n
 * 5. Compute (x, y) = u1 * G + u2 * Q
 * 6. v = x mod n
 * 7. Accept if v == r
 *
 * @param key ECC key
 * @param message Message to verify
 * @param message_len Length of the message
 * @param signature ECDSA signature structure
 * @param hash_algo Hash algorithm
 * @return noxtls_return_t NOXTLS_RETURN_SUCCESS on success, NOXTLS_RETURN_NULL if key is NULL
 */
noxtls_return_t noxtls_ecdsa_verify(ecc_key_t *key, const uint8_t *message, uint32_t message_len, const ecdsa_signature_t *signature, noxtls_hash_algos_t hash_algo)
{
    uint8_t *hash = NULL;
    uint8_t *h = NULL;
    uint8_t *s_inv = NULL;
    uint8_t *u1 = NULL;
    uint8_t *u2 = NULL;
    ecc_point_t *u1G = NULL;
    ecc_point_t *u2Q = NULL;
    ecc_point_t result;  /* keep on stack: single output point */
    uint8_t *v = NULL;
    uint32_t size;
    uint32_t hash_len;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    
    if(key == NULL || message == NULL || signature == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(key->curve == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    
    size = key->curve->size;
#if defined(NOXTLS_ECDSA_VERIFY_DEBUG)
    printf("[ecdsa_verify] size=%u message_len=%u\n", (unsigned)size, (unsigned)message_len);
    fflush(stdout);
#endif

    /* Allocate buffers (heap to reduce stack usage) */
    hash = (uint8_t*)calloc(64, 1);  /* Max hash size (SHA-512) */
    h = (uint8_t*)calloc(size, 1);
    s_inv = (uint8_t*)calloc(size, 1);
    /* u1, u2 hold mul result (2*size bytes) before bn_mod; after mod, size-byte value in first bytes */
    u1 = (uint8_t*)calloc(size * 2, 1);
    u2 = (uint8_t*)calloc(size * 2, 1);
    v = (uint8_t*)calloc(size, 1);
    u1G = (ecc_point_t*)calloc(1, sizeof(ecc_point_t));
    u2Q = (ecc_point_t*)calloc(1, sizeof(ecc_point_t));
    
    if(!hash || !h || !s_inv || !u1 || !u2 || !v || !u1G || !u2Q) {
        rc = NOXTLS_RETURN_FAILED;
        goto cleanup_verify;
    }

    noxtls_ecc_point_init(u1G, size);
    noxtls_ecc_point_init(u2Q, size);
    noxtls_ecc_point_init(&result, size);

    /* Step 1: Verify r and s are in [1, n-1] */
    if(noxtls_bn_is_zero(signature->r, size) ||
       noxtls_bn_cmp(signature->r, key->curve->n, size) >= 0) {
        rc = NOXTLS_RETURN_FAILED;
        goto cleanup_verify;
    }

    if(noxtls_bn_is_zero(signature->s, size) ||
       noxtls_bn_cmp(signature->s, key->curve->n, size) >= 0) {
        rc = NOXTLS_RETURN_FAILED;
        goto cleanup_verify;
    }

    /* Step 2: Hash the message */
    rc = ecdsa_hash_message(hash, &hash_len, message, message_len, hash_algo);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup_verify;
    }
        
        /* Truncate or pad hash to curve size (leftmost bits) */
        if(hash_len >= size) {
            memcpy(h, hash, size);
        } else {
            memcpy(h, hash, hash_len);
            /* Pad with zeros on the right (hash is already left-aligned) */
        }
        
        /* Reduce h mod n if h >= n */
        if(noxtls_bn_cmp(h, key->curve->n, size) >= 0) {
            noxtls_bn_mod(h, h, size, key->curve->n, size);
        }
#if defined(NOXTLS_ECDSA_VERIFY_DEBUG)
    printf("[ecdsa_verify] hash_len=%u\n", (unsigned)hash_len);
    fflush(stdout);
    ecdsa_debug_hex("h", h, size);
    ecdsa_debug_hex("signature->r", signature->r, size);
    ecdsa_debug_hex("signature->s", signature->s, size);
#endif

    /* Step 3: u1 = s^-1 * h mod n
     * Curve orders are prime for the supported NIST curves; use Fermat inverse
     * for consistency with signing and to avoid edge failures in generic mod_inv. */
    rc = ecdsa_mod_inv_prime(s_inv, signature->s, key->curve->n, size);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup_verify;
    }
    noxtls_bn_mul(u1, s_inv, size, h, size);
    noxtls_bn_mod(u1, u1, size * 2, key->curve->n, size);

    /* Step 4: u2 = s^-1 * r mod n */
    noxtls_bn_mul(u2, s_inv, size, signature->r, size);
    noxtls_bn_mod(u2, u2, size * 2, key->curve->n, size);
#if defined(NOXTLS_ECDSA_VERIFY_DEBUG)
    ecdsa_debug_hex("s_inv", s_inv, size);
    ecdsa_debug_hex("u1", u1, size);
    ecdsa_debug_hex("u2", u2, size);
#endif

    /* Step 5: Compute (x, y) = u1 * G + u2 * Q */
    rc = noxtls_ecc_point_multiply(u1G, u1, &key->curve->G, key->curve);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup_verify;
    }

    rc = noxtls_ecc_point_multiply(u2Q, u2, &key->Q, key->curve);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup_verify;
    }

    rc = noxtls_ecc_point_add(&result, u1G, u2Q, key->curve);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        goto cleanup_verify;
    }
#if defined(NOXTLS_ECDSA_VERIFY_DEBUG)
    ecdsa_debug_hex("u1G.x", u1G->x, size);
    ecdsa_debug_hex("u1G.y", u1G->y, size);
    ecdsa_debug_hex("u2Q.x", u2Q->x, size);
    ecdsa_debug_hex("u2Q.y", u2Q->y, size);
    ecdsa_debug_hex("result.x", result.x, size);
    ecdsa_debug_hex("result.y", result.y, size);
#endif

    /* Step 6: v = x mod n */
    noxtls_bn_mod(v, result.x, size, key->curve->n, size);
#if defined(NOXTLS_ECDSA_VERIFY_DEBUG)
    ecdsa_debug_hex("result.x (before mod n)", result.x, size);
    ecdsa_debug_hex("v", v, size);
    ecdsa_debug_hex("signature->r (compare)", signature->r, size);
    printf("[ecdsa_verify] v %s r (cmp=%d)\n",
           noxtls_bn_cmp(v, signature->r, size) == 0 ? "==" : "!=",
           noxtls_bn_cmp(v, signature->r, size));
    fflush(stdout);
#endif

    /* Step 7: Accept if v == r */
    if(noxtls_bn_cmp(v, signature->r, size) == 0) {
        rc = NOXTLS_RETURN_SUCCESS;
    } else {
        rc = NOXTLS_RETURN_FAILED;
        /* Unconditional debug when verify fails (no define needed) */
        {
            uint32_t i;
            uint8_t u1_plus_u2_buf[ECC_MAX_KEY_SIZE + 1];
            uint8_t u1_plus_u2_mod_n_buf[ECC_MAX_KEY_SIZE];
            uint8_t s_times_s_inv[ECC_MAX_KEY_SIZE * 2];
            uint8_t s_times_s_inv_mod_n[ECC_MAX_KEY_SIZE];
            uint16_t carry = 0;
            memset(u1_plus_u2_buf, 0, sizeof(u1_plus_u2_buf));
            memset(u1_plus_u2_mod_n_buf, 0, sizeof(u1_plus_u2_mod_n_buf));
            memset(s_times_s_inv, 0, sizeof(s_times_s_inv));
            memset(s_times_s_inv_mod_n, 0, sizeof(s_times_s_inv_mod_n));
            noxtls_bn_mul(s_times_s_inv, signature->s, size, s_inv, size);
            noxtls_bn_mod(s_times_s_inv_mod_n, s_times_s_inv, size * 2, key->curve->n, size);
            for(i = size; i > 0; i--) {
                uint16_t sum = (uint16_t)u1[i-1] + (uint16_t)u2[i-1] + carry;
                u1_plus_u2_buf[i] = (uint8_t)(sum & 0xFF);
                carry = sum >> 8;
            }
            u1_plus_u2_buf[0] = (uint8_t)carry;
            noxtls_bn_mod(u1_plus_u2_mod_n_buf, carry ? u1_plus_u2_buf : (u1_plus_u2_buf + 1), carry ? (size + 1) : size, key->curve->n, size);
            printf("[ecdsa_verify] FAILED v != r (size=%u)\n", (unsigned)size);
            printf("  s*s_inv mod n= ");
            for(i = 0; i < size; i++) printf("%02X", s_times_s_inv_mod_n[i]);
            printf("  (expect 00...01)\n");
            printf("  h            = ");
            for(i = 0; i < size; i++) printf("%02X", h[i]);
            printf("\n  signature->r = ");
            for(i = 0; i < size; i++) printf("%02X", signature->r[i]);
            printf("\n  signature->s = ");
            for(i = 0; i < size; i++) printf("%02X", signature->s[i]);
            printf("\n  s_inv        = ");
            for(i = 0; i < size; i++) printf("%02X", s_inv[i]);
            printf("\n  u1           = ");
            for(i = 0; i < size; i++) printf("%02X", u1[i]);
            printf("\n  u2           = ");
            for(i = 0; i < size; i++) printf("%02X", u2[i]);
            printf("\n  (u1+u2) mod n = ");
            for(i = 0; i < size; i++) printf("%02X", u1_plus_u2_mod_n_buf[i]);
            printf("  (expect 00...01 when u1+u2=1)\n");
            printf("  u1G.x        = ");
            for(i = 0; i < size; i++) printf("%02X", u1G->x[i]);
            printf("\n  u2Q.x        = ");
            for(i = 0; i < size; i++) printf("%02X", u2Q->x[i]);
            printf("\n  result.x     = ");
            for(i = 0; i < size; i++) printf("%02X", result.x[i]);
            printf("\n  v            = ");
            for(i = 0; i < size; i++) printf("%02X", v[i]);
            printf("\n");
            fflush(stdout);
        }
#if defined(NOXTLS_ECDSA_VERIFY_DEBUG)
        {
            uint32_t i;
            printf("[ecdsa_verify] FAILED: v != r\n  v = ");
            for(i = 0; i < size; i++) printf("%02X", v[i]);
            printf("\n  r = ");
            for(i = 0; i < size; i++) printf("%02X", signature->r[i]);
            printf("\n");
            fflush(stdout);
        }
#endif
    }

cleanup_verify:
    if(hash) free(hash);
    if(h) free(h);
    if(s_inv) free(s_inv);
    if(u1) free(u1);
    if(u2) free(u2);
    if(v) free(v);
    if(u1G) free(u1G);
    if(u2Q) free(u2Q);

    return rc;
}

