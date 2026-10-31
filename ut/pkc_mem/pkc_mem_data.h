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
* File:    pkc_mem_data.h
* Summary: Known-answer vector tables and helpers shared by the pkc_mem tests
*
*****************************************************************************/

#ifndef PKC_MEM_DATA_H_
#define PKC_MEM_DATA_H_

#include <stdint.h>

#include "noxtls_common.h"

/*
 * Feature selection for the pkc_mem tests. Library features come from the
 * NOXTLS_FEATURE_* definitions the build passes (0/1). Per-curve knobs
 * (NOXTLS_ECC_ENABLE_<curve>) are optional: an undefined knob means "enabled",
 * so the tests also build against trees that do not have the knobs yet.
 */
#if defined(NOXTLS_FEATURE_ECC) && NOXTLS_FEATURE_ECC
#define PKC_MEM_HAVE_ECC 1
#else
#define PKC_MEM_HAVE_ECC 0
#endif

#if PKC_MEM_HAVE_ECC && defined(NOXTLS_FEATURE_ECDSA) && NOXTLS_FEATURE_ECDSA
#define PKC_MEM_HAVE_ECDSA 1
#else
#define PKC_MEM_HAVE_ECDSA 0
#endif

#if PKC_MEM_HAVE_ECC && defined(NOXTLS_FEATURE_ECDH) && NOXTLS_FEATURE_ECDH
#define PKC_MEM_HAVE_ECDH 1
#else
#define PKC_MEM_HAVE_ECDH 0
#endif

#if !PKC_MEM_HAVE_ECC || (defined(NOXTLS_ECC_ENABLE_SECP256R1) && !NOXTLS_ECC_ENABLE_SECP256R1)
#define PKC_MEM_HAVE_P256 0
#else
#define PKC_MEM_HAVE_P256 1
#endif

#if !PKC_MEM_HAVE_ECC || (defined(NOXTLS_ECC_ENABLE_SECP384R1) && !NOXTLS_ECC_ENABLE_SECP384R1)
#define PKC_MEM_HAVE_P384 0
#else
#define PKC_MEM_HAVE_P384 1
#endif

#if !PKC_MEM_HAVE_ECC || (defined(NOXTLS_ECC_ENABLE_SECP521R1) && !NOXTLS_ECC_ENABLE_SECP521R1)
#define PKC_MEM_HAVE_P521 0
#else
#define PKC_MEM_HAVE_P521 1
#endif

#if PKC_MEM_HAVE_P256 || PKC_MEM_HAVE_P384 || PKC_MEM_HAVE_P521
#define PKC_MEM_HAVE_ECC_CURVES 1
#else
#define PKC_MEM_HAVE_ECC_CURVES 0
#endif

#if defined(NOXTLS_FEATURE_RSA) && NOXTLS_FEATURE_RSA
#define PKC_MEM_HAVE_RSA 1
#else
#define PKC_MEM_HAVE_RSA 0
#endif

#if defined(NOXTLS_FEATURE_X25519) && NOXTLS_FEATURE_X25519
#define PKC_MEM_HAVE_X25519 1
#else
#define PKC_MEM_HAVE_X25519 0
#endif

#if defined(NOXTLS_FEATURE_X448) && NOXTLS_FEATURE_X448
#define PKC_MEM_HAVE_X448 1
#else
#define PKC_MEM_HAVE_X448 0
#endif

#if defined(NOXTLS_FEATURE_ED25519) && NOXTLS_FEATURE_ED25519
#define PKC_MEM_HAVE_ED25519 1
#else
#define PKC_MEM_HAVE_ED25519 0
#endif

#if defined(NOXTLS_FEATURE_DH) && NOXTLS_FEATURE_DH
#define PKC_MEM_HAVE_DH 1
#else
#define PKC_MEM_HAVE_DH 0
#endif

#if PKC_MEM_HAVE_ECC_CURVES || PKC_MEM_HAVE_RSA || PKC_MEM_HAVE_X25519 || PKC_MEM_HAVE_X448 || \
    PKC_MEM_HAVE_ED25519 || PKC_MEM_HAVE_DH
#define PKC_MEM_HAVE_ANY 1
#else
#define PKC_MEM_HAVE_ANY 0
#endif

/* SHA-256 is mandatory for every PKC test here; SHA-384/512 vectors are optional. */
#if !defined(NOXTLS_FEATURE_SHA384) || NOXTLS_FEATURE_SHA384
#define PKC_MEM_HAVE_SHA384 1
#else
#define PKC_MEM_HAVE_SHA384 0
#endif

#if !defined(NOXTLS_FEATURE_SHA512) || NOXTLS_FEATURE_SHA512
#define PKC_MEM_HAVE_SHA512 1
#else
#define PKC_MEM_HAVE_SHA512 0
#endif

/** Largest decoded vector element (RSA-4096 values). */
#define PKC_MEM_MAX_BYTES 512U

/** ECC key pair (RFC 6979 A.2.5-A.2.7): private scalar and public point, big-endian hex. */
typedef struct
{
    uint32_t curve_bits;   /**< 256, 384 or 521. */
    const char *d;
    const char *qx;
    const char *qy;
} pkc_mem_ecc_keypair_t;

/** Affine point, big-endian hex. */
typedef struct
{
    uint32_t curve_bits;
    const char *x;
    const char *y;
} pkc_mem_ecc_point_hex_t;

/** ECDSA verify-only known answer. */
typedef struct
{
    const char *source;
    uint32_t curve_bits;   /**< 256, 384 or 521. */
    uint32_t hash_bits;    /**< 256, 384 or 512 (SHA-2). */
    uint32_t expect_valid; /**< 1: must verify; 0: must be rejected. */
    const char *msg;       /**< Message (hashed by the verifier). */
    const char *qx;
    const char *qy;
    const char *r;
    const char *s;
} pkc_mem_ecdsa_kat_t;

/** ECC CDH primitive known answer (NIST CAVP). */
typedef struct
{
    const char *source;
    uint32_t curve_bits;
    const char *peer_x;    /**< QCAVSx */
    const char *peer_y;    /**< QCAVSy */
    const char *d;         /**< dIUT */
    const char *qx;        /**< QIUTx = x(dIUT * G) */
    const char *qy;        /**< QIUTy */
    const char *z;         /**< ZIUT */
} pkc_mem_ecdh_kat_t;

/** RSA key (OpenSSL generated) with its known answers. */
typedef struct
{
    uint32_t bits;
    const char *n;
    const char *e;
    const char *d;
    const char *p;
    const char *q;
    const char *dp;
    const char *dq;
    const char *qi;        /**< q^-1 mod p */
    const char *msg;
    uint32_t pkcs1_hash_bits;
    const char *pkcs1_sig; /**< RSASSA-PKCS1-v1_5 (deterministic). */
    uint32_t pss_hash_bits;
    const char *pss_sig;   /**< RSASSA-PSS, MGF1 same hash, salt length = hash length. */
    const char *pt;
    const char *ct;        /**< RSAES-PKCS1-v1_5 encryption of pt. */
} pkc_mem_rsa_kat_t;

/** X25519 / X448 function known answer (RFC 7748 little-endian encoding). */
typedef struct
{
    const char *scalar;
    const char *u;
    const char *out;
} pkc_mem_xdh_kat_t;

/** X25519 / X448 Diffie-Hellman known answer (RFC 7748 6.1 / 6.2). */
typedef struct
{
    const char *a;
    const char *pub_a;
    const char *b;
    const char *pub_b;
    const char *k;
} pkc_mem_xdh_dh_kat_t;

#define PKC_MEM_RFC6979_KEY_COUNT 3U
#define PKC_MEM_ECDSA_KAT_COUNT   37U
#define PKC_MEM_ECDH_KAT_COUNT    9U
#define PKC_MEM_RSA_KAT_COUNT     3U

extern const pkc_mem_ecc_keypair_t pkc_mem_rfc6979_keys[PKC_MEM_RFC6979_KEY_COUNT];
extern const pkc_mem_ecc_point_hex_t pkc_mem_small_x_points[PKC_MEM_RFC6979_KEY_COUNT];
extern const pkc_mem_ecdsa_kat_t pkc_mem_ecdsa_kats[PKC_MEM_ECDSA_KAT_COUNT];
extern const pkc_mem_ecdh_kat_t pkc_mem_ecdh_kats[PKC_MEM_ECDH_KAT_COUNT];
extern const pkc_mem_rsa_kat_t pkc_mem_rsa_kats[PKC_MEM_RSA_KAT_COUNT];
extern const pkc_mem_xdh_kat_t pkc_mem_x25519_kats[2];
extern const char *const pkc_mem_x25519_iter1;
extern const char *const pkc_mem_x25519_iter1000;
extern const pkc_mem_xdh_dh_kat_t pkc_mem_x25519_dh;
extern const pkc_mem_xdh_kat_t pkc_mem_x448_kats[2];
extern const char *const pkc_mem_x448_iter1;
extern const char *const pkc_mem_x448_iter1000;
extern const pkc_mem_xdh_dh_kat_t pkc_mem_x448_dh;
extern const char *const pkc_mem_ed25519_t3_sk;
extern const char *const pkc_mem_ed25519_t3_pk;
extern const char *const pkc_mem_ed25519_t3_msg;
extern const char *const pkc_mem_ed25519_t3_sig;

/**
 * @brief Decode a hex string.
 * @param[out] out Destination.
 * @param[in]  cap Capacity of @p out in bytes.
 * @param[in]  hex NUL-terminated hex string (even length).
 * @return Number of bytes written, or 0 on malformed input / overflow.
 */
uint32_t pkc_mem_unhex(uint8_t *out, uint32_t cap, const char *hex);

/**
 * @brief Decode a hex string right-aligned into exactly @p width bytes (zero-padded on the left).
 * @return 1 on success, 0 if the value does not fit or is malformed.
 */
int pkc_mem_unhex_fixed(uint8_t *out, uint32_t width, const char *hex);

#endif /* PKC_MEM_DATA_H_ */
