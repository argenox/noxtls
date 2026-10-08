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
* File:    noxtls_ecjpake_zkp.c
* Summary: Schnorr NIZK proofs and ECJPAKEKeyKP encoding for EC-JPAKE
*
*
*****************************************************************************/

/**
 * @file noxtls_ecjpake_zkp.c
 * @brief Schnorr NIZK proof generation / verification and ECJPAKEKeyKP codec.
 * @ingroup noxtls_ecjpake
 *
 * - Proof: RFC 8235 section 3.2 (V = G x [v], r = v - a*c mod n; the
 *   verifier checks V = G x [r] + A x [c]) with the challenge of section 3.3.
 * - Challenge encoding: draft-cragie-tls-ecjpake-01 section 8.2,
 *   h = int(SHA-256(len||G || len||V || len||X || len||ID)) mod n with
 *   4-octet big-endian lengths (RFC 8235 section 2.3 recommendation).
 * - Wire format: draft-cragie-tls-ecjpake-01 sections 7.1.1 (ECJPAKEKeyKP)
 *   and 7.1.2 (ECSchnorrZKP), ECPoint per RFC 4492 section 5.4.
 */

#include <stdint.h>

#include "noxtls_ecjpake_internal.h"
#include "mdigest/sha256/noxtls_sha256.h"
#include "common/noxtls_ct.h"

/** @brief Bits per byte, for the big-endian length prefix. */
#define NOXTLS_ECJPAKE_BITS_PER_BYTE (8U)
/** @brief Mask selecting one byte. */
#define NOXTLS_ECJPAKE_BYTE_MASK (0xFFU)

/**
 * @brief Absorb a 4-octet big-endian length followed by the item (draft section 8.2).
 * @internal
 *
 * @param[in,out] sha Running SHA-256 context.
 * @param[in] item Item octets (may be NULL when item_len is 0).
 * @param[in] item_len Item length.
 *
 * @return NOXTLS_RETURN_SUCCESS or NOXTLS_RETURN_FAILED.
 */
static noxtls_return_t noxtls_ecjpake_hash_item(noxtls_sha_ctx_t *sha,
                                                const uint8_t *item, uint32_t item_len)
{
    uint8_t prefix[NOXTLS_ECJPAKE_HASH_LENGTH_PREFIX_SIZE];
    uint32_t index;
    noxtls_return_t rc;

    /* SEC 1 v2.0 section 2.3.7 integer-to-octet-string, mlen = 4. */
    for (index = 0U; index < NOXTLS_ECJPAKE_HASH_LENGTH_PREFIX_SIZE; ++index) {
        uint32_t shift = (NOXTLS_ECJPAKE_HASH_LENGTH_PREFIX_SIZE - 1U - index) * NOXTLS_ECJPAKE_BITS_PER_BYTE;

        prefix[index] = (uint8_t)((item_len >> shift) & NOXTLS_ECJPAKE_BYTE_MASK);
    }

    rc = noxtls_sha256_update(sha, prefix, NOXTLS_ECJPAKE_HASH_LENGTH_PREFIX_SIZE);
    if ((rc == NOXTLS_RETURN_SUCCESS) && (item_len > 0U)) {
        rc = noxtls_sha256_update(sha, item, item_len);
    }

    return (rc == NOXTLS_RETURN_SUCCESS) ? NOXTLS_RETURN_SUCCESS : NOXTLS_RETURN_FAILED;
}

noxtls_return_t noxtls_ecjpake_zkp_hash(const uint8_t gen[NOXTLS_ECJPAKE_POINT_SIZE],
                                        const uint8_t V[NOXTLS_ECJPAKE_POINT_SIZE],
                                        const uint8_t X[NOXTLS_ECJPAKE_POINT_SIZE],
                                        const uint8_t *id, uint32_t id_len,
                                        uint8_t h[NOXTLS_ECJPAKE_SCALAR_SIZE])
{
    noxtls_sha_ctx_t sha;
    uint8_t digest[NOXTLS_ECJPAKE_HASH_SIZE];
    noxtls_return_t rc;

    if ((gen == NULL) || (V == NULL) || (X == NULL) || (h == NULL) ||
        ((id == NULL) && (id_len > 0U))) {
        return NOXTLS_RETURN_NULL;
    }

    rc = (noxtls_sha256_init(&sha, NOXTLS_HASH_SHA_256) == NOXTLS_RETURN_SUCCESS) ?
         NOXTLS_RETURN_SUCCESS : NOXTLS_RETURN_FAILED;
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_ecjpake_hash_item(&sha, gen, NOXTLS_ECJPAKE_POINT_SIZE);
    }

    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_ecjpake_hash_item(&sha, V, NOXTLS_ECJPAKE_POINT_SIZE);
    }

    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_ecjpake_hash_item(&sha, X, NOXTLS_ECJPAKE_POINT_SIZE);
    }

    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_ecjpake_hash_item(&sha, id, id_len);
    }

    if ((rc == NOXTLS_RETURN_SUCCESS) && (noxtls_sha256_finish(&sha, digest) != NOXTLS_RETURN_SUCCESS)) {
        rc = NOXTLS_RETURN_FAILED;
    }

    /* draft section 8.2 / section 4.5: h = int(H) mod n. */
    if (rc == NOXTLS_RETURN_SUCCESS) {
        noxtls_ecjpake_scalar_reduce(digest, NOXTLS_ECJPAKE_HASH_SIZE, h);
    } else {
        noxtls_secure_zero(h, NOXTLS_ECJPAKE_SCALAR_SIZE);
    }

    noxtls_secure_zero(digest, sizeof(digest));
    noxtls_secure_zero(&sha, sizeof(sha));
    return rc;
}

noxtls_return_t noxtls_ecjpake_zkp_prove(const uint8_t gen[NOXTLS_ECJPAKE_POINT_SIZE],
                                         const uint8_t x[NOXTLS_ECJPAKE_SCALAR_SIZE],
                                         const uint8_t X[NOXTLS_ECJPAKE_POINT_SIZE],
                                         const uint8_t v[NOXTLS_ECJPAKE_SCALAR_SIZE],
                                         const uint8_t *id, uint32_t id_len,
                                         noxtls_ecjpake_key_kp_t *kp)
{
    uint8_t h[NOXTLS_ECJPAKE_SCALAR_SIZE];
    uint8_t xh[NOXTLS_ECJPAKE_SCALAR_SIZE];
    noxtls_return_t rc;

    if ((gen == NULL) || (x == NULL) || (X == NULL) || (v == NULL) || (kp == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    noxtls_secure_zero(kp, sizeof(*kp));
    noxtls_copy_u8(kp->X, NOXTLS_ECJPAKE_POINT_SIZE, X, NOXTLS_ECJPAKE_POINT_SIZE);

    /* RFC 8235 section 3.2: V = gen x [v]. */
    rc = noxtls_ecjpake_point_mul(v, gen, kp->V);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_ecjpake_zkp_hash(gen, kp->V, X, id, id_len, h);
    }

    /* r = v - x*h mod n. */
    if (rc == NOXTLS_RETURN_SUCCESS) {
        noxtls_ecjpake_scalar_mul(x, h, xh);
        noxtls_ecjpake_scalar_sub(v, xh, kp->r);
    } else {
        noxtls_secure_zero(kp, sizeof(*kp));
    }

    noxtls_secure_zero(h, sizeof(h));
    noxtls_secure_zero(xh, sizeof(xh));
    return rc;
}

noxtls_return_t noxtls_ecjpake_zkp_verify(const uint8_t gen[NOXTLS_ECJPAKE_POINT_SIZE],
                                          const noxtls_ecjpake_key_kp_t *kp,
                                          const uint8_t *id, uint32_t id_len)
{
    uint8_t h[NOXTLS_ECJPAKE_SCALAR_SIZE];
    uint8_t gr[NOXTLS_ECJPAKE_POINT_SIZE];
    uint8_t xh[NOXTLS_ECJPAKE_POINT_SIZE];
    uint8_t v_check[NOXTLS_ECJPAKE_POINT_SIZE];
    noxtls_return_t x_rc;
    noxtls_return_t v_rc;
    uint32_t r_ok;
    noxtls_return_t rc;

    if ((gen == NULL) || (kp == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    /* RFC 8235 section 3.2: X must be a valid point and X x [cofactor] not the
     * identity (cofactor 1). V is checked the same way, and r must be a scalar. */
    x_rc = noxtls_ecjpake_point_validate(kp->X);
    v_rc = noxtls_ecjpake_point_validate(kp->V);
    r_ok = noxtls_ecjpake_scalar_is_below_order(kp->r);
    if ((x_rc != NOXTLS_RETURN_SUCCESS) || (v_rc != NOXTLS_RETURN_SUCCESS) || (r_ok == 0U)) {
        return NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER;
    }

    rc = noxtls_ecjpake_zkp_hash(gen, kp->V, kp->X, id, id_len, h);

    /* V' = gen x [r] + X x [h] must equal V. */
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_ecjpake_point_mul(kp->r, gen, gr);
    }

    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_ecjpake_point_mul(h, kp->X, xh);
    }

    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_ecjpake_point_add(gr, xh, 0U, v_check);
    }

    if ((rc == NOXTLS_RETURN_SUCCESS) &&
        (noxtls_ct_memcmp(v_check, kp->V, NOXTLS_ECJPAKE_POINT_SIZE) != 0)) {
        rc = NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER;
    }

    noxtls_secure_zero(h, sizeof(h));
    return rc;
}

noxtls_return_t noxtls_ecjpake_kp_write(const noxtls_ecjpake_key_kp_t *kp,
                                        uint8_t *out, uint32_t out_size, uint32_t *out_len)
{
    uint32_t skip = 0U;
    uint32_t r_len;
    uint32_t total;
    uint32_t offset = 0U;

    if ((kp == NULL) || (out == NULL) || (out_len == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    /* r is written big-endian without leading zero octets, at least one octet. */
    while ((skip < (NOXTLS_ECJPAKE_SCALAR_SIZE - NOXTLS_ECJPAKE_ZKP_R_MIN_SIZE)) && (kp->r[skip] == 0U)) {
        ++skip;
    }

    r_len = NOXTLS_ECJPAKE_SCALAR_SIZE - skip;
    total = (2U * (NOXTLS_ECJPAKE_TLS_LENGTH_OCTET_SIZE + NOXTLS_ECJPAKE_POINT_SIZE)) +
            NOXTLS_ECJPAKE_TLS_LENGTH_OCTET_SIZE + r_len;
    if (out_size < total) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    out[offset] = (uint8_t)NOXTLS_ECJPAKE_POINT_SIZE;
    offset += NOXTLS_ECJPAKE_TLS_LENGTH_OCTET_SIZE;
    noxtls_copy_u8(&out[offset], NOXTLS_ECJPAKE_POINT_SIZE, kp->X, NOXTLS_ECJPAKE_POINT_SIZE);
    offset += NOXTLS_ECJPAKE_POINT_SIZE;
    out[offset] = (uint8_t)NOXTLS_ECJPAKE_POINT_SIZE;
    offset += NOXTLS_ECJPAKE_TLS_LENGTH_OCTET_SIZE;
    noxtls_copy_u8(&out[offset], NOXTLS_ECJPAKE_POINT_SIZE, kp->V, NOXTLS_ECJPAKE_POINT_SIZE);
    offset += NOXTLS_ECJPAKE_POINT_SIZE;
    out[offset] = (uint8_t)r_len;
    offset += NOXTLS_ECJPAKE_TLS_LENGTH_OCTET_SIZE;
    noxtls_copy_u8(&out[offset], r_len, &kp->r[skip], r_len);
    *out_len = offset + r_len;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Read one ECPoint (opaque point<1..2^8-1>) that must be 65 octets long.
 * @internal
 *
 * @param[in] in Input.
 * @param[in] in_len Octets available.
 * @param[in,out] offset Read position.
 * @param[out] point 65-octet destination.
 *
 * @return NOXTLS_RETURN_SUCCESS or NOXTLS_RETURN_TLS_ALERT_DECODE_ERROR.
 */
static noxtls_return_t noxtls_ecjpake_read_point(const uint8_t *in, uint32_t in_len, uint32_t *offset,
                                                 uint8_t point[NOXTLS_ECJPAKE_POINT_SIZE])
{
    if ((in_len - *offset) < (NOXTLS_ECJPAKE_TLS_LENGTH_OCTET_SIZE + NOXTLS_ECJPAKE_POINT_SIZE)) {
        return NOXTLS_RETURN_TLS_ALERT_DECODE_ERROR;
    }

    if (in[*offset] != (uint8_t)NOXTLS_ECJPAKE_POINT_SIZE) {
        return NOXTLS_RETURN_TLS_ALERT_DECODE_ERROR;
    }

    *offset += NOXTLS_ECJPAKE_TLS_LENGTH_OCTET_SIZE;
    noxtls_copy_u8(point, NOXTLS_ECJPAKE_POINT_SIZE, &in[*offset], NOXTLS_ECJPAKE_POINT_SIZE);
    *offset += NOXTLS_ECJPAKE_POINT_SIZE;
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_ecjpake_kp_read(const uint8_t *in, uint32_t in_len,
                                       noxtls_ecjpake_key_kp_t *kp, uint32_t *used)
{
    uint32_t offset = 0U;
    noxtls_return_t rc;

    if ((in == NULL) || (kp == NULL) || (used == NULL)) {
        return NOXTLS_RETURN_NULL;
    }

    noxtls_secure_zero(kp, sizeof(*kp));
    rc = noxtls_ecjpake_read_point(in, in_len, &offset, kp->X);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_ecjpake_read_point(in, in_len, &offset, kp->V);
    }

    if (rc == NOXTLS_RETURN_SUCCESS) {
        if (offset >= in_len) {
            rc = NOXTLS_RETURN_TLS_ALERT_DECODE_ERROR;
        } else {
            uint32_t r_len = in[offset];

            offset += NOXTLS_ECJPAKE_TLS_LENGTH_OCTET_SIZE;

            /* r<1..2^8-1>, and as a scalar mod n it fits in 32 octets. */
            if ((r_len < NOXTLS_ECJPAKE_ZKP_R_MIN_SIZE) || (r_len > NOXTLS_ECJPAKE_ZKP_R_MAX_SIZE) ||
                (r_len > (in_len - offset))) {
                rc = NOXTLS_RETURN_TLS_ALERT_DECODE_ERROR;
            } else {
                noxtls_copy_u8(&kp->r[NOXTLS_ECJPAKE_SCALAR_SIZE - r_len], r_len, &in[offset], r_len);
                offset += r_len;
            }
        }
    }

    if (rc == NOXTLS_RETURN_SUCCESS) {
        *used = offset;
    } else {
        noxtls_secure_zero(kp, sizeof(*kp));
    }

    return rc;
}
