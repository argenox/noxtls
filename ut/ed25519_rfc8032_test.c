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
* File:    ed25519_rfc8032_test.c
* Summary: RFC 8032 §7.1 Ed25519 vector 1 positive and negative tests
*
*
*****************************************************************************/

/**
 * @file ed25519_rfc8032_test.c
 * @brief Host unit test for Ed25519 using RFC 8032 §7.1 test vector 1.
 * @ingroup noxtls_ed25519
 */

#include <stdio.h>
#include <string.h>

#include "noxtls_common.h"
#include "pkc/ed25519/noxtls_ed25519.h"

/* RFC 8032 §7.1 TEST 1 — empty message. */
static const uint8_t tv1_sk[NOXTLS_ED25519_PRIVATE_KEY_SIZE] = {
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
    0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
    0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60
};

static const uint8_t tv1_pk[NOXTLS_ED25519_PUBLIC_KEY_SIZE] = {
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
    0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
    0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a
};

static const uint8_t tv1_sig[NOXTLS_ED25519_SIGNATURE_SIZE] = {
    0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72,
    0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a,
    0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74,
    0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55,
    0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac,
    0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b,
    0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
    0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b
};

/* RFC 8032 §7.1 TEST 2 — one-byte message 0x72. */
static const uint8_t tv2_sk[NOXTLS_ED25519_PRIVATE_KEY_SIZE] = {
    0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda,
    0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
    0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24,
    0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb
};

static const uint8_t tv2_pk[NOXTLS_ED25519_PUBLIC_KEY_SIZE] = {
    0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a,
    0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e, 0xbc,
    0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c,
    0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4, 0x66, 0x0c
};

static const uint8_t tv2_msg[1] = { 0x72 };

static const uint8_t tv2_sig[NOXTLS_ED25519_SIGNATURE_SIZE] = {
    0x92, 0xa0, 0x09, 0xa9, 0xf0, 0xd4, 0xca, 0xb8,
    0x72, 0x0e, 0x82, 0x0b, 0x5f, 0x64, 0x25, 0x40,
    0xa2, 0xb2, 0x7b, 0x54, 0x16, 0x50, 0x3f, 0x8f,
    0xb3, 0x76, 0x22, 0x23, 0xeb, 0xdb, 0x69, 0xda,
    0x08, 0x5a, 0xc1, 0xe4, 0x3e, 0x15, 0x99, 0x6e,
    0x45, 0x8f, 0x36, 0x13, 0xd0, 0xf1, 0x1d, 0x8c,
    0x38, 0x7b, 0x2e, 0xae, 0xb4, 0x30, 0x2a, 0xee,
    0xb0, 0x0d, 0x29, 0x16, 0x12, 0xbb, 0x0c, 0x00
};

/**
 * @brief Fail helper that prints a message.
 * @internal
 *
 * @param[in] cond Non-zero for pass.
 * @param[in] msg Failure description.
 *
 * @return 1 on pass, 0 on fail.
 */
static int expect(int cond, const char *msg)
{
    if(cond == 0) {
        fprintf(stderr, "FAIL: %s\n", msg);
        return 0;
    }
    return 1;
}

int main(void)
{
    uint8_t pk[NOXTLS_ED25519_PUBLIC_KEY_SIZE];
    uint8_t sig[NOXTLS_ED25519_SIGNATURE_SIZE];
    uint8_t bad_sig[NOXTLS_ED25519_SIGNATURE_SIZE];
    uint8_t msg_nonempty[1] = {0x00};
    noxtls_return_t rc;
    int ok = 1;

    /* Positive: public key from seed (RFC 8032 §5.1.5 / §7.1). */
    rc = noxtls_ed25519_public_key(tv1_sk, pk);
    ok &= expect(rc == NOXTLS_RETURN_SUCCESS, "public_key succeeds");
    ok &= expect(memcmp(pk, tv1_pk, sizeof(tv1_pk)) == 0, "public_key matches vector 1");

    /* Positive: sign empty message. */
    rc = noxtls_ed25519_sign(tv1_sk, NULL, 0U, sig);
    ok &= expect(rc == NOXTLS_RETURN_SUCCESS, "sign empty message succeeds");
    ok &= expect(memcmp(sig, tv1_sig, sizeof(tv1_sig)) == 0, "signature matches vector 1");

    /* Positive: verify known signature. */
    rc = noxtls_ed25519_verify(tv1_pk, NULL, 0U, tv1_sig);
    ok &= expect(rc == NOXTLS_RETURN_SUCCESS, "verify vector 1 succeeds");

    /* Positive: verify freshly signed signature. */
    rc = noxtls_ed25519_verify(pk, NULL, 0U, sig);
    ok &= expect(rc == NOXTLS_RETURN_SUCCESS, "verify produced signature succeeds");

    /* Negative: wrong message. */
    rc = noxtls_ed25519_verify(tv1_pk, msg_nonempty, 1U, tv1_sig);
    ok &= expect(rc != NOXTLS_RETURN_SUCCESS, "verify rejects wrong message");

    /* Negative: corrupted R (first byte of signature). */
    memcpy(bad_sig, tv1_sig, sizeof(bad_sig));
    bad_sig[0] = (uint8_t)(bad_sig[0] ^ 0x01U);
    rc = noxtls_ed25519_verify(tv1_pk, NULL, 0U, bad_sig);
    ok &= expect(rc != NOXTLS_RETURN_SUCCESS, "verify rejects bad R");

    /* Negative: corrupted S (last byte of signature). */
    memcpy(bad_sig, tv1_sig, sizeof(bad_sig));
    bad_sig[NOXTLS_ED25519_SIGNATURE_SIZE - 1U] =
        (uint8_t)(bad_sig[NOXTLS_ED25519_SIGNATURE_SIZE - 1U] ^ 0x01U);
    rc = noxtls_ed25519_verify(tv1_pk, NULL, 0U, bad_sig);
    ok &= expect(rc != NOXTLS_RETURN_SUCCESS, "verify rejects bad S");

    /* Negative: S >= L (set high bytes to make S large). */
    memcpy(bad_sig, tv1_sig, sizeof(bad_sig));
    memset(bad_sig + NOXTLS_ED25519_PUBLIC_KEY_SIZE, 0xFF, NOXTLS_ED25519_PUBLIC_KEY_SIZE);
    rc = noxtls_ed25519_verify(tv1_pk, NULL, 0U, bad_sig);
    ok &= expect(rc != NOXTLS_RETURN_SUCCESS, "verify rejects S >= L");

    /* Positive: RFC 8032 §7.1 TEST 2 (message 0x72). */
    rc = noxtls_ed25519_public_key(tv2_sk, pk);
    ok &= expect(rc == NOXTLS_RETURN_SUCCESS, "tv2 public_key succeeds");
    ok &= expect(memcmp(pk, tv2_pk, sizeof(tv2_pk)) == 0, "tv2 public_key matches");
    rc = noxtls_ed25519_sign(tv2_sk, tv2_msg, sizeof(tv2_msg), sig);
    ok &= expect(rc == NOXTLS_RETURN_SUCCESS, "tv2 sign succeeds");
    ok &= expect(memcmp(sig, tv2_sig, sizeof(tv2_sig)) == 0, "tv2 signature matches");
    rc = noxtls_ed25519_verify(tv2_pk, tv2_msg, sizeof(tv2_msg), tv2_sig);
    ok &= expect(rc == NOXTLS_RETURN_SUCCESS, "tv2 verify succeeds");

    /* Negative: NULL private key / signature buffers. */
    rc = noxtls_ed25519_sign(NULL, NULL, 0U, sig);
    ok &= expect(rc == NOXTLS_RETURN_NULL, "sign rejects NULL private key");
    rc = noxtls_ed25519_verify(NULL, NULL, 0U, tv1_sig);
    ok &= expect(rc == NOXTLS_RETURN_NULL, "verify rejects NULL public key");

    if(ok != 0) {
        printf("ed25519_rfc8032_test: PASS\n");
        return 0;
    }
    printf("ed25519_rfc8032_test: FAIL\n");
    return 1;
}
