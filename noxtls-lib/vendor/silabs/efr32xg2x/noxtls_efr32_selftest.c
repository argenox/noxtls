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
* File:    noxtls_efr32_selftest.c
* Summary: Known-answer self-test of the EFR32xG2x hardware path
*
*****************************************************************************/

/**
 * @file noxtls_efr32_selftest.c
 * @brief Known-answer tests of the RADIOAES and Secure Engine drivers.
 * @ingroup noxtls_efr32
 */

#include <stddef.h>
#include <string.h>

#include "noxtls_efr32_selftest.h"

/** @brief A test could not run (unit unavailable). */
#define NOXTLS_EFR32_ST_SKIP            0U
/** @brief A test passed. */
#define NOXTLS_EFR32_ST_PASS            1U
/** @brief A test failed. */
#define NOXTLS_EFR32_ST_FAIL            2U
/** @brief AES block bytes. */
#define NOXTLS_EFR32_ST_BLK             16U
/** @brief Bytes of the CCM vector tag. */
#define NOXTLS_EFR32_ST_CCM_TAG         4U

/** FIPS 197 Appendix C plaintext. */
static const uint8_t s_pt[NOXTLS_EFR32_ST_BLK] = {
    0x00U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x66U, 0x77U, 0x88U, 0x99U, 0xAAU, 0xBBU, 0xCCU, 0xDDU, 0xEEU, 0xFFU };
/** FIPS 197 C.1 key (AES-128) and the first half of the C.3 key. */
static const uint8_t s_key256[32] = {
    0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U, 0x08U, 0x09U, 0x0AU, 0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU,
    0x10U, 0x11U, 0x12U, 0x13U, 0x14U, 0x15U, 0x16U, 0x17U, 0x18U, 0x19U, 0x1AU, 0x1BU, 0x1CU, 0x1DU, 0x1EU, 0x1FU };
/** FIPS 197 C.1 ciphertext. */
static const uint8_t s_ct128[NOXTLS_EFR32_ST_BLK] = {
    0x69U, 0xC4U, 0xE0U, 0xD8U, 0x6AU, 0x7BU, 0x04U, 0x30U, 0xD8U, 0xCDU, 0xB7U, 0x80U, 0x70U, 0xB4U, 0xC5U, 0x5AU };
/** FIPS 197 C.3 ciphertext. */
static const uint8_t s_ct256[NOXTLS_EFR32_ST_BLK] = {
    0x8EU, 0xA2U, 0xB7U, 0xCAU, 0x51U, 0x67U, 0x45U, 0xBFU, 0xEAU, 0xFCU, 0x49U, 0x90U, 0x4BU, 0x49U, 0x60U, 0x89U };
/** SP 800-38A key. */
static const uint8_t s_key_38a[NOXTLS_EFR32_ST_BLK] = {
    0x2BU, 0x7EU, 0x15U, 0x16U, 0x28U, 0xAEU, 0xD2U, 0xA6U, 0xABU, 0xF7U, 0x15U, 0x88U, 0x09U, 0xCFU, 0x4FU, 0x3CU };
/** SP 800-38A plaintext blocks 1 and 2. */
static const uint8_t s_pt_38a[2U * NOXTLS_EFR32_ST_BLK] = {
    0x6BU, 0xC1U, 0xBEU, 0xE2U, 0x2EU, 0x40U, 0x9FU, 0x96U, 0xE9U, 0x3DU, 0x7EU, 0x11U, 0x73U, 0x93U, 0x17U, 0x2AU,
    0xAEU, 0x2DU, 0x8AU, 0x57U, 0x1EU, 0x03U, 0xACU, 0x9CU, 0x9EU, 0xB7U, 0x6FU, 0xACU, 0x45U, 0xAFU, 0x8EU, 0x51U };
/** SP 800-38A F.2.1 IV. */
static const uint8_t s_iv_cbc[NOXTLS_EFR32_ST_BLK] = {
    0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U, 0x08U, 0x09U, 0x0AU, 0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU };
/** SP 800-38A F.2.1 ciphertext blocks 1 and 2. */
static const uint8_t s_ct_cbc[2U * NOXTLS_EFR32_ST_BLK] = {
    0x76U, 0x49U, 0xABU, 0xACU, 0x81U, 0x19U, 0xB2U, 0x46U, 0xCEU, 0xE9U, 0x8EU, 0x9BU, 0x12U, 0xE9U, 0x19U, 0x7DU,
    0x50U, 0x86U, 0xCBU, 0x9BU, 0x50U, 0x72U, 0x19U, 0xEEU, 0x95U, 0xDBU, 0x11U, 0x3AU, 0x91U, 0x76U, 0x78U, 0xB2U };
/** SP 800-38A F.5.1 initial counter block. */
static const uint8_t s_ctr0[NOXTLS_EFR32_ST_BLK] = {
    0xF0U, 0xF1U, 0xF2U, 0xF3U, 0xF4U, 0xF5U, 0xF6U, 0xF7U, 0xF8U, 0xF9U, 0xFAU, 0xFBU, 0xFCU, 0xFDU, 0xFEU, 0xFFU };
/** SP 800-38A F.5.1 ciphertext blocks 1 and 2. */
static const uint8_t s_ct_ctr[2U * NOXTLS_EFR32_ST_BLK] = {
    0x87U, 0x4DU, 0x61U, 0x91U, 0xB6U, 0x20U, 0xE3U, 0x26U, 0x1BU, 0xEFU, 0x68U, 0x64U, 0x99U, 0x0DU, 0xB6U, 0xCEU,
    0x98U, 0x06U, 0xF6U, 0x6BU, 0x79U, 0x70U, 0xFDU, 0xFFU, 0x86U, 0x17U, 0x18U, 0x7BU, 0xB9U, 0xFFU, 0xFDU, 0xFFU };
/** SP 800-38C C.1 key. */
static const uint8_t s_key_ccm[NOXTLS_EFR32_ST_BLK] = {
    0x40U, 0x41U, 0x42U, 0x43U, 0x44U, 0x45U, 0x46U, 0x47U, 0x48U, 0x49U, 0x4AU, 0x4BU, 0x4CU, 0x4DU, 0x4EU, 0x4FU };
/** SP 800-38C C.1 nonce. */
static const uint8_t s_nonce_ccm[7] = { 0x10U, 0x11U, 0x12U, 0x13U, 0x14U, 0x15U, 0x16U };
/** SP 800-38C C.1 associated data. */
static const uint8_t s_aad_ccm[8] = { 0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U };
/** SP 800-38C C.1 payload. */
static const uint8_t s_pt_ccm[4] = { 0x20U, 0x21U, 0x22U, 0x23U };
/** SP 800-38C C.1 ciphertext. */
static const uint8_t s_ct_ccm[4] = { 0x71U, 0x62U, 0x01U, 0x5BU };
/** SP 800-38C C.1 tag. */
static const uint8_t s_tag_ccm[NOXTLS_EFR32_ST_CCM_TAG] = { 0x4DU, 0xACU, 0x25U, 0x5DU };

/** SHA-256 initial value (FIPS 180-4 §5.3.3), byte order of the SE. */
static const uint8_t s_h256[NOXTLS_EFR32_SE_STATE_256] = {
    0x6AU, 0x09U, 0xE6U, 0x67U, 0xBBU, 0x67U, 0xAEU, 0x85U, 0x3CU, 0x6EU, 0xF3U, 0x72U, 0xA5U, 0x4FU, 0xF5U, 0x3AU,
    0x51U, 0x0EU, 0x52U, 0x7FU, 0x9BU, 0x05U, 0x68U, 0x8CU, 0x1FU, 0x83U, 0xD9U, 0xABU, 0x5BU, 0xE0U, 0xCDU, 0x19U };
/** SHA-256("abc") (FIPS 180-4 Appendix B.1). */
static const uint8_t s_d256[NOXTLS_EFR32_SE_STATE_256] = {
    0xBAU, 0x78U, 0x16U, 0xBFU, 0x8FU, 0x01U, 0xCFU, 0xEAU, 0x41U, 0x41U, 0x40U, 0xDEU, 0x5DU, 0xAEU, 0x22U, 0x23U,
    0xB0U, 0x03U, 0x61U, 0xA3U, 0x96U, 0x17U, 0x7AU, 0x9CU, 0xB4U, 0x10U, 0xFFU, 0x61U, 0xF2U, 0x00U, 0x15U, 0xADU };
/** SHA-512 initial value (FIPS 180-4 §5.3.5). */
static const uint8_t s_h512[NOXTLS_EFR32_SE_STATE_512] = {
    0x6AU, 0x09U, 0xE6U, 0x67U, 0xF3U, 0xBCU, 0xC9U, 0x08U, 0xBBU, 0x67U, 0xAEU, 0x85U, 0x84U, 0xCAU, 0xA7U, 0x3BU,
    0x3CU, 0x6EU, 0xF3U, 0x72U, 0xFEU, 0x94U, 0xF8U, 0x2BU, 0xA5U, 0x4FU, 0xF5U, 0x3AU, 0x5FU, 0x1DU, 0x36U, 0xF1U,
    0x51U, 0x0EU, 0x52U, 0x7FU, 0xADU, 0xE6U, 0x82U, 0xD1U, 0x9BU, 0x05U, 0x68U, 0x8CU, 0x2BU, 0x3EU, 0x6CU, 0x1FU,
    0x1FU, 0x83U, 0xD9U, 0xABU, 0xFBU, 0x41U, 0xBDU, 0x6BU, 0x5BU, 0xE0U, 0xCDU, 0x19U, 0x13U, 0x7EU, 0x21U, 0x79U };
/** SHA-512("abc") (FIPS 180-4 Appendix C.1). */
static const uint8_t s_d512[NOXTLS_EFR32_SE_STATE_512] = {
    0xDDU, 0xAFU, 0x35U, 0xA1U, 0x93U, 0x61U, 0x7AU, 0xBAU, 0xCCU, 0x41U, 0x73U, 0x49U, 0xAEU, 0x20U, 0x41U, 0x31U,
    0x12U, 0xE6U, 0xFAU, 0x4EU, 0x89U, 0xA9U, 0x7EU, 0xA2U, 0x0AU, 0x9EU, 0xEEU, 0xE6U, 0x4BU, 0x55U, 0xD3U, 0x9AU,
    0x21U, 0x92U, 0x99U, 0x2AU, 0x27U, 0x4FU, 0xC1U, 0xA8U, 0x36U, 0xBAU, 0x3CU, 0x23U, 0xA3U, 0xFEU, 0xEBU, 0xBDU,
    0x45U, 0x4DU, 0x44U, 0x23U, 0x64U, 0x3CU, 0xE8U, 0x0EU, 0x2AU, 0x9AU, 0xC9U, 0x4FU, 0xA5U, 0x4CU, 0xA4U, 0x9FU };

/** NIST P-256 generator x (SP 800-186 §3.2.1.3). */
static const uint8_t s_gx[32] = {
    0x6BU, 0x17U, 0xD1U, 0xF2U, 0xE1U, 0x2CU, 0x42U, 0x47U, 0xF8U, 0xBCU, 0xE6U, 0xE5U, 0x63U, 0xA4U, 0x40U, 0xF2U,
    0x77U, 0x03U, 0x7DU, 0x81U, 0x2DU, 0xEBU, 0x33U, 0xA0U, 0xF4U, 0xA1U, 0x39U, 0x45U, 0xD8U, 0x98U, 0xC2U, 0x96U };
/** NIST P-256 generator y. */
static const uint8_t s_gy[32] = {
    0x4FU, 0xE3U, 0x42U, 0xE2U, 0xFEU, 0x1AU, 0x7FU, 0x9BU, 0x8EU, 0xE7U, 0xEBU, 0x4AU, 0x7CU, 0x0FU, 0x9EU, 0x16U,
    0x2BU, 0xCEU, 0x33U, 0x57U, 0x6BU, 0x31U, 0x5EU, 0xCEU, 0xCBU, 0xB6U, 0x40U, 0x68U, 0x37U, 0xBFU, 0x51U, 0xF5U };
/** 2 * G, x. */
static const uint8_t s_g2x[32] = {
    0x7CU, 0xF2U, 0x7BU, 0x18U, 0x8DU, 0x03U, 0x4FU, 0x7EU, 0x8AU, 0x52U, 0x38U, 0x03U, 0x04U, 0xB5U, 0x1AU, 0xC3U,
    0xC0U, 0x89U, 0x69U, 0xE2U, 0x77U, 0xF2U, 0x1BU, 0x35U, 0xA6U, 0x0BU, 0x48U, 0xFCU, 0x47U, 0x66U, 0x99U, 0x78U };
/** 2 * G, y. */
static const uint8_t s_g2y[32] = {
    0x07U, 0x77U, 0x55U, 0x10U, 0xDBU, 0x8EU, 0xD0U, 0x40U, 0x29U, 0x3DU, 0x9AU, 0xC6U, 0x9FU, 0x74U, 0x30U, 0xDBU,
    0xBAU, 0x7DU, 0xADU, 0xE6U, 0x3CU, 0xE9U, 0x82U, 0x29U, 0x9EU, 0x04U, 0xB7U, 0x9DU, 0x22U, 0x78U, 0x73U, 0xD1U };
/** RFC 6979 A.2.5 private key. */
static const uint8_t s_d[32] = {
    0xC9U, 0xAFU, 0xA9U, 0xD8U, 0x45U, 0xBAU, 0x75U, 0x16U, 0x6BU, 0x5CU, 0x21U, 0x57U, 0x67U, 0xB1U, 0xD6U, 0x93U,
    0x4EU, 0x50U, 0xC3U, 0xDBU, 0x36U, 0xE8U, 0x9BU, 0x12U, 0x7BU, 0x8AU, 0x62U, 0x2BU, 0x12U, 0x0FU, 0x67U, 0x21U };
/** RFC 6979 A.2.5 public key x. */
static const uint8_t s_qx[32] = {
    0x60U, 0xFEU, 0xD4U, 0xBAU, 0x25U, 0x5AU, 0x9DU, 0x31U, 0xC9U, 0x61U, 0xEBU, 0x74U, 0xC6U, 0x35U, 0x6DU, 0x68U,
    0xC0U, 0x49U, 0xB8U, 0x92U, 0x3BU, 0x61U, 0xFAU, 0x6CU, 0xE6U, 0x69U, 0x62U, 0x2EU, 0x60U, 0xF2U, 0x9FU, 0xB6U };
/** RFC 6979 A.2.5 public key y. */
static const uint8_t s_qy[32] = {
    0x79U, 0x03U, 0xFEU, 0x10U, 0x08U, 0xB8U, 0xBCU, 0x99U, 0xA4U, 0x1AU, 0xE9U, 0xE9U, 0x56U, 0x28U, 0xBCU, 0x64U,
    0xF2U, 0xF1U, 0xB2U, 0x0CU, 0x2DU, 0x7EU, 0x9FU, 0x51U, 0x77U, 0xA3U, 0xC2U, 0x94U, 0xD4U, 0x46U, 0x22U, 0x99U };
/** SHA-256("sample"). */
static const uint8_t s_hash[32] = {
    0xAFU, 0x2BU, 0xDBU, 0xE1U, 0xAAU, 0x9BU, 0x6EU, 0xC1U, 0xE2U, 0xADU, 0xE1U, 0xD6U, 0x94U, 0xF4U, 0x1FU, 0xC7U,
    0x1AU, 0x83U, 0x1DU, 0x02U, 0x68U, 0xE9U, 0x89U, 0x15U, 0x62U, 0x11U, 0x3DU, 0x8AU, 0x62U, 0xADU, 0xD1U, 0xBFU };
/** RFC 6979 A.2.5 signature r (SHA-256, "sample"). */
static const uint8_t s_sr[32] = {
    0xEFU, 0xD4U, 0x8BU, 0x2AU, 0xACU, 0xB6U, 0xA8U, 0xFDU, 0x11U, 0x40U, 0xDDU, 0x9CU, 0xD4U, 0x5EU, 0x81U, 0xD6U,
    0x9DU, 0x2CU, 0x87U, 0x7BU, 0x56U, 0xAAU, 0xF9U, 0x91U, 0xC3U, 0x4DU, 0x0EU, 0xA8U, 0x4EU, 0xAFU, 0x37U, 0x16U };
/** RFC 6979 A.2.5 signature s. */
static const uint8_t s_ss[32] = {
    0xF7U, 0xCBU, 0x1CU, 0x94U, 0x2DU, 0x65U, 0x7CU, 0x41U, 0xD4U, 0x36U, 0xC7U, 0xA1U, 0xB6U, 0xE2U, 0x9FU, 0x65U,
    0xF3U, 0xE9U, 0x00U, 0xDBU, 0xB9U, 0xAFU, 0xF4U, 0x06U, 0x4DU, 0xC4U, 0xABU, 0x2FU, 0x84U, 0x3AU, 0xCDU, 0xA8U };

/**
 * @brief Classify a driver result against an expected match.
 * @internal
 *
 * @param[in] rc    Driver result.
 * @param[in] match Non-zero when the produced data equals the vector.
 *
 * @return NOXTLS_EFR32_ST_SKIP / PASS / FAIL.
 */
static uint8_t noxtls_efr32_st_judge(noxtls_return_t rc, uint8_t match)
{
    uint8_t out = NOXTLS_EFR32_ST_FAIL;

    if (rc == NOXTLS_RETURN_NOT_SUPPORTED) {
        out = NOXTLS_EFR32_ST_SKIP;
    } else if ((rc == NOXTLS_RETURN_SUCCESS) && (match != 0U)) {
        out = NOXTLS_EFR32_ST_PASS;
    } else {
        /* Failed or wrong answer. */
    }
    return out;
}

/**
 * @brief Byte-wise comparison to a flag.
 * @internal
 *
 * @param[in] a Data.
 * @param[in] b Expected.
 * @param[in] n Bytes.
 *
 * @return 1 when equal.
 */
static uint8_t noxtls_efr32_st_eq(const uint8_t *a, const uint8_t *b, uint32_t n)
{
    return (memcmp(a, b, n) == 0) ? 1U : 0U;
}

/**
 * @brief AES-128 ECB or AES-256 ECB known answer.
 * @internal
 *
 * @param[in] big Non-zero for AES-256.
 *
 * @return Test outcome.
 */
static uint8_t noxtls_efr32_st_ecb(uint8_t big)
{
    uint8_t out[NOXTLS_EFR32_ST_BLK];
    uint8_t back[NOXTLS_EFR32_ST_BLK];
    uint32_t klen = (big != 0U) ? 32U : 16U;
    noxtls_return_t rc = noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_ECB, 0U, s_key256, klen, NULL, s_pt, out, sizeof(out));
    uint8_t match = noxtls_efr32_st_eq(out, (big != 0U) ? s_ct256 : s_ct128, sizeof(out));

    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_efr32_aes_crypt(NOXTLS_EFR32_AES_ECB, 1U, s_key256, klen, NULL, out, back, sizeof(back));
        match = (uint8_t)(match & noxtls_efr32_st_eq(back, s_pt, sizeof(back)));
    }
    return noxtls_efr32_st_judge(rc, match);
}

/**
 * @brief CBC (two blocks, encrypt and decrypt) or CTR (two blocks) known answer.
 * @internal
 *
 * @param[in] ctr Non-zero for CTR.
 *
 * @return Test outcome.
 */
static uint8_t noxtls_efr32_st_chain(uint8_t ctr)
{
    uint8_t out[2U * NOXTLS_EFR32_ST_BLK];
    uint8_t back[2U * NOXTLS_EFR32_ST_BLK];
    uint8_t iv[NOXTLS_EFR32_ST_BLK];
    noxtls_efr32_aes_mode_t mode = (ctr != 0U) ? NOXTLS_EFR32_AES_CTR : NOXTLS_EFR32_AES_CBC;
    noxtls_return_t rc;
    uint8_t match;

    (void)memcpy(iv, (ctr != 0U) ? s_ctr0 : s_iv_cbc, sizeof(iv));
    rc = noxtls_efr32_aes_crypt(mode, 0U, s_key_38a, NOXTLS_EFR32_ST_BLK, iv, s_pt_38a, out, sizeof(out));
    match = noxtls_efr32_st_eq(out, (ctr != 0U) ? s_ct_ctr : s_ct_cbc, sizeof(out));
    if (rc == NOXTLS_RETURN_SUCCESS) {
        (void)memcpy(iv, (ctr != 0U) ? s_ctr0 : s_iv_cbc, sizeof(iv));
        rc = noxtls_efr32_aes_crypt(mode, 1U, s_key_38a, NOXTLS_EFR32_ST_BLK, iv, out, back, sizeof(back));
        match = (uint8_t)(match & noxtls_efr32_st_eq(back, s_pt_38a, sizeof(back)));
    }
    return noxtls_efr32_st_judge(rc, match);
}

/**
 * @brief CCM known answer, encrypt and decrypt.
 * @internal
 *
 * @return Test outcome.
 */
static uint8_t noxtls_efr32_st_ccm(void)
{
    uint8_t out[sizeof(s_pt_ccm)];
    uint8_t back[sizeof(s_pt_ccm)];
    uint8_t tag[NOXTLS_EFR32_ST_CCM_TAG];
    noxtls_return_t rc = noxtls_efr32_aes_ccm(0U, s_key_ccm, NOXTLS_EFR32_ST_BLK, s_nonce_ccm, sizeof(s_nonce_ccm), s_aad_ccm,
                                              sizeof(s_aad_ccm), s_pt_ccm, out, sizeof(out), tag, sizeof(tag));
    uint8_t match = (uint8_t)(noxtls_efr32_st_eq(out, s_ct_ccm, sizeof(out)) & noxtls_efr32_st_eq(tag, s_tag_ccm, sizeof(tag)));

    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_efr32_aes_ccm(1U, s_key_ccm, NOXTLS_EFR32_ST_BLK, s_nonce_ccm, sizeof(s_nonce_ccm), s_aad_ccm,
                                  sizeof(s_aad_ccm), out, back, sizeof(back), tag, sizeof(tag));
        match = (uint8_t)(match & noxtls_efr32_st_eq(back, s_pt_ccm, sizeof(back)));
    }
    return noxtls_efr32_st_judge(rc, match);
}

/**
 * @brief SHA-256 or SHA-512 compression of the padded one-block message "abc".
 * @internal
 *
 * @param[in] big Non-zero for SHA-512.
 *
 * @return Test outcome.
 */
static uint8_t noxtls_efr32_st_sha(uint8_t big)
{
    /* Static: the SE reads the block by DMA and the buffer must be SRAM. */
    static uint8_t block[NOXTLS_EFR32_SE_BLOCK_512];
    uint8_t state[NOXTLS_EFR32_SE_STATE_512];
    uint32_t blen = (big != 0U) ? NOXTLS_EFR32_SE_BLOCK_512 : NOXTLS_EFR32_SE_BLOCK_256;
    uint32_t slen = (big != 0U) ? NOXTLS_EFR32_SE_STATE_512 : NOXTLS_EFR32_SE_STATE_256;
    noxtls_return_t rc;
    uint8_t match;

    (void)memset(block, 0, sizeof(block));
    block[0] = 0x61U;
    block[1] = 0x62U;
    block[2] = 0x63U;
    block[3] = 0x80U;
    block[blen - 1U] = 0x18U;
    (void)memcpy(state, (big != 0U) ? s_h512 : s_h256, slen);
    rc = noxtls_efr32_se_hash_blocks((big != 0U) ? NOXTLS_EFR32_SE_HASH_SHA512 : NOXTLS_EFR32_SE_HASH_SHA256, state, block, 1U);
    match = noxtls_efr32_st_eq(state, (big != 0U) ? s_d512 : s_d256, slen);
    return noxtls_efr32_st_judge(rc, match);
}

/**
 * @brief TRNG: two draws that are not zero and differ.
 * @internal
 *
 * @return Test outcome.
 */
static uint8_t noxtls_efr32_st_trng(void)
{
    uint8_t a[32] = { 0U };
    uint8_t b[32] = { 0U };
    noxtls_return_t rc = noxtls_efr32_se_trng_fill(a, sizeof(a));
    uint8_t match;

    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_efr32_se_trng_fill(b, sizeof(b));
    }
    match = (uint8_t)((noxtls_efr32_is_zero(a, sizeof(a)) == 0U) && (noxtls_efr32_is_zero(b, sizeof(b)) == 0U) &&
                      (memcmp(a, b, sizeof(a)) != 0));
    return noxtls_efr32_st_judge(rc, match);
}

/**
 * @brief Point multiplication: 2 * G and 3 * (2 * G) == 2 * (3 * G) (the ECDH agreement).
 * @internal
 *
 * @return Test outcome.
 */
static uint8_t noxtls_efr32_st_mul(void)
{
    uint8_t two[32] = { 0U };
    uint8_t three[32] = { 0U };
    uint8_t ax[32] = { 0U };
    uint8_t ay[32] = { 0U };
    uint8_t bx[32] = { 0U };
    uint8_t by[32] = { 0U };
    uint8_t cx[32] = { 0U };
    uint8_t cy[32] = { 0U };
    noxtls_return_t rc;
    uint8_t match;

    two[31] = 2U;
    three[31] = 3U;
    rc = noxtls_efr32_se_ecc_mul(32U, two, s_gx, s_gy, ax, ay);
    match = (uint8_t)(noxtls_efr32_st_eq(ax, s_g2x, 32U) & noxtls_efr32_st_eq(ay, s_g2y, 32U));
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_efr32_se_ecc_mul(32U, three, ax, ay, bx, by);
    }
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_efr32_se_ecc_mul(32U, three, s_gx, s_gy, cx, cy);
    }
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_efr32_se_ecc_mul(32U, two, cx, cy, cx, cy);
    }
    match = (uint8_t)(match & noxtls_efr32_st_eq(bx, cx, 32U) & noxtls_efr32_st_eq(by, cy, 32U));
    return noxtls_efr32_st_judge(rc, match);
}

/**
 * @brief ECDSA verify: the RFC 6979 signature is accepted, a modified one is rejected.
 * @internal
 *
 * @return Test outcome.
 */
static uint8_t noxtls_efr32_st_verify(void)
{
    uint8_t bad[32];
    noxtls_return_t rc = noxtls_efr32_se_ecdsa_verify(32U, s_qx, s_qy, s_hash, s_sr, s_ss);
    uint8_t match = 1U;

    if (rc == NOXTLS_RETURN_SUCCESS) {
        (void)memcpy(bad, s_ss, sizeof(bad));
        bad[31] ^= 1U;
        match = (noxtls_efr32_se_ecdsa_verify(32U, s_qx, s_qy, s_hash, s_sr, bad) == NOXTLS_RETURN_BAD_DATA) ? 1U : 0U;
    }
    return noxtls_efr32_st_judge(rc, match);
}

/**
 * @brief ECDSA sign: the signature verifies under the public key.
 * @internal
 *
 * @return Test outcome.
 */
static uint8_t noxtls_efr32_st_sign(void)
{
    uint8_t r[32];
    uint8_t s[32];
    noxtls_return_t rc = noxtls_efr32_se_ecdsa_sign(32U, s_d, s_hash, r, s);
    uint8_t match = 1U;

    if (rc == NOXTLS_RETURN_SUCCESS) {
        match = (noxtls_efr32_se_ecdsa_verify(32U, s_qx, s_qy, s_hash, r, s) == NOXTLS_RETURN_SUCCESS) ? 1U : 0U;
    }
    return noxtls_efr32_st_judge(rc, match);
}

/**
 * @brief Record one outcome.
 * @internal
 *
 * @param[in,out] res     Result masks.
 * @param[in]     bit     Test bit.
 * @param[in]     outcome NOXTLS_EFR32_ST_SKIP / PASS / FAIL.
 */
static void noxtls_efr32_st_record(noxtls_efr32_selftest_t *res, uint32_t bit, uint8_t outcome)
{
    if (outcome == NOXTLS_EFR32_ST_SKIP) {
        res->skipped |= bit;
    } else {
        res->ran |= bit;
        if (outcome == NOXTLS_EFR32_ST_PASS) {
            res->passed |= bit;
        }
    }
}

noxtls_return_t noxtls_efr32_selftest(noxtls_efr32_selftest_t *result, uint8_t disable_failed)
{
    noxtls_return_t rc = NOXTLS_RETURN_NULL;

    if (result != NULL) {
        uint32_t failed;
        uint32_t aes_off = 0U;
        uint32_t ops_off = 0U;

        result->ran = 0U;
        result->passed = 0U;
        result->skipped = 0U;
        noxtls_efr32_st_record(result, NOXTLS_EFR32_ST_AES128_ECB, noxtls_efr32_st_ecb(0U));
        noxtls_efr32_st_record(result, NOXTLS_EFR32_ST_AES256_ECB, noxtls_efr32_st_ecb(1U));
        noxtls_efr32_st_record(result, NOXTLS_EFR32_ST_AES_CBC, noxtls_efr32_st_chain(0U));
        noxtls_efr32_st_record(result, NOXTLS_EFR32_ST_AES_CTR, noxtls_efr32_st_chain(1U));
        noxtls_efr32_st_record(result, NOXTLS_EFR32_ST_AES_CCM, noxtls_efr32_st_ccm());
        noxtls_efr32_st_record(result, NOXTLS_EFR32_ST_SHA256, noxtls_efr32_st_sha(0U));
        noxtls_efr32_st_record(result, NOXTLS_EFR32_ST_SHA512, noxtls_efr32_st_sha(1U));
        noxtls_efr32_st_record(result, NOXTLS_EFR32_ST_TRNG, noxtls_efr32_st_trng());
        noxtls_efr32_st_record(result, NOXTLS_EFR32_ST_ECC_MUL, noxtls_efr32_st_mul());
        noxtls_efr32_st_record(result, NOXTLS_EFR32_ST_ECDSA_VERIFY, noxtls_efr32_st_verify());
        noxtls_efr32_st_record(result, NOXTLS_EFR32_ST_ECDSA_SIGN, noxtls_efr32_st_sign());
        failed = result->ran & ~result->passed;
        rc = (failed == 0U) ? NOXTLS_RETURN_SUCCESS : NOXTLS_RETURN_FAILED;
        if ((disable_failed != 0U) && (failed != 0U)) {
            if ((failed & (NOXTLS_EFR32_ST_AES128_ECB | NOXTLS_EFR32_ST_AES256_ECB)) != 0U) {
                aes_off |= UINT32_C(1) << NOXTLS_EFR32_AES_MODE_ECB;
            }
            if ((failed & NOXTLS_EFR32_ST_AES_CBC) != 0U) {
                aes_off |= UINT32_C(1) << NOXTLS_EFR32_AES_MODE_CBC;
            }
            if ((failed & NOXTLS_EFR32_ST_AES_CTR) != 0U) {
                aes_off |= UINT32_C(1) << NOXTLS_EFR32_AES_MODE_CTR;
            }
            if ((failed & NOXTLS_EFR32_ST_AES_CCM) != 0U) {
                aes_off |= UINT32_C(1) << NOXTLS_EFR32_AES_MODE_CCM;
            }
            ops_off |= ((failed & NOXTLS_EFR32_ST_SHA256) != 0U) ? NOXTLS_EFR32_OP_SHA256 : 0U;
            ops_off |= ((failed & NOXTLS_EFR32_ST_SHA512) != 0U) ? NOXTLS_EFR32_OP_SHA512 : 0U;
            ops_off |= ((failed & NOXTLS_EFR32_ST_TRNG) != 0U) ? NOXTLS_EFR32_OP_TRNG : 0U;
            ops_off |= ((failed & NOXTLS_EFR32_ST_ECC_MUL) != 0U) ? NOXTLS_EFR32_OP_ECC_MUL : 0U;
            ops_off |= ((failed & NOXTLS_EFR32_ST_ECDSA_VERIFY) != 0U) ? NOXTLS_EFR32_OP_ECDSA_VERIFY : 0U;
            ops_off |= ((failed & NOXTLS_EFR32_ST_ECDSA_SIGN) != 0U) ? NOXTLS_EFR32_OP_ECDSA_SIGN : 0U;
            noxtls_efr32_aes_set_modes_disabled(aes_off);
            noxtls_efr32_set_ops_disabled(ops_off);
        }
    }
    return rc;
}
