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
* File:    noxtls_speed_sym.c
* Summary: AES-ECB, AES-CCM and SHA-256 cases of the EFR32xG26 NoxTLS speed benchmark
*
*****************************************************************************/

/**
 * @file noxtls_speed_sym.c
 * @brief Software versus hardware timing of AES-128 ECB, AES-128 CCM and SHA-256.
 * @ingroup noxtls_speed
 *
 * Each case runs once untimed (warm-up and reference output), then in a timed
 * loop, first on the software backend and then on the hardware backend, and
 * the outputs are compared byte for byte.
 */

#include <stddef.h>
#include <string.h>

#include "encryption/aes/noxtls_aes.h"
#include "encryption/aes/noxtls_aes_ccm.h"
#include "mdigest/noxtls_sha.h"
#include "noxtls_efr32_accel.h"

#include "noxtls_speed_bench.h"
#include "noxtls_speed_config.h"
#include "noxtls_speed_timer.h"

/** @brief Multiplier of the test pattern generator. */
#define SPEED_PATTERN_MUL       7U
/** @brief Offset of the test pattern generator. */
#define SPEED_PATTERN_ADD       3U
/** @brief Offset of the key pattern. */
#define SPEED_KEY_ADD           0x40U
/** @brief Offset of the nonce pattern. */
#define SPEED_NONCE_ADD         0x90U
/** @brief Value the AAD bytes take. */
#define SPEED_AAD_BASE          0xA0U

/** @brief Plaintext. */
static uint8_t s_plain[NOXTLS_SPEED_BUF_MAX];
/** @brief Software-backend output. */
static uint8_t s_out_sw[NOXTLS_SPEED_BUF_MAX];
/** @brief Hardware-backend output. */
static uint8_t s_out_hw[NOXTLS_SPEED_BUF_MAX];
/** @brief Scratch for the decrypt-side checks. */
static uint8_t s_scratch[NOXTLS_SPEED_BUF_MAX];
/** @brief AES key. */
static uint8_t s_key[NOXTLS_SPEED_KEY_BYTES];
/** @brief CCM nonce. */
static uint8_t s_nonce[NOXTLS_SPEED_CCM_NONCE_BYTES];
/** @brief CCM associated data. */
static uint8_t s_aad[NOXTLS_SPEED_CCM_AAD_BYTES];
/** @brief Software-backend CCM tag. */
static uint8_t s_tag_sw[NOXTLS_SPEED_CCM_TAG_BYTES];
/** @brief Hardware-backend CCM tag. */
static uint8_t s_tag_hw[NOXTLS_SPEED_CCM_TAG_BYTES];
/** @brief Hash context. */
static noxtls_sha_ctx_t s_sha;

/**
 * @brief Fill the fixed inputs.
 * @internal
 */
static void speed_sym_fill(void)
{
    uint32_t i;

    for (i = 0U; i < NOXTLS_SPEED_BUF_MAX; i++) {
        s_plain[i] = (uint8_t)((i * SPEED_PATTERN_MUL) + SPEED_PATTERN_ADD);
    }
    for (i = 0U; i < NOXTLS_SPEED_KEY_BYTES; i++) {
        s_key[i] = (uint8_t)(i + SPEED_KEY_ADD);
    }
    for (i = 0U; i < NOXTLS_SPEED_CCM_NONCE_BYTES; i++) {
        s_nonce[i] = (uint8_t)(i + SPEED_NONCE_ADD);
    }
    for (i = 0U; i < NOXTLS_SPEED_CCM_AAD_BYTES; i++) {
        s_aad[i] = (uint8_t)(i + SPEED_AAD_BASE);
    }
}

/**
 * @brief One AES-128 ECB block operation.
 * @internal
 *
 * @param[in]  decrypt Non-zero to decrypt.
 * @param[in]  in      Input block.
 * @param[out] out     Output block.
 *
 * @return Library result.
 */
static noxtls_return_t speed_ecb_block(uint8_t decrypt, const uint8_t *in, uint8_t *out)
{
    return (decrypt != 0U) ?
        noxtls_aes_decrypt_ecb(s_key, in, NOXTLS_SPEED_AES_BLOCK_BYTES, NULL, out, NOXTLS_AES_128_BIT) :
        noxtls_aes_encrypt_ecb(s_key, in, NOXTLS_SPEED_AES_BLOCK_BYTES, NULL, out, NOXTLS_AES_128_BIT);
}

/**
 * @brief Time one ECB direction on both backends and compare the blocks.
 * @internal
 *
 * @param[in] name    Row name.
 * @param[in] decrypt Non-zero for decryption.
 */
static void speed_case_ecb(const char *name, uint8_t decrypt)
{
    noxtls_speed_row_t *row = noxtls_speed_row_begin(name, NOXTLS_SPEED_AES_BLOCK_BYTES, 1U);
    noxtls_return_t rc;
    uint8_t ok = 1U;
    uint32_t start;
    uint32_t activity;
    uint32_t i;

    noxtls_speed_backend_set(NOXTLS_SPEED_BACKEND_SW);
    rc = speed_ecb_block(decrypt, s_plain, s_out_sw);
    ok &= (rc == NOXTLS_RETURN_SUCCESS) ? 1U : 0U;
    start = noxtls_speed_timer_cycles();
    for (i = 0U; i < NOXTLS_SPEED_ITERS_AES_BLOCK; i++) {
        rc = speed_ecb_block(decrypt, s_plain, s_scratch);
        ok &= (rc == NOXTLS_RETURN_SUCCESS) ? 1U : 0U;
    }
    row->sw_cycles = noxtls_speed_avg(start, NOXTLS_SPEED_ITERS_AES_BLOCK);

    noxtls_speed_backend_set(NOXTLS_SPEED_BACKEND_HW);
    rc = speed_ecb_block(decrypt, s_plain, s_out_hw);
    ok &= (rc == NOXTLS_RETURN_SUCCESS) ? 1U : 0U;
    activity = noxtls_speed_hw_activity();
    start = noxtls_speed_timer_cycles();
    for (i = 0U; i < NOXTLS_SPEED_ITERS_AES_BLOCK; i++) {
        rc = speed_ecb_block(decrypt, s_plain, s_scratch);
        ok &= (rc == NOXTLS_RETURN_SUCCESS) ? 1U : 0U;
    }
    row->hw_cycles = noxtls_speed_avg(start, NOXTLS_SPEED_ITERS_AES_BLOCK);
    row->hw_used = (noxtls_speed_hw_activity() != activity) ? 1U : 0U;

    row->run_ok = ok;
    row->match = (memcmp(s_out_sw, s_out_hw, NOXTLS_SPEED_AES_BLOCK_BYTES) == 0) ? 1U : 0U;
    noxtls_speed_row_end(row);
}

/**
 * @brief CCM encryption of the fixed inputs.
 * @internal
 *
 * @param[in]  len Payload bytes.
 * @param[out] ct  Ciphertext.
 * @param[out] tag Tag.
 *
 * @return Library result.
 */
static noxtls_return_t speed_ccm_enc(uint32_t len, uint8_t *ct, uint8_t *tag)
{
    return noxtls_aes_ccm_encrypt(s_key, NOXTLS_AES_128_BIT, s_nonce, NOXTLS_SPEED_CCM_NONCE_BYTES, s_aad,
                                  NOXTLS_SPEED_CCM_AAD_BYTES, s_plain, len, ct, tag, NOXTLS_SPEED_CCM_TAG_BYTES);
}

/**
 * @brief CCM decryption.
 * @internal
 *
 * @param[in]  len Payload bytes.
 * @param[in]  ct  Ciphertext.
 * @param[in]  tag Tag.
 * @param[out] pt  Plaintext.
 *
 * @return Library result.
 */
static noxtls_return_t speed_ccm_dec(uint32_t len, const uint8_t *ct, const uint8_t *tag, uint8_t *pt)
{
    return noxtls_aes_ccm_decrypt(s_key, NOXTLS_AES_128_BIT, s_nonce, NOXTLS_SPEED_CCM_NONCE_BYTES, s_aad,
                                  NOXTLS_SPEED_CCM_AAD_BYTES, ct, len, tag, NOXTLS_SPEED_CCM_TAG_BYTES, pt);
}

/**
 * @brief Time CCM encryption on both backends and compare ciphertext and tag.
 * @internal
 *
 * @param[in] len Payload bytes.
 */
static void speed_case_ccm_enc(uint32_t len)
{
    noxtls_speed_row_t *row = noxtls_speed_row_begin("aes128_ccm_enc", len, 1U);
    uint8_t ok = 1U;
    uint32_t start;
    uint32_t activity;
    uint32_t i;

    noxtls_speed_backend_set(NOXTLS_SPEED_BACKEND_SW);
    ok &= (speed_ccm_enc(len, s_out_sw, s_tag_sw) == NOXTLS_RETURN_SUCCESS) ? 1U : 0U;
    start = noxtls_speed_timer_cycles();
    for (i = 0U; i < NOXTLS_SPEED_ITERS_CCM; i++) {
        ok &= (speed_ccm_enc(len, s_scratch, s_tag_hw) == NOXTLS_RETURN_SUCCESS) ? 1U : 0U;
    }
    row->sw_cycles = noxtls_speed_avg(start, NOXTLS_SPEED_ITERS_CCM);

    noxtls_speed_backend_set(NOXTLS_SPEED_BACKEND_HW);
    ok &= (speed_ccm_enc(len, s_out_hw, s_tag_hw) == NOXTLS_RETURN_SUCCESS) ? 1U : 0U;
    activity = noxtls_speed_hw_activity();
    start = noxtls_speed_timer_cycles();
    for (i = 0U; i < NOXTLS_SPEED_ITERS_CCM; i++) {
        ok &= (speed_ccm_enc(len, s_scratch, s_tag_hw) == NOXTLS_RETURN_SUCCESS) ? 1U : 0U;
    }
    row->hw_cycles = noxtls_speed_avg(start, NOXTLS_SPEED_ITERS_CCM);
    row->hw_used = (noxtls_speed_hw_activity() != activity) ? 1U : 0U;

    /* The timed loop overwrote the hardware tag with the same value; recompute it for a clean compare. */
    ok &= (speed_ccm_enc(len, s_out_hw, s_tag_hw) == NOXTLS_RETURN_SUCCESS) ? 1U : 0U;
    row->run_ok = ok;
    row->match = ((memcmp(s_out_sw, s_out_hw, len) == 0) && (memcmp(s_tag_sw, s_tag_hw, sizeof(s_tag_sw)) == 0)) ? 1U : 0U;
    noxtls_speed_row_end(row);
}

/**
 * @brief Time CCM decryption of the software-produced ciphertext on both backends.
 * @internal
 *
 * Each backend must return the plaintext, and must reject a ciphertext whose tag is
 * altered (NOXTLS_RETURN_BAD_DATA) without leaving plaintext behind.
 *
 * @param[in] len Payload bytes.
 */
static void speed_case_ccm_dec(uint32_t len)
{
    noxtls_speed_row_t *row = noxtls_speed_row_begin("aes128_ccm_dec", len, 1U);
    uint8_t bad_tag[NOXTLS_SPEED_CCM_TAG_BYTES];
    uint8_t ok = 1U;
    uint8_t match = 1U;
    uint32_t start;
    uint32_t activity;
    uint32_t i;

    /* Reference ciphertext and tag from the software backend. */
    noxtls_speed_backend_set(NOXTLS_SPEED_BACKEND_SW);
    ok &= (speed_ccm_enc(len, s_out_sw, s_tag_sw) == NOXTLS_RETURN_SUCCESS) ? 1U : 0U;
    (void)memcpy(bad_tag, s_tag_sw, sizeof(bad_tag));
    bad_tag[0] ^= 1U;

    ok &= (speed_ccm_dec(len, s_out_sw, s_tag_sw, s_out_hw) == NOXTLS_RETURN_SUCCESS) ? 1U : 0U;
    match &= (memcmp(s_out_hw, s_plain, len) == 0) ? 1U : 0U;
    match &= (speed_ccm_dec(len, s_out_sw, bad_tag, s_scratch) == NOXTLS_RETURN_BAD_DATA) ? 1U : 0U;
    start = noxtls_speed_timer_cycles();
    for (i = 0U; i < NOXTLS_SPEED_ITERS_CCM; i++) {
        ok &= (speed_ccm_dec(len, s_out_sw, s_tag_sw, s_scratch) == NOXTLS_RETURN_SUCCESS) ? 1U : 0U;
    }
    row->sw_cycles = noxtls_speed_avg(start, NOXTLS_SPEED_ITERS_CCM);

    noxtls_speed_backend_set(NOXTLS_SPEED_BACKEND_HW);
    (void)memset(s_out_hw, 0, len);
    ok &= (speed_ccm_dec(len, s_out_sw, s_tag_sw, s_out_hw) == NOXTLS_RETURN_SUCCESS) ? 1U : 0U;
    match &= (memcmp(s_out_hw, s_plain, len) == 0) ? 1U : 0U;
    match &= (speed_ccm_dec(len, s_out_sw, bad_tag, s_scratch) == NOXTLS_RETURN_BAD_DATA) ? 1U : 0U;
    activity = noxtls_speed_hw_activity();
    start = noxtls_speed_timer_cycles();
    for (i = 0U; i < NOXTLS_SPEED_ITERS_CCM; i++) {
        ok &= (speed_ccm_dec(len, s_out_sw, s_tag_sw, s_scratch) == NOXTLS_RETURN_SUCCESS) ? 1U : 0U;
    }
    row->hw_cycles = noxtls_speed_avg(start, NOXTLS_SPEED_ITERS_CCM);
    row->hw_used = (noxtls_speed_hw_activity() != activity) ? 1U : 0U;

    row->run_ok = ok;
    row->match = match;
    noxtls_speed_row_end(row);
}

/**
 * @brief SHA-256 of the first @p len bytes of the plaintext pattern.
 * @internal
 *
 * @param[in]  len    Message bytes.
 * @param[out] digest Digest.
 *
 * @return Library result.
 */
static noxtls_return_t speed_sha(uint32_t len, uint8_t *digest)
{
    noxtls_return_t rc = noxtls_sha_init(&s_sha, NOXTLS_HASH_SHA_256);

    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_sha_update(&s_sha, s_plain, len);
    }
    if (rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_sha_finish(&s_sha, digest);
    }
    return rc;
}

/**
 * @brief Time SHA-256 on both backends and compare the digests.
 * @internal
 *
 * @param[in] len Message bytes.
 */
static void speed_case_sha(uint32_t len)
{
    /* The SE hash port serves requests of at least NOXTLS_EFR32_CONFIG_SE_HASH_MIN_BLOCKS whole blocks. */
    const uint8_t expected = ((len / NOXTLS_SPEED_SHA_BLOCK_BYTES) >= (uint32_t)NOXTLS_EFR32_CONFIG_SE_HASH_MIN_BLOCKS) ? 1U : 0U;
    noxtls_speed_row_t *row = noxtls_speed_row_begin("sha256", len, expected);
    uint8_t digest_sw[NOXTLS_SPEED_SHA256_BYTES];
    uint8_t digest_hw[NOXTLS_SPEED_SHA256_BYTES];
    uint8_t ok = 1U;
    uint32_t start;
    uint32_t activity;
    uint32_t i;

    noxtls_speed_backend_set(NOXTLS_SPEED_BACKEND_SW);
    ok &= (speed_sha(len, digest_sw) == NOXTLS_RETURN_SUCCESS) ? 1U : 0U;
    start = noxtls_speed_timer_cycles();
    for (i = 0U; i < NOXTLS_SPEED_ITERS_SHA; i++) {
        ok &= (speed_sha(len, digest_hw) == NOXTLS_RETURN_SUCCESS) ? 1U : 0U;
    }
    row->sw_cycles = noxtls_speed_avg(start, NOXTLS_SPEED_ITERS_SHA);

    noxtls_speed_backend_set(NOXTLS_SPEED_BACKEND_HW);
    ok &= (speed_sha(len, digest_hw) == NOXTLS_RETURN_SUCCESS) ? 1U : 0U;
    activity = noxtls_speed_hw_activity();
    start = noxtls_speed_timer_cycles();
    for (i = 0U; i < NOXTLS_SPEED_ITERS_SHA; i++) {
        ok &= (speed_sha(len, s_scratch) == NOXTLS_RETURN_SUCCESS) ? 1U : 0U;
    }
    row->hw_cycles = noxtls_speed_avg(start, NOXTLS_SPEED_ITERS_SHA);
    row->hw_used = (noxtls_speed_hw_activity() != activity) ? 1U : 0U;

    row->run_ok = ok;
    row->match = (memcmp(digest_sw, digest_hw, sizeof(digest_sw)) == 0) ? 1U : 0U;
    noxtls_speed_row_end(row);
}

void noxtls_speed_run_sym(void)
{
    static const uint32_t k_ccm_sizes[NOXTLS_SPEED_CCM_SIZE_COUNT] = NOXTLS_SPEED_CCM_SIZES;
    static const uint32_t k_sha_sizes[NOXTLS_SPEED_SHA_SIZE_COUNT] = NOXTLS_SPEED_SHA_SIZES;
    uint32_t i;

    speed_sym_fill();
    speed_case_ecb("aes128_ecb_enc", 0U);
    speed_case_ecb("aes128_ecb_dec", 1U);
    for (i = 0U; i < NOXTLS_SPEED_CCM_SIZE_COUNT; i++) {
        speed_case_ccm_enc(k_ccm_sizes[i]);
    }
    for (i = 0U; i < NOXTLS_SPEED_CCM_SIZE_COUNT; i++) {
        speed_case_ccm_dec(k_ccm_sizes[i]);
    }
    for (i = 0U; i < NOXTLS_SPEED_SHA_SIZE_COUNT; i++) {
        speed_case_sha(k_sha_sizes[i]);
    }
}
