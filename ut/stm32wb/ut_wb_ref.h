/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    ut_wb_ref.h
* Summary: Independent AES / GHASH / big-number reference used by the STM32WB peripheral model
*****************************************************************************/

/**
 * @file ut_wb_ref.h
 * @brief Test-only reference primitives (FIPS 197 AES, GCM GF(2^128) product, big-endian modular arithmetic).
 * @ingroup noxtls_stm32wb_ut
 *
 * These are written independently of the NoxTLS sources so the peripheral model
 * does not share code (or bugs) with the code under test.
 */

#ifndef UT_WB_REF_H
#define UT_WB_REF_H

#include <stdint.h>

/** Expanded AES key. */
typedef struct {
    uint8_t rk[240];
    uint8_t rounds;
} ut_ref_aes_t;

/**
 * @brief Expand an AES key (FIPS 197 5.2).
 *
 * @param[out] ctx     Expanded key.
 * @param[in]  key     Key bytes.
 * @param[in]  key_len 16, 24 or 32.
 */
void ut_ref_aes_set_key(ut_ref_aes_t *ctx, const uint8_t *key, uint32_t key_len);

/**
 * @brief Encrypt one block.
 *
 * @param[in]  ctx Expanded key.
 * @param[in]  in  Plaintext block.
 * @param[out] out Ciphertext block (may equal @p in).
 */
void ut_ref_aes_enc(const ut_ref_aes_t *ctx, const uint8_t *in, uint8_t *out);

/**
 * @brief Decrypt one block.
 *
 * @param[in]  ctx Expanded key.
 * @param[in]  in  Ciphertext block.
 * @param[out] out Plaintext block (may equal @p in).
 */
void ut_ref_aes_dec(const ut_ref_aes_t *ctx, const uint8_t *in, uint8_t *out);

/**
 * @brief GCM field multiplication x = x * h in GF(2^128) (SP 800-38D 6.3).
 *
 * @param[in,out] x Block.
 * @param[in]     h Hash subkey.
 */
void ut_ref_gf_mul(uint8_t *x, const uint8_t *h);

/**
 * @brief out = (a * b) mod m for big-endian values of @p len bytes (a, b < m).
 *
 * @param[out] out Result.
 * @param[in]  a   First operand.
 * @param[in]  b   Second operand.
 * @param[in]  m   Modulus.
 * @param[in]  len Bytes.
 */
void ut_ref_mulmod(uint8_t *out, const uint8_t *a, const uint8_t *b, const uint8_t *m, uint32_t len);

/**
 * @brief out = base ^ exp mod m for big-endian values (base < m).
 *
 * @param[out] out     Result (@p len bytes).
 * @param[in]  base    Base (@p len bytes).
 * @param[in]  exp     Exponent.
 * @param[in]  exp_len Exponent bytes.
 * @param[in]  m       Modulus (@p len bytes).
 * @param[in]  len     Bytes.
 */
void ut_ref_modexp(uint8_t *out, const uint8_t *base, const uint8_t *exp, uint32_t exp_len, const uint8_t *m,
                   uint32_t len);

#endif /* UT_WB_REF_H */
