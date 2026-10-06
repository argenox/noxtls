/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*****************************************************************************/

/**
 * @file noxtls_aes_keywrap.h
 * @brief AES Key Wrap / Unwrap (RFC 3394 §2.2, default IV A6A6A6A6A6A6A6A6).
 * @ingroup noxtls_aes
 *
 * Used by IEEE 802.11 EAPOL-Key Key Data encryption (802.11-2020
 * §12.7.2, AES key wrap with the KEK) and other key-transport protocols.
 */

#ifndef NOXTLS_AES_KEYWRAP_H
#define NOXTLS_AES_KEYWRAP_H

#include <stdint.h>

#include "noxtls_common.h"
#include "noxtls_aes.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Key wrap semiblock size (RFC 3394: 64-bit blocks). */
#define NOXTLS_AES_KW_SEMIBLOCK 8U

/**
 * @brief Wrap key data (RFC 3394 §2.2.1).
 *
 * @param [in] kek Key-encryption key (16, 24 or 32 octets per @p type).
 * @param [in] type AES key size of @p kek.
 * @param [in] plain Key data to wrap (multiple of 8 octets, >= 16).
 * @param [in] plain_len Length of @p plain.
 * @param [out] wrapped Output of plain_len + 8 octets.
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL, or
 *         NOXTLS_RETURN_INVALID_PARAM for an invalid length.
 */
noxtls_return_t noxtls_aes_key_wrap(const uint8_t *kek, noxtls_aes_type_t type,
                                    const uint8_t *plain, uint32_t plain_len,
                                    uint8_t *wrapped);

/**
 * @brief Unwrap key data and verify the integrity check value (RFC 3394 §2.2.2).
 *
 * @param [in] kek Key-encryption key (16, 24 or 32 octets per @p type).
 * @param [in] type AES key size of @p kek.
 * @param [in] wrapped Wrapped key data (multiple of 8 octets, >= 24).
 * @param [in] wrapped_len Length of @p wrapped.
 * @param [out] plain Output of wrapped_len - 8 octets (cleared on failure).
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL,
 *         NOXTLS_RETURN_INVALID_PARAM for an invalid length, or
 *         NOXTLS_RETURN_FAILED when the integrity check fails.
 */
noxtls_return_t noxtls_aes_key_unwrap(const uint8_t *kek, noxtls_aes_type_t type,
                                      const uint8_t *wrapped, uint32_t wrapped_len,
                                      uint8_t *plain);

/**
 * @brief Run RFC 3394 §4.1 known-answer test (128-bit KEK, 128-bit data).
 *
 * @return NOXTLS_RETURN_SUCCESS when wrap and unwrap match, else
 *         NOXTLS_RETURN_FAILED.
 */
noxtls_return_t noxtls_aes_keywrap_self_test(void);

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_AES_KEYWRAP_H */
