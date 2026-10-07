/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_aes_accel_stm32_port.c
* Summary: STM32 AES acceleration port hook.
*****************************************************************************/

#include <stddef.h>
#include <stdint.h>

#include "noxtls_aes_accel.h"
#include "vendor/st/common/noxtls_stm32_gcm_core.h"
#include "vendor/st/common/noxtls_stm32_u5_aes_core.h"
#include "vendor/st/noxtls_hw_accel_autoconfig.h"
#include "vendor/st/noxtls_stm32_accel.h"
#include "vendor/st/noxtls_target_detect.h"

#if NOXTLS_FEATURE_AES_ACCEL_STM32
static int noxtls_aes_stm32_port_selftest_ok(void)
{
#if !defined(NOXTLS_STM32_HAS_AES_PERIPH)
    return 0;
#else
    static int selftest_state;
    static const uint8_t expected[16] = {
        0xdcU, 0x95U, 0xc0U, 0x78U, 0xa2U, 0x40U, 0x89U, 0x89U,
        0xadU, 0x48U, 0xa2U, 0x14U, 0x92U, 0x84U, 0x20U, 0x87U
    };
    uint8_t key[32] = {0};
    uint8_t block[16] = {0};
    uint8_t out[16] = {0};
    uint32_t i;
    uint8_t diff = 0U;

    if(selftest_state != 0) {
        return selftest_state > 0;
    }

    if(noxtls_aes_accel_stm32_encrypt_block(key, block, out, NOXTLS_AES_256_BIT) != NOXTLS_RETURN_SUCCESS) {
        selftest_state = -1;
        return 0;
    }

    for(i = 0U; i < (size_t)sizeof(expected); i += 1U) {
        diff |= (uint8_t)(out[i] ^ expected[i]);
    }
    selftest_state = (diff == 0U) ? 1 : -1;
    return selftest_state > 0;
#endif
}
#endif

static noxtls_return_t noxtls_stm32_gcm_accel_encrypt_dispatch(const uint8_t *key,
                                                                noxtls_aes_type_t type,
                                                                const uint8_t nonce[12],
                                                                const uint8_t *aad,
                                                                uint32_t aad_len,
                                                                const uint8_t *plaintext,
                                                                uint32_t plaintext_len,
                                                                uint8_t *ciphertext,
                                                                uint8_t tag[16])
{
#if NOXTLS_FEATURE_AES_ACCEL_STM32 && defined(NOXTLS_STM32_FAMILY_H7)
    return noxtls_stm32_gcm_encrypt(NOXTLS_STM32_ACCEL_H7, key, type, nonce, aad, aad_len,
                                    plaintext, plaintext_len, ciphertext, tag);
#elif NOXTLS_FEATURE_AES_ACCEL_STM32 && defined(NOXTLS_STM32_F4_HAS_CRYP)
    return noxtls_stm32_gcm_encrypt(NOXTLS_STM32_ACCEL_F4, key, type, nonce, aad, aad_len,
                                    plaintext, plaintext_len, ciphertext, tag);
#elif NOXTLS_FEATURE_AES_ACCEL_STM32 && defined(NOXTLS_STM32_F7_HAS_CRYP)
    return noxtls_stm32_gcm_encrypt(NOXTLS_STM32_ACCEL_F7, key, type, nonce, aad, aad_len,
                                    plaintext, plaintext_len, ciphertext, tag);
#elif NOXTLS_FEATURE_AES_ACCEL_STM32 && defined(NOXTLS_STM32_F2_HAS_CRYP)
    return noxtls_stm32_gcm_encrypt(NOXTLS_STM32_ACCEL_F2, key, type, nonce, aad, aad_len,
                                    plaintext, plaintext_len, ciphertext, tag);
#elif NOXTLS_FEATURE_AES_ACCEL_STM32 && defined(NOXTLS_STM32_U5_HAS_AES)
    return noxtls_stm32_u5_gcm_encrypt(key, type, nonce, aad, aad_len,
                                       plaintext, plaintext_len, ciphertext, tag);
#else
    (void)key;
    (void)type;
    (void)nonce;
    (void)aad;
    (void)aad_len;
    (void)plaintext;
    (void)plaintext_len;
    (void)ciphertext;
    (void)tag;
    return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
}

static noxtls_return_t noxtls_stm32_gcm_accel_decrypt_dispatch(const uint8_t *key,
                                                                noxtls_aes_type_t type,
                                                                const uint8_t nonce[12],
                                                                const uint8_t *aad,
                                                                uint32_t aad_len,
                                                                const uint8_t *ciphertext,
                                                                uint32_t ciphertext_len,
                                                                const uint8_t tag[16],
                                                                uint8_t *plaintext)
{
#if NOXTLS_FEATURE_AES_ACCEL_STM32 && defined(NOXTLS_STM32_FAMILY_H7)
    return noxtls_stm32_gcm_decrypt(NOXTLS_STM32_ACCEL_H7, key, type, nonce, aad, aad_len,
                                    ciphertext, ciphertext_len, tag, plaintext);
#elif NOXTLS_FEATURE_AES_ACCEL_STM32 && defined(NOXTLS_STM32_F4_HAS_CRYP)
    return noxtls_stm32_gcm_decrypt(NOXTLS_STM32_ACCEL_F4, key, type, nonce, aad, aad_len,
                                    ciphertext, ciphertext_len, tag, plaintext);
#elif NOXTLS_FEATURE_AES_ACCEL_STM32 && defined(NOXTLS_STM32_F7_HAS_CRYP)
    return noxtls_stm32_gcm_decrypt(NOXTLS_STM32_ACCEL_F7, key, type, nonce, aad, aad_len,
                                    ciphertext, ciphertext_len, tag, plaintext);
#elif NOXTLS_FEATURE_AES_ACCEL_STM32 && defined(NOXTLS_STM32_F2_HAS_CRYP)
    return noxtls_stm32_gcm_decrypt(NOXTLS_STM32_ACCEL_F2, key, type, nonce, aad, aad_len,
                                    ciphertext, ciphertext_len, tag, plaintext);
#elif NOXTLS_FEATURE_AES_ACCEL_STM32 && defined(NOXTLS_STM32_U5_HAS_AES)
    return noxtls_stm32_u5_gcm_decrypt(key, type, nonce, aad, aad_len,
                                       ciphertext, ciphertext_len, tag, plaintext);
#else
    (void)key;
    (void)type;
    (void)nonce;
    (void)aad;
    (void)aad_len;
    (void)ciphertext;
    (void)ciphertext_len;
    (void)tag;
    (void)plaintext;
    return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
}

static int noxtls_stm32_gcm_port_selftest_ok(void)
{
    static int selftest_state;
    static const uint8_t expected_ct[16] = {
        0xceU, 0xa7U, 0x40U, 0x3dU, 0x4dU, 0x60U, 0x6bU, 0x6eU,
        0x07U, 0x4eU, 0xc5U, 0xd3U, 0xbaU, 0xf3U, 0x9dU, 0x18U
    };
    static const uint8_t expected_tag[16] = {
        0xd0U, 0xd1U, 0xc8U, 0xa7U, 0x99U, 0x99U, 0x6bU, 0xf0U,
        0x26U, 0x5bU, 0x98U, 0xb5U, 0xd4U, 0x8aU, 0xb9U, 0x19U
    };
    uint8_t key[32] = {0};
    uint8_t nonce[12] = {0};
    uint8_t pt[16] = {0};
    uint8_t ct[16] = {0};
    uint8_t tag[16] = {0};
    uint8_t diff = 0U;
    uint32_t i;
    noxtls_return_t rc;

    if(selftest_state != 0) {
        return selftest_state > 0;
    }

    rc = noxtls_stm32_gcm_accel_encrypt_dispatch(key, NOXTLS_AES_256_BIT, nonce, NULL, 0U,
                                                 pt, sizeof(pt), ct, tag);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        selftest_state = -1;
        return 0;
    }

    for(i = 0U; i < (size_t)sizeof(ct); i += 1U) {
        diff |= (uint8_t)(ct[i] ^ expected_ct[i]);
        diff |= (uint8_t)(tag[i] ^ expected_tag[i]);
    }
    selftest_state = (diff == 0U) ? 1 : -1;
    return selftest_state > 0;
}

int noxtls_aes_gcm_accel_port_is_enabled(void) { return noxtls_stm32_gcm_port_selftest_ok(); }

noxtls_return_t noxtls_aes_accel_port_encrypt_block(const uint8_t *key,
                                                     const uint8_t *data,
                                                     uint8_t *output,
                                                     noxtls_aes_type_t type)
{
#if NOXTLS_FEATURE_AES_ACCEL_STM32
    if(noxtls_aes_stm32_port_selftest_ok() == 0) {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }
    return noxtls_aes_accel_stm32_encrypt_block(key, data, output, type);
#else
    (void)key;
    (void)data;
    (void)output;
    (void)type;
    return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
}

noxtls_return_t noxtls_aes_accel_port_decrypt_block(const uint8_t *key,
                                                     const uint8_t *data,
                                                     uint8_t *output,
                                                     noxtls_aes_type_t type)
{
#if NOXTLS_FEATURE_AES_ACCEL_STM32
    if(noxtls_aes_stm32_port_selftest_ok() == 0) {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }
    return noxtls_aes_accel_stm32_decrypt_block(key, data, output, type);
#else
    (void)key;
    (void)data;
    (void)output;
    (void)type;
    return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
}

noxtls_return_t noxtls_aes_accel_port_encrypt_blocks(const uint8_t *key,
                                                      const uint8_t *input,
                                                      uint8_t *output,
                                                      uint32_t block_count,
                                                      noxtls_aes_type_t type)
{
    uint32_t i;

    if(key == NULL || input == NULL || output == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    for(i = 0U; i < block_count; i += 1U) {
        noxtls_return_t rc = noxtls_aes_accel_port_encrypt_block(key,
                                                                  &input[(i * 16U)],
                                                                  &output[(i * 16U)],
                                                                  type);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
    }
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_aes_gcm_encrypt_accel_port(const uint8_t *key,
                                                   noxtls_aes_type_t type,
                                                   const uint8_t nonce[12],
                                                   const uint8_t *aad,
                                                   uint32_t aad_len,
                                                   const uint8_t *plaintext,
                                                   uint32_t plaintext_len,
                                                   uint8_t *ciphertext,
                                                   uint8_t tag[16])
{
    if(noxtls_stm32_gcm_port_selftest_ok() == 0) {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }
    return noxtls_stm32_gcm_accel_encrypt_dispatch(key, type, nonce, aad, aad_len,
                                                   plaintext, plaintext_len, ciphertext, tag);
}

noxtls_return_t noxtls_aes_gcm_decrypt_accel_port(const uint8_t *key,
                                                   noxtls_aes_type_t type,
                                                   const uint8_t nonce[12],
                                                   const uint8_t *aad,
                                                   uint32_t aad_len,
                                                   const uint8_t *ciphertext,
                                                   uint32_t ciphertext_len,
                                                   const uint8_t tag[16],
                                                   uint8_t *plaintext)
{
    if(noxtls_stm32_gcm_port_selftest_ok() == 0) {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }
    return noxtls_stm32_gcm_accel_decrypt_dispatch(key, type, nonce, aad, aad_len,
                                                   ciphertext, ciphertext_len, tag, plaintext);
}
