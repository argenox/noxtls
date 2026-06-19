/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_aes_accel_stm32_port.c
* Summary: STM32 AES acceleration port hook.
*****************************************************************************/

#include <stdint.h>

#include "noxtls_aes_accel.h"
#include "vendor/st/common/noxtls_stm32_gcm_core.h"
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
        0xdc, 0x95, 0xc0, 0x78, 0xa2, 0x40, 0x89, 0x89,
        0xad, 0x48, 0xa2, 0x14, 0x92, 0x84, 0x20, 0x87
    };
    uint8_t key[32] = {0};
    uint8_t block[16] = {0};
    uint8_t out[16] = {0};
    uint32_t i;
    uint8_t diff = 0u;

    if(selftest_state != 0) {
        return selftest_state > 0;
    }

    if(noxtls_aes_accel_stm32_encrypt_block(key, block, out, NOXTLS_AES_256_BIT) != NOXTLS_RETURN_SUCCESS) {
        selftest_state = -1;
        return 0;
    }

    for(i = 0u; i < sizeof(expected); i++) {
        diff |= (uint8_t)(out[i] ^ expected[i]);
    }
    selftest_state = (diff == 0u) ? 1 : -1;
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
        0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e,
        0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d, 0x18
    };
    static const uint8_t expected_tag[16] = {
        0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0,
        0x26, 0x5b, 0x98, 0xb5, 0xd4, 0x8a, 0xb9, 0x19
    };
    uint8_t key[32] = {0};
    uint8_t nonce[12] = {0};
    uint8_t pt[16] = {0};
    uint8_t ct[16] = {0};
    uint8_t tag[16] = {0};
    uint8_t diff = 0u;
    uint32_t i;
    noxtls_return_t rc;

    if(selftest_state != 0) {
        return selftest_state > 0;
    }

    rc = noxtls_stm32_gcm_accel_encrypt_dispatch(key, NOXTLS_AES_256_BIT, nonce, NULL, 0u,
                                                 pt, sizeof(pt), ct, tag);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        selftest_state = -1;
        return 0;
    }

    for(i = 0u; i < sizeof(ct); i++) {
        diff |= (uint8_t)(ct[i] ^ expected_ct[i]);
        diff |= (uint8_t)(tag[i] ^ expected_tag[i]);
    }
    selftest_state = (diff == 0u) ? 1 : -1;
    return selftest_state > 0;
}

int noxtls_aes_gcm_accel_port_is_enabled(void)
{
    return noxtls_stm32_gcm_port_selftest_ok();
}

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

    for(i = 0U; i < block_count; i++) {
        noxtls_return_t rc = noxtls_aes_accel_port_encrypt_block(key,
                                                                  input + (i * 16U),
                                                                  output + (i * 16U),
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
