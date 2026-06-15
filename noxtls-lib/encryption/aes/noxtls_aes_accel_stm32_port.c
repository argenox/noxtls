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
#include "vendor/st/noxtls_hw_accel_autoconfig.h"
#include "vendor/st/noxtls_stm32_accel.h"

#if NOXTLS_FEATURE_AES_ACCEL_STM32
static int noxtls_aes_stm32_port_selftest_ok(void)
{
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
}
#endif

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
}
