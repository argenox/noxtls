/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_aes_accel_nrf52_port.c
* Summary: nRF52 ECB peripheral AES acceleration hook.
*****************************************************************************/

#include <stdint.h>
#include <string.h>

#include "../../../noxtls_common.h"
#include "noxtls_aes.h"

#ifndef NOXTLS_FEATURE_NRF52_HW_ACCEL
#define NOXTLS_FEATURE_NRF52_HW_ACCEL 0
#endif

#define NOXTLS_NRF52_ECB_BASE_ADDR        ((uintptr_t)0x4000E000u)
#define NOXTLS_NRF52_TASKS_STARTECB_OFF   (0x000UL)
#define NOXTLS_NRF52_TASKS_STOPECB_OFF    (0x004UL)
#define NOXTLS_NRF52_EVENTS_ENDECB_OFF    (0x100UL)
#define NOXTLS_NRF52_EVENTS_ERRORECB_OFF  (0x104UL)
#define NOXTLS_NRF52_ECBDATAPTR_OFF       (0x504UL)
#define NOXTLS_NRF52_ECB_TIMEOUT_SPINS    (2000000UL)

typedef struct
{
    uint8_t key[16];
    uint8_t cleartext[16];
    uint8_t ciphertext[16];
} noxtls_nrf52_ecb_data_t;

static volatile uint32_t *noxtls_nrf52_reg(uint32_t offset)
{
    return (volatile uint32_t *)(NOXTLS_NRF52_ECB_BASE_ADDR + (uintptr_t)offset);
}

static noxtls_return_t noxtls_nrf52_ecb_encrypt_128(const uint8_t *key,
                                                     const uint8_t *data,
                                                     uint8_t *output)
{
    noxtls_nrf52_ecb_data_t ecb_data;
    volatile uint32_t *task_start = noxtls_nrf52_reg(NOXTLS_NRF52_TASKS_STARTECB_OFF);
    volatile uint32_t *task_stop = noxtls_nrf52_reg(NOXTLS_NRF52_TASKS_STOPECB_OFF);
    volatile uint32_t *event_end = noxtls_nrf52_reg(NOXTLS_NRF52_EVENTS_ENDECB_OFF);
    volatile uint32_t *event_error = noxtls_nrf52_reg(NOXTLS_NRF52_EVENTS_ERRORECB_OFF);
    volatile uint32_t *ecb_ptr = noxtls_nrf52_reg(NOXTLS_NRF52_ECBDATAPTR_OFF);
    uint32_t spins;

    if(key == NULL || data == NULL || output == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    memcpy(ecb_data.key, key, sizeof(ecb_data.key));
    memcpy(ecb_data.cleartext, data, sizeof(ecb_data.cleartext));
    memset(ecb_data.ciphertext, 0, sizeof(ecb_data.ciphertext));

    *event_end = 0U;
    *event_error = 0U;
    *ecb_ptr = (uint32_t)(uintptr_t)&ecb_data;
    *task_start = 1U;

    for(spins = 0U; spins < NOXTLS_NRF52_ECB_TIMEOUT_SPINS; ++spins) {
        if(*event_end != 0U) {
            memcpy(output, ecb_data.ciphertext, sizeof(ecb_data.ciphertext));
            *event_end = 0U;
            return NOXTLS_RETURN_SUCCESS;
        }

        if(*event_error != 0U) {
            *task_stop = 1U;
            *event_error = 0U;
            return NOXTLS_RETURN_FAILED;
        }
    }

    *task_stop = 1U;
    return NOXTLS_RETURN_TIMEOUT;
}

noxtls_return_t noxtls_aes_accel_port_encrypt_block(const uint8_t *key,
                                                     const uint8_t *data,
                                                     uint8_t *output,
                                                     noxtls_aes_type_t type)
{
#if NOXTLS_FEATURE_NRF52_HW_ACCEL
    if(type != NOXTLS_AES_128_BIT) {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }
    return noxtls_nrf52_ecb_encrypt_128(key, data, output);
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
    (void)key;
    (void)data;
    (void)output;
    (void)type;
    return NOXTLS_RETURN_NOT_SUPPORTED;
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

    for(i = 0U; i < block_count; ++i) {
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
