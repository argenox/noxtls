/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_aes_accel_noxv_port.c
* Summary: NoxV AES-128 accelerator hook.
*****************************************************************************/

#include <stddef.h>
#include <stdint.h>

#include "../../../noxtls_common.h"
#include "noxtls_aes.h"

#ifndef NOXTLS_FEATURE_NOXV_HW_ACCEL
#define NOXTLS_FEATURE_NOXV_HW_ACCEL 0
#endif

#ifndef NOXTLS_NOXV_AES_BASE_ADDR
#define NOXTLS_NOXV_AES_BASE_ADDR       ((uintptr_t)0x20005000u)
#endif

#ifndef NOXTLS_NOXV_AES_TIMEOUT_SPINS
#define NOXTLS_NOXV_AES_TIMEOUT_SPINS   (4096u)
#endif

#define NOXTLS_NOXV_AES_CTRL_OFF        (0x00u)
#define NOXTLS_NOXV_AES_STATUS_OFF      (0x04u)
#define NOXTLS_NOXV_AES_KEY_OFF         (0x08u)
#define NOXTLS_NOXV_AES_BLOCK_IN_OFF    (0x18u)
#define NOXTLS_NOXV_AES_BLOCK_OUT_OFF   (0x28u)

#define NOXTLS_NOXV_AES_CTRL_START      (1u << 1)
#define NOXTLS_NOXV_AES_CTRL_CLEAR      (1u << 2)
#define NOXTLS_NOXV_AES_STATUS_DONE     (1u << 1)

#if defined(__GNUC__) || defined(__clang__)
#define NOXTLS_NOXV_WEAK __attribute__((weak))
#else
#define NOXTLS_NOXV_WEAK
#endif

/*
 * The firmware may override these hooks to integrate MMIO mocking and its
 * interrupt critical-section implementation.  Keeping interrupts disabled for
 * the short block operation prevents an ISR from deadlocking on the shared
 * accelerator while an interrupted task owns it.
 */
NOXTLS_NOXV_WEAK uint32_t noxtls_noxv_aes_mmio_read(uint32_t offset)
{
    volatile uint32_t *reg =
        (volatile uint32_t *)(NOXTLS_NOXV_AES_BASE_ADDR + (uintptr_t)offset);
    return *reg;
}

NOXTLS_NOXV_WEAK void noxtls_noxv_aes_mmio_write(uint32_t offset, uint32_t value)
{
    volatile uint32_t *reg =
        (volatile uint32_t *)(NOXTLS_NOXV_AES_BASE_ADDR + (uintptr_t)offset);
    *reg = value;
}

NOXTLS_NOXV_WEAK uintptr_t noxtls_noxv_aes_irq_save(void)
{
    return 0u;
}

NOXTLS_NOXV_WEAK void noxtls_noxv_aes_irq_restore(uintptr_t state)
{
    (void)state;
}

static uint32_t noxtls_noxv_pack_be32(const uint8_t *bytes)
{
    return ((uint32_t)bytes[0] << 24) |
           ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) |
           (uint32_t)bytes[3];
}

static void noxtls_noxv_unpack_be32(uint32_t word, uint8_t *bytes)
{
    bytes[0] = (uint8_t)(word >> 24);
    bytes[1] = (uint8_t)(word >> 16);
    bytes[2] = (uint8_t)(word >> 8);
    bytes[3] = (uint8_t)word;
}

static noxtls_return_t noxtls_noxv_aes_encrypt_128(const uint8_t *key,
                                                    const uint8_t *data,
                                                    uint8_t *output)
{
    uintptr_t irq_state;
    uint32_t word;
    uint32_t spins;

    irq_state = noxtls_noxv_aes_irq_save();
    noxtls_noxv_aes_mmio_write(NOXTLS_NOXV_AES_CTRL_OFF,
                               NOXTLS_NOXV_AES_CTRL_CLEAR);

    for(word = 0u; word < 4u; ++word) {
        noxtls_noxv_aes_mmio_write(NOXTLS_NOXV_AES_KEY_OFF + (word * 4u),
                                   noxtls_noxv_pack_be32(key + (word * 4u)));
        noxtls_noxv_aes_mmio_write(NOXTLS_NOXV_AES_BLOCK_IN_OFF + (word * 4u),
                                   noxtls_noxv_pack_be32(data + (word * 4u)));
    }

    noxtls_noxv_aes_mmio_write(NOXTLS_NOXV_AES_CTRL_OFF,
                               NOXTLS_NOXV_AES_CTRL_START);
    for(spins = 0u; spins < NOXTLS_NOXV_AES_TIMEOUT_SPINS; ++spins) {
        if((noxtls_noxv_aes_mmio_read(NOXTLS_NOXV_AES_STATUS_OFF) &
            NOXTLS_NOXV_AES_STATUS_DONE) != 0u) {
            for(word = 0u; word < 4u; ++word) {
                noxtls_noxv_unpack_be32(
                    noxtls_noxv_aes_mmio_read(NOXTLS_NOXV_AES_BLOCK_OUT_OFF +
                                              (word * 4u)),
                    output + (word * 4u));
            }
            noxtls_noxv_aes_irq_restore(irq_state);
            return NOXTLS_RETURN_SUCCESS;
        }
    }

    noxtls_noxv_aes_irq_restore(irq_state);
    return NOXTLS_RETURN_TIMEOUT;
}

noxtls_return_t noxtls_aes_accel_port_encrypt_block(const uint8_t *key,
                                                     const uint8_t *data,
                                                     uint8_t *output,
                                                     noxtls_aes_type_t type)
{
    if(key == NULL || data == NULL || output == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(type != NOXTLS_AES_128_BIT) {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }
#if NOXTLS_FEATURE_NOXV_HW_ACCEL
    return noxtls_noxv_aes_encrypt_128(key, data, output);
#else
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
    for(i = 0u; i < block_count; ++i) {
        noxtls_return_t result = noxtls_aes_accel_port_encrypt_block(
            key, input + (i * 16u), output + (i * 16u), type);
        if(result != NOXTLS_RETURN_SUCCESS) {
            return result;
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
    (void)key; (void)type; (void)nonce; (void)aad; (void)aad_len;
    (void)plaintext; (void)plaintext_len; (void)ciphertext; (void)tag;
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
    (void)key; (void)type; (void)nonce; (void)aad; (void)aad_len;
    (void)ciphertext; (void)ciphertext_len; (void)tag; (void)plaintext;
    return NOXTLS_RETURN_NOT_SUPPORTED;
}
