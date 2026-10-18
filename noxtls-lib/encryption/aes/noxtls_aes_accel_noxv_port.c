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
#include <string.h>

#include "noxtls_aes_accel.h"
#include "../../common/noxtls_ct.h"

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

#define NOXTLS_NOXV_AES_CTRL_START      (1u << 1U)
#define NOXTLS_NOXV_AES_CTRL_CLEAR      (1u << 2U)
#define NOXTLS_NOXV_AES_STATUS_DONE     (1u << 1U)

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
uint32_t noxtls_noxv_aes_mmio_read(uint32_t offset);
void noxtls_noxv_aes_mmio_write(uint32_t offset, uint32_t value);
uintptr_t noxtls_noxv_aes_irq_save(void);
void noxtls_noxv_aes_irq_restore(uintptr_t state);
/* Native fixtures inject the complete I/O seam, including on MSVC where
 * weak function interposition is unavailable. Production keeps its defaults. */
#if !defined(NOXTLS_NOXV_AES_EXTERNAL_IO) || !NOXTLS_NOXV_AES_EXTERNAL_IO
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
    return 0U;
}

NOXTLS_NOXV_WEAK void noxtls_noxv_aes_irq_restore(uintptr_t state)
{
    (void)state;
}

#endif

static uint32_t noxtls_noxv_pack_be32(const uint8_t *bytes)
{
    return ((uint32_t)bytes[0] <<24U) |
           ((uint32_t)bytes[1] <<16U) |
           ((uint32_t)bytes[2] <<8U) |
           (uint32_t)bytes[3];
}

static void noxtls_noxv_unpack_be32(uint32_t word, uint8_t *bytes)
{
    bytes[0] = (uint8_t)(word >>24U);
    bytes[1] = (uint8_t)(word >>16U);
    bytes[2] = (uint8_t)(word >>8U);
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

    for(word = 0U; word < 4U; word += 1U) {
        noxtls_noxv_aes_mmio_write(NOXTLS_NOXV_AES_KEY_OFF + (word * 4U),
                                   noxtls_noxv_pack_be32(&key[(word * 4U)]));
        noxtls_noxv_aes_mmio_write(NOXTLS_NOXV_AES_BLOCK_IN_OFF + (word * 4U),
                                   noxtls_noxv_pack_be32(&data[(word * 4U)]));
    }

    noxtls_noxv_aes_mmio_write(NOXTLS_NOXV_AES_CTRL_OFF,
                               NOXTLS_NOXV_AES_CTRL_START);
    for(spins = 0U; spins < NOXTLS_NOXV_AES_TIMEOUT_SPINS; spins += 1U) {
        if((noxtls_noxv_aes_mmio_read(NOXTLS_NOXV_AES_STATUS_OFF) &
            NOXTLS_NOXV_AES_STATUS_DONE) != 0U) {
            for(word = 0U; word < 4U; word += 1U) {
                noxtls_noxv_unpack_be32(
                    noxtls_noxv_aes_mmio_read(NOXTLS_NOXV_AES_BLOCK_OUT_OFF +
                                              (word * 4U)),
                    &output[(word * 4U)]);
            }
            (void)noxtls_noxv_aes_irq_restore(irq_state);
            return NOXTLS_RETURN_SUCCESS;
        }
    }

    (void)noxtls_noxv_aes_irq_restore(irq_state);
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
    for(i = 0U; i < block_count; i += 1U) {
        noxtls_return_t result = noxtls_aes_accel_port_encrypt_block(
            key, &input[(i * 16U)], &output[(i * 16U)], type);
        if(result != NOXTLS_RETURN_SUCCESS) {
            return result;
        }
    }
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_aes_gcm_encrypt_accel_port(const uint8_t *key,
                                                   noxtls_aes_type_t type,
                                                   const uint8_t *nonce,
                                                   const uint8_t *aad,
                                                   uint32_t aad_len,
                                                   const uint8_t *plaintext,
                                                   uint32_t plaintext_len,
                                                   uint8_t *ciphertext,
                                                   uint8_t *tag)
{
    (void)key; (void)type; (void)nonce; (void)aad; (void)aad_len;
    (void)plaintext; (void)plaintext_len; (void)ciphertext; (void)tag;
    return NOXTLS_RETURN_NOT_SUPPORTED;
}

noxtls_return_t noxtls_aes_gcm_decrypt_accel_port(const uint8_t *key,
                                                   noxtls_aes_type_t type,
                                                   const uint8_t *nonce,
                                                   const uint8_t *aad,
                                                   uint32_t aad_len,
                                                   const uint8_t *ciphertext,
                                                   uint32_t ciphertext_len,
                                                   const uint8_t *tag,
                                                   uint8_t *plaintext)
{
    (void)key; (void)type; (void)nonce; (void)aad; (void)aad_len;
    (void)ciphertext; (void)ciphertext_len; (void)tag; (void)plaintext;
    return NOXTLS_RETURN_NOT_SUPPORTED;
}

#if NOXTLS_FEATURE_NOXV_HW_ACCEL && NOXTLS_FEATURE_NOXV_CCM_ACCEL
/* One bounded transaction owns the accelerator key across its CBC-MAC and
 * CTR blocks. No key/plaintext cache survives this call. The geometry limits
 * interrupt masking to the short BLE control/telemetry class under test. */
typedef union { uint8_t byte[16]; uint32_t word[4]; } noxv_ccm_block_t;

static noxtls_return_t noxv_ccm_block_locked(noxv_ccm_block_t *input,
                                            noxv_ccm_block_t *output)
{
    uint32_t i, spins;
    /* AAR can arbitrate for the physical AES engine even while CPU IRQs are
     * masked. Clear prior completion and reject a denied START explicitly;
     * an old DONE must never authenticate a new block. Key registers persist. */
    noxtls_noxv_aes_mmio_write(NOXTLS_NOXV_AES_CTRL_OFF, NOXTLS_NOXV_AES_CTRL_CLEAR);
    for(i = 0u; i < 4u; ++i)
        noxtls_noxv_aes_mmio_write(NOXTLS_NOXV_AES_BLOCK_IN_OFF + 4u*i,
            noxtls_noxv_pack_be32(input->byte + 4u*i));
    noxtls_noxv_aes_mmio_write(NOXTLS_NOXV_AES_CTRL_OFF, NOXTLS_NOXV_AES_CTRL_START);
    for(spins = 0u; spins < NOXTLS_NOXV_AES_TIMEOUT_SPINS; ++spins) {
        uint32_t status = noxtls_noxv_aes_mmio_read(NOXTLS_NOXV_AES_STATUS_OFF);
        if((status & (1u << 4)) != 0u) return NOXTLS_RETURN_FAILED;
        if((status & NOXTLS_NOXV_AES_STATUS_DONE) != 0u) {
            for(i = 0u; i < 4u; ++i)
                noxtls_noxv_unpack_be32(noxtls_noxv_aes_mmio_read(
                    NOXTLS_NOXV_AES_BLOCK_OUT_OFF + 4u*i), output->byte + 4u*i);
            return NOXTLS_RETURN_SUCCESS;
        }
    }
    return NOXTLS_RETURN_TIMEOUT;
}

static noxtls_return_t noxv_ccm_counter_locked(const noxv_ccm_block_t *counter_template,
    uint32_t counter, noxv_ccm_block_t *block)
{
    *block = *counter_template;
    block->byte[15] = (uint8_t)counter;
    return noxv_ccm_block_locked(block, block);
}

static noxtls_return_t noxv_ccm_mac_locked(const noxv_ccm_block_t *counter_template,
    const uint8_t *aad, const uint8_t *plain, uint32_t length,
    noxv_ccm_block_t *mac, noxv_ccm_block_t *block)
{
    uint32_t i, offset;
    noxtls_return_t rc;
    *block = *counter_template;
    block->byte[0] = 0x49u; /* Adata, four-byte MIC, L=2. */
    block->byte[15] = (uint8_t)length;
    rc = noxv_ccm_block_locked(block, mac);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    memset(block, 0, sizeof(*block));
    block->byte[1] = 1u;
    block->byte[2] = aad[0];
    for(i = 0u; i < 4u; ++i) block->word[i] ^= mac->word[i];
    rc = noxv_ccm_block_locked(block, mac);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    for(offset = 0u; offset < length; offset += 16u) {
        uint32_t take = length - offset;
        if(take > 16u) take = 16u;
        memset(block, 0, sizeof(*block));
        memcpy(block->byte, plain + offset, take);
        for(i = 0u; i < 4u; ++i) block->word[i] ^= mac->word[i];
        rc = noxv_ccm_block_locked(block, mac);
        if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    }
    return NOXTLS_RETURN_SUCCESS;
}

static noxtls_return_t noxv_ccm_short(const uint8_t *key,
    const uint8_t *nonce, const uint8_t *aad, const uint8_t *input,
    uint32_t length, const uint8_t *tag_in, uint8_t *output,
    uint8_t *tag_out, uint8_t decrypt)
{
    noxv_ccm_block_t mac, block, counter_template;
    uint8_t plain[16];
    uint8_t diff = 0u;
    uint32_t i, offset, spins;
    uintptr_t irq = noxtls_noxv_aes_irq_save();
    noxtls_return_t rc = NOXTLS_RETURN_TIMEOUT;
    counter_template.byte[0] = 1u;
    memcpy(counter_template.byte + 1u, nonce, 13u);
    counter_template.byte[14] = counter_template.byte[15] = 0u;
    /* Do not overwrite a still-running operation after a prior timeout. */
    for(spins = 0u; spins < NOXTLS_NOXV_AES_TIMEOUT_SPINS; ++spins)
        if((noxtls_noxv_aes_mmio_read(NOXTLS_NOXV_AES_STATUS_OFF) & 1u) == 0u) break;
    if(spins == NOXTLS_NOXV_AES_TIMEOUT_SPINS) goto done;
    noxtls_noxv_aes_mmio_write(NOXTLS_NOXV_AES_CTRL_OFF, NOXTLS_NOXV_AES_CTRL_CLEAR);
    for(i = 0u; i < 4u; ++i)
        noxtls_noxv_aes_mmio_write(NOXTLS_NOXV_AES_KEY_OFF + 4u*i,
            noxtls_noxv_pack_be32(key + 4u*i));
    if(decrypt != 0u) {
        for(offset = 0u; offset < length; offset += 16u) {
            uint32_t take = length - offset;
            if(take > 16u) take = 16u;
            rc = noxv_ccm_counter_locked(&counter_template, 1u + offset/16u, &block);
            if(rc != NOXTLS_RETURN_SUCCESS) goto done;
            for(i = 0u; i < take; ++i) plain[offset+i] = input[offset+i] ^ block.byte[i];
        }
    }
    rc = noxv_ccm_mac_locked(&counter_template, aad, decrypt != 0u ? plain : input,
                            length, &mac, &block);
    if(rc != NOXTLS_RETURN_SUCCESS) goto done;
    rc = noxv_ccm_counter_locked(&counter_template, 0u, &block);
    if(rc != NOXTLS_RETURN_SUCCESS) goto done;
    if(decrypt != 0u) {
        for(i = 0u; i < 4u; ++i) diff |= tag_in[i] ^ mac.byte[i] ^ block.byte[i];
        if(diff != 0u) { rc = NOXTLS_RETURN_BAD_DATA; goto done; }
        memcpy(output, plain, length); /* Publish only authenticated plaintext. */
    } else {
        for(i = 0u; i < 4u; ++i) tag_out[i] = mac.byte[i] ^ block.byte[i];
        for(offset = 0u; offset < length; offset += 16u) {
            uint32_t take = length - offset;
            if(take > 16u) take = 16u;
            rc = noxv_ccm_counter_locked(&counter_template, 1u + offset/16u, &block);
            if(rc != NOXTLS_RETURN_SUCCESS) goto done;
            for(i = 0u; i < take; ++i) output[offset+i] = input[offset+i] ^ block.byte[i];
        }
    }
    rc = NOXTLS_RETURN_SUCCESS;
done:
    noxtls_noxv_aes_irq_restore(irq);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_secure_zero(output, length);
        if(decrypt == 0u) noxtls_secure_zero(tag_out, 4u);
    }
    noxtls_secure_zero(&mac, sizeof(mac));
    noxtls_secure_zero(&block, sizeof(block));
    noxtls_secure_zero(&counter_template, sizeof(counter_template));
    if(decrypt != 0u) noxtls_secure_zero(plain, length);
    return rc;
}
#endif

noxtls_return_t noxtls_aes_ccm_encrypt_accel_port(const uint8_t *key,
    noxtls_aes_type_t type, const uint8_t *nonce, uint32_t nonce_len,
    const uint8_t *aad, uint32_t aad_len, const uint8_t *plaintext,
    uint32_t plaintext_len, uint8_t *ciphertext, uint8_t *tag, uint32_t tag_len)
{
#if NOXTLS_FEATURE_NOXV_HW_ACCEL && NOXTLS_FEATURE_NOXV_CCM_ACCEL
    if(type != NOXTLS_AES_128_BIT || nonce_len != 13u || aad_len != 1u ||
       tag_len != 4u || plaintext_len > 16u) return NOXTLS_RETURN_NOT_SUPPORTED;
    if(key == NULL || nonce == NULL || aad == NULL || plaintext == NULL ||
       ciphertext == NULL || tag == NULL) return NOXTLS_RETURN_NULL;
    return noxv_ccm_short(key, nonce, aad, plaintext, plaintext_len,
                          NULL, ciphertext, tag, 0u);
#else
    (void)key;(void)type;(void)nonce;(void)nonce_len;(void)aad;(void)aad_len;
    (void)plaintext;(void)plaintext_len;(void)ciphertext;(void)tag;(void)tag_len;
    return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
}

noxtls_return_t noxtls_aes_ccm_decrypt_accel_port(const uint8_t *key,
    noxtls_aes_type_t type, const uint8_t *nonce, uint32_t nonce_len,
    const uint8_t *aad, uint32_t aad_len, const uint8_t *ciphertext,
    uint32_t ciphertext_len, const uint8_t *tag, uint32_t tag_len,
    uint8_t *plaintext)
{
#if NOXTLS_FEATURE_NOXV_HW_ACCEL && NOXTLS_FEATURE_NOXV_CCM_ACCEL
    if(type != NOXTLS_AES_128_BIT || nonce_len != 13u || aad_len != 1u ||
       tag_len != 4u || ciphertext_len > 16u) return NOXTLS_RETURN_NOT_SUPPORTED;
    if(key == NULL || nonce == NULL || aad == NULL || plaintext == NULL ||
       ciphertext == NULL || tag == NULL) return NOXTLS_RETURN_NULL;
    return noxv_ccm_short(key, nonce, aad, ciphertext, ciphertext_len,
                          tag, plaintext, NULL, 1u);
#else
    (void)key;(void)type;(void)nonce;(void)nonce_len;(void)aad;(void)aad_len;
    (void)ciphertext;(void)ciphertext_len;(void)tag;(void)tag_len;(void)plaintext;
    return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
}
