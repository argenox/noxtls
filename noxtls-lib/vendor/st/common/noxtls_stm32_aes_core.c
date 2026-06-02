/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_stm32_aes_core.c
* Summary: In-house STM32 AES register-level backend helpers.
*****************************************************************************/

#include "vendor/st/common/noxtls_stm32_aes_core.h"

#include <string.h>

typedef struct
{
    uintptr_t aes_base;
} noxtls_stm32_aes_family_cfg_t;


static int noxtls_stm32_aes_wait_flag(uintptr_t aes_base, uint32_t mask, uint32_t value)
{
    uint32_t i;
    for(i = 0u; i < NOXTLS_STM32_AES_POLL_LIMIT; i++) {
        if((NOXTLS_STM32_REG32(aes_base + NOXTLS_STM32_AES_SR_OFF) & mask) == value) {
            return 1;
        }
    }
    return 0;
}

static noxtls_return_t noxtls_stm32_aes_get_cfg(noxtls_stm32_accel_family_t family,
                                                 noxtls_stm32_aes_family_cfg_t *cfg)
{
    if(cfg == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    memset(cfg, 0, sizeof(*cfg));
    switch(family) {
        case NOXTLS_STM32_ACCEL_F2:
            cfg->aes_base = (uintptr_t)NOXTLS_STM32_F2_AES_BASE;
            break;
        case NOXTLS_STM32_ACCEL_F4:
            cfg->aes_base = (uintptr_t)NOXTLS_STM32_F4_AES_BASE;
            break;
        case NOXTLS_STM32_ACCEL_F7:
            cfg->aes_base = (uintptr_t)NOXTLS_STM32_F7_AES_BASE;
            break;
        case NOXTLS_STM32_ACCEL_H7:
            cfg->aes_base = (uintptr_t)NOXTLS_STM32_H7_AES_BASE;
            break;
        case NOXTLS_STM32_ACCEL_L4:
            cfg->aes_base = (uintptr_t)NOXTLS_STM32_L4_AES_BASE;
            break;
        case NOXTLS_STM32_ACCEL_U3:
            cfg->aes_base = (uintptr_t)NOXTLS_STM32_U3_AES_BASE;
            break;
        case NOXTLS_STM32_ACCEL_U5:
            cfg->aes_base = (uintptr_t)NOXTLS_STM32_U5_AES_BASE;
            break;
        case NOXTLS_STM32_ACCEL_WB:
            cfg->aes_base = (uintptr_t)NOXTLS_STM32_WB_AES_BASE;
            break;
        default:
            return NOXTLS_RETURN_NOT_SUPPORTED;
    }

    if(cfg->aes_base == (uintptr_t)0u) {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }
    return NOXTLS_RETURN_SUCCESS;
}

static noxtls_return_t noxtls_stm32_aes_key_size_bits(noxtls_aes_type_t type, uint32_t *key_bytes, uint32_t *bits)
{
    if(key_bytes == NULL || bits == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    switch(type) {
        case NOXTLS_AES_128_BIT:
            *key_bytes = 16u;
            *bits = 0u;
            return NOXTLS_RETURN_SUCCESS;
        case NOXTLS_AES_192_BIT:
            *key_bytes = 24u;
            *bits = 1u;
            return NOXTLS_RETURN_SUCCESS;
        case NOXTLS_AES_256_BIT:
            *key_bytes = 32u;
            *bits = 2u;
            return NOXTLS_RETURN_SUCCESS;
        default:
            return NOXTLS_RETURN_INVALID_KEY_SIZE;
    }
}

static uint32_t noxtls_load_be32(const uint8_t *src)
{
    return ((uint32_t)src[0] << 24) |
           ((uint32_t)src[1] << 16) |
           ((uint32_t)src[2] << 8) |
           ((uint32_t)src[3]);
}

static void noxtls_store_be32(uint8_t *dst, uint32_t val)
{
    dst[0] = (uint8_t)(val >> 24);
    dst[1] = (uint8_t)(val >> 16);
    dst[2] = (uint8_t)(val >> 8);
    dst[3] = (uint8_t)(val);
}

static noxtls_return_t noxtls_stm32_aes_process_block(noxtls_stm32_accel_family_t family,
                                                       const uint8_t *key,
                                                       const uint8_t *data,
                                                       uint8_t *output,
                                                       noxtls_aes_type_t type,
                                                       int decrypt)
{
    noxtls_stm32_aes_family_cfg_t cfg;
    uint32_t key_bytes = 0u;
    uint32_t key_size_bits = 0u;
    uint32_t i;
    uint32_t cr;
    noxtls_return_t rc = noxtls_stm32_aes_get_cfg(family, &cfg);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(key == NULL || data == NULL || output == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = noxtls_stm32_aes_key_size_bits(type, &key_bytes, &key_size_bits);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    NOXTLS_STM32_REG32(cfg.aes_base + NOXTLS_STM32_AES_CR_OFF) = 0u;
    NOXTLS_STM32_REG32(cfg.aes_base + NOXTLS_STM32_AES_CR_OFF) = NOXTLS_STM32_AES_CR_FFLUSH;

    for(i = 0u; i < key_bytes / NOXTLS_STM32_AES_WORD_BYTES; i++) {
        NOXTLS_STM32_REG32(cfg.aes_base + NOXTLS_STM32_AES_K0LR_OFF + (i * 4u)) =
            noxtls_load_be32(key + (i * 4u));
    }
    for(i = key_bytes / NOXTLS_STM32_AES_WORD_BYTES; i < 8u; i++) {
        NOXTLS_STM32_REG32(cfg.aes_base + NOXTLS_STM32_AES_K0LR_OFF + (i * 4u)) = 0u;
    }
    for(i = 0u; i < 4u; i++) {
        NOXTLS_STM32_REG32(cfg.aes_base + NOXTLS_STM32_AES_IV0LR_OFF + (i * 4u)) = 0u;
    }

    cr = NOXTLS_STM32_AES_CR_DATATYPE_8B |
         (key_size_bits << NOXTLS_STM32_AES_CR_KEYSIZE_SHIFT) |
         NOXTLS_STM32_AES_CR_EN;
    if(decrypt != 0) {
        cr |= NOXTLS_STM32_AES_CR_ALGODIR;
    }
    NOXTLS_STM32_REG32(cfg.aes_base + NOXTLS_STM32_AES_CR_OFF) = cr;

    for(i = 0u; i < NOXTLS_STM32_WORDS_PER_BLOCK; i++) {
        if(noxtls_stm32_aes_wait_flag(cfg.aes_base, NOXTLS_STM32_AES_SR_IFNF, NOXTLS_STM32_AES_SR_IFNF) == 0) {
            NOXTLS_STM32_REG32(cfg.aes_base + NOXTLS_STM32_AES_CR_OFF) = 0u;
            return NOXTLS_RETURN_TIMEOUT;
        }
        NOXTLS_STM32_REG32(cfg.aes_base + NOXTLS_STM32_AES_DIN_OFF) = noxtls_load_be32(data + (i * 4u));
    }

    for(i = 0u; i < NOXTLS_STM32_WORDS_PER_BLOCK; i++) {
        if(noxtls_stm32_aes_wait_flag(cfg.aes_base, NOXTLS_STM32_AES_SR_OFNE, NOXTLS_STM32_AES_SR_OFNE) == 0) {
            NOXTLS_STM32_REG32(cfg.aes_base + NOXTLS_STM32_AES_CR_OFF) = 0u;
            return NOXTLS_RETURN_TIMEOUT;
        }
        noxtls_store_be32(output + (i * 4u), NOXTLS_STM32_REG32(cfg.aes_base + NOXTLS_STM32_AES_DOUT_OFF));
    }

    (void)noxtls_stm32_aes_wait_flag(cfg.aes_base, NOXTLS_STM32_AES_SR_BUSY, 0u);
    NOXTLS_STM32_REG32(cfg.aes_base + NOXTLS_STM32_AES_CR_OFF) = 0u;

    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_stm32_aes_core_encrypt_block(noxtls_stm32_accel_family_t family,
                                                     const uint8_t *key,
                                                     const uint8_t *data,
                                                     uint8_t *output,
                                                     noxtls_aes_type_t type)
{
    return noxtls_stm32_aes_process_block(family, key, data, output, type, 0);
}

noxtls_return_t noxtls_stm32_aes_core_decrypt_block(noxtls_stm32_accel_family_t family,
                                                     const uint8_t *key,
                                                     const uint8_t *data,
                                                     uint8_t *output,
                                                     noxtls_aes_type_t type)
{
    return noxtls_stm32_aes_process_block(family, key, data, output, type, 1);
}
