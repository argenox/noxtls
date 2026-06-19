/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_stm32_gcm_core.c
* Summary: STM32 CRYP AES-GCM register-level backend.
*****************************************************************************/

#include "vendor/st/common/noxtls_stm32_gcm_core.h"

#include <string.h>

#include "vendor/st/noxtls_target_detect.h"

#define NOXTLS_STM32_GCM_POLL_LIMIT       1000000u
#define NOXTLS_STM32_H7_CRYP_BASE         0x48021000u
#define NOXTLS_STM32_H7_RCC_AHB2ENR       0x580244DCu
#define NOXTLS_STM32_H7_RCC_AHB2RSTR      0x5802447Cu
#define NOXTLS_STM32_H7_RCC_AHB2ENR_CRYPEN (1u << 4)
#define NOXTLS_STM32_H7_RCC_AHB2RSTR_CRYPRST (1u << 4)

#define NOXTLS_CRYP_CR_OFF                0x00u
#define NOXTLS_CRYP_SR_OFF                0x04u
#define NOXTLS_CRYP_DIN_OFF               0x08u
#define NOXTLS_CRYP_DOUT_OFF              0x0Cu
#define NOXTLS_CRYP_K0LR_OFF              0x20u
#define NOXTLS_CRYP_IV0LR_OFF             0x40u

#define NOXTLS_CRYP_CR_ALGODIR            (1u << 2)
#define NOXTLS_CRYP_CR_AES_GCM            (1u << 19)
#define NOXTLS_CRYP_CR_KEYSIZE_256        (2u << 8)
#define NOXTLS_CRYP_CR_CRYPEN             (1u << 15)
#define NOXTLS_CRYP_CR_GCM_PHASE_MASK     (3u << 16)
#define NOXTLS_CRYP_CR_GCM_PHASE_INIT     (0u << 16)
#define NOXTLS_CRYP_CR_GCM_PHASE_HEADER   (1u << 16)
#define NOXTLS_CRYP_CR_GCM_PHASE_PAYLOAD  (2u << 16)
#define NOXTLS_CRYP_CR_GCM_PHASE_FINAL    (3u << 16)
#define NOXTLS_CRYP_CR_NPBLB_MASK         (0xFu << 20)

#define NOXTLS_CRYP_SR_IFEM               (1u << 0)
#define NOXTLS_CRYP_SR_IFNF               (1u << 1)
#define NOXTLS_CRYP_SR_OFNE               (1u << 2)
#define NOXTLS_CRYP_SR_BUSY               (1u << 4)

#define NOXTLS_STM32_REG32(addr)          (*(volatile uint32_t *)(uintptr_t)(addr))

#if defined(NOXTLS_STM32_H7_HAS_CRYP_HASH) || defined(NOXTLS_STM32H7_FORCE_CRYP_HASH)
#define NOXTLS_STM32_GCM_CAN_TOUCH_H7_CRYP 1
#else
#define NOXTLS_STM32_GCM_CAN_TOUCH_H7_CRYP 0
#endif

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
    dst[3] = (uint8_t)val;
}

static int noxtls_wait_sr(uintptr_t base, uint32_t mask, uint32_t value)
{
    uint32_t i;
    for(i = 0u; i < NOXTLS_STM32_GCM_POLL_LIMIT; i++) {
        if((NOXTLS_STM32_REG32(base + NOXTLS_CRYP_SR_OFF) & mask) == value) {
            return 1;
        }
    }
    return 0;
}

static int noxtls_wait_cr(uintptr_t base, uint32_t mask, uint32_t value)
{
    uint32_t i;
    for(i = 0u; i < NOXTLS_STM32_GCM_POLL_LIMIT; i++) {
        if((NOXTLS_STM32_REG32(base + NOXTLS_CRYP_CR_OFF) & mask) == value) {
            return 1;
        }
    }
    return 0;
}

static void noxtls_set_phase(uintptr_t base, uint32_t phase)
{
    uint32_t cr = NOXTLS_STM32_REG32(base + NOXTLS_CRYP_CR_OFF);
    cr &= ~NOXTLS_CRYP_CR_GCM_PHASE_MASK;
    cr |= phase;
    NOXTLS_STM32_REG32(base + NOXTLS_CRYP_CR_OFF) = cr;
}

static void noxtls_h7_cryp_clock_reset(void)
{
    volatile uint32_t readback;

    NOXTLS_STM32_REG32(NOXTLS_STM32_H7_RCC_AHB2ENR) |= NOXTLS_STM32_H7_RCC_AHB2ENR_CRYPEN;
    readback = NOXTLS_STM32_REG32(NOXTLS_STM32_H7_RCC_AHB2ENR);
    (void)readback;

    NOXTLS_STM32_REG32(NOXTLS_STM32_H7_RCC_AHB2RSTR) |= NOXTLS_STM32_H7_RCC_AHB2RSTR_CRYPRST;
    readback = NOXTLS_STM32_REG32(NOXTLS_STM32_H7_RCC_AHB2RSTR);
    (void)readback;
    NOXTLS_STM32_REG32(NOXTLS_STM32_H7_RCC_AHB2RSTR) &= ~NOXTLS_STM32_H7_RCC_AHB2RSTR_CRYPRST;
    readback = NOXTLS_STM32_REG32(NOXTLS_STM32_H7_RCC_AHB2RSTR);
    (void)readback;
}

static noxtls_return_t noxtls_get_cryp_base(noxtls_stm32_accel_family_t family, uintptr_t *base)
{
    if(base == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(family != NOXTLS_STM32_ACCEL_H7) {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }
    if(NOXTLS_STM32_GCM_CAN_TOUCH_H7_CRYP == 0) {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }
    *base = (uintptr_t)NOXTLS_STM32_H7_CRYP_BASE;
    return NOXTLS_RETURN_SUCCESS;
}

static noxtls_return_t noxtls_cryp_write_block(uintptr_t base, const uint8_t *block)
{
    uint32_t i;
    for(i = 0u; i < 4u; i++) {
        if(noxtls_wait_sr(base, NOXTLS_CRYP_SR_IFNF, NOXTLS_CRYP_SR_IFNF) == 0) {
            return NOXTLS_RETURN_TIMEOUT;
        }
        NOXTLS_STM32_REG32(base + NOXTLS_CRYP_DIN_OFF) = noxtls_load_be32(block + (i * 4u));
    }
    return NOXTLS_RETURN_SUCCESS;
}

static noxtls_return_t noxtls_cryp_read_block(uintptr_t base, uint8_t *block)
{
    uint32_t i;
    if(noxtls_wait_sr(base, NOXTLS_CRYP_SR_OFNE, NOXTLS_CRYP_SR_OFNE) == 0) {
        return NOXTLS_RETURN_TIMEOUT;
    }
    for(i = 0u; i < 4u; i++) {
        noxtls_store_be32(block + (i * 4u), NOXTLS_STM32_REG32(base + NOXTLS_CRYP_DOUT_OFF));
    }
    return NOXTLS_RETURN_SUCCESS;
}

static noxtls_return_t noxtls_stm32_gcm_process(noxtls_stm32_accel_family_t family,
                                                 const uint8_t *key,
                                                 noxtls_aes_type_t type,
                                                 const uint8_t nonce[12],
                                                 const uint8_t *aad,
                                                 uint32_t aad_len,
                                                 const uint8_t *input,
                                                 uint32_t input_len,
                                                 uint8_t *output,
                                                 uint8_t out_tag[16],
                                                 int decrypt)
{
    uintptr_t base = 0u;
    uint32_t i;
    uint32_t cr;
    noxtls_return_t rc;

    if(key == NULL || nonce == NULL || output == NULL || out_tag == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(input_len != 0u && input == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(aad_len != 0u && aad == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(type != NOXTLS_AES_256_BIT) {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }

    /* v1 avoids the ST H7 GCM tail-block errata path and byte-width header
     * padding. The generic NoxTLS software path covers those records.
     */
    if(((input_len & 0x0Fu) != 0u) || ((aad_len & 0x0Fu) != 0u)) {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }

    rc = noxtls_get_cryp_base(family, &base);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    noxtls_h7_cryp_clock_reset();

    NOXTLS_STM32_REG32(base + NOXTLS_CRYP_CR_OFF) = 0u;
    noxtls_set_phase(base, NOXTLS_CRYP_CR_GCM_PHASE_INIT);

    for(i = 0u; i < 8u; i++) {
        NOXTLS_STM32_REG32(base + NOXTLS_CRYP_K0LR_OFF + (i * 4u)) = noxtls_load_be32(key + (i * 4u));
    }
    for(i = 0u; i < 3u; i++) {
        NOXTLS_STM32_REG32(base + NOXTLS_CRYP_IV0LR_OFF + (i * 4u)) = noxtls_load_be32(nonce + (i * 4u));
    }
    NOXTLS_STM32_REG32(base + NOXTLS_CRYP_IV0LR_OFF + 12u) = 2u;

    cr = NOXTLS_CRYP_CR_AES_GCM | NOXTLS_CRYP_CR_KEYSIZE_256;
    if(decrypt != 0) {
        cr |= NOXTLS_CRYP_CR_ALGODIR;
    }
    NOXTLS_STM32_REG32(base + NOXTLS_CRYP_CR_OFF) = cr | NOXTLS_CRYP_CR_CRYPEN;

    if(noxtls_wait_cr(base, NOXTLS_CRYP_CR_CRYPEN, 0u) == 0) {
        NOXTLS_STM32_REG32(base + NOXTLS_CRYP_CR_OFF) = 0u;
        return NOXTLS_RETURN_TIMEOUT;
    }

    if(aad_len != 0u) {
        noxtls_set_phase(base, NOXTLS_CRYP_CR_GCM_PHASE_HEADER);
        NOXTLS_STM32_REG32(base + NOXTLS_CRYP_CR_OFF) |= NOXTLS_CRYP_CR_CRYPEN;
        for(i = 0u; i < aad_len; i += 16u) {
            rc = noxtls_cryp_write_block(base, aad + i);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                NOXTLS_STM32_REG32(base + NOXTLS_CRYP_CR_OFF) = 0u;
                return rc;
            }
            if(noxtls_wait_sr(base, NOXTLS_CRYP_SR_IFEM, NOXTLS_CRYP_SR_IFEM) == 0) {
                NOXTLS_STM32_REG32(base + NOXTLS_CRYP_CR_OFF) = 0u;
                return NOXTLS_RETURN_TIMEOUT;
            }
        }
        if(noxtls_wait_sr(base, NOXTLS_CRYP_SR_BUSY, 0u) == 0) {
            NOXTLS_STM32_REG32(base + NOXTLS_CRYP_CR_OFF) = 0u;
            return NOXTLS_RETURN_TIMEOUT;
        }
    }

    NOXTLS_STM32_REG32(base + NOXTLS_CRYP_CR_OFF) &= ~NOXTLS_CRYP_CR_CRYPEN;
    NOXTLS_STM32_REG32(base + NOXTLS_CRYP_CR_OFF) &= ~NOXTLS_CRYP_CR_NPBLB_MASK;
    noxtls_set_phase(base, NOXTLS_CRYP_CR_GCM_PHASE_PAYLOAD);
    NOXTLS_STM32_REG32(base + NOXTLS_CRYP_CR_OFF) |= NOXTLS_CRYP_CR_CRYPEN;

    for(i = 0u; i < input_len; i += 16u) {
        rc = noxtls_cryp_write_block(base, input + i);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            NOXTLS_STM32_REG32(base + NOXTLS_CRYP_CR_OFF) = 0u;
            return rc;
        }
        rc = noxtls_cryp_read_block(base, output + i);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            NOXTLS_STM32_REG32(base + NOXTLS_CRYP_CR_OFF) = 0u;
            return rc;
        }
    }

    if(noxtls_wait_sr(base, NOXTLS_CRYP_SR_BUSY, 0u) == 0) {
        NOXTLS_STM32_REG32(base + NOXTLS_CRYP_CR_OFF) = 0u;
        return NOXTLS_RETURN_TIMEOUT;
    }

    NOXTLS_STM32_REG32(base + NOXTLS_CRYP_CR_OFF) &= ~NOXTLS_CRYP_CR_CRYPEN;
    noxtls_set_phase(base, NOXTLS_CRYP_CR_GCM_PHASE_FINAL);
    NOXTLS_STM32_REG32(base + NOXTLS_CRYP_CR_OFF) &= ~NOXTLS_CRYP_CR_ALGODIR;
    NOXTLS_STM32_REG32(base + NOXTLS_CRYP_CR_OFF) |= NOXTLS_CRYP_CR_CRYPEN;

    if(noxtls_wait_sr(base, NOXTLS_CRYP_SR_IFNF, NOXTLS_CRYP_SR_IFNF) == 0) {
        NOXTLS_STM32_REG32(base + NOXTLS_CRYP_CR_OFF) = 0u;
        return NOXTLS_RETURN_TIMEOUT;
    }
    NOXTLS_STM32_REG32(base + NOXTLS_CRYP_DIN_OFF) = 0u;
    NOXTLS_STM32_REG32(base + NOXTLS_CRYP_DIN_OFF) = aad_len * 8u;
    NOXTLS_STM32_REG32(base + NOXTLS_CRYP_DIN_OFF) = 0u;
    NOXTLS_STM32_REG32(base + NOXTLS_CRYP_DIN_OFF) = input_len * 8u;

    rc = noxtls_cryp_read_block(base, out_tag);
    NOXTLS_STM32_REG32(base + NOXTLS_CRYP_CR_OFF) = 0u;
    return rc;
}

int noxtls_stm32_gcm_is_supported(void)
{
    return NOXTLS_STM32_GCM_CAN_TOUCH_H7_CRYP;
}

int noxtls_stm32_gcm_support_status(void)
{
#if defined(NOXTLS_STM32H7_FORCE_CRYP_HASH)
    return NOXTLS_STM32_GCM_STATUS_FORCED;
#elif defined(NOXTLS_STM32_H7_HAS_CRYP_HASH)
    return NOXTLS_STM32_GCM_STATUS_READY;
#elif defined(NOXTLS_STM32_H7_NO_CRYP_HASH)
    return NOXTLS_STM32_GCM_STATUS_H7_NO_CRYP;
#elif defined(NOXTLS_STM32_FAMILY_H7)
    return NOXTLS_STM32_GCM_STATUS_H7_UNSUPPORTED;
#else
    return NOXTLS_STM32_GCM_STATUS_NOT_STM32H7;
#endif
}

noxtls_return_t noxtls_stm32_gcm_encrypt(noxtls_stm32_accel_family_t family,
                                          const uint8_t *key,
                                          noxtls_aes_type_t type,
                                          const uint8_t nonce[12],
                                          const uint8_t *aad,
                                          uint32_t aad_len,
                                          const uint8_t *plaintext,
                                          uint32_t plaintext_len,
                                          uint8_t *ciphertext,
                                          uint8_t tag[16])
{
    return noxtls_stm32_gcm_process(family, key, type, nonce, aad, aad_len,
                                    plaintext, plaintext_len, ciphertext, tag, 0);
}

noxtls_return_t noxtls_stm32_gcm_decrypt(noxtls_stm32_accel_family_t family,
                                          const uint8_t *key,
                                          noxtls_aes_type_t type,
                                          const uint8_t nonce[12],
                                          const uint8_t *aad,
                                          uint32_t aad_len,
                                          const uint8_t *ciphertext,
                                          uint32_t ciphertext_len,
                                          const uint8_t tag[16],
                                          uint8_t *plaintext)
{
    uint8_t computed_tag[16];
    noxtls_return_t rc;

    if(tag == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = noxtls_stm32_gcm_process(family, key, type, nonce, aad, aad_len,
                                                  ciphertext, ciphertext_len, plaintext,
                                                  computed_tag, 1);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(memcmp(tag, computed_tag, sizeof(computed_tag)) != 0) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    return NOXTLS_RETURN_SUCCESS;
}
