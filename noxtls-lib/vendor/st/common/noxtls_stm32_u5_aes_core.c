/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_stm32_u5_aes_core.c
* Summary: STM32U5 AES-IP ECB and AES-GCM register-level backend (RM0456).
*
* Matches the STM32U5 AES programming model used by ST HAL / Oryx Embedded:
* Init phase with DATATYPE_32B + BE IV/key, then DATATYPE_8B + LE DINR/DOUTR
* for header/payload/final. Clears CCF via AES_ICR only (no CR.CCFC; U5 CR
* bit 15 is reserved and bit 31 is IPRST).
*
* When FLASH OPTR.TZEN is set, uses secure aliases (AES 0x520C0000 /
* RCC 0x56020C00); otherwise non-secure (0x420C0000 / 0x46020C00).
*****************************************************************************/

#include "vendor/st/common/noxtls_stm32_u5_aes_core.h"

#include <string.h>

#include "vendor/st/noxtls_target_detect.h"

#if !defined(NOXTLS_STM32_U5_HAS_AES)

noxtls_return_t noxtls_stm32_u5_aes_encrypt_block(const uint8_t *key,
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

noxtls_return_t noxtls_stm32_u5_aes_decrypt_block(const uint8_t *key,
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

noxtls_return_t noxtls_stm32_u5_gcm_encrypt(const uint8_t *key,
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

noxtls_return_t noxtls_stm32_u5_gcm_decrypt(const uint8_t *key,
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

#else /* NOXTLS_STM32_U5_HAS_AES */

#define NOXTLS_U5_AES_POLL_LIMIT         1000000u

#define NOXTLS_U5_AES_BASE_NS            0x420C0000u
#define NOXTLS_U5_AES_BASE_S             0x520C0000u
#define NOXTLS_U5_RCC_BASE_NS            0x46020C00u
#define NOXTLS_U5_RCC_BASE_S             0x56020C00u
#define NOXTLS_U5_FLASH_OPTR_NS          0x40022040u
#define NOXTLS_U5_FLASH_OPTR_S           0x50022040u
#define NOXTLS_U5_FLASH_OPTR_TZEN        (1u << 31)

#define NOXTLS_U5_RCC_AHB2ENR1_OFF       0x8Cu
#define NOXTLS_U5_RCC_AHB2RSTR1_OFF      0x64u
#define NOXTLS_U5_RCC_AESEN              (1u << 16)
#define NOXTLS_U5_RCC_AESRST             (1u << 16)

#define NOXTLS_U5_AES_CR_OFF             0x00u
#define NOXTLS_U5_AES_SR_OFF             0x04u
#define NOXTLS_U5_AES_DINR_OFF           0x08u
#define NOXTLS_U5_AES_DOUTR_OFF          0x0Cu
#define NOXTLS_U5_AES_KEYR0_OFF          0x10u
#define NOXTLS_U5_AES_IVR0_OFF           0x20u
#define NOXTLS_U5_AES_KEYR4_OFF          0x30u
#define NOXTLS_U5_AES_ICR_OFF            0x308u

#define NOXTLS_U5_AES_CR_EN              (1u << 0)
#define NOXTLS_U5_AES_CR_DATATYPE_8B     (1u << 2)
#define NOXTLS_U5_AES_CR_MODE_KEYDERIV   (1u << 3)
#define NOXTLS_U5_AES_CR_MODE_DECRYPT    (1u << 4)
#define NOXTLS_U5_AES_CR_CHMOD_GCM       ((1u << 5) | (1u << 6))
#define NOXTLS_U5_AES_CR_GCMPH_MASK      ((1u << 13) | (1u << 14))
#define NOXTLS_U5_AES_CR_GCMPH_INIT      (0u << 13)
#define NOXTLS_U5_AES_CR_GCMPH_HEADER    (1u << 13)
#define NOXTLS_U5_AES_CR_GCMPH_PAYLOAD   (1u << 14)
#define NOXTLS_U5_AES_CR_GCMPH_FINAL     ((1u << 13) | (1u << 14))
#define NOXTLS_U5_AES_CR_KEYSIZE_256     (1u << 18)
#define NOXTLS_U5_AES_CR_MODE_MASK       ((1u << 3) | (1u << 4))
#define NOXTLS_U5_AES_CR_DATATYPE_MASK   ((1u << 1) | (1u << 2))
#define NOXTLS_U5_AES_CR_IPRST           (1u << 31)

#define NOXTLS_U5_AES_SR_CCF             (1u << 0)
#define NOXTLS_U5_AES_SR_KEYVALID        (1u << 7)
#define NOXTLS_U5_AES_ICR_CCF            (1u << 0)

#define NOXTLS_U5_REG32(addr)            (*(volatile uint32_t *)(uintptr_t)(addr))

static uintptr_t g_aes_base;
static uintptr_t g_rcc_base;
static uint8_t g_aes_ready;

static uint32_t noxtls_u5_load_be32(const uint8_t *src)
{
    return ((uint32_t)src[0] << 24) |
           ((uint32_t)src[1] << 16) |
           ((uint32_t)src[2] << 8) |
           ((uint32_t)src[3]);
}

static uint32_t noxtls_u5_load_le32(const uint8_t *src)
{
    return ((uint32_t)src[0]) |
           ((uint32_t)src[1] << 8) |
           ((uint32_t)src[2] << 16) |
           ((uint32_t)src[3] << 24);
}

static void noxtls_u5_store_le32(uint8_t *dst, uint32_t val)
{
    dst[0] = (uint8_t)val;
    dst[1] = (uint8_t)(val >> 8);
    dst[2] = (uint8_t)(val >> 16);
    dst[3] = (uint8_t)(val >> 24);
}

static int noxtls_u5_tzen_enabled(void)
{
    uint32_t optr = NOXTLS_U5_REG32(NOXTLS_U5_FLASH_OPTR_NS);
    if((optr & NOXTLS_U5_FLASH_OPTR_TZEN) != 0u) {
        return 1;
    }
    optr = NOXTLS_U5_REG32(NOXTLS_U5_FLASH_OPTR_S);
    return ((optr & NOXTLS_U5_FLASH_OPTR_TZEN) != 0u) ? 1 : 0;
}

static void noxtls_u5_rcc_enable_aes(uintptr_t rcc_base)
{
    volatile uint32_t readback;

    NOXTLS_U5_REG32(rcc_base + NOXTLS_U5_RCC_AHB2ENR1_OFF) |= NOXTLS_U5_RCC_AESEN;
    readback = NOXTLS_U5_REG32(rcc_base + NOXTLS_U5_RCC_AHB2ENR1_OFF);
    (void)readback;
    NOXTLS_U5_REG32(rcc_base + NOXTLS_U5_RCC_AHB2RSTR1_OFF) |= NOXTLS_U5_RCC_AESRST;
    readback = NOXTLS_U5_REG32(rcc_base + NOXTLS_U5_RCC_AHB2RSTR1_OFF);
    (void)readback;
    NOXTLS_U5_REG32(rcc_base + NOXTLS_U5_RCC_AHB2RSTR1_OFF) &= ~NOXTLS_U5_RCC_AESRST;
    readback = NOXTLS_U5_REG32(rcc_base + NOXTLS_U5_RCC_AHB2RSTR1_OFF);
    (void)readback;
}

static int noxtls_u5_aes_probe_base(uintptr_t aes_base)
{
    uint32_t cr;

    /* Soft-reset the IP, clear CCF, set a distinctive KEYSIZE bit, read back. */
    NOXTLS_U5_REG32(aes_base + NOXTLS_U5_AES_CR_OFF) = NOXTLS_U5_AES_CR_IPRST;
    NOXTLS_U5_REG32(aes_base + NOXTLS_U5_AES_CR_OFF) = 0u;
    NOXTLS_U5_REG32(aes_base + NOXTLS_U5_AES_ICR_OFF) = NOXTLS_U5_AES_ICR_CCF;
    NOXTLS_U5_REG32(aes_base + NOXTLS_U5_AES_CR_OFF) = NOXTLS_U5_AES_CR_KEYSIZE_256;
    cr = NOXTLS_U5_REG32(aes_base + NOXTLS_U5_AES_CR_OFF);
    NOXTLS_U5_REG32(aes_base + NOXTLS_U5_AES_CR_OFF) = 0u;
    return ((cr & NOXTLS_U5_AES_CR_KEYSIZE_256) != 0u) ? 1 : 0;
}

static void noxtls_u5_aes_enable_clock(void)
{
    if(g_aes_ready != 0u) {
        return;
    }

    /* Always poke NS RCC; also poke S RCC when TZEN may be set. */
    noxtls_u5_rcc_enable_aes(NOXTLS_U5_RCC_BASE_NS);
    if(noxtls_u5_tzen_enabled() != 0) {
        noxtls_u5_rcc_enable_aes(NOXTLS_U5_RCC_BASE_S);
    }

    if(noxtls_u5_tzen_enabled() != 0 &&
       noxtls_u5_aes_probe_base(NOXTLS_U5_AES_BASE_S) != 0) {
        g_aes_base = (uintptr_t)NOXTLS_U5_AES_BASE_S;
        g_rcc_base = (uintptr_t)NOXTLS_U5_RCC_BASE_S;
    } else if(noxtls_u5_aes_probe_base(NOXTLS_U5_AES_BASE_NS) != 0) {
        g_aes_base = (uintptr_t)NOXTLS_U5_AES_BASE_NS;
        g_rcc_base = (uintptr_t)NOXTLS_U5_RCC_BASE_NS;
    } else {
        /* Last resort: prefer S alias under TZEN, else NS. */
        if(noxtls_u5_tzen_enabled() != 0) {
            g_aes_base = (uintptr_t)NOXTLS_U5_AES_BASE_S;
            g_rcc_base = (uintptr_t)NOXTLS_U5_RCC_BASE_S;
        } else {
            g_aes_base = (uintptr_t)NOXTLS_U5_AES_BASE_NS;
            g_rcc_base = (uintptr_t)NOXTLS_U5_RCC_BASE_NS;
        }
    }

    (void)g_rcc_base;
    g_aes_ready = 1u;
}

static int noxtls_u5_wait_ccf(void)
{
    uint32_t i;
    for(i = 0u; i < NOXTLS_U5_AES_POLL_LIMIT; i++) {
        if((NOXTLS_U5_REG32(g_aes_base + NOXTLS_U5_AES_SR_OFF) &
            NOXTLS_U5_AES_SR_CCF) != 0u) {
            return 1;
        }
    }
    return 0;
}

static int noxtls_u5_wait_keyvalid(void)
{
    uint32_t i;
    for(i = 0u; i < NOXTLS_U5_AES_POLL_LIMIT; i++) {
        if((NOXTLS_U5_REG32(g_aes_base + NOXTLS_U5_AES_SR_OFF) &
            NOXTLS_U5_AES_SR_KEYVALID) != 0u) {
            return 1;
        }
    }
    return 0;
}

static void noxtls_u5_clear_ccf(void)
{
    NOXTLS_U5_REG32(g_aes_base + NOXTLS_U5_AES_ICR_OFF) = NOXTLS_U5_AES_ICR_CCF;
}

static void noxtls_u5_set_gcmpH(uint32_t phase)
{
    uint32_t cr = NOXTLS_U5_REG32(g_aes_base + NOXTLS_U5_AES_CR_OFF);
    cr &= ~NOXTLS_U5_AES_CR_GCMPH_MASK;
    cr |= phase;
    NOXTLS_U5_REG32(g_aes_base + NOXTLS_U5_AES_CR_OFF) = cr;
}

static noxtls_return_t noxtls_u5_load_key(const uint8_t *key, uint32_t key_bytes)
{
    uint32_t cr = NOXTLS_U5_REG32(g_aes_base + NOXTLS_U5_AES_CR_OFF);

    cr &= ~NOXTLS_U5_AES_CR_KEYSIZE_256;
    if(key_bytes == 32u) {
        cr |= NOXTLS_U5_AES_CR_KEYSIZE_256;
        NOXTLS_U5_REG32(g_aes_base + NOXTLS_U5_AES_CR_OFF) = cr;
        NOXTLS_U5_REG32(g_aes_base + NOXTLS_U5_AES_KEYR4_OFF + 12u) = noxtls_u5_load_be32(key);
        NOXTLS_U5_REG32(g_aes_base + NOXTLS_U5_AES_KEYR4_OFF + 8u) = noxtls_u5_load_be32(key + 4u);
        NOXTLS_U5_REG32(g_aes_base + NOXTLS_U5_AES_KEYR4_OFF + 4u) = noxtls_u5_load_be32(key + 8u);
        NOXTLS_U5_REG32(g_aes_base + NOXTLS_U5_AES_KEYR4_OFF + 0u) = noxtls_u5_load_be32(key + 12u);
        NOXTLS_U5_REG32(g_aes_base + NOXTLS_U5_AES_KEYR0_OFF + 12u) = noxtls_u5_load_be32(key + 16u);
        NOXTLS_U5_REG32(g_aes_base + NOXTLS_U5_AES_KEYR0_OFF + 8u) = noxtls_u5_load_be32(key + 20u);
        NOXTLS_U5_REG32(g_aes_base + NOXTLS_U5_AES_KEYR0_OFF + 4u) = noxtls_u5_load_be32(key + 24u);
        NOXTLS_U5_REG32(g_aes_base + NOXTLS_U5_AES_KEYR0_OFF + 0u) = noxtls_u5_load_be32(key + 28u);
    } else if(key_bytes == 16u) {
        NOXTLS_U5_REG32(g_aes_base + NOXTLS_U5_AES_CR_OFF) = cr;
        NOXTLS_U5_REG32(g_aes_base + NOXTLS_U5_AES_KEYR0_OFF + 12u) = noxtls_u5_load_be32(key);
        NOXTLS_U5_REG32(g_aes_base + NOXTLS_U5_AES_KEYR0_OFF + 8u) = noxtls_u5_load_be32(key + 4u);
        NOXTLS_U5_REG32(g_aes_base + NOXTLS_U5_AES_KEYR0_OFF + 4u) = noxtls_u5_load_be32(key + 8u);
        NOXTLS_U5_REG32(g_aes_base + NOXTLS_U5_AES_KEYR0_OFF + 0u) = noxtls_u5_load_be32(key + 12u);
    } else {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }

    if(noxtls_u5_wait_keyvalid() == 0) {
        return NOXTLS_RETURN_TIMEOUT;
    }
    return NOXTLS_RETURN_SUCCESS;
}

static void noxtls_u5_write_block_le(const uint8_t *block)
{
    uint32_t i;
    for(i = 0u; i < 4u; i++) {
        NOXTLS_U5_REG32(g_aes_base + NOXTLS_U5_AES_DINR_OFF) =
            noxtls_u5_load_le32(block + (i * 4u));
    }
}

static noxtls_return_t noxtls_u5_read_block_le(uint8_t *block)
{
    uint32_t i;
    uint32_t word;

    if(noxtls_u5_wait_ccf() == 0) {
        return NOXTLS_RETURN_TIMEOUT;
    }
    for(i = 0u; i < 4u; i++) {
        word = NOXTLS_U5_REG32(g_aes_base + NOXTLS_U5_AES_DOUTR_OFF);
        noxtls_u5_store_le32(block + (i * 4u), word);
    }
    noxtls_u5_clear_ccf();
    return NOXTLS_RETURN_SUCCESS;
}

static noxtls_return_t noxtls_u5_aes_process_block(const uint8_t *key,
                                                   const uint8_t *data,
                                                   uint8_t *output,
                                                   noxtls_aes_type_t type,
                                                   int decrypt)
{
    uint32_t key_bytes;
    uint32_t cr;
    noxtls_return_t rc;

    if(key == NULL || data == NULL || output == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(type == NOXTLS_AES_256_BIT) {
        key_bytes = 32u;
    } else if(type == NOXTLS_AES_128_BIT) {
        key_bytes = 16u;
    } else {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }

    noxtls_u5_aes_enable_clock();
    NOXTLS_U5_REG32(g_aes_base + NOXTLS_U5_AES_CR_OFF) = 0u;
    noxtls_u5_clear_ccf();

    rc = noxtls_u5_load_key(key, key_bytes);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    if(decrypt != 0) {
        cr = NOXTLS_U5_REG32(g_aes_base + NOXTLS_U5_AES_CR_OFF);
        cr &= ~NOXTLS_U5_AES_CR_MODE_MASK;
        cr |= NOXTLS_U5_AES_CR_MODE_KEYDERIV;
        NOXTLS_U5_REG32(g_aes_base + NOXTLS_U5_AES_CR_OFF) = cr | NOXTLS_U5_AES_CR_EN;
        if(noxtls_u5_wait_ccf() == 0) {
            NOXTLS_U5_REG32(g_aes_base + NOXTLS_U5_AES_CR_OFF) = 0u;
            return NOXTLS_RETURN_TIMEOUT;
        }
        noxtls_u5_clear_ccf();
        cr = NOXTLS_U5_REG32(g_aes_base + NOXTLS_U5_AES_CR_OFF);
        cr &= ~(NOXTLS_U5_AES_CR_MODE_MASK | NOXTLS_U5_AES_CR_EN);
        cr |= NOXTLS_U5_AES_CR_MODE_DECRYPT | NOXTLS_U5_AES_CR_DATATYPE_8B;
        NOXTLS_U5_REG32(g_aes_base + NOXTLS_U5_AES_CR_OFF) = cr | NOXTLS_U5_AES_CR_EN;
    } else {
        cr = NOXTLS_U5_REG32(g_aes_base + NOXTLS_U5_AES_CR_OFF);
        cr &= ~NOXTLS_U5_AES_CR_MODE_MASK;
        cr |= NOXTLS_U5_AES_CR_DATATYPE_8B;
        NOXTLS_U5_REG32(g_aes_base + NOXTLS_U5_AES_CR_OFF) = cr | NOXTLS_U5_AES_CR_EN;
    }

    noxtls_u5_write_block_le(data);
    rc = noxtls_u5_read_block_le(output);
    NOXTLS_U5_REG32(g_aes_base + NOXTLS_U5_AES_CR_OFF) = 0u;
    if(rc != NOXTLS_RETURN_SUCCESS) {
        memset(output, 0, 16u);
    }
    return rc;
}

static noxtls_return_t noxtls_u5_gcm_process(const uint8_t *key,
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
    uint32_t key_bytes;
    uint32_t i;
    uint32_t cr;
    uint64_t bits;
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
    if(((input_len & 0x0Fu) != 0u) || ((aad_len & 0x0Fu) != 0u)) {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }
    if(type == NOXTLS_AES_256_BIT) {
        key_bytes = 32u;
    } else if(type == NOXTLS_AES_128_BIT) {
        key_bytes = 16u;
    } else {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }

    noxtls_u5_aes_enable_clock();
    NOXTLS_U5_REG32(g_aes_base + NOXTLS_U5_AES_CR_OFF) = 0u;
    noxtls_u5_clear_ccf();

    /* Init: DATATYPE_32B (no swap) + BE IV/key, per RM0456 / Oryx. */
    cr = NOXTLS_U5_AES_CR_CHMOD_GCM | NOXTLS_U5_AES_CR_GCMPH_INIT;
    if(decrypt != 0) {
        cr |= NOXTLS_U5_AES_CR_MODE_DECRYPT;
    }
    NOXTLS_U5_REG32(g_aes_base + NOXTLS_U5_AES_CR_OFF) = cr;

    rc = noxtls_u5_load_key(key, key_bytes);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        NOXTLS_U5_REG32(g_aes_base + NOXTLS_U5_AES_CR_OFF) = 0u;
        return rc;
    }

    NOXTLS_U5_REG32(g_aes_base + NOXTLS_U5_AES_IVR0_OFF + 12u) = noxtls_u5_load_be32(nonce);
    NOXTLS_U5_REG32(g_aes_base + NOXTLS_U5_AES_IVR0_OFF + 8u) = noxtls_u5_load_be32(nonce + 4u);
    NOXTLS_U5_REG32(g_aes_base + NOXTLS_U5_AES_IVR0_OFF + 4u) = noxtls_u5_load_be32(nonce + 8u);
    NOXTLS_U5_REG32(g_aes_base + NOXTLS_U5_AES_IVR0_OFF + 0u) = 2u;

    NOXTLS_U5_REG32(g_aes_base + NOXTLS_U5_AES_CR_OFF) |= NOXTLS_U5_AES_CR_EN;
    if(noxtls_u5_wait_ccf() == 0) {
        NOXTLS_U5_REG32(g_aes_base + NOXTLS_U5_AES_CR_OFF) = 0u;
        return NOXTLS_RETURN_TIMEOUT;
    }
    noxtls_u5_clear_ccf();

    /* After init, switch to byte-swap datatype for LE DINR/DOUTR path. */
    cr = NOXTLS_U5_REG32(g_aes_base + NOXTLS_U5_AES_CR_OFF);
    cr &= ~NOXTLS_U5_AES_CR_DATATYPE_MASK;
    cr |= NOXTLS_U5_AES_CR_DATATYPE_8B;
    NOXTLS_U5_REG32(g_aes_base + NOXTLS_U5_AES_CR_OFF) = cr;

    noxtls_u5_set_gcmpH(NOXTLS_U5_AES_CR_GCMPH_HEADER);
    NOXTLS_U5_REG32(g_aes_base + NOXTLS_U5_AES_CR_OFF) |= NOXTLS_U5_AES_CR_EN;
    for(i = 0u; i < aad_len; i += 16u) {
        noxtls_u5_write_block_le(aad + i);
        if(noxtls_u5_wait_ccf() == 0) {
            NOXTLS_U5_REG32(g_aes_base + NOXTLS_U5_AES_CR_OFF) = 0u;
            return NOXTLS_RETURN_TIMEOUT;
        }
        noxtls_u5_clear_ccf();
    }

    noxtls_u5_set_gcmpH(NOXTLS_U5_AES_CR_GCMPH_PAYLOAD);
    for(i = 0u; i < input_len; i += 16u) {
        noxtls_u5_write_block_le(input + i);
        rc = noxtls_u5_read_block_le(output + i);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            NOXTLS_U5_REG32(g_aes_base + NOXTLS_U5_AES_CR_OFF) = 0u;
            return rc;
        }
    }

    noxtls_u5_set_gcmpH(NOXTLS_U5_AES_CR_GCMPH_FINAL);
    cr = NOXTLS_U5_REG32(g_aes_base + NOXTLS_U5_AES_CR_OFF);
    cr &= ~NOXTLS_U5_AES_CR_MODE_MASK;
    NOXTLS_U5_REG32(g_aes_base + NOXTLS_U5_AES_CR_OFF) = cr;

    /* With DATATYPE_8B, length words are little-endian bit counts. */
    bits = (uint64_t)aad_len * 8u;
    NOXTLS_U5_REG32(g_aes_base + NOXTLS_U5_AES_DINR_OFF) = (uint32_t)(bits >> 32);
    NOXTLS_U5_REG32(g_aes_base + NOXTLS_U5_AES_DINR_OFF) = (uint32_t)bits;
    bits = (uint64_t)input_len * 8u;
    NOXTLS_U5_REG32(g_aes_base + NOXTLS_U5_AES_DINR_OFF) = (uint32_t)(bits >> 32);
    NOXTLS_U5_REG32(g_aes_base + NOXTLS_U5_AES_DINR_OFF) = (uint32_t)bits;

    rc = noxtls_u5_read_block_le(out_tag);
    NOXTLS_U5_REG32(g_aes_base + NOXTLS_U5_AES_CR_OFF) = 0u;
    return rc;
}

noxtls_return_t noxtls_stm32_u5_aes_encrypt_block(const uint8_t *key,
                                                   const uint8_t *data,
                                                   uint8_t *output,
                                                   noxtls_aes_type_t type)
{
    return noxtls_u5_aes_process_block(key, data, output, type, 0);
}

noxtls_return_t noxtls_stm32_u5_aes_decrypt_block(const uint8_t *key,
                                                   const uint8_t *data,
                                                   uint8_t *output,
                                                   noxtls_aes_type_t type)
{
    return noxtls_u5_aes_process_block(key, data, output, type, 1);
}

noxtls_return_t noxtls_stm32_u5_gcm_encrypt(const uint8_t *key,
                                             noxtls_aes_type_t type,
                                             const uint8_t nonce[12],
                                             const uint8_t *aad,
                                             uint32_t aad_len,
                                             const uint8_t *plaintext,
                                             uint32_t plaintext_len,
                                             uint8_t *ciphertext,
                                             uint8_t tag[16])
{
    return noxtls_u5_gcm_process(key, type, nonce, aad, aad_len, plaintext,
                                 plaintext_len, ciphertext, tag, 0);
}

noxtls_return_t noxtls_stm32_u5_gcm_decrypt(const uint8_t *key,
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
    rc = noxtls_u5_gcm_process(key, type, nonce, aad, aad_len, ciphertext,
                               ciphertext_len, plaintext, computed_tag, 1);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(memcmp(tag, computed_tag, sizeof(computed_tag)) != 0) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    return NOXTLS_RETURN_SUCCESS;
}

#endif /* NOXTLS_STM32_U5_HAS_AES */
