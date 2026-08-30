/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_sha256_accel_noxv_port.c
* Summary: NoxV SHA-256 accelerator hook.
*****************************************************************************/

#include <stddef.h>
#include <stdint.h>

#include "noxtls_sha.h"
#include "noxtls_common.h"

#ifndef NOXTLS_NOXV_SHA256_BASE_ADDR
#define NOXTLS_NOXV_SHA256_BASE_ADDR ((uintptr_t)0x20006000u)
#endif

#ifndef NOXTLS_NOXV_SHA256_TIMEOUT_SPINS
#define NOXTLS_NOXV_SHA256_TIMEOUT_SPINS (4096u)
#endif

#define NOXTLS_NOXV_SHA_CTRL_OFF          (0x00u)
#define NOXTLS_NOXV_SHA_STATUS_OFF        (0x04u)
#define NOXTLS_NOXV_SHA_BLOCK_OFF         (0x08u)
#define NOXTLS_NOXV_SHA_DIGEST_OFF        (0x48u)
#define NOXTLS_NOXV_SHA_CTRL_INIT         (1u << 1)
#define NOXTLS_NOXV_SHA_CTRL_NEXT         (1u << 2)
#define NOXTLS_NOXV_SHA_CTRL_CLEAR        (1u << 3)
#define NOXTLS_NOXV_SHA_STATUS_DONE       (1u << 1)
#define NOXTLS_NOXV_SHA_STATUS_VALID      (1u << 2)

#if defined(__GNUC__) || defined(__clang__)
#define NOXTLS_NOXV_WEAK __attribute__((weak))
#else
#define NOXTLS_NOXV_WEAK
#endif

static const uint32_t s_sha256_iv[8] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
};

static const noxtls_sha_ctx_t *s_active_ctx;
static uint32_t s_active_digest[8];

NOXTLS_NOXV_WEAK uint32_t noxtls_noxv_sha256_mmio_read(uint32_t offset)
{
    volatile uint32_t *reg =
        (volatile uint32_t *)(NOXTLS_NOXV_SHA256_BASE_ADDR + (uintptr_t)offset);
    return *reg;
}

NOXTLS_NOXV_WEAK void noxtls_noxv_sha256_mmio_write(uint32_t offset,
                                                     uint32_t value)
{
    volatile uint32_t *reg =
        (volatile uint32_t *)(NOXTLS_NOXV_SHA256_BASE_ADDR + (uintptr_t)offset);
    *reg = value;
}

NOXTLS_NOXV_WEAK uintptr_t noxtls_noxv_sha256_irq_save(void)
{
    return 0u;
}

NOXTLS_NOXV_WEAK void noxtls_noxv_sha256_irq_restore(uintptr_t state)
{
    (void)state;
}

static uint32_t load_be32(const uint8_t *bytes)
{
    return ((uint32_t)bytes[0] << 24) |
           ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) |
           (uint32_t)bytes[3];
}

static int words_equal(const uint32_t lhs[8], const uint32_t rhs[8])
{
    uint32_t i;

    for(i = 0u; i < 8u; ++i) {
        if(lhs[i] != rhs[i]) {
            return 0;
        }
    }
    return 1;
}

static noxtls_return_t process_blocks(noxtls_sha_ctx_t *ctx,
                                      const uint8_t *input,
                                      uint32_t block_count)
{
    uintptr_t irq_state;
    uint32_t block;
    uint32_t i;
    uint32_t spins;
    uint32_t command;
    uint32_t status;

    if(ctx == NULL || input == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(ctx->algo != NOXTLS_HASH_SHA_256 || block_count == 0u) {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }

    irq_state = noxtls_noxv_sha256_irq_save();
    if(words_equal(ctx->h, s_sha256_iv)) {
        command = NOXTLS_NOXV_SHA_CTRL_INIT;
    } else if(s_active_ctx == ctx && words_equal(ctx->h, s_active_digest)) {
        command = NOXTLS_NOXV_SHA_CTRL_NEXT;
    } else {
        noxtls_noxv_sha256_irq_restore(irq_state);
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }

    for(block = 0u; block < block_count; ++block) {
        noxtls_noxv_sha256_mmio_write(NOXTLS_NOXV_SHA_CTRL_OFF,
                                      NOXTLS_NOXV_SHA_CTRL_CLEAR);
        for(i = 0u; i < 16u; ++i) {
            noxtls_noxv_sha256_mmio_write(
                NOXTLS_NOXV_SHA_BLOCK_OFF + (i * 4u),
                load_be32(input + (block * 64u) + (i * 4u)));
        }
        noxtls_noxv_sha256_mmio_write(NOXTLS_NOXV_SHA_CTRL_OFF, command);

        status = 0u;
        for(spins = 0u; spins < NOXTLS_NOXV_SHA256_TIMEOUT_SPINS; ++spins) {
            status = noxtls_noxv_sha256_mmio_read(NOXTLS_NOXV_SHA_STATUS_OFF);
            if((status & NOXTLS_NOXV_SHA_STATUS_DONE) != 0u) {
                break;
            }
        }
        if((status & (NOXTLS_NOXV_SHA_STATUS_DONE |
                      NOXTLS_NOXV_SHA_STATUS_VALID)) !=
           (NOXTLS_NOXV_SHA_STATUS_DONE | NOXTLS_NOXV_SHA_STATUS_VALID)) {
            s_active_ctx = NULL;
            noxtls_noxv_sha256_irq_restore(irq_state);
            return NOXTLS_RETURN_TIMEOUT;
        }

        for(i = 0u; i < 8u; ++i) {
            ctx->h[i] = noxtls_noxv_sha256_mmio_read(
                NOXTLS_NOXV_SHA_DIGEST_OFF + (i * 4u));
            s_active_digest[i] = ctx->h[i];
        }
        s_active_ctx = ctx;
        command = NOXTLS_NOXV_SHA_CTRL_NEXT;
    }

    noxtls_noxv_sha256_irq_restore(irq_state);
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_sha256_round_accel_port(noxtls_sha_ctx_t *ctx,
                                                const uint8_t *input)
{
    return process_blocks(ctx, input, 1u);
}

noxtls_return_t noxtls_sha256_blocks_accel_port(noxtls_sha_ctx_t *ctx,
                                                 const uint8_t *input,
                                                 uint32_t block_count)
{
    return process_blocks(ctx, input, block_count);
}
