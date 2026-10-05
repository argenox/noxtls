/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_ecc_accel_noxv_port.c
* Summary: NoxV secp256r1 point-multiplication accelerator hook.
*****************************************************************************/

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "noxtls_ecc.h"
#include "noxtls_common.h"

#ifndef NOXTLS_NOXV_ECC_P256_BASE_ADDR
#define NOXTLS_NOXV_ECC_P256_BASE_ADDR ((uintptr_t)0x20007000u)
#endif

#ifndef NOXTLS_NOXV_ECC_P256_TIMEOUT_SPINS
#define NOXTLS_NOXV_ECC_P256_TIMEOUT_SPINS (2000000u)
#endif

#define NOXTLS_NOXV_ECC_CTRL_OFF       (0x000u)
#define NOXTLS_NOXV_ECC_STATUS_OFF     (0x004u)
#define NOXTLS_NOXV_ECC_PRIV_OFF       (0x010u)
#define NOXTLS_NOXV_ECC_PUB_X_OFF      (0x070u)
#define NOXTLS_NOXV_ECC_PUB_Y_OFF      (0x090u)
#define NOXTLS_NOXV_ECC_RES_X_OFF      (0x0f0u)
#define NOXTLS_NOXV_ECC_RES_Y_OFF      (0x110u)
#define NOXTLS_NOXV_ECC_CTRL_START     (1u << 1)
#define NOXTLS_NOXV_ECC_CTRL_CLEAR     (1u << 2)
#define NOXTLS_NOXV_ECC_CTRL_ZEROIZE   (1u << 3)
#define NOXTLS_NOXV_ECC_OP_ECDH        (1u << 4)
#define NOXTLS_NOXV_ECC_STATUS_DONE    (1u << 1)
#define NOXTLS_NOXV_ECC_STATUS_VALID   (1u << 2)
#define NOXTLS_NOXV_ECC_STATUS_ERRORS  (0x3f30u)

#if defined(__GNUC__) || defined(__clang__)
#define NOXTLS_NOXV_WEAK __attribute__((weak))
#else
#define NOXTLS_NOXV_WEAK
#endif

/* Match the platform telemetry contract without retaining key material. */
static uint32_t s_noxv_ecc_operations;
static uint32_t s_noxv_ecc_fallbacks;
static uint32_t s_noxv_ecc_ready;
static int32_t s_noxv_ecc_last_rc = NOXTLS_RETURN_NOT_SUPPORTED;
static uint32_t s_noxv_ecc_last_status;
static uint32_t s_noxv_ecc_last_stage;

int noxtls_ecc_accel_is_ready(void) { return s_noxv_ecc_ready != 0u; }
uint32_t noxtls_ecc_accel_operation_count(void) { return s_noxv_ecc_operations; }
uint32_t noxtls_ecc_accel_fallback_count(void) { return s_noxv_ecc_fallbacks; }
void noxtls_ecc_accel_note_fallback(void) { ++s_noxv_ecc_fallbacks; }
int32_t noxtls_ecc_accel_last_rc(void) { return s_noxv_ecc_last_rc; }
uint32_t noxtls_ecc_accel_last_status(void) { return s_noxv_ecc_last_status; }
uint32_t noxtls_ecc_accel_last_stage(void) { return s_noxv_ecc_last_stage; }
int noxtls_ecc_accel_input_echo_ok(void) { return 0; }

static const uint8_t s_p256_prime_be[32] = {
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

static const uint8_t s_p256_a_be[32] = {
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc
};

NOXTLS_NOXV_WEAK uint32_t noxtls_noxv_ecc_p256_mmio_read(uint32_t offset)
{
    volatile uint32_t *reg =
        (volatile uint32_t *)(NOXTLS_NOXV_ECC_P256_BASE_ADDR + (uintptr_t)offset);
    return *reg;
}

NOXTLS_NOXV_WEAK void noxtls_noxv_ecc_p256_mmio_write(uint32_t offset,
                                                       uint32_t value)
{
    volatile uint32_t *reg =
        (volatile uint32_t *)(NOXTLS_NOXV_ECC_P256_BASE_ADDR + (uintptr_t)offset);
    *reg = value;
}

static uint32_t load_be32(const uint8_t *bytes)
{
    return ((uint32_t)bytes[0] << 24) |
           ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) |
           (uint32_t)bytes[3];
}

static void store_be32(uint32_t word, uint8_t *bytes)
{
    bytes[0] = (uint8_t)(word >> 24);
    bytes[1] = (uint8_t)(word >> 16);
    bytes[2] = (uint8_t)(word >> 8);
    bytes[3] = (uint8_t)word;
}

static int curve_is_p256(const ecc_curve_params_t *curve)
{
    return curve != NULL && curve->size == 32u && curve->p != NULL &&
           curve->a != NULL &&
           memcmp(curve->p, s_p256_prime_be, sizeof(s_p256_prime_be)) == 0 &&
           memcmp(curve->a, s_p256_a_be, sizeof(s_p256_a_be)) == 0;
}

noxtls_return_t noxtls_ecc_point_multiply_accel_port(
    ecc_point_t *result,
    const uint8_t *scalar,
    const ecc_point_t *point,
    const ecc_curve_params_t *curve)
{
    uint32_t status = 0u;
    uint32_t i;
    uint32_t spins;

    s_noxv_ecc_last_stage = 1u;
    s_noxv_ecc_last_status = 0u;

    if(result == NULL || scalar == NULL || point == NULL || curve == NULL) {
        s_noxv_ecc_last_rc = NOXTLS_RETURN_NULL;
        return NOXTLS_RETURN_NULL;
    }
    if(!curve_is_p256(curve) || point->size != 32u) {
        s_noxv_ecc_last_rc = NOXTLS_RETURN_NOT_SUPPORTED;
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }

    /* NoxOS is cooperative and no interrupt handler uses ECC. Keep radio
     * interrupts enabled while the comparatively long scalar operation is
     * in progress; the calling task cannot be switched without yielding. */
    s_noxv_ecc_last_stage = 2u;
    noxtls_noxv_ecc_p256_mmio_write(NOXTLS_NOXV_ECC_CTRL_OFF,
                                    NOXTLS_NOXV_ECC_CTRL_CLEAR);
    for(i = 0u; i < 8u; ++i) {
        noxtls_noxv_ecc_p256_mmio_write(NOXTLS_NOXV_ECC_PRIV_OFF + (i * 4u),
                                        load_be32(scalar + (i * 4u)));
        noxtls_noxv_ecc_p256_mmio_write(NOXTLS_NOXV_ECC_PUB_X_OFF + (i * 4u),
                                        load_be32(point->x + (i * 4u)));
        noxtls_noxv_ecc_p256_mmio_write(NOXTLS_NOXV_ECC_PUB_Y_OFF + (i * 4u),
                                        load_be32(point->y + (i * 4u)));
    }
    noxtls_noxv_ecc_p256_mmio_write(NOXTLS_NOXV_ECC_CTRL_OFF,
                                    NOXTLS_NOXV_ECC_OP_ECDH |
                                    NOXTLS_NOXV_ECC_CTRL_START);

    for(spins = 0u; spins < NOXTLS_NOXV_ECC_P256_TIMEOUT_SPINS; ++spins) {
        status = noxtls_noxv_ecc_p256_mmio_read(NOXTLS_NOXV_ECC_STATUS_OFF);
        if((status & NOXTLS_NOXV_ECC_STATUS_DONE) != 0u) {
            break;
        }
    }
    s_noxv_ecc_last_status = status;
    s_noxv_ecc_last_stage = 3u;

    if((status & (NOXTLS_NOXV_ECC_STATUS_DONE |
                  NOXTLS_NOXV_ECC_STATUS_VALID)) ==
       (NOXTLS_NOXV_ECC_STATUS_DONE | NOXTLS_NOXV_ECC_STATUS_VALID) &&
       (status & NOXTLS_NOXV_ECC_STATUS_ERRORS) == 0u) {
        for(i = 0u; i < 8u; ++i) {
            store_be32(noxtls_noxv_ecc_p256_mmio_read(
                           NOXTLS_NOXV_ECC_RES_X_OFF + (i * 4u)),
                       result->x + (i * 4u));
            store_be32(noxtls_noxv_ecc_p256_mmio_read(
                           NOXTLS_NOXV_ECC_RES_Y_OFF + (i * 4u)),
                       result->y + (i * 4u));
        }
        result->size = 32u;
        noxtls_noxv_ecc_p256_mmio_write(NOXTLS_NOXV_ECC_CTRL_OFF,
                                        NOXTLS_NOXV_ECC_CTRL_ZEROIZE);
        s_noxv_ecc_ready = 1u;
        ++s_noxv_ecc_operations;
        s_noxv_ecc_last_rc = NOXTLS_RETURN_SUCCESS;
        s_noxv_ecc_last_stage = 4u;
        return NOXTLS_RETURN_SUCCESS;
    }

    noxtls_noxv_ecc_p256_mmio_write(NOXTLS_NOXV_ECC_CTRL_OFF,
                                    NOXTLS_NOXV_ECC_CTRL_ZEROIZE);
    s_noxv_ecc_last_rc = (spins == NOXTLS_NOXV_ECC_P256_TIMEOUT_SPINS) ?
        NOXTLS_RETURN_TIMEOUT : NOXTLS_RETURN_FAILED;
    return (noxtls_return_t)s_noxv_ecc_last_rc;
}
