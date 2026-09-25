/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File: noxtls_ecc_accel_nrf54_cracen.c
* Summary: nRF54 CRACEN BA414ep P-256 point-multiplication port.
*
* The control flow, MMIO accessors, error handling, and integration in this
* file are NoxTLS code.  The BA414ep microcode payload is vendor firmware;
* its copyright notice and Nordic five-clause license are retained verbatim
* in ecc/vendor/nordic/.
*****************************************************************************/

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "noxtls_ecc.h"
#include "noxtls_common.h"
#include "noxtls_ct.h"
#include "drbg/noxtls_drbg.h"
#include "vendor/nordic/ba414ep_microcode.h"

_Static_assert((BA414EP_UCODE_SIZE * sizeof(uint32_t)) <= 0x1400u,
               "BA414ep microcode exceeds the nRF54 CRACEN code-RAM window");

/* nRF54L CRACEN APB wrapper and CRACENCORE base addresses. */
#define NOXTLS_NRF54_CRACEN_BASE                 ((uintptr_t)0x50048000u)
#define NOXTLS_NRF54_CRACENCORE_BASE             ((uintptr_t)0x51800000u)
#define NOXTLS_NRF54_CRACEN_ENABLE_OFF           (0x400u)
/* CRACEN acquisition powers the shared CryptoMaster/RNG/PKE clock domains. */
#define NOXTLS_NRF54_CRACEN_ENABLE_CRYPTOMASTER  (1u << 0)
#define NOXTLS_NRF54_CRACEN_ENABLE_RNG           (1u << 1)
#define NOXTLS_NRF54_CRACEN_ENABLE_PKEIKG        (1u << 2)
#define NOXTLS_NRF54_CRACEN_ENABLE_PKE_MASK      (NOXTLS_NRF54_CRACEN_ENABLE_CRYPTOMASTER | \
                                                   NOXTLS_NRF54_CRACEN_ENABLE_RNG | \
                                                   NOXTLS_NRF54_CRACEN_ENABLE_PKEIKG)

/* BA414ep register and memory windows within CRACENCORE. */
/*
 * CRACENCORE exposes CryptoMaster DMA at offset 0x0000.  The BA414ep PKE
 * register bank is the PK sub-block at offset 0x2000; its operand and code
 * RAM windows remain at 0x8000 and 0xc000 respectively.
 */
#define NOXTLS_NRF54_PKE_REGS_BASE               (NOXTLS_NRF54_CRACENCORE_BASE + 0x2000u)
#define NOXTLS_NRF54_PKE_DATA_BASE               (NOXTLS_NRF54_CRACENCORE_BASE + 0x8000u)
#define NOXTLS_NRF54_PKE_CODE_BASE               (NOXTLS_NRF54_CRACENCORE_BASE + 0xc000u)
#define NOXTLS_NRF54_PKE_CONFIG_OFF              (0x00u)
#define NOXTLS_NRF54_PKE_COMMAND_OFF             (0x04u)
#define NOXTLS_NRF54_PKE_CONTROL_OFF             (0x08u)
#define NOXTLS_NRF54_PKE_STATUS_OFF              (0x0cu)
#define NOXTLS_NRF54_PKE_HWCONFIG_OFF            (0x18u)

#define NOXTLS_NRF54_PKE_CONTROL_START           (0x00000001u)
#define NOXTLS_NRF54_PKE_CONTROL_CLEAR_IRQ       (0x00000002u)
#define NOXTLS_NRF54_PKE_STATUS_BUSY             (0x00010000u)
#define NOXTLS_NRF54_PKE_STATUS_ERRORS           (0x001fff0u)

/* BA414ep command encoding for ECC point multiply, P-256 and big-endian I/O. */
#define NOXTLS_NRF54_PKE_CMD_ECC_PTMUL           (0x00000022u)
#define NOXTLS_NRF54_PKE_CMD_BIG_ENDIAN          (1u << 28)
#define NOXTLS_NRF54_PKE_CMD_P256                (0x00100000u)
#define NOXTLS_NRF54_PKE_CMD_RESQUARE_R          (1u << 31)
#define NOXTLS_NRF54_PKE_CMD_RAND_SCALAR         (1u << 24)
#define NOXTLS_NRF54_PKE_CMD_RAND_PROJECTIVE     (1u << 25)

/* Each slot is 4096 bits on nRF54L CRACEN. */
#define NOXTLS_NRF54_PKE_SLOT_BYTES              (0x200u)
#define NOXTLS_NRF54_PKE_OPERAND_BYTES           (32u)
#define NOXTLS_NRF54_PKE_SLOT_INPUT_X            (12u)
#define NOXTLS_NRF54_PKE_SLOT_INPUT_Y            (13u)
#define NOXTLS_NRF54_PKE_SLOT_SCALAR             (8u)
#define NOXTLS_NRF54_PKE_SLOT_OUTPUT_X           (10u)
#define NOXTLS_NRF54_PKE_SLOT_OUTPUT_Y           (11u)
#define NOXTLS_NRF54_PKE_SLOT_BLIND_FACTOR       (15u)
#define NOXTLS_NRF54_PKE_BLIND_FACTOR_BYTES      (8u)
#define NOXTLS_NRF54_PKE_TIMEOUT_SPINS           (3000000u)
/* ECC point multiply selects point P at A=12, scalar at B=8, result at C=10. */
#define NOXTLS_NRF54_PKE_CONFIG_ECC_PTMUL        ((NOXTLS_NRF54_PKE_SLOT_INPUT_X) | \
                                                   (NOXTLS_NRF54_PKE_SLOT_SCALAR << 8) | \
                                                   (NOXTLS_NRF54_PKE_SLOT_OUTPUT_X << 16))

static volatile uint32_t s_nrf54_cracen_lock;
static uint32_t s_nrf54_cracen_microcode_loaded;
static uint32_t s_nrf54_cracen_ready;
static uint32_t s_nrf54_cracen_operation_count;
static uint32_t s_nrf54_cracen_fallback_count;
static int32_t s_nrf54_cracen_last_rc = NOXTLS_RETURN_NOT_SUPPORTED;
static uint32_t s_nrf54_cracen_last_status;
static uint32_t s_nrf54_cracen_last_stage;
static uint32_t s_nrf54_cracen_input_echo_ok;

int noxtls_ecc_accel_is_ready(void)
{
    return s_nrf54_cracen_ready != 0u;
}

uint32_t noxtls_ecc_accel_operation_count(void)
{
    return s_nrf54_cracen_operation_count;
}

uint32_t noxtls_ecc_accel_fallback_count(void)
{
    return s_nrf54_cracen_fallback_count;
}

void noxtls_ecc_accel_note_fallback(void)
{
    ++s_nrf54_cracen_fallback_count;
}

int32_t noxtls_ecc_accel_last_rc(void)
{
    return s_nrf54_cracen_last_rc;
}

uint32_t noxtls_ecc_accel_last_status(void)
{
    return s_nrf54_cracen_last_status;
}

uint32_t noxtls_ecc_accel_last_stage(void)
{
    return s_nrf54_cracen_last_stage;
}

int noxtls_ecc_accel_input_echo_ok(void)
{
    return s_nrf54_cracen_input_echo_ok != 0u;
}

static volatile uint32_t *noxtls_nrf54_reg(uintptr_t base, uint32_t offset)
{
    return (volatile uint32_t *)(base + (uintptr_t)offset);
}

/*
 * The modern Nordic platform RNG uses the same CRACEN wrapper.  Keep these
 * functions externally visible so that platform entropy collection and PKE
 * operations share one ownership lock without making NoxTLS depend on
 * BlueNox.  Only one Nordic accelerator backend may be selected at a time.
 */
int noxtls_nordic_crypto_try_acquire(void)
{
#if defined(__GNUC__) || defined(__clang__)
    return __atomic_exchange_n(&s_nrf54_cracen_lock, 1u, __ATOMIC_ACQUIRE) == 0u;
#else
    if(s_nrf54_cracen_lock != 0u) {
        return 0;
    }
    s_nrf54_cracen_lock = 1u;
    return 1;
#endif
}

void noxtls_nordic_crypto_release(void)
{
#if defined(__GNUC__) || defined(__clang__)
    __atomic_store_n(&s_nrf54_cracen_lock, 0u, __ATOMIC_RELEASE);
#else
    s_nrf54_cracen_lock = 0u;
#endif
}

static int noxtls_nrf54_pke_wait(void)
{
    uint32_t spin;
    for(spin = 0u; spin < NOXTLS_NRF54_PKE_TIMEOUT_SPINS; ++spin) {
        if((*noxtls_nrf54_reg(NOXTLS_NRF54_PKE_REGS_BASE,
                              NOXTLS_NRF54_PKE_STATUS_OFF) & NOXTLS_NRF54_PKE_STATUS_BUSY) == 0u) {
            return 1;
        }
    }
    return 0;
}

static void noxtls_nrf54_pke_clear_slot(uint32_t slot)
{
    volatile uint32_t *destination =
        (volatile uint32_t *)(NOXTLS_NRF54_PKE_DATA_BASE +
                              ((uintptr_t)slot * NOXTLS_NRF54_PKE_SLOT_BYTES));
    uint32_t i;

    /* nRF54L15 uses the base CRACEN generation.  Its PKE does not implement
     * the clear-memory command (that command is a CRACEN Lite feature), so
     * clear sensitive slots explicitly through aligned crypto-RAM writes. */
    for(i = 0u; i < NOXTLS_NRF54_PKE_SLOT_BYTES / sizeof(uint32_t); ++i) {
        destination[i] = 0u;
    }
}

static void noxtls_nrf54_pke_clear_operation_slots(void)
{
    noxtls_nrf54_pke_clear_slot(NOXTLS_NRF54_PKE_SLOT_SCALAR);
    noxtls_nrf54_pke_clear_slot(NOXTLS_NRF54_PKE_SLOT_OUTPUT_X);
    noxtls_nrf54_pke_clear_slot(NOXTLS_NRF54_PKE_SLOT_OUTPUT_Y);
    noxtls_nrf54_pke_clear_slot(NOXTLS_NRF54_PKE_SLOT_INPUT_X);
    noxtls_nrf54_pke_clear_slot(NOXTLS_NRF54_PKE_SLOT_INPUT_Y);
}

static int noxtls_nrf54_pke_load_microcode(void)
{
    uint32_t i;
    volatile uint32_t *code;

    if(s_nrf54_cracen_microcode_loaded != 0u) {
        return 1;
    }
    if(!noxtls_nrf54_pke_wait()) {
        return 0;
    }
    code = (volatile uint32_t *)NOXTLS_NRF54_PKE_CODE_BASE;
    for(i = 0u; i < (uint32_t)BA414EP_UCODE_SIZE; ++i) {
        code[i] = ba414ep_ucode[i];
    }
    /* CRACEN code RAM is Device memory.  A compiler/CPU acquire-release
     * fence alone does not guarantee that all posted APB writes have reached
     * the PKE before START.  Complete the writes, then read them back both as
     * a bus barrier and as an integrity check. */
#if (defined(__GNUC__) || defined(__clang__)) && \
    (defined(__arm__) || defined(__thumb__) || defined(__ARM_ARCH))
    __asm__ volatile ("dsb sy" ::: "memory");
#elif defined(__GNUC__) || defined(__clang__)
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
#endif
    for(i = 0u; i < (uint32_t)BA414EP_UCODE_SIZE; ++i) {
        if(code[i] != ba414ep_ucode[i]) {
            return 0;
        }
    }
#if (defined(__GNUC__) || defined(__clang__)) && \
    (defined(__arm__) || defined(__thumb__) || defined(__ARM_ARCH))
    __asm__ volatile ("dsb sy" ::: "memory");
#endif
    s_nrf54_cracen_microcode_loaded = 1u;
    s_nrf54_cracen_ready = 1u;
    return 1;
}

static volatile uint8_t *noxtls_nrf54_pke_slot(uint32_t slot)
{
    /* Big-endian BA414 commands right-align their operands in each slot. */
    return (volatile uint8_t *)(NOXTLS_NRF54_PKE_DATA_BASE +
                                ((uintptr_t)slot * NOXTLS_NRF54_PKE_SLOT_BYTES) +
                                (NOXTLS_NRF54_PKE_SLOT_BYTES - NOXTLS_NRF54_PKE_OPERAND_BYTES));
}

static void noxtls_nrf54_pke_write_slot(uint32_t slot, const uint8_t *source)
{
    volatile uint32_t *destination = (volatile uint32_t *)noxtls_nrf54_pke_slot(slot);
    uint32_t i;
    /* CRACEN's crypto-RAM accepts aligned word accesses.  Byte stores may be
     * ignored by this aperture even though byte loads appear legal. */
    for(i = 0u; i < NOXTLS_NRF54_PKE_OPERAND_BYTES / 4u; ++i) {
        uint32_t offset = i * 4u;
        destination[i] = (uint32_t)source[offset] |
                         ((uint32_t)source[offset + 1u] << 8) |
                         ((uint32_t)source[offset + 2u] << 16) |
                         ((uint32_t)source[offset + 3u] << 24);
    }
}

static void noxtls_nrf54_pke_read_slot(uint8_t *destination, uint32_t slot)
{
    volatile uint32_t *source = (volatile uint32_t *)noxtls_nrf54_pke_slot(slot);
    uint32_t i;
    for(i = 0u; i < NOXTLS_NRF54_PKE_OPERAND_BYTES / 4u; ++i) {
        uint32_t value = source[i];
        uint32_t offset = i * 4u;
        destination[offset] = (uint8_t)value;
        destination[offset + 1u] = (uint8_t)(value >> 8);
        destination[offset + 2u] = (uint8_t)(value >> 16);
        destination[offset + 3u] = (uint8_t)(value >> 24);
    }
}

static void noxtls_nrf54_pke_write_blind_factor(const uint8_t *factor)
{
    volatile uint32_t *destination =
        (volatile uint32_t *)(NOXTLS_NRF54_PKE_DATA_BASE +
                              ((uintptr_t)(NOXTLS_NRF54_PKE_SLOT_BLIND_FACTOR + 1u) *
                               NOXTLS_NRF54_PKE_SLOT_BYTES) -
                              NOXTLS_NRF54_PKE_BLIND_FACTOR_BYTES);
    uint32_t i;

    for(i = 0u; i < NOXTLS_NRF54_PKE_BLIND_FACTOR_BYTES / 4u; ++i) {
        uint32_t offset = i * 4u;
        destination[i] = (uint32_t)factor[offset] |
                         ((uint32_t)factor[offset + 1u] << 8) |
                         ((uint32_t)factor[offset + 2u] << 16) |
                         ((uint32_t)factor[offset + 3u] << 24);
    }
}

static int noxtls_nrf54_is_p256(const ecc_curve_params_t *curve)
{
    static const uint8_t p256_prime[NOXTLS_NRF54_PKE_OPERAND_BYTES] = {
        0xffu, 0xffu, 0xffu, 0xffu, 0x00u, 0x00u, 0x00u, 0x01u,
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0x00u, 0x00u, 0xffu, 0xffu, 0xffu, 0xffu,
        0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu
    };

    return curve != NULL && curve->size == NOXTLS_NRF54_PKE_OPERAND_BYTES &&
           curve->p != NULL && memcmp(curve->p, p256_prime, sizeof(p256_prime)) == 0;
}

noxtls_return_t noxtls_ecc_point_multiply_accel_port(ecc_point_t *result,
                                                      const uint8_t *scalar,
                                                      const ecc_point_t *point,
                                                      const ecc_curve_params_t *curve)
{
    uint32_t command;
    uint32_t status;
    uint8_t blind_factor[NOXTLS_NRF54_PKE_BLIND_FACTOR_BYTES];
    noxtls_return_t rc = NOXTLS_RETURN_NOT_SUPPORTED;

    if(result == NULL || scalar == NULL || point == NULL || !noxtls_nrf54_is_p256(curve) ||
       point->size != NOXTLS_NRF54_PKE_OPERAND_BYTES) {
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }
    s_nrf54_cracen_last_stage = 1u;
    s_nrf54_cracen_last_status = 0u;
    memset(blind_factor, 0, sizeof(blind_factor));
    if(noxtls_drbg_get_entropy(blind_factor, sizeof(blind_factor)) != NOXTLS_RETURN_SUCCESS) {
        s_nrf54_cracen_last_rc = NOXTLS_RETURN_NOT_SUPPORTED;
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }
    /* BA414ep requires an odd 64-bit factor with bits 63..62 clear and bit
     * 61 set.  In big-endian mode the most-significant byte is stored first. */
    blind_factor[0] = (uint8_t)((blind_factor[0] & 0x3fu) | 0x20u);
    blind_factor[NOXTLS_NRF54_PKE_BLIND_FACTOR_BYTES - 1u] |= 1u;
    if(!noxtls_nordic_crypto_try_acquire()) {
        s_nrf54_cracen_last_stage = 1u;
        s_nrf54_cracen_last_rc = NOXTLS_RETURN_NOT_SUPPORTED;
        noxtls_secure_zero(blind_factor, sizeof(blind_factor));
        return NOXTLS_RETURN_NOT_SUPPORTED;
    }
    s_nrf54_cracen_last_stage = 2u;

    /* Preserve any pre-existing users while powering CRACEN's shared domains. */
    *noxtls_nrf54_reg(NOXTLS_NRF54_CRACEN_BASE, NOXTLS_NRF54_CRACEN_ENABLE_OFF) |=
        NOXTLS_NRF54_CRACEN_ENABLE_PKE_MASK;
    s_nrf54_cracen_last_stage = 3u;

    if(!noxtls_nrf54_pke_load_microcode()) {
        goto cleanup;
    }
    s_nrf54_cracen_last_stage = 4u;
    noxtls_nrf54_pke_clear_operation_slots();
    noxtls_nrf54_pke_clear_slot(NOXTLS_NRF54_PKE_SLOT_BLIND_FACTOR);

    /* COMMAND configures how the PKE consumes crypto-RAM.  Program it before
     * writing operands so the first request after reset does not populate the
     * window under the command register's reset configuration. */
    command = NOXTLS_NRF54_PKE_CMD_ECC_PTMUL |
              NOXTLS_NRF54_PKE_CMD_BIG_ENDIAN |
              NOXTLS_NRF54_PKE_CMD_P256 |
              NOXTLS_NRF54_PKE_CMD_RESQUARE_R |
              NOXTLS_NRF54_PKE_CMD_RAND_SCALAR |
              NOXTLS_NRF54_PKE_CMD_RAND_PROJECTIVE |
              ((NOXTLS_NRF54_PKE_OPERAND_BYTES - 1u) << 8);
    *noxtls_nrf54_reg(NOXTLS_NRF54_PKE_REGS_BASE, NOXTLS_NRF54_PKE_COMMAND_OFF) = command;
    s_nrf54_cracen_last_stage = 5u;

    noxtls_nrf54_pke_write_slot(NOXTLS_NRF54_PKE_SLOT_INPUT_X, point->x);
    noxtls_nrf54_pke_write_slot(NOXTLS_NRF54_PKE_SLOT_INPUT_Y, point->y);
    noxtls_nrf54_pke_write_slot(NOXTLS_NRF54_PKE_SLOT_SCALAR, scalar);
    noxtls_nrf54_pke_write_blind_factor(blind_factor);
    noxtls_secure_zero(blind_factor, sizeof(blind_factor));
    {
        uint8_t x_echo[NOXTLS_NRF54_PKE_OPERAND_BYTES];
        uint8_t y_echo[NOXTLS_NRF54_PKE_OPERAND_BYTES];
        uint8_t scalar_echo[NOXTLS_NRF54_PKE_OPERAND_BYTES];

        /* Verify all three operands immediately before START.  This is a
         * diagnostic-only boolean: it never exposes key material, but it
         * makes an MMIO packing or slot-addressing fault distinguishable
         * from a PKE arithmetic rejection. */
        noxtls_nrf54_pke_read_slot(x_echo, NOXTLS_NRF54_PKE_SLOT_INPUT_X);
        noxtls_nrf54_pke_read_slot(y_echo, NOXTLS_NRF54_PKE_SLOT_INPUT_Y);
        noxtls_nrf54_pke_read_slot(scalar_echo, NOXTLS_NRF54_PKE_SLOT_SCALAR);
        s_nrf54_cracen_input_echo_ok =
            (memcmp(x_echo, point->x, sizeof(x_echo)) == 0 &&
             memcmp(y_echo, point->y, sizeof(y_echo)) == 0 &&
             memcmp(scalar_echo, scalar, sizeof(scalar_echo)) == 0) ? 1u : 0u;
        noxtls_secure_zero(x_echo, sizeof(x_echo));
        noxtls_secure_zero(y_echo, sizeof(y_echo));
        noxtls_secure_zero(scalar_echo, sizeof(scalar_echo));
    }
    *noxtls_nrf54_reg(NOXTLS_NRF54_PKE_REGS_BASE, NOXTLS_NRF54_PKE_CONFIG_OFF) =
        NOXTLS_NRF54_PKE_CONFIG_ECC_PTMUL;

    *noxtls_nrf54_reg(NOXTLS_NRF54_PKE_REGS_BASE, NOXTLS_NRF54_PKE_CONTROL_OFF) =
        NOXTLS_NRF54_PKE_CONTROL_START | NOXTLS_NRF54_PKE_CONTROL_CLEAR_IRQ;
    s_nrf54_cracen_last_stage = 6u;
    if(!noxtls_nrf54_pke_wait()) {
        goto cleanup;
    }

    status = *noxtls_nrf54_reg(NOXTLS_NRF54_PKE_REGS_BASE, NOXTLS_NRF54_PKE_STATUS_OFF);
    s_nrf54_cracen_last_status = status;
    s_nrf54_cracen_last_stage = 7u;
    if((status & NOXTLS_NRF54_PKE_STATUS_ERRORS) != 0u) {
        /* A reset/power event can discard PKE code RAM; reload next time. */
        if((status & (1u << 5)) != 0u) {
            s_nrf54_cracen_microcode_loaded = 0u;
        }
        goto cleanup;
    }

    noxtls_nrf54_pke_read_slot(result->x, NOXTLS_NRF54_PKE_SLOT_OUTPUT_X);
    noxtls_nrf54_pke_read_slot(result->y, NOXTLS_NRF54_PKE_SLOT_OUTPUT_Y);
    result->size = NOXTLS_NRF54_PKE_OPERAND_BYTES;
    ++s_nrf54_cracen_operation_count;
    rc = NOXTLS_RETURN_SUCCESS;
    s_nrf54_cracen_ready = 1u;
    s_nrf54_cracen_last_stage = 8u;

cleanup:
    /* Scalar and peer-point material must not persist in CRACEN PKE RAM. */
    noxtls_nrf54_pke_clear_operation_slots();
    noxtls_nrf54_pke_clear_slot(NOXTLS_NRF54_PKE_SLOT_BLIND_FACTOR);
    noxtls_secure_zero(blind_factor, sizeof(blind_factor));
    if(rc != NOXTLS_RETURN_SUCCESS) {
        s_nrf54_cracen_ready = 0u;
    }
    s_nrf54_cracen_last_rc = rc;
    noxtls_nordic_crypto_release();
    return rc;
}
