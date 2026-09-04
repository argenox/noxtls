/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File: noxtls_ecc_accel_nrf53_cc312.c
* Summary: Clean-room nRF5340 CryptoCell 312 PKA P-256 backend.
*
* This driver uses only the published CC312 register contract.  It does not
* link, embed, or derive code from Nordic's binary CryptoCell distribution.
*****************************************************************************/

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "drbg/noxtls_drbg.h"
#include "noxtls_common.h"
#include "noxtls_ct.h"
#include "noxtls_ecc.h"

#define CC312_WRAPPER_BASE             ((uintptr_t)0x50844000u)
#define CC312_ENGINE_BASE              ((uintptr_t)0x50845000u)
#define CC312_WRAPPER_ENABLE_OFF       0x500u

#define CC312_PKA_MAP_OFF              0x000u
#define CC312_PKA_OPCODE_OFF           0x080u
#define CC312_PKA_SPECIAL_MAP_OFF      0x084u
#define CC312_PKA_STATUS_OFF           0x088u
#define CC312_PKA_RESET_OFF            0x08cu
#define CC312_PKA_L0_OFF               0x090u
#define CC312_PKA_L1_OFF               0x094u
#define CC312_PKA_PIPE_READY_OFF       0x0b0u
#define CC312_PKA_DONE_OFF             0x0b4u
#define CC312_PKA_SRAM_ADDR_OFF        0x0d4u
#define CC312_PKA_SRAM_WDATA_OFF       0x0d8u
#define CC312_PKA_SRAM_RDATA_OFF       0x0dcu
#define CC312_PKA_SRAM_RADDR_OFF       0x0e4u
#define CC312_PKA_CLOCK_OFF            0x81cu

#define CC312_PKA_REGISTER_BYTES       48u
#define CC312_PKA_REGISTER_WORDS       (CC312_PKA_REGISTER_BYTES / 4u)
#define CC312_PKA_REGISTER_COUNT       32u
#define CC312_PKA_TIMEOUT_SPINS        3000000u
#define CC312_PKA_STATUS_ZERO          (1u << 12)

#define CC312_OP_MOD_ADD               0x06u
#define CC312_OP_MOD_SUB               0x07u
#define CC312_OP_AND                   0x08u
#define CC312_OP_XOR_COMPARE           0x0au
#define CC312_OP_MOD_MUL               0x11u
#define CC312_OP_MOD_EXP               0x13u

#define CC312_REG_N                    0u
#define CC312_REG_NP                   1u
#define CC312_REG_N_MASK               2u
#define CC312_REG_PX                   3u
#define CC312_REG_PY                   4u
#define CC312_REG_RX                   5u
#define CC312_REG_RY                   6u
#define CC312_REG_RZ                   7u
#define CC312_REG_DX                   8u
#define CC312_REG_DY                   9u
#define CC312_REG_DZ                   10u
#define CC312_REG_AX                   11u
#define CC312_REG_AY                   12u
#define CC312_REG_AZ                   13u
#define CC312_REG_B                    14u
#define CC312_REG_B3                   15u
#define CC312_REG_T0                   16u
#define CC312_REG_T1                   17u
#define CC312_REG_T2                   18u
#define CC312_REG_T3                   19u
#define CC312_REG_T4                   20u
#define CC312_REG_T5                   21u
#define CC312_REG_T6                   22u
#define CC312_REG_T7                   23u
#define CC312_REG_T8                   24u
#define CC312_REG_ZINV                 25u
#define CC312_REG_P_MINUS_2            26u
#define CC312_REG_ZERO                 27u
#define CC312_REG_A_SCRATCH            29u
#define CC312_REG_TEMP0                30u
#define CC312_REG_TEMP1                31u

#define CC312_P256_BYTES               32u
#define CC312_BLINDED_SCALAR_WORDS      9u
#define CC312_BLINDED_SCALAR_BITS       (CC312_BLINDED_SCALAR_WORDS * 32u)

static const uint8_t s_p256_prime[CC312_P256_BYTES] = {
    0xffu,0xffu,0xffu,0xffu,0x00u,0x00u,0x00u,0x01u,
    0x00u,0x00u,0x00u,0x00u,0x00u,0x00u,0x00u,0x00u,
    0x00u,0x00u,0x00u,0x00u,0xffu,0xffu,0xffu,0xffu,
    0xffu,0xffu,0xffu,0xffu,0xffu,0xffu,0xffu,0xffu
};

static const uint8_t s_p256_b[CC312_P256_BYTES] = {
    0x5au,0xc6u,0x35u,0xd8u,0xaau,0x3au,0x93u,0xe7u,
    0xb3u,0xebu,0xbdu,0x55u,0x76u,0x98u,0x86u,0xbcu,
    0x65u,0x1du,0x06u,0xb0u,0xccu,0x53u,0xb0u,0xf6u,
    0x3bu,0xceu,0x3cu,0x3eu,0x27u,0xd2u,0x60u,0x4bu
};

static const uint8_t s_p256_p_minus_2[CC312_P256_BYTES] = {
    0xffu,0xffu,0xffu,0xffu,0x00u,0x00u,0x00u,0x01u,
    0x00u,0x00u,0x00u,0x00u,0x00u,0x00u,0x00u,0x00u,
    0x00u,0x00u,0x00u,0x00u,0xffu,0xffu,0xffu,0xffu,
    0xffu,0xffu,0xffu,0xffu,0xffu,0xffu,0xffu,0xfdu
};

/* secp256r1 group order, least-significant word first. */
static const uint32_t s_p256_order_le[8] = {
    0xfc632551u,0xf3b9cac2u,0xa7179e84u,0xbce6faadu,
    0xffffffffu,0xffffffffu,0x00000000u,0xffffffffu
};

/* floor(2^327 / p), least-significant word first. */
static const uint32_t s_p256_barrett_np[3] = {
    0xffffffffu, 0x0000007fu, 0x00000080u
};

static volatile uint32_t s_cc312_lock;
static uint32_t s_cc312_ready;
static uint32_t s_cc312_operations;
static uint32_t s_cc312_fallbacks;
static int32_t s_cc312_last_rc = NOXTLS_RETURN_NOT_SUPPORTED;
static uint32_t s_cc312_last_status;
static uint32_t s_cc312_last_stage;
static uint32_t s_cc312_input_echo_ok;
static uint32_t s_cc312_fault;

static volatile uint32_t *cc312_reg(uint32_t offset)
{
    return (volatile uint32_t *)(CC312_ENGINE_BASE + (uintptr_t)offset);
}

/* Shared with the BlueNox CC312 entropy path through weak platform hooks. */
int noxtls_nordic_crypto_try_acquire(void)
{
#if defined(__GNUC__) || defined(__clang__)
    return __atomic_exchange_n(&s_cc312_lock, 1u, __ATOMIC_ACQUIRE) == 0u;
#else
    if(s_cc312_lock != 0u) return 0;
    s_cc312_lock = 1u;
    return 1;
#endif
}

void noxtls_nordic_crypto_release(void)
{
#if defined(__GNUC__) || defined(__clang__)
    __atomic_store_n(&s_cc312_lock, 0u, __ATOMIC_RELEASE);
#else
    s_cc312_lock = 0u;
#endif
}

static int cc312_wait(uint32_t offset)
{
    uint32_t spin;
    for(spin = 0u; spin < CC312_PKA_TIMEOUT_SPINS; ++spin) {
        if(*cc312_reg(offset) != 0u) return 1;
    }
    s_cc312_fault = 1u;
    return 0;
}

static uint32_t cc312_opcode(uint32_t op, uint32_t a, uint32_t b,
                             uint32_t result, uint32_t length_id,
                             uint32_t discard)
{
    return ((op & 0x1fu) << 27) | ((length_id & 7u) << 24) |
           ((a & 0x1fu) << 18) | ((b & 0x1fu) << 12) |
           ((discard & 1u) << 11) | ((result & 0x1fu) << 6);
}

static void cc312_submit(uint32_t op, uint32_t a, uint32_t b,
                         uint32_t result, uint32_t length_id)
{
    if(s_cc312_fault != 0u || !cc312_wait(CC312_PKA_PIPE_READY_OFF)) return;
    *cc312_reg(CC312_PKA_OPCODE_OFF) = cc312_opcode(op, a, b, result, length_id, 0u);
}

static void cc312_mod_add(uint32_t a, uint32_t b, uint32_t result)
{
    cc312_submit(CC312_OP_MOD_ADD, a, b, result, 1u);
}

static void cc312_mod_sub(uint32_t a, uint32_t b, uint32_t result)
{
    cc312_submit(CC312_OP_MOD_SUB, a, b, result, 1u);
}

static void cc312_mod_mul(uint32_t a, uint32_t b, uint32_t result)
{
    cc312_submit(CC312_OP_MOD_MUL, a, b, result, 0u);
    /* Exact-modulus operations may leave undefined overflow-area bits in the
     * wider physical register.  Clear them before the value is reused by an
     * extended-length ALU operation or comparison. */
    cc312_submit(CC312_OP_AND, result, CC312_REG_N_MASK, result, 1u);
}

static void cc312_mod_exp(uint32_t base, uint32_t exponent, uint32_t result)
{
    cc312_submit(CC312_OP_MOD_EXP, base, exponent, result, 0u);
    cc312_submit(CC312_OP_AND, result, CC312_REG_N_MASK, result, 1u);
}

static void cc312_mul_a(uint32_t input, uint32_t result)
{
    uint32_t doubled = result;

    /* P-256 has a = -3. */
    if(input == result) doubled = CC312_REG_A_SCRATCH;
    cc312_mod_add(input, input, doubled);
    cc312_mod_add(doubled, input, result);
    cc312_mod_sub(CC312_REG_ZERO, result, result);
}

static uint32_t cc312_map(uint32_t reg)
{
    return *cc312_reg(CC312_PKA_MAP_OFF + reg * 4u);
}

static void cc312_sram_write_words(uint32_t address,
                                   const uint32_t *words, uint32_t count)
{
    uint32_t i;
    if(!cc312_wait(CC312_PKA_DONE_OFF)) return;
    *cc312_reg(CC312_PKA_SRAM_ADDR_OFF) = address;
    if(!cc312_wait(CC312_PKA_DONE_OFF)) return;
    for(i = 0u; i < count; ++i) {
        *cc312_reg(CC312_PKA_SRAM_WDATA_OFF) = words[i];
        if(!cc312_wait(CC312_PKA_DONE_OFF)) return;
    }
}

static void cc312_write_le(uint32_t reg, const uint32_t *words, uint32_t count)
{
    uint32_t padded[CC312_PKA_REGISTER_WORDS];
    uint32_t i;
    memset(padded, 0, sizeof(padded));
    for(i = 0u; i < count && i < CC312_PKA_REGISTER_WORDS; ++i) padded[i] = words[i];
    cc312_sram_write_words(cc312_map(reg), padded, CC312_PKA_REGISTER_WORDS);
    noxtls_secure_zero(padded, sizeof(padded));
}

static void cc312_write_be(uint32_t reg, const uint8_t value[CC312_P256_BYTES])
{
    uint32_t words[CC312_PKA_REGISTER_WORDS];
    uint32_t i;
    memset(words, 0, sizeof(words));
    for(i = 0u; i < 8u; ++i) {
        uint32_t off = CC312_P256_BYTES - 4u * (i + 1u);
        words[i] = ((uint32_t)value[off] << 24) |
                   ((uint32_t)value[off + 1u] << 16) |
                   ((uint32_t)value[off + 2u] << 8) |
                   (uint32_t)value[off + 3u];
    }
    cc312_write_le(reg, words, 8u);
    noxtls_secure_zero(words, sizeof(words));
}

static void cc312_read_be(uint32_t reg, uint8_t value[CC312_P256_BYTES])
{
    uint32_t i;
    if(!cc312_wait(CC312_PKA_DONE_OFF)) return;
    *cc312_reg(CC312_PKA_SRAM_RADDR_OFF) = cc312_map(reg);
    if(!cc312_wait(CC312_PKA_DONE_OFF)) return;
    for(i = 0u; i < 8u; ++i) {
        uint32_t word = *cc312_reg(CC312_PKA_SRAM_RDATA_OFF);
        uint32_t off = CC312_P256_BYTES - 4u * (i + 1u);
        value[off] = (uint8_t)(word >> 24);
        value[off + 1u] = (uint8_t)(word >> 16);
        value[off + 2u] = (uint8_t)(word >> 8);
        value[off + 3u] = (uint8_t)word;
    }
}

static void cc312_clear_sram(void)
{
    uint32_t zeros[CC312_PKA_REGISTER_WORDS];
    uint32_t reg;

    /* A failed pipeline operation must not turn cleanup into 32 consecutive
     * full-length timeouts.  Reset once, then either clear the complete mapped
     * SRAM window or give up after one additional bounded wait. */
    if(s_cc312_fault != 0u) {
        *cc312_reg(CC312_PKA_RESET_OFF) = 1u;
        s_cc312_fault = 0u;
        if(!cc312_wait(CC312_PKA_DONE_OFF)) return;
    }
    memset(zeros, 0, sizeof(zeros));
    for(reg = 0u; reg < CC312_PKA_REGISTER_COUNT; ++reg) {
        cc312_sram_write_words(reg * CC312_PKA_REGISTER_WORDS,
                               zeros, CC312_PKA_REGISTER_WORDS);
        if(s_cc312_fault != 0u) break;
    }
}

static int cc312_is_zero(uint32_t reg)
{
    uint32_t opcode;
    if(s_cc312_fault != 0u || !cc312_wait(CC312_PKA_PIPE_READY_OFF)) return 0;
    opcode = cc312_opcode(CC312_OP_XOR_COMPARE, reg, 0u, 0u, 1u, 1u);
    opcode |= (1u << 17); /* B is immediate zero. */
    *cc312_reg(CC312_PKA_OPCODE_OFF) = opcode;
    if(!cc312_wait(CC312_PKA_DONE_OFF)) return 0;
    s_cc312_last_status = *cc312_reg(CC312_PKA_STATUS_OFF);
    return (s_cc312_last_status & CC312_PKA_STATUS_ZERO) != 0u;
}

static int cc312_equal(uint32_t a, uint32_t b)
{
    if(s_cc312_fault != 0u || !cc312_wait(CC312_PKA_PIPE_READY_OFF)) return 0;
    *cc312_reg(CC312_PKA_OPCODE_OFF) =
        cc312_opcode(CC312_OP_XOR_COMPARE, a, b, 0u, 1u, 1u);
    if(!cc312_wait(CC312_PKA_DONE_OFF)) return 0;
    s_cc312_last_status = *cc312_reg(CC312_PKA_STATUS_OFF);
    return (s_cc312_last_status & CC312_PKA_STATUS_ZERO) != 0u;
}

static int cc312_equal_immediate(uint32_t reg, uint32_t immediate)
{
    uint32_t opcode;
    if(s_cc312_fault != 0u || immediate > 15u ||
       !cc312_wait(CC312_PKA_PIPE_READY_OFF)) return 0;
    opcode = cc312_opcode(CC312_OP_XOR_COMPARE, reg, immediate, 0u, 1u, 1u);
    opcode |= (1u << 17);
    *cc312_reg(CC312_PKA_OPCODE_OFF) = opcode;
    if(!cc312_wait(CC312_PKA_DONE_OFF)) return 0;
    s_cc312_last_status = *cc312_reg(CC312_PKA_STATUS_OFF);
    return (s_cc312_last_status & CC312_PKA_STATUS_ZERO) != 0u;
}

static int cc312_init(void)
{
    uint32_t reg;
    *(volatile uint32_t *)(CC312_WRAPPER_BASE + CC312_WRAPPER_ENABLE_OFF) = 1u;
    *cc312_reg(CC312_PKA_CLOCK_OFF) = 1u;
    *cc312_reg(CC312_PKA_RESET_OFF) = 1u;
    if(!cc312_wait(CC312_PKA_DONE_OFF)) return 0;

    *cc312_reg(CC312_PKA_L0_OFF) = 256u;
    *cc312_reg(CC312_PKA_L1_OFF) = CC312_PKA_REGISTER_BYTES * 8u;
    for(reg = 0u; reg < CC312_PKA_REGISTER_COUNT; ++reg) {
        *cc312_reg(CC312_PKA_MAP_OFF + reg * 4u) =
            reg * CC312_PKA_REGISTER_WORDS;
    }
    *cc312_reg(CC312_PKA_SPECIAL_MAP_OFF) =
        CC312_REG_N | (CC312_REG_NP << 5) |
        (CC312_REG_TEMP0 << 10) | (CC312_REG_TEMP1 << 15);

    cc312_write_be(CC312_REG_N, s_p256_prime);
    cc312_write_le(CC312_REG_NP, s_p256_barrett_np, 3u);
    {
        uint32_t modulus_mask[8];
        for(reg = 0u; reg < 8u; ++reg) modulus_mask[reg] = 0xffffffffu;
        cc312_write_le(CC312_REG_N_MASK, modulus_mask, 8u);
        noxtls_secure_zero(modulus_mask, sizeof(modulus_mask));
    }
    cc312_write_be(CC312_REG_B, s_p256_b);
    cc312_write_be(CC312_REG_P_MINUS_2, s_p256_p_minus_2);
    cc312_write_le(CC312_REG_ZERO, NULL, 0u);
    cc312_mod_add(CC312_REG_B, CC312_REG_B, CC312_REG_B3);
    cc312_mod_add(CC312_REG_B3, CC312_REG_B, CC312_REG_B3);
    return cc312_wait(CC312_PKA_DONE_OFF) && s_cc312_fault == 0u;
}

/* Complete, exception-free projective doubling for short-Weierstrass a=-3.
 * Coordinates are affine x=X/Z and y=Y/Z. */
static void cc312_double(void)
{
    cc312_mod_mul(CC312_REG_RX, CC312_REG_RX, CC312_REG_T0); /* xx */
    cc312_mod_mul(CC312_REG_RY, CC312_REG_RY, CC312_REG_T1); /* yy */
    cc312_mod_mul(CC312_REG_RZ, CC312_REG_RZ, CC312_REG_T2); /* zz */
    cc312_mod_mul(CC312_REG_RX, CC312_REG_RY, CC312_REG_T3);
    cc312_mod_add(CC312_REG_T3, CC312_REG_T3, CC312_REG_T3); /* xy2 */
    cc312_mod_mul(CC312_REG_RX, CC312_REG_RZ, CC312_REG_T4);
    cc312_mod_add(CC312_REG_T4, CC312_REG_T4, CC312_REG_T4); /* xz2 */
    cc312_mul_a(CC312_REG_T4, CC312_REG_T5);                 /* axz2 */
    cc312_mod_mul(CC312_REG_T2, CC312_REG_B3, CC312_REG_T6);
    cc312_mod_add(CC312_REG_T5, CC312_REG_T6, CC312_REG_T6); /* bzz3 */
    cc312_mod_sub(CC312_REG_T1, CC312_REG_T6, CC312_REG_T7); /* yy-bzz3 */
    cc312_mod_add(CC312_REG_T1, CC312_REG_T6, CC312_REG_T8); /* yy+bzz3 */
    cc312_mod_mul(CC312_REG_T8, CC312_REG_T7, CC312_REG_DY);
    cc312_mod_mul(CC312_REG_T7, CC312_REG_T3, CC312_REG_DX);
    cc312_mod_mul(CC312_REG_T4, CC312_REG_B3, CC312_REG_T6); /* bxz3 */
    cc312_mul_a(CC312_REG_T2, CC312_REG_T5);                 /* azz */
    cc312_mod_sub(CC312_REG_T0, CC312_REG_T5, CC312_REG_T8);
    cc312_mul_a(CC312_REG_T8, CC312_REG_T8);
    cc312_mod_add(CC312_REG_T8, CC312_REG_T6, CC312_REG_T8); /* b3_xz */
    cc312_mod_add(CC312_REG_T0, CC312_REG_T0, CC312_REG_T6);
    cc312_mod_add(CC312_REG_T6, CC312_REG_T0, CC312_REG_T6);
    cc312_mod_add(CC312_REG_T6, CC312_REG_T5, CC312_REG_T6); /* 3xx+azz */
    cc312_mod_mul(CC312_REG_T6, CC312_REG_T8, CC312_REG_T6);
    cc312_mod_add(CC312_REG_DY, CC312_REG_T6, CC312_REG_DY);
    cc312_mod_mul(CC312_REG_RY, CC312_REG_RZ, CC312_REG_T5);
    cc312_mod_add(CC312_REG_T5, CC312_REG_T5, CC312_REG_T5); /* yz2 */
    cc312_mod_mul(CC312_REG_T8, CC312_REG_T5, CC312_REG_T6);
    cc312_mod_sub(CC312_REG_DX, CC312_REG_T6, CC312_REG_DX);
    cc312_mod_mul(CC312_REG_T5, CC312_REG_T1, CC312_REG_T6);
    cc312_mod_add(CC312_REG_T6, CC312_REG_T6, CC312_REG_T6);
    cc312_mod_add(CC312_REG_T6, CC312_REG_T6, CC312_REG_DZ); /* 4*yz2*yy */
}

/* Complete mixed addition: A = D + affine P. */
static void cc312_add_mixed(void)
{
    cc312_mod_mul(CC312_REG_DX, CC312_REG_PX, CC312_REG_T0); /* xx */
    cc312_mod_mul(CC312_REG_DY, CC312_REG_PY, CC312_REG_T1); /* yy */
    cc312_mod_add(CC312_REG_DX, CC312_REG_DY, CC312_REG_T2);
    cc312_mod_add(CC312_REG_PX, CC312_REG_PY, CC312_REG_T3);
    cc312_mod_mul(CC312_REG_T2, CC312_REG_T3, CC312_REG_T2);
    cc312_mod_add(CC312_REG_T0, CC312_REG_T1, CC312_REG_T3);
    cc312_mod_sub(CC312_REG_T2, CC312_REG_T3, CC312_REG_T2); /* xy pairs */
    cc312_mod_mul(CC312_REG_PX, CC312_REG_DZ, CC312_REG_T3);
    cc312_mod_add(CC312_REG_T3, CC312_REG_DX, CC312_REG_T3); /* xz pairs */
    cc312_mod_mul(CC312_REG_PY, CC312_REG_DZ, CC312_REG_T4);
    cc312_mod_add(CC312_REG_T4, CC312_REG_DY, CC312_REG_T4); /* yz pairs */
    cc312_mul_a(CC312_REG_T3, CC312_REG_T5);                 /* axz */
    cc312_mod_mul(CC312_REG_DZ, CC312_REG_B3, CC312_REG_T6);
    cc312_mod_add(CC312_REG_T5, CC312_REG_T6, CC312_REG_T6); /* bz3 */
    cc312_mod_sub(CC312_REG_T1, CC312_REG_T6, CC312_REG_T7);
    cc312_mod_add(CC312_REG_T1, CC312_REG_T6, CC312_REG_T8);
    cc312_mul_a(CC312_REG_DZ, CC312_REG_T5);                 /* azz */
    cc312_mod_add(CC312_REG_T0, CC312_REG_T0, CC312_REG_T6);
    cc312_mod_add(CC312_REG_T6, CC312_REG_T0, CC312_REG_T6);
    cc312_mod_add(CC312_REG_T6, CC312_REG_T5, CC312_REG_T6); /* 3xx+azz */
    cc312_mod_sub(CC312_REG_T0, CC312_REG_T5, CC312_REG_T1);
    cc312_mul_a(CC312_REG_T1, CC312_REG_T1);
    cc312_mod_mul(CC312_REG_T3, CC312_REG_B3, CC312_REG_T3);
    cc312_mod_add(CC312_REG_T1, CC312_REG_T3, CC312_REG_T3); /* b3*xz pairs */
    cc312_mod_mul(CC312_REG_T7, CC312_REG_T2, CC312_REG_T1);
    cc312_mod_mul(CC312_REG_T4, CC312_REG_T3, CC312_REG_T5);
    cc312_mod_sub(CC312_REG_T1, CC312_REG_T5, CC312_REG_AX);
    cc312_mod_mul(CC312_REG_T8, CC312_REG_T7, CC312_REG_T1);
    cc312_mod_mul(CC312_REG_T6, CC312_REG_T3, CC312_REG_T5);
    cc312_mod_add(CC312_REG_T1, CC312_REG_T5, CC312_REG_AY);
    cc312_mod_mul(CC312_REG_T8, CC312_REG_T4, CC312_REG_T1);
    cc312_mod_mul(CC312_REG_T2, CC312_REG_T6, CC312_REG_T5);
    cc312_mod_add(CC312_REG_T1, CC312_REG_T5, CC312_REG_AZ);
}

static void cc312_select_result(uint32_t bit)
{
    uint32_t mask = 0u - (bit & 1u);
    uint32_t r[3];
    uint32_t d[3];
    uint32_t a[3];
    uint32_t i;
    if(!cc312_wait(CC312_PKA_DONE_OFF)) return;
    for(i = 0u; i < 3u; ++i) {
        r[i] = cc312_map(CC312_REG_RX + i);
        d[i] = cc312_map(CC312_REG_DX + i);
        a[i] = cc312_map(CC312_REG_AX + i);
    }
    for(i = 0u; i < 3u; ++i) {
        uint32_t chosen = (d[i] & ~mask) | (a[i] & mask);
        uint32_t new_d = (r[i] & ~mask) | (d[i] & mask);
        uint32_t new_a = (a[i] & ~mask) | (r[i] & mask);
        *cc312_reg(CC312_PKA_MAP_OFF + (CC312_REG_RX + i) * 4u) = chosen;
        *cc312_reg(CC312_PKA_MAP_OFF + (CC312_REG_DX + i) * 4u) = new_d;
        *cc312_reg(CC312_PKA_MAP_OFF + (CC312_REG_AX + i) * 4u) = new_a;
    }
}

static void cc312_make_blinded_scalar(uint32_t out[CC312_BLINDED_SCALAR_WORDS],
                                      const uint8_t scalar[CC312_P256_BYTES],
                                      uint32_t multiplier)
{
    uint64_t carry = 0u;
    uint32_t i;
    for(i = 0u; i < 8u; ++i) {
        uint64_t product = (uint64_t)s_p256_order_le[i] * multiplier + carry;
        out[i] = (uint32_t)product;
        carry = product >> 32;
    }
    out[8] = (uint32_t)carry;
    carry = 0u;
    for(i = 0u; i < 8u; ++i) {
        uint32_t off = CC312_P256_BYTES - 4u * (i + 1u);
        uint32_t word = ((uint32_t)scalar[off] << 24) |
                        ((uint32_t)scalar[off + 1u] << 16) |
                        ((uint32_t)scalar[off + 2u] << 8) |
                        (uint32_t)scalar[off + 3u];
        uint64_t sum = (uint64_t)out[i] + word + carry;
        out[i] = (uint32_t)sum;
        carry = sum >> 32;
    }
    out[8] += (uint32_t)carry;
}

static int cc312_validate_point(uint32_t x, uint32_t y)
{
    /* y^2 == x^3 - 3x + b */
    cc312_mod_mul(y, y, CC312_REG_T0);
    cc312_mod_mul(x, x, CC312_REG_T1);
    cc312_mod_mul(CC312_REG_T1, x, CC312_REG_T1);
    cc312_mul_a(x, CC312_REG_T2);
    cc312_mod_add(CC312_REG_T1, CC312_REG_T2, CC312_REG_T1);
    cc312_mod_add(CC312_REG_T1, CC312_REG_B, CC312_REG_T1);
    return cc312_equal(CC312_REG_T0, CC312_REG_T1);
}

static int cc312_is_p256(const ecc_curve_params_t *curve)
{
    return curve != NULL && curve->size == CC312_P256_BYTES && curve->p != NULL &&
           memcmp(curve->p, s_p256_prime, sizeof(s_p256_prime)) == 0;
}

int noxtls_ecc_accel_is_ready(void) { return s_cc312_ready != 0u; }
uint32_t noxtls_ecc_accel_operation_count(void) { return s_cc312_operations; }
uint32_t noxtls_ecc_accel_fallback_count(void) { return s_cc312_fallbacks; }
void noxtls_ecc_accel_note_fallback(void) { ++s_cc312_fallbacks; }
int32_t noxtls_ecc_accel_last_rc(void) { return s_cc312_last_rc; }
uint32_t noxtls_ecc_accel_last_status(void) { return s_cc312_last_status; }
uint32_t noxtls_ecc_accel_last_stage(void) { return s_cc312_last_stage; }
int noxtls_ecc_accel_input_echo_ok(void) { return s_cc312_input_echo_ok != 0u; }

noxtls_return_t noxtls_ecc_point_multiply_accel_port(ecc_point_t *result,
                                                      const uint8_t *scalar,
                                                      const ecc_point_t *point,
                                                      const ecc_curve_params_t *curve)
{
    uint32_t blinded[CC312_BLINDED_SCALAR_WORDS];
    uint8_t entropy[4];
    uint8_t echo_x[CC312_P256_BYTES];
    uint8_t echo_y[CC312_P256_BYTES];
    uint32_t multiplier;
    int32_t bit;
    noxtls_return_t rc = NOXTLS_RETURN_NOT_SUPPORTED;

    if(result == NULL || scalar == NULL || point == NULL || !cc312_is_p256(curve) ||
       point->size != CC312_P256_BYTES) return NOXTLS_RETURN_NOT_SUPPORTED;
    s_cc312_last_stage = 1u;
    s_cc312_last_status = 0u;
    s_cc312_input_echo_ok = 0u;
    s_cc312_fault = 0u;
    memset(blinded, 0, sizeof(blinded));
    memset(entropy, 0, sizeof(entropy));

    if(noxtls_drbg_get_entropy(entropy, sizeof(entropy)) != NOXTLS_RETURN_SUCCESS) goto cleanup_stack;
    multiplier = ((uint32_t)entropy[0] << 24) | ((uint32_t)entropy[1] << 16) |
                 ((uint32_t)entropy[2] << 8) | (uint32_t)entropy[3];
    multiplier |= 0x80000001u;
    cc312_make_blinded_scalar(blinded, scalar, multiplier);
    noxtls_secure_zero(entropy, sizeof(entropy));

    if(!noxtls_nordic_crypto_try_acquire()) goto cleanup_stack;
    s_cc312_last_stage = 2u;
    if(!cc312_init()) goto cleanup_hw;
    s_cc312_last_stage = 3u;

    cc312_write_be(CC312_REG_PX, point->x);
    cc312_write_be(CC312_REG_PY, point->y);
    cc312_read_be(CC312_REG_PX, echo_x);
    cc312_read_be(CC312_REG_PY, echo_y);
    s_cc312_input_echo_ok =
        (memcmp(echo_x, point->x, sizeof(echo_x)) == 0 &&
         memcmp(echo_y, point->y, sizeof(echo_y)) == 0) ? 1u : 0u;
    noxtls_secure_zero(echo_x, sizeof(echo_x));
    noxtls_secure_zero(echo_y, sizeof(echo_y));
    if(s_cc312_input_echo_ok == 0u ||
       !cc312_validate_point(CC312_REG_PX, CC312_REG_PY)) goto cleanup_hw;
    s_cc312_last_stage = 4u;

    /* Projective identity (0:1:0). */
    cc312_write_le(CC312_REG_RX, NULL, 0u);
    cc312_write_le(CC312_REG_RY, NULL, 0u);
    cc312_write_le(CC312_REG_RZ, NULL, 0u);
    {
        uint32_t one = 1u;
        cc312_write_le(CC312_REG_RY, &one, 1u);
    }

    /* Every scalar follows the same 288 doublings, additions, and selections.
     * k + r*n is group-equivalent to k and hides the original scalar trace. */
    for(bit = (int32_t)CC312_BLINDED_SCALAR_BITS - 1; bit >= 0; --bit) {
        uint32_t selected = (blinded[(uint32_t)bit >> 5] >> ((uint32_t)bit & 31u)) & 1u;
        cc312_double();
        cc312_add_mixed();
        cc312_select_result(selected);
        if(s_cc312_fault != 0u) goto cleanup_hw;
    }
    s_cc312_last_stage = 5u;
    if(cc312_is_zero(CC312_REG_RZ)) goto cleanup_hw;
    s_cc312_last_stage = 51u;

    cc312_mod_exp(CC312_REG_RZ, CC312_REG_P_MINUS_2, CC312_REG_ZINV);
    if(!cc312_wait(CC312_PKA_DONE_OFF) || s_cc312_fault != 0u) goto cleanup_hw;
    s_cc312_last_stage = 52u;
    cc312_mod_mul(CC312_REG_RZ, CC312_REG_ZINV, CC312_REG_T0);
    if(!cc312_equal_immediate(CC312_REG_T0, 1u)) goto cleanup_hw;
    s_cc312_last_stage = 53u;
    cc312_mod_mul(CC312_REG_RX, CC312_REG_ZINV, CC312_REG_AX);
    cc312_mod_mul(CC312_REG_RY, CC312_REG_ZINV, CC312_REG_AY);
    if(!cc312_wait(CC312_PKA_DONE_OFF) || s_cc312_fault != 0u) goto cleanup_hw;
    s_cc312_last_stage = 54u;
    if(!cc312_validate_point(CC312_REG_AX, CC312_REG_AY)) goto cleanup_hw;
    s_cc312_last_stage = 6u;

    cc312_read_be(CC312_REG_AX, result->x);
    cc312_read_be(CC312_REG_AY, result->y);
    result->size = CC312_P256_BYTES;
    ++s_cc312_operations;
    s_cc312_ready = 1u;
    rc = NOXTLS_RETURN_SUCCESS;
    s_cc312_last_stage = 7u;

cleanup_hw:
    s_cc312_last_status = *cc312_reg(CC312_PKA_STATUS_OFF);
    cc312_clear_sram();
    *cc312_reg(CC312_PKA_CLOCK_OFF) = 0u;
    if(rc != NOXTLS_RETURN_SUCCESS) s_cc312_ready = 0u;
    noxtls_nordic_crypto_release();
cleanup_stack:
    noxtls_secure_zero(blinded, sizeof(blinded));
    noxtls_secure_zero(entropy, sizeof(entropy));
    noxtls_secure_zero(echo_x, sizeof(echo_x));
    noxtls_secure_zero(echo_y, sizeof(echo_y));
    s_cc312_last_rc = rc;
    return rc;
}
