/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
* This file is part of the NoxTLS Library.
*
* Licensed under the GNU General Public License v2.0 or later,
* or alternatively under a commercial license from
* Argenox Technologies LLC.
*
* See the LICENSE file in the project root for full details.
* CONTACT: info@argenox.com
*
*
* File:    noxtls_efr32_core.c
* Summary: EFR32xG2x backend core: register access seam, DMA windows, engine ownership
*
*****************************************************************************/

/**
 * @file noxtls_efr32_core.c
 * @brief Register access seam, DMA windows, run-time enables, statistics and
 *        internal ownership flags of the EFR32xG2x backend.
 * @ingroup noxtls_efr32
 */

#include <stddef.h>
#include <stdint.h>

#include "noxtls_efr32_core.h"

/** @brief Flag value: free. */
#define NOXTLS_EFR32_FLAG_FREE      0U
/** @brief Flag value: taken. */
#define NOXTLS_EFR32_FLAG_TAKEN     1U

/**
 * @brief Default 32-bit volatile register read.
 * @internal
 *
 * @param[in] addr Address.
 *
 * @return Value.
 */
static uint32_t noxtls_efr32_mmio_read32(uintptr_t addr)
{
    /* MISRA C:2025 Rule 11.4 deviation: memory-mapped register access. */
    return *((const volatile uint32_t *)addr);
}

/**
 * @brief Default 32-bit volatile register write.
 * @internal
 *
 * @param[in] addr  Address.
 * @param[in] value Value.
 */
static void noxtls_efr32_mmio_write32(uintptr_t addr, uint32_t value)
{
    /* MISRA C:2025 Rule 11.4 deviation: memory-mapped register access. */
    *((volatile uint32_t *)addr) = value;
}

/** Default register access layer. */
static const noxtls_efr32_io_t s_noxtls_efr32_default_io = { noxtls_efr32_mmio_read32, noxtls_efr32_mmio_write32 };

/** Active register access layer. */
static noxtls_efr32_io_t s_noxtls_efr32_io = { noxtls_efr32_mmio_read32, noxtls_efr32_mmio_write32 };

/** Initializer of the build default instances. */
#define NOXTLS_EFR32_HW_DEFAULT_INIT { (uintptr_t)NOXTLS_EFR32_CONFIG_RADIOAES_BASE, \
                                       (uintptr_t)NOXTLS_EFR32_CONFIG_SEMAILBOX_BASE, \
                                       (uintptr_t)NOXTLS_EFR32_CONFIG_CMU_BASE }

/** Build default instances. */
static const noxtls_efr32_hw_t s_noxtls_efr32_default_hw = NOXTLS_EFR32_HW_DEFAULT_INIT;

/** Active instances. */
static noxtls_efr32_hw_t s_noxtls_efr32_hw = NOXTLS_EFR32_HW_DEFAULT_INIT;

/** Counters. */
static noxtls_efr32_stats_t s_noxtls_efr32_stats;

/** Run-time enables (bit per unit). */
static uint32_t s_noxtls_efr32_enabled = NOXTLS_EFR32_UNIT_ALL;

/** Internal ownership flags of the two units. */
static volatile uint32_t s_noxtls_efr32_flag_aes;
/** Internal ownership flag of the Secure Engine. */
static volatile uint32_t s_noxtls_efr32_flag_se;

/** DMA window overrides (size 0: build defaults). */
static uintptr_t s_noxtls_efr32_in_start;
/** Input window bytes override. */
static uintptr_t s_noxtls_efr32_in_size;
/** Output window start override. */
static uintptr_t s_noxtls_efr32_out_start;
/** Output window bytes override. */
static uintptr_t s_noxtls_efr32_out_size;
/** Required buffer alignment. */
static uint32_t s_noxtls_efr32_align = NOXTLS_EFR32_CONFIG_DMA_ALIGN;

/**
 * @brief Pointer to the ownership flag of a unit.
 * @internal
 *
 * @param[in] unit Unit selector.
 *
 * @return Flag storage.
 */
static volatile uint32_t *noxtls_efr32_flag_of(uint32_t unit)
{
    return (unit == NOXTLS_EFR32_UNIT_AES) ? &s_noxtls_efr32_flag_aes : &s_noxtls_efr32_flag_se;
}

uint8_t noxtls_efr32_flag_op(uint32_t unit, uint8_t take)
{
    volatile uint32_t *flag = noxtls_efr32_flag_of(unit);
    uint8_t ok = 1U;

    if (take != 0U) {
#if defined(__GNUC__) || defined(__clang__)
        ok = (__atomic_exchange_n(flag, NOXTLS_EFR32_FLAG_TAKEN, __ATOMIC_ACQUIRE) == NOXTLS_EFR32_FLAG_FREE) ? 1U : 0U;
#else
        if (*flag == NOXTLS_EFR32_FLAG_FREE) {
            *flag = NOXTLS_EFR32_FLAG_TAKEN;
        } else {
            ok = 0U;
        }
#endif
    } else {
#if defined(__GNUC__) || defined(__clang__)
        __atomic_store_n(flag, NOXTLS_EFR32_FLAG_FREE, __ATOMIC_RELEASE);
#else
        *flag = NOXTLS_EFR32_FLAG_FREE;
#endif
    }
    return ok;
}

/**
 * @brief Whether either internal ownership flag is taken.
 * @internal
 *
 * @return 1 when a unit is owned.
 */
static uint8_t noxtls_efr32_any_owned(void)
{
    return ((s_noxtls_efr32_flag_aes != NOXTLS_EFR32_FLAG_FREE) || (s_noxtls_efr32_flag_se != NOXTLS_EFR32_FLAG_FREE)) ?
           1U : 0U;
}

noxtls_return_t noxtls_efr32_io_set(const noxtls_efr32_io_t *io)
{
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if (noxtls_efr32_any_owned() != 0U) {
        rc = NOXTLS_RETURN_FAILED;
    } else if (io == NULL) {
        s_noxtls_efr32_io = s_noxtls_efr32_default_io;
    } else if ((io->read32 == NULL) || (io->write32 == NULL)) {
        rc = NOXTLS_RETURN_NULL;
    } else {
        s_noxtls_efr32_io = *io;
    }
    return rc;
}

noxtls_return_t noxtls_efr32_hw_set(const noxtls_efr32_hw_t *hw)
{
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if (noxtls_efr32_any_owned() != 0U) {
        rc = NOXTLS_RETURN_FAILED;
    } else {
        s_noxtls_efr32_hw = (hw != NULL) ? *hw : s_noxtls_efr32_default_hw;
    }
    return rc;
}

void noxtls_efr32_set_enabled(uint32_t units, uint8_t enabled)
{
    if (enabled != 0U) {
        s_noxtls_efr32_enabled |= (units & NOXTLS_EFR32_UNIT_ALL);
    } else {
        s_noxtls_efr32_enabled &= ~(units & NOXTLS_EFR32_UNIT_ALL);
    }
}

uint8_t noxtls_efr32_is_enabled(uint32_t unit)
{
    return ((s_noxtls_efr32_enabled & unit) != 0U) ? 1U : 0U;
}

/** Operations refused at run time. */
static uint32_t s_noxtls_efr32_ops_off;

void noxtls_efr32_set_ops_disabled(uint32_t ops)
{
    s_noxtls_efr32_ops_off = ops;
}

uint8_t noxtls_efr32_op_allowed(uint32_t op)
{
    return ((s_noxtls_efr32_ops_off & op) == 0U) ? 1U : 0U;
}

const noxtls_efr32_stats_t *noxtls_efr32_stats(void)
{
    return &s_noxtls_efr32_stats;
}

noxtls_efr32_stats_t *noxtls_efr32_stats_rw(void)
{
    return &s_noxtls_efr32_stats;
}

void noxtls_efr32_reset_stats(void)
{
    noxtls_efr32_wipe(&s_noxtls_efr32_stats, (uint32_t)sizeof(s_noxtls_efr32_stats));
}

uint32_t noxtls_efr32_aes_rd(uint32_t off)
{
    return s_noxtls_efr32_io.read32(s_noxtls_efr32_hw.aes + (uintptr_t)off);
}

void noxtls_efr32_aes_wr(uint32_t off, uint32_t value)
{
    s_noxtls_efr32_io.write32(s_noxtls_efr32_hw.aes + (uintptr_t)off, value);
}

uint32_t noxtls_efr32_sem_rd(uint32_t off)
{
    return s_noxtls_efr32_io.read32(s_noxtls_efr32_hw.sem + (uintptr_t)off);
}

void noxtls_efr32_sem_wr(uint32_t off, uint32_t value)
{
    s_noxtls_efr32_io.write32(s_noxtls_efr32_hw.sem + (uintptr_t)off, value);
}

void noxtls_efr32_cmu_wr(uint32_t off, uint32_t value)
{
    s_noxtls_efr32_io.write32(s_noxtls_efr32_hw.cmu + (uintptr_t)off, value);
}

void noxtls_efr32_barrier(void)
{
#if defined(__ARM_ARCH)
    /* MISRA C:2025 Dir 4.3 deviation: encapsulated inline assembly (Armv8-M DSB). */
    __asm volatile ("dsb 0xF" : : : "memory");
#elif defined(__GNUC__) || defined(__clang__)
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
#endif
}

void noxtls_efr32_wipe(void *buf, uint32_t len)
{
    volatile uint8_t *p = (volatile uint8_t *)buf;
    uint32_t i;

    for (i = 0U; i < len; i++) {
        p[i] = 0U;
    }
}

uint8_t noxtls_efr32_is_zero(const uint8_t *buf, uint32_t len)
{
    uint8_t acc = 0U;
    uint32_t i;

    for (i = 0U; i < len; i++) {
        acc |= buf[i];
    }
    return (acc == 0U) ? 1U : 0U;
}

uint64_t noxtls_efr32_us_to_spins(uint32_t timeout_us)
{
    uint64_t spins = (uint64_t)timeout_us * (uint64_t)NOXTLS_EFR32_CONFIG_SPINS_PER_US;

    return (spins == 0U) ? 1U : spins;
}

/**
 * @brief Whether [buf, buf + len) lies inside [start, start + size) and is aligned.
 * @internal
 *
 * @param[in] buf   Buffer.
 * @param[in] len   Bytes.
 * @param[in] start Window start.
 * @param[in] size  Window size.
 *
 * @return 1 inside and aligned, 0 otherwise.
 */
static uint8_t noxtls_efr32_in_window(const void *buf, uint32_t len, uintptr_t start, uintptr_t size)
{
    uintptr_t addr = (uintptr_t)buf;
    uint8_t ok = 0U;

    if ((buf != NULL) && ((addr % (uintptr_t)s_noxtls_efr32_align) == 0U) && (addr >= start) &&
        ((addr - start) <= size) && ((uintptr_t)len <= (size - (addr - start)))) {
        ok = 1U;
    }
    return ok;
}

uint8_t noxtls_efr32_dma_in_ok(const void *buf, uint32_t len)
{
    uintptr_t start = (s_noxtls_efr32_in_size != 0U) ? s_noxtls_efr32_in_start : (uintptr_t)NOXTLS_EFR32_CONFIG_DMA_IN_START;
    uintptr_t size = (s_noxtls_efr32_in_size != 0U) ? s_noxtls_efr32_in_size : (uintptr_t)NOXTLS_EFR32_CONFIG_DMA_IN_SIZE;

    return noxtls_efr32_in_window(buf, len, start, size);
}

uint8_t noxtls_efr32_dma_out_ok(const void *buf, uint32_t len)
{
    uintptr_t start = (s_noxtls_efr32_in_size != 0U) ? s_noxtls_efr32_out_start :
                      (uintptr_t)NOXTLS_EFR32_CONFIG_DMA_OUT_START;
    uintptr_t size = (s_noxtls_efr32_in_size != 0U) ? s_noxtls_efr32_out_size : (uintptr_t)NOXTLS_EFR32_CONFIG_DMA_OUT_SIZE;

    return noxtls_efr32_in_window(buf, len, start, size);
}

void noxtls_efr32_set_dma_window(uintptr_t in_start, uintptr_t in_size, uintptr_t out_start, uintptr_t out_size,
                                 uint32_t align)
{
    if (in_size == 0U) {
        s_noxtls_efr32_in_start = 0U;
        s_noxtls_efr32_in_size = 0U;
        s_noxtls_efr32_out_start = 0U;
        s_noxtls_efr32_out_size = 0U;
        s_noxtls_efr32_align = NOXTLS_EFR32_CONFIG_DMA_ALIGN;
    } else {
        s_noxtls_efr32_in_start = in_start;
        s_noxtls_efr32_in_size = in_size;
        s_noxtls_efr32_out_start = out_start;
        s_noxtls_efr32_out_size = out_size;
        s_noxtls_efr32_align = (align == 0U) ? 1U : align;
    }
}
