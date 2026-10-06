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
* File:    noxtls_nrf54_cracen.c
* Summary: nRF54L CRACEN core: ownership, power, waits, interrupt, CryptoMaster jobs
*
*****************************************************************************/

/**
 * @file noxtls_nrf54_cracen.c
 * @brief CRACEN core shared by the nRF54L backend modules.
 * @ingroup noxtls_nrf54
 *
 * CryptoMaster job (nRF54L product specifications, CRACEN chapter): with the
 * CryptoMaster powered, enable its push-stopped and bus-error interrupt
 * sources, write the first fetch / push descriptor addresses, select
 * scatter/gather mode and start both DMA engines. The job is complete when the
 * push DMA has stopped and STATUS reports idle; a bus error aborts it and the
 * DMA is soft-reset (SOFTRST held for at least 1 us).
 */

#include <stddef.h>
#include <stdint.h>

#include "noxtls_nrf54_cracen.h"

/** @brief Microseconds per millisecond. */
#define NOXTLS_NRF54_US_PER_MS          1000U
/** @brief Bytes per KiB. */
#define NOXTLS_NRF54_BYTES_PER_KIB      1024U
/** @brief Value of the ownership flag when free. */
#define NOXTLS_NRF54_LOCK_FREE          0U
/** @brief Value of the ownership flag when taken. */
#define NOXTLS_NRF54_LOCK_TAKEN         1U

/**
 * @brief Default 32-bit volatile register read.
 * @internal
 *
 * @param[in] addr Address.
 *
 * @return Value.
 */
static uint32_t noxtls_nrf54_mmio_read32(uintptr_t addr)
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
static void noxtls_nrf54_mmio_write32(uintptr_t addr, uint32_t value)
{
    /* MISRA C:2025 Rule 11.4 deviation: memory-mapped register access. */
    *((volatile uint32_t *)addr) = value;
}

/**
 * @brief Whether the CPU is in handler mode (IPSR != 0).
 * @internal
 *
 * @return Non-zero in an interrupt handler.
 */
static uint8_t noxtls_nrf54_cpu_in_isr(void)
{
#if defined(__ARM_ARCH)
    uint32_t ipsr;

    /* MISRA C:2025 Dir 4.3 deviation: encapsulated inline assembly (Armv8-M MRS IPSR). */
    __asm volatile ("mrs %0, ipsr" : "=r" (ipsr));
    return (ipsr != 0U) ? 1U : 0U;
#else
    /* Host builds have no handler mode. */
    return 0U;
#endif
}

/**
 * @brief Make descriptor and operand writes visible to the DMA before a start (DSB).
 * @internal
 */
static void noxtls_nrf54_barrier(void)
{
#if defined(__ARM_ARCH)
    /* MISRA C:2025 Dir 4.3 deviation: encapsulated inline assembly (Armv8-M DSB). */
    __asm volatile ("dsb 0xF" : : : "memory");
#elif defined(__GNUC__) || defined(__clang__)
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
#endif
}

/** Default register access layer. */
static const noxtls_nrf54_io_t s_noxtls_nrf54_default_io = {
    noxtls_nrf54_mmio_read32, noxtls_nrf54_mmio_write32, noxtls_nrf54_cpu_in_isr
};

/** Active register access layer. */
static noxtls_nrf54_io_t s_noxtls_nrf54_io = {
    noxtls_nrf54_mmio_read32, noxtls_nrf54_mmio_write32, noxtls_nrf54_cpu_in_isr
};

#if (NOXTLS_NRF54_CONFIG_CHIP_L15 != 0)
/** Initializer of the build default instance (nRF54L15). */
#define NOXTLS_NRF54_HW_DEFAULT_INIT {     (uintptr_t)NOXTLS_NRF54_CRACEN_BASE_L15, (uintptr_t)NOXTLS_NRF54_CORE_BASE_L15,     (uintptr_t)NOXTLS_NRF54_KMU_BASE_L15, (uintptr_t)NOXTLS_NRF54_PROT_KEY0_L15,     NOXTLS_NRF54_CRACEN_IRQN_L15, NOXTLS_NRF54_RAM_SIZE_L15, (uint8_t)NOXTLS_NRF54_VARIANT_BASE }
#else
/** Initializer of the build default instance (nRF54LM20). */
#define NOXTLS_NRF54_HW_DEFAULT_INIT {     (uintptr_t)NOXTLS_NRF54_CRACEN_BASE_LM20, (uintptr_t)NOXTLS_NRF54_CORE_BASE_LM20,     (uintptr_t)NOXTLS_NRF54_KMU_BASE_LM20, (uintptr_t)NOXTLS_NRF54_PROT_KEY0_LM20,     NOXTLS_NRF54_CRACEN_IRQN_LM20, NOXTLS_NRF54_RAM_SIZE_LM20, (uint8_t)NOXTLS_NRF54_VARIANT_LITE }
#endif

/** Build default instance. */
static const noxtls_nrf54_hw_t s_noxtls_nrf54_default_hw = NOXTLS_NRF54_HW_DEFAULT_INIT;

/** Active instance. */
static noxtls_nrf54_hw_t s_noxtls_nrf54_hw = NOXTLS_NRF54_HW_DEFAULT_INIT;

/** OS port. */
static noxtls_nrf54_port_t s_noxtls_nrf54_port;

/** Capabilities. */
static noxtls_nrf54_caps_t s_noxtls_nrf54_caps;

/** Counters. */
static noxtls_nrf54_stats_t s_noxtls_nrf54_stats;

/** Ownership flag (noxtls_nordic_crypto_try_acquire()). */
static volatile uint32_t s_noxtls_nrf54_lock;

/** Non-zero while the port OS lock is held by the current owner. */
static uint8_t s_noxtls_nrf54_os_locked;

/** Run-time enable of the hardware paths. */
static uint8_t s_noxtls_nrf54_enabled = 1U;

/** DMA window override (size 0: defaults). */
static uintptr_t s_noxtls_nrf54_win_start;
/** DMA window override size. */
static uintptr_t s_noxtls_nrf54_win_size;

/** Completion state of the CryptoMaster job in flight. */
typedef struct {
    uint8_t error; /**< Non-zero: bus error or engine stuck. */
} noxtls_nrf54_cm_state_t;

int noxtls_nordic_crypto_try_acquire(void)
{
#if defined(__GNUC__) || defined(__clang__)
    return (__atomic_exchange_n(&s_noxtls_nrf54_lock, NOXTLS_NRF54_LOCK_TAKEN, __ATOMIC_ACQUIRE) ==
            NOXTLS_NRF54_LOCK_FREE) ? 1 : 0;
#else
    int taken = 0;

    if (s_noxtls_nrf54_lock == NOXTLS_NRF54_LOCK_FREE) {
        s_noxtls_nrf54_lock = NOXTLS_NRF54_LOCK_TAKEN;
        taken = 1;
    }
    return taken;
#endif
}

void noxtls_nordic_crypto_release(void)
{
#if defined(__GNUC__) || defined(__clang__)
    __atomic_store_n(&s_noxtls_nrf54_lock, NOXTLS_NRF54_LOCK_FREE, __ATOMIC_RELEASE);
#else
    s_noxtls_nrf54_lock = NOXTLS_NRF54_LOCK_FREE;
#endif
}

void noxtls_nrf54_wipe(void *buf, uint32_t len)
{
    volatile uint8_t *p = (volatile uint8_t *)buf;
    uint32_t i;

    for (i = 0U; i < len; i++) {
        p[i] = 0U;
    }
}

uint32_t noxtls_nrf54_core_rd(uint32_t off)
{
    return s_noxtls_nrf54_io.read32(s_noxtls_nrf54_hw.core + (uintptr_t)off);
}

void noxtls_nrf54_core_wr(uint32_t off, uint32_t value)
{
    s_noxtls_nrf54_io.write32(s_noxtls_nrf54_hw.core + (uintptr_t)off, value);
}

uint32_t noxtls_nrf54_wrap_rd(uint32_t off)
{
    return s_noxtls_nrf54_io.read32(s_noxtls_nrf54_hw.base + (uintptr_t)off);
}

void noxtls_nrf54_wrap_wr(uint32_t off, uint32_t value)
{
    s_noxtls_nrf54_io.write32(s_noxtls_nrf54_hw.base + (uintptr_t)off, value);
}

uint32_t noxtls_nrf54_kmu_rd(uint32_t off)
{
    return s_noxtls_nrf54_io.read32(s_noxtls_nrf54_hw.kmu + (uintptr_t)off);
}

void noxtls_nrf54_kmu_wr(uint32_t off, uint32_t value)
{
    s_noxtls_nrf54_io.write32(s_noxtls_nrf54_hw.kmu + (uintptr_t)off, value);
}

void noxtls_nrf54_event_clear(uint32_t off)
{
    noxtls_nrf54_wrap_wr(off, NOXTLS_NRF54_EVENT_CLEAR);
    (void)noxtls_nrf54_wrap_rd(off);
}

/**
 * @brief Enable CRACEN_IRQn in the NVIC with the configured priority.
 * @internal
 */
static void noxtls_nrf54_nvic_enable(void)
{
    uint32_t irqn = s_noxtls_nrf54_hw.irqn;
    uintptr_t ipr = (uintptr_t)NOXTLS_NRF54_NVIC_IPR +
                    (uintptr_t)((irqn / NOXTLS_NRF54_NVIC_IRQS_PER_IPR) * NOXTLS_NRF54_NVIC_WORD_BYTES);
    uint32_t shift = (irqn % NOXTLS_NRF54_NVIC_IRQS_PER_IPR) * NOXTLS_NRF54_NVIC_BITS_PER_BYTE;
    uint32_t prio = ((uint32_t)NOXTLS_NRF54_CONFIG_IRQ_PRIORITY & NOXTLS_NRF54_NVIC_PRIO_MAX) <<
                    (NOXTLS_NRF54_NVIC_BITS_PER_BYTE - NOXTLS_NRF54_NVIC_PRIO_BITS);
    uintptr_t word = (uintptr_t)((irqn / NOXTLS_NRF54_NVIC_IRQS_PER_WORD) * NOXTLS_NRF54_NVIC_WORD_BYTES);
    uint32_t bit = UINT32_C(1) << (irqn % NOXTLS_NRF54_NVIC_IRQS_PER_WORD);
    uint32_t val = s_noxtls_nrf54_io.read32(ipr);

    val = (val & ~(NOXTLS_NRF54_NVIC_BYTE_MSK << shift)) | (prio << shift);
    s_noxtls_nrf54_io.write32(ipr, val);
    s_noxtls_nrf54_io.write32((uintptr_t)NOXTLS_NRF54_NVIC_ICPR + word, bit);
    s_noxtls_nrf54_io.write32((uintptr_t)NOXTLS_NRF54_NVIC_ISER + word, bit);
}

noxtls_return_t noxtls_nrf54_cracen_set_port(const noxtls_nrf54_port_t *port)
{
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if ((port != NULL) && (((port->wait != NULL) && (port->signal == NULL)) ||
                           ((port->lock != NULL) && (port->unlock == NULL)))) {
        rc = NOXTLS_RETURN_NULL;
    } else if (s_noxtls_nrf54_lock != NOXTLS_NRF54_LOCK_FREE) {
        rc = NOXTLS_RETURN_FAILED;
    } else if (port == NULL) {
        s_noxtls_nrf54_port.wait = NULL;
        s_noxtls_nrf54_port.signal = NULL;
        s_noxtls_nrf54_port.lock = NULL;
        s_noxtls_nrf54_port.unlock = NULL;
        s_noxtls_nrf54_port.ctx = NULL;
    } else {
        s_noxtls_nrf54_port = *port;
        if (port->wait != NULL) {
            noxtls_nrf54_wrap_wr(NOXTLS_NRF54_INTENCLR, NOXTLS_NRF54_MOD_ALL);
            noxtls_nrf54_nvic_enable();
        }
    }
    return rc;
}

noxtls_return_t noxtls_nrf54_cracen_set_hw(const noxtls_nrf54_hw_t *hw)
{
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if (s_noxtls_nrf54_lock != NOXTLS_NRF54_LOCK_FREE) {
        rc = NOXTLS_RETURN_FAILED;
    } else {
        s_noxtls_nrf54_hw = (hw != NULL) ? *hw : s_noxtls_nrf54_default_hw;
        s_noxtls_nrf54_caps.valid = 0U;
    }
    return rc;
}

const noxtls_nrf54_hw_t *noxtls_nrf54_cracen_hw(void)
{
    return &s_noxtls_nrf54_hw;
}

noxtls_return_t noxtls_nrf54_cracen_set_io(const noxtls_nrf54_io_t *io)
{
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if (io == NULL) {
        s_noxtls_nrf54_io = s_noxtls_nrf54_default_io;
    } else if ((io->read32 == NULL) || (io->write32 == NULL) || (io->in_isr == NULL)) {
        rc = NOXTLS_RETURN_NULL;
    } else {
        s_noxtls_nrf54_io = *io;
    }
    return rc;
}

void noxtls_nrf54_cracen_set_enabled(uint8_t enabled)
{
    s_noxtls_nrf54_enabled = (enabled != 0U) ? 1U : 0U;
}

uint8_t noxtls_nrf54_cracen_is_enabled(void)
{
    return s_noxtls_nrf54_enabled;
}

/**
 * @brief Read the engine capabilities (CryptoMaster powered).
 * @internal
 */
static void noxtls_nrf54_read_caps(void)
{
    noxtls_nrf54_caps_t *caps = &s_noxtls_nrf54_caps;
    uint32_t cfg1 = noxtls_nrf54_core_rd(NOXTLS_NRF54_HW_BA411_CFG1);

    caps->inclips = noxtls_nrf54_core_rd(NOXTLS_NRF54_HW_INCLIPS);
    caps->aes_modes = ((caps->inclips & NOXTLS_NRF54_INCLIPS_BA411) != 0U) ? (cfg1 & NOXTLS_NRF54_BA411_MODE_MSK) : 0U;
    caps->aes_keys = (cfg1 >> NOXTLS_NRF54_BA411_KEYSZ_POS) & NOXTLS_NRF54_BA411_KEYSZ_MSK;
    caps->ctr_bits = noxtls_nrf54_core_rd(NOXTLS_NRF54_HW_BA411_CFG2) & NOXTLS_NRF54_BA411_CTRSZ_MSK;
    caps->hash_algos = ((caps->inclips & NOXTLS_NRF54_INCLIPS_BA413) != 0U) ?
                       (noxtls_nrf54_core_rd(NOXTLS_NRF54_HW_BA413_CFG) & NOXTLS_NRF54_BA413_ALGO_MSK) : 0U;
    caps->valid = 1U;
}

noxtls_return_t noxtls_nrf54_cracen_acquire(uint32_t modules)
{
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    uint8_t os_lock = ((s_noxtls_nrf54_port.lock != NULL) && (s_noxtls_nrf54_io.in_isr() == 0U)) ? 1U : 0U;

    if ((modules == 0U) || ((modules & ~NOXTLS_NRF54_MOD_ALL) != 0U)) {
        rc = NOXTLS_RETURN_INVALID_PARAM;
    } else if (s_noxtls_nrf54_enabled == 0U) {
        rc = NOXTLS_RETURN_NOT_SUPPORTED;
    } else {
        if (os_lock != 0U) {
            s_noxtls_nrf54_port.lock(s_noxtls_nrf54_port.ctx);
        }
        if (noxtls_nordic_crypto_try_acquire() == 0) {
            if (os_lock != 0U) {
                s_noxtls_nrf54_port.unlock(s_noxtls_nrf54_port.ctx);
            }
            s_noxtls_nrf54_stats.busy++;
            rc = NOXTLS_RETURN_NOT_SUPPORTED;
        } else {
            s_noxtls_nrf54_os_locked = os_lock;
            s_noxtls_nrf54_stats.acquires++;
            noxtls_nrf54_wrap_wr(NOXTLS_NRF54_INTENCLR, NOXTLS_NRF54_MOD_ALL);
            noxtls_nrf54_wrap_wr(NOXTLS_NRF54_ENABLE, modules | NOXTLS_NRF54_MOD_CM);
            if (s_noxtls_nrf54_caps.valid == 0U) {
                noxtls_nrf54_read_caps();
            }
        }
    }
    return rc;
}

void noxtls_nrf54_cracen_release(void)
{
    uint8_t os_lock = s_noxtls_nrf54_os_locked;

    noxtls_nrf54_wrap_wr(NOXTLS_NRF54_INTENCLR, NOXTLS_NRF54_MOD_ALL);
    noxtls_nrf54_wrap_wr(NOXTLS_NRF54_ENABLE, 0U);
    noxtls_nrf54_event_clear(NOXTLS_NRF54_EVENTS_CRYPTOMASTER);
    noxtls_nrf54_event_clear(NOXTLS_NRF54_EVENTS_RNG);
    noxtls_nrf54_event_clear(NOXTLS_NRF54_EVENTS_PKEIKG);
    s_noxtls_nrf54_os_locked = 0U;
    noxtls_nordic_crypto_release();
    if (os_lock != 0U) {
        s_noxtls_nrf54_port.unlock(s_noxtls_nrf54_port.ctx);
    }
}

const noxtls_nrf54_caps_t *noxtls_nrf54_cracen_caps(void)
{
    return &s_noxtls_nrf54_caps;
}

noxtls_return_t noxtls_nrf54_cracen_wait(uint32_t module, noxtls_nrf54_done_fn_t done, void *ctx,
                                         uint32_t timeout_us)
{
    uint8_t complete = done(ctx);
    uint64_t poll_us = (uint64_t)timeout_us;

    if ((complete == 0U) && (s_noxtls_nrf54_port.wait != NULL) && (s_noxtls_nrf54_io.in_isr() == 0U)) {
        uint32_t slice_us = (uint32_t)NOXTLS_NRF54_CONFIG_WAIT_SLICE_MS * NOXTLS_NRF54_US_PER_MS;
        uint32_t slices = (timeout_us + (slice_us - 1U)) / slice_us;
        uint32_t wakes = 0U;
        uint8_t declined = 0U;

        s_noxtls_nrf54_stats.sleeps++;
        if (slices == 0U) {
            slices = 1U;
        }
        while ((complete == 0U) && (declined == 0U) && (slices > 0U) &&
               (wakes < (uint32_t)NOXTLS_NRF54_CONFIG_WAIT_WAKES_MAX)) {
            noxtls_return_t w;

            /* Arm: an event that is already latched raises the interrupt at once. */
            noxtls_nrf54_wrap_wr(NOXTLS_NRF54_INTENSET, module);
            w = s_noxtls_nrf54_port.wait(s_noxtls_nrf54_port.ctx, NOXTLS_NRF54_CONFIG_WAIT_SLICE_MS);
            if (w == NOXTLS_RETURN_SUCCESS) {
                wakes++;
            } else if (w == NOXTLS_RETURN_NOT_SUPPORTED) {
                /* The OS cannot block now (for example before the scheduler runs): poll the rest. */
                declined = 1U;
            } else {
                slices--;
            }
            complete = done(ctx);
        }
        noxtls_nrf54_wrap_wr(NOXTLS_NRF54_INTENCLR, module);
        poll_us = (declined != 0U) ? ((uint64_t)slices * (uint64_t)slice_us) : 0U;
    }
    if ((complete == 0U) && (poll_us != 0U)) {
        uint64_t spins = poll_us * (uint64_t)NOXTLS_NRF54_CONFIG_SPINS_PER_US;

        s_noxtls_nrf54_stats.polled++;
        while ((complete == 0U) && (spins > 0U)) {
            spins--;
            complete = done(ctx);
        }
    }
    if (complete == 0U) {
        s_noxtls_nrf54_stats.timeouts++;
    }
    return (complete != 0U) ? NOXTLS_RETURN_SUCCESS : NOXTLS_RETURN_TIMEOUT;
}

/**
 * @brief Soft-reset the CryptoMaster DMA (aborts the job in flight).
 * @internal
 */
static void noxtls_nrf54_cm_softreset(void)
{
    uint32_t spins;

    noxtls_nrf54_core_wr(NOXTLS_NRF54_CM_CONFIG, NOXTLS_NRF54_CM_CFG_SOFTRST);
    /* Reset pulse of at least 1 us: each register read takes several bus cycles. */
    for (spins = 0U; spins < (uint32_t)NOXTLS_NRF54_CONFIG_SOFTRST_SPINS; spins++) {
        (void)noxtls_nrf54_core_rd(NOXTLS_NRF54_CM_STATUS);
    }
    noxtls_nrf54_core_wr(NOXTLS_NRF54_CM_CONFIG, NOXTLS_NRF54_CM_CFG_NONE);
    spins = (uint32_t)NOXTLS_NRF54_CONFIG_IDLE_SPINS;
    while (((noxtls_nrf54_core_rd(NOXTLS_NRF54_CM_STATUS) & NOXTLS_NRF54_CM_ST_SOFTRST_BUSY) != 0U) && (spins > 0U)) {
        spins--;
    }
}

/**
 * @brief Completion check of a CryptoMaster job.
 * @internal
 *
 * @param[in,out] ctx noxtls_nrf54_cm_state_t.
 *
 * @return Non-zero when the job ended.
 */
static uint8_t noxtls_nrf54_cm_done(void *ctx)
{
    noxtls_nrf54_cm_state_t *st = (noxtls_nrf54_cm_state_t *)ctx;
    uint32_t raw = noxtls_nrf54_core_rd(NOXTLS_NRF54_CM_INTSTATRAW);
    uint8_t done = 0U;

    if ((raw & NOXTLS_NRF54_CM_INT_ERRORS) != 0U) {
        st->error = 1U;
        done = 1U;
    } else if ((raw & NOXTLS_NRF54_CM_INT_PUSH_STOP) != 0U) {
        uint32_t spins = (uint32_t)NOXTLS_NRF54_CONFIG_IDLE_SPINS;
        uint32_t busy = noxtls_nrf54_core_rd(NOXTLS_NRF54_CM_STATUS) & NOXTLS_NRF54_CM_ST_BUSY;

        /* The push DMA stops last: the engine is expected idle at once. */
        while ((busy != 0U) && (spins > 0U)) {
            spins--;
            busy = noxtls_nrf54_core_rd(NOXTLS_NRF54_CM_STATUS) & NOXTLS_NRF54_CM_ST_BUSY;
        }
        st->error = (busy != 0U) ? 1U : 0U;
        done = 1U;
    } else {
        /* Still running. */
    }
    return done;
}

noxtls_return_t noxtls_nrf54_cracen_cm_run(const noxtls_nrf54_desc_t *fetch, const noxtls_nrf54_desc_t *push,
                                           uint32_t bytes)
{
    noxtls_nrf54_cm_state_t st = { 0U };
    uint64_t timeout = (uint64_t)NOXTLS_NRF54_CONFIG_CM_TIMEOUT_US +
                       ((((uint64_t)bytes + (NOXTLS_NRF54_BYTES_PER_KIB - 1U)) / NOXTLS_NRF54_BYTES_PER_KIB) *
                        (uint64_t)NOXTLS_NRF54_CONFIG_CM_US_PER_KIB);
    noxtls_return_t rc;

    s_noxtls_nrf54_stats.cm_jobs++;
    noxtls_nrf54_core_wr(NOXTLS_NRF54_CM_INTEN, NOXTLS_NRF54_CM_INT_NONE);
    noxtls_nrf54_core_wr(NOXTLS_NRF54_CM_INTSTATCLR, NOXTLS_NRF54_CM_INT_CLEAR_ALL);
    noxtls_nrf54_core_wr(NOXTLS_NRF54_CM_INTEN, NOXTLS_NRF54_CM_INT_USED);
    noxtls_nrf54_event_clear(NOXTLS_NRF54_EVENTS_CRYPTOMASTER);
    noxtls_nrf54_barrier();
    noxtls_nrf54_core_wr(NOXTLS_NRF54_CM_FETCHADDR, (uint32_t)(uintptr_t)fetch);
    noxtls_nrf54_core_wr(NOXTLS_NRF54_CM_PUSHADDR, (uint32_t)(uintptr_t)push);
    noxtls_nrf54_core_wr(NOXTLS_NRF54_CM_CONFIG, NOXTLS_NRF54_CM_CFG_SG);
    noxtls_nrf54_core_wr(NOXTLS_NRF54_CM_START, NOXTLS_NRF54_CM_START_BOTH);
    rc = noxtls_nrf54_cracen_wait(NOXTLS_NRF54_MOD_CM, noxtls_nrf54_cm_done, &st,
                                  (timeout > (uint64_t)UINT32_MAX) ? UINT32_MAX : (uint32_t)timeout);
    if ((rc != NOXTLS_RETURN_SUCCESS) || (st.error != 0U)) {
        noxtls_nrf54_cm_softreset();
        s_noxtls_nrf54_stats.cm_errors++;
        if (rc == NOXTLS_RETURN_SUCCESS) {
            rc = NOXTLS_RETURN_FAILED;
        }
    }
    noxtls_nrf54_core_wr(NOXTLS_NRF54_CM_INTSTATCLR, NOXTLS_NRF54_CM_INT_CLEAR_ALL);
    noxtls_nrf54_event_clear(NOXTLS_NRF54_EVENTS_CRYPTOMASTER);
    noxtls_nrf54_barrier();
    return rc;
}

void noxtls_nrf54_cracen_irq_handler(void)
{
    static const uint32_t events[3] = {
        NOXTLS_NRF54_EVENTS_CRYPTOMASTER, NOXTLS_NRF54_EVENTS_RNG, NOXTLS_NRF54_EVENTS_PKEIKG
    };
    static const uint32_t mods[3] = { NOXTLS_NRF54_MOD_CM, NOXTLS_NRF54_MOD_RNG, NOXTLS_NRF54_MOD_PKE };
    uint32_t fired = 0U;
    uint32_t i;

    for (i = 0U; i < 3U; i++) {
        if (noxtls_nrf54_wrap_rd(events[i]) != 0U) {
            /* Mask first: a level source (CRACEN Lite PKE) would otherwise re-raise the event. */
            noxtls_nrf54_wrap_wr(NOXTLS_NRF54_INTENCLR, mods[i]);
            noxtls_nrf54_event_clear(events[i]);
            fired |= mods[i];
        }
    }
    if ((fired & NOXTLS_NRF54_MOD_CM) != 0U) {
        s_noxtls_nrf54_stats.irq_cm++;
    }
    if ((fired & NOXTLS_NRF54_MOD_RNG) != 0U) {
        s_noxtls_nrf54_stats.irq_rng++;
    }
    if ((fired & NOXTLS_NRF54_MOD_PKE) != 0U) {
        s_noxtls_nrf54_stats.irq_pke++;
    }
    if ((fired != 0U) && (s_noxtls_nrf54_port.signal != NULL)) {
        s_noxtls_nrf54_port.signal(s_noxtls_nrf54_port.ctx);
    }
}

void noxtls_nrf54_desc_set(noxtls_nrf54_desc_t *desc, const void *addr, uint32_t length, uint32_t tag)
{
    desc->addr = (uint32_t)(uintptr_t)addr;
    desc->next = NOXTLS_NRF54_DESC_STOP;
    desc->length = length;
    desc->tag = tag;
}

void noxtls_nrf54_desc_link(noxtls_nrf54_desc_t *desc, uint32_t count, uint8_t fetch)
{
    uint32_t i;

    for (i = 0U; (i + 1U) < count; i++) {
        desc[i].next = (uint32_t)(uintptr_t)&desc[i + 1U];
    }
    desc[count - 1U].next = NOXTLS_NRF54_DESC_STOP;
    desc[count - 1U].length |= NOXTLS_NRF54_DESC_REALIGN;
    if (fetch != 0U) {
        desc[count - 1U].tag |= NOXTLS_NRF54_TAG_LAST;
    }
}

/**
 * @brief Whether [buf, buf + len) lies inside [start, start + size).
 * @internal
 *
 * @param[in] buf   Buffer.
 * @param[in] len   Bytes.
 * @param[in] start Window start.
 * @param[in] size  Window size.
 *
 * @return 1 inside, 0 otherwise.
 */
static uint8_t noxtls_nrf54_in_window(const void *buf, uint32_t len, uintptr_t start, uintptr_t size)
{
    uintptr_t addr = (uintptr_t)buf;
    uint8_t ok = 0U;

    if ((addr >= start) && ((addr - start) <= size) && ((uintptr_t)len <= (size - (addr - start)))) {
        ok = 1U;
    }
    return ok;
}

uint8_t noxtls_nrf54_dma_in_ok(const void *buf, uint32_t len)
{
    uintptr_t start = (uintptr_t)NOXTLS_NRF54_RAM_BASE;
    uintptr_t size = (uintptr_t)s_noxtls_nrf54_hw.ram_size;

    if (s_noxtls_nrf54_win_size != 0U) {
        start = s_noxtls_nrf54_win_start;
        size = s_noxtls_nrf54_win_size;
    } else if (NOXTLS_NRF54_CONFIG_DMA_RRAM != 0) {
        start = (uintptr_t)NOXTLS_NRF54_CONFIG_DMA_START;
        size = ((uintptr_t)NOXTLS_NRF54_RAM_BASE - start) + (uintptr_t)s_noxtls_nrf54_hw.ram_size;
    } else {
        /* Data RAM only. */
    }
    return ((buf != NULL) && (noxtls_nrf54_in_window(buf, len, start, size) != 0U)) ? 1U : 0U;
}

uint8_t noxtls_nrf54_dma_out_ok(const void *buf, uint32_t len)
{
    uintptr_t start = (uintptr_t)NOXTLS_NRF54_RAM_BASE;
    uintptr_t size = (uintptr_t)s_noxtls_nrf54_hw.ram_size;

    if (s_noxtls_nrf54_win_size != 0U) {
        start = s_noxtls_nrf54_win_start;
        size = s_noxtls_nrf54_win_size;
    }
    return ((buf != NULL) && (noxtls_nrf54_in_window(buf, len, start, size) != 0U)) ? 1U : 0U;
}

void noxtls_nrf54_cracen_set_dma_window(uintptr_t start, uintptr_t size)
{
    s_noxtls_nrf54_win_start = start;
    s_noxtls_nrf54_win_size = size;
}

const noxtls_nrf54_stats_t *noxtls_nrf54_cracen_stats(void)
{
    return &s_noxtls_nrf54_stats;
}

void noxtls_nrf54_cracen_reset_stats(void)
{
    noxtls_nrf54_wipe(&s_noxtls_nrf54_stats, (uint32_t)sizeof(s_noxtls_nrf54_stats));
}

#if (NOXTLS_NRF54_CONFIG_DEFINE_VECTOR != 0)
/**
 * @brief CRACEN interrupt vector (overrides the weak startup vector).
 */
void CRACEN_IRQHandler(void);

void CRACEN_IRQHandler(void)
{
    noxtls_nrf54_cracen_irq_handler();
}
#endif
