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
* File:    noxtls_nrf54_cracen.h
* Summary: nRF54L CRACEN core: ownership, power, waits, interrupt, CryptoMaster jobs
*
*****************************************************************************/

/**
 * @defgroup noxtls_nrf54 NoxTLS nRF54L CRACEN backend
 * @brief Register-level CRACEN drivers (AES, AES-GCM/CCM, SHA-2, TRNG, KMU,
 *        BA414EP public key) behind the NoxTLS accelerator ports, for the
 *        nRF54LM20 (CRACEN Lite) and the nRF54L15.
 */

/**
 * @file noxtls_nrf54_cracen.h
 * @brief CRACEN core shared by every nRF54L backend module.
 * @ingroup noxtls_nrf54
 *
 * Ownership: every operation runs between noxtls_nrf54_cracen_acquire() and
 * noxtls_nrf54_cracen_release(). Acquire takes the optional OS lock of the
 * port, then the NoxTLS try-acquire flag noxtls_nordic_crypto_try_acquire()
 * (shared with any other user of the CRACEN wrapper). When the flag is held
 * elsewhere (for example by an interrupt-context user) acquire fails with
 * NOXTLS_RETURN_NOT_SUPPORTED and the caller falls back to software.
 *
 * Waiting: NoxTLS is OS agnostic. An OS installs a noxtls_nrf54_port_t whose
 * wait hook blocks the calling task (for example on a semaphore) and whose
 * signal hook is called from CRACEN_IRQn. The backend arms the module
 * interrupt, sleeps in the wait hook and re-checks the hardware after every
 * wake, so a lost or stale signal only costs a wait slice. Without a port, or
 * when called from an interrupt handler, the backend polls with a bounded
 * spin. The interrupt handler masks the module interrupt it serviced, so each
 * armed wait sees at most one interrupt.
 */

#ifndef NOXTLS_NRF54_CRACEN_H
#define NOXTLS_NRF54_CRACEN_H

#include <stdint.h>

#include "noxtls_common.h"
#include "noxtls_nrf54_config.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Chip variant: CRACEN Lite of the nRF54LM20 (PKE microcode in ROM, clear-memory command, 16-bit CTR counter). */
#define NOXTLS_NRF54_VARIANT_LITE   0U
/** Chip variant: CRACEN of the nRF54L15 (PKE microcode loaded into RAM by software). */
#define NOXTLS_NRF54_VARIANT_BASE   1U

/** Addresses and variant of the CRACEN / KMU instance. */
typedef struct {
    uintptr_t base;      /**< CRACEN wrapper. */
    uintptr_t core;      /**< CRACENCORE. */
    uintptr_t kmu;       /**< KMU. */
    uintptr_t prot_key0; /**< KMU push destination of AES key 0 (CRACEN protected RAM). */
    uint32_t irqn;       /**< CRACEN_IRQn. */
    uint32_t ram_size;   /**< Data RAM bytes (DMA output window). */
    uint8_t variant;     /**< NOXTLS_NRF54_VARIANT_LITE or NOXTLS_NRF54_VARIANT_BASE. */
} noxtls_nrf54_hw_t;

/** Register access layer and CPU context probe (all members non-NULL). */
typedef struct {
    uint32_t (*read32)(uintptr_t addr);              /**< Read a 32-bit register. */
    void (*write32)(uintptr_t addr, uint32_t value); /**< Write a 32-bit register. */
    uint8_t (*in_isr)(void);                         /**< Non-zero when called from an interrupt handler. */
} noxtls_nrf54_io_t;

/**
 * @brief Block the calling task until signal() or the timeout.
 *
 * @param[in] ctx        Port context.
 * @param[in] timeout_ms Timeout in milliseconds (>= 1).
 *
 * @return NOXTLS_RETURN_SUCCESS when signalled, NOXTLS_RETURN_TIMEOUT otherwise, or
 *         NOXTLS_RETURN_NOT_SUPPORTED when the task cannot block now (for example
 *         before the scheduler runs): the backend then polls for the remaining time.
 */
typedef noxtls_return_t (*noxtls_nrf54_wait_fn_t)(void *ctx, uint32_t timeout_ms);

/**
 * @brief Wake the task blocked in wait() (called from CRACEN_IRQn).
 *
 * @param[in] ctx Port context.
 */
typedef void (*noxtls_nrf54_signal_fn_t)(void *ctx);

/**
 * @brief Take or give the OS lock that serialises tasks using CRACEN.
 *
 * @param[in] ctx Port context.
 */
typedef void (*noxtls_nrf54_lock_fn_t)(void *ctx);

/** OS port: interrupt-driven waits and task locking (every member optional, see noxtls_nrf54_cracen_set_port()). */
typedef struct {
    noxtls_nrf54_wait_fn_t wait;     /**< Sleep until signalled (NULL: bounded polling). */
    noxtls_nrf54_signal_fn_t signal; /**< Signal from the interrupt (required with wait). */
    noxtls_nrf54_lock_fn_t lock;     /**< Take the OS lock (NULL: try-acquire only). */
    noxtls_nrf54_lock_fn_t unlock;   /**< Give the OS lock (required with lock). */
    void *ctx;                       /**< Context of every hook. */
} noxtls_nrf54_port_t;

/** Engine capabilities read from the hardware configuration registers. */
typedef struct {
    uint32_t inclips;    /**< Included engines (NOXTLS_NRF54_INCLIPS_*). */
    uint32_t aes_modes;  /**< BA411 modes, bit n = mode number n. */
    uint32_t aes_keys;   /**< BA411 key sizes: bit0 128, bit1 192, bit2 256. */
    uint32_t ctr_bits;   /**< BA411 CTR counter width in bits. */
    uint32_t hash_algos; /**< BA413 algorithms (NOXTLS_NRF54_HASH_ALGO_* bits). */
    uint8_t valid;       /**< Non-zero once read. */
} noxtls_nrf54_caps_t;

/** Run-time counters (diagnostics; reset with noxtls_nrf54_cracen_reset_stats()). */
typedef struct {
    uint32_t acquires;      /**< Successful acquisitions. */
    uint32_t busy;          /**< Acquisitions refused because CRACEN was in use. */
    uint32_t cm_jobs;       /**< CryptoMaster jobs started. */
    uint32_t cm_errors;     /**< CryptoMaster jobs that failed (bus error or timeout). */
    uint32_t irq_cm;        /**< CryptoMaster interrupts serviced. */
    uint32_t irq_rng;       /**< TRNG interrupts serviced. */
    uint32_t irq_pke;       /**< PKE interrupts serviced. */
    uint32_t sleeps;        /**< Port waits entered. */
    uint32_t polled;        /**< Waits completed by polling (no port or interrupt context). */
    uint32_t timeouts;      /**< Waits that timed out. */
} noxtls_nrf54_stats_t;

/** CryptoMaster scatter/gather descriptor (hardware layout: four 32-bit words, word aligned). */
typedef struct {
    uint32_t addr;   /**< Data address. */
    uint32_t next;   /**< Next descriptor or NOXTLS_NRF54_DESC_STOP. */
    uint32_t length; /**< Byte count | NOXTLS_NRF54_DESC_* flags. */
    uint32_t tag;    /**< DMA tag (fetch descriptors). */
} noxtls_nrf54_desc_t;

/**
 * @brief Completion check used by noxtls_nrf54_cracen_wait().
 *
 * @param[in,out] ctx Operation context.
 *
 * @return Non-zero when the operation is complete (successfully or not).
 */
typedef uint8_t (*noxtls_nrf54_done_fn_t)(void *ctx);

/**
 * @brief Install the OS port (copied). NULL removes it (bounded polling, try-acquire only).
 *
 * With a wait hook the backend enables CRACEN_IRQn in the NVIC at
 * NOXTLS_NRF54_CONFIG_IRQ_PRIORITY.
 *
 * @param[in] port Port or NULL.
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL (wait without signal or
 *         lock without unlock) or NOXTLS_RETURN_FAILED (CRACEN in use).
 */
noxtls_return_t noxtls_nrf54_cracen_set_port(const noxtls_nrf54_port_t *port);

/**
 * @brief Replace the instance addresses / variant (tests, other chips).
 *
 * @param[in] hw Instance (copied); NULL restores the build default.
 *
 * @return NOXTLS_RETURN_SUCCESS or NOXTLS_RETURN_FAILED (CRACEN in use).
 */
noxtls_return_t noxtls_nrf54_cracen_set_hw(const noxtls_nrf54_hw_t *hw);

/**
 * @brief Active instance description.
 *
 * @return Instance (never NULL).
 */
const noxtls_nrf54_hw_t *noxtls_nrf54_cracen_hw(void);

/**
 * @brief Install a register access layer (tests).
 *
 * @param[in] io Access layer (copied); NULL restores the MMIO accessors.
 *
 * @return NOXTLS_RETURN_SUCCESS or NOXTLS_RETURN_NULL (a member is NULL).
 */
noxtls_return_t noxtls_nrf54_cracen_set_io(const noxtls_nrf54_io_t *io);

/**
 * @brief Enable or disable the hardware paths at run time (disabled: every
 *        accelerator port reports NOT_SUPPORTED and NoxTLS uses software).
 *
 * @param[in] enabled Non-zero to use CRACEN.
 */
void noxtls_nrf54_cracen_set_enabled(uint8_t enabled);

/**
 * @brief Whether the hardware paths are enabled.
 *
 * @return Non-zero when enabled.
 */
uint8_t noxtls_nrf54_cracen_is_enabled(void);

/**
 * @brief Take ownership of CRACEN and power the requested modules.
 *
 * @param[in] modules NOXTLS_NRF54_MOD_* bits (the CryptoMaster is powered for the capability read).
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NOT_SUPPORTED (disabled or in use)
 *         or NOXTLS_RETURN_INVALID_PARAM (no or unknown module).
 */
noxtls_return_t noxtls_nrf54_cracen_acquire(uint32_t modules);

/**
 * @brief Power CRACEN down, mask its interrupts and give ownership back.
 */
void noxtls_nrf54_cracen_release(void);

/**
 * @brief Engine capabilities (valid after the first successful acquire).
 *
 * @return Capabilities (never NULL).
 */
const noxtls_nrf54_caps_t *noxtls_nrf54_cracen_caps(void);

/**
 * @brief Wait until @p done reports completion: sleeping in the port wait hook
 *        with the module interrupt armed, or polling.
 *
 * @param[in]     module     NOXTLS_NRF54_MOD_* bit of the interrupt to arm.
 * @param[in]     done       Completion check (also advances multi-step operations).
 * @param[in,out] ctx        Context of @p done.
 * @param[in]     timeout_us Timeout in microseconds.
 *
 * @return NOXTLS_RETURN_SUCCESS (complete) or NOXTLS_RETURN_TIMEOUT.
 */
noxtls_return_t noxtls_nrf54_cracen_wait(uint32_t module, noxtls_nrf54_done_fn_t done, void *ctx,
                                         uint32_t timeout_us);

/**
 * @brief Run one CryptoMaster job (fetch chain -> engine -> push chain) and wait for it.
 *
 * @param[in] fetch First fetch descriptor (linked chain).
 * @param[in] push  First push descriptor (linked chain).
 * @param[in] bytes Data bytes moved (sizes the timeout).
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_FAILED (DMA bus error, the
 *         engine is soft-reset) or NOXTLS_RETURN_TIMEOUT.
 */
noxtls_return_t noxtls_nrf54_cracen_cm_run(const noxtls_nrf54_desc_t *fetch, const noxtls_nrf54_desc_t *push,
                                           uint32_t bytes);

/**
 * @brief CRACEN interrupt service: masks and clears the module events and
 *        signals the waiting task. Called by CRACEN_IRQHandler (or by the
 *        component that owns that vector).
 */
void noxtls_nrf54_cracen_irq_handler(void);

/**
 * @brief Read a CRACENCORE register.
 *
 * @param[in] off Offset inside CRACENCORE.
 *
 * @return Value.
 */
uint32_t noxtls_nrf54_core_rd(uint32_t off);

/**
 * @brief Write a CRACENCORE register.
 *
 * @param[in] off   Offset inside CRACENCORE.
 * @param[in] value Value.
 */
void noxtls_nrf54_core_wr(uint32_t off, uint32_t value);

/**
 * @brief Read a CRACEN wrapper register.
 *
 * @param[in] off Offset inside the wrapper.
 *
 * @return Value.
 */
uint32_t noxtls_nrf54_wrap_rd(uint32_t off);

/**
 * @brief Write a CRACEN wrapper register.
 *
 * @param[in] off   Offset inside the wrapper.
 * @param[in] value Value.
 */
void noxtls_nrf54_wrap_wr(uint32_t off, uint32_t value);

/**
 * @brief Read a KMU register.
 *
 * @param[in] off Offset inside the KMU.
 *
 * @return Value.
 */
uint32_t noxtls_nrf54_kmu_rd(uint32_t off);

/**
 * @brief Write a KMU register.
 *
 * @param[in] off   Offset inside the KMU.
 * @param[in] value Value.
 */
void noxtls_nrf54_kmu_wr(uint32_t off, uint32_t value);

/**
 * @brief Clear a wrapper event and read it back.
 *
 * @param[in] off Event register offset.
 */
void noxtls_nrf54_event_clear(uint32_t off);

/**
 * @brief Fill one descriptor (next = STOP).
 *
 * @param[out] desc   Descriptor.
 * @param[in]  addr   Data address (NULL for discard descriptors).
 * @param[in]  length Byte count | flags.
 * @param[in]  tag    DMA tag (0 for push descriptors).
 */
void noxtls_nrf54_desc_set(noxtls_nrf54_desc_t *desc, const void *addr, uint32_t length, uint32_t tag);

/**
 * @brief Link @p count descriptors; the last one gets REALIGN and, in a fetch chain, LAST.
 *
 * @param[in,out] desc  First descriptor of an array.
 * @param[in]     count Descriptors (>= 1).
 * @param[in]     fetch Non-zero for a fetch chain.
 */
void noxtls_nrf54_desc_link(noxtls_nrf54_desc_t *desc, uint32_t count, uint8_t fetch);

/**
 * @brief Whether the DMA may read @p len bytes at @p buf directly.
 *
 * @param[in] buf Buffer.
 * @param[in] len Bytes.
 *
 * @return 1 when readable, 0 otherwise.
 */
uint8_t noxtls_nrf54_dma_in_ok(const void *buf, uint32_t len);

/**
 * @brief Whether the DMA may write @p len bytes at @p buf directly.
 *
 * @param[in] buf Buffer.
 * @param[in] len Bytes.
 *
 * @return 1 when writable, 0 otherwise.
 */
uint8_t noxtls_nrf54_dma_out_ok(const void *buf, uint32_t len);

/**
 * @brief Restrict the DMA windows (input and output) to one range (tests);
 *        @p size 0 restores the defaults (input: RRAM + RAM, output: RAM).
 *
 * @param[in] start First address.
 * @param[in] size  Bytes.
 */
void noxtls_nrf54_cracen_set_dma_window(uintptr_t start, uintptr_t size);

/**
 * @brief Counters since the last reset.
 *
 * @return Counters (never NULL).
 */
const noxtls_nrf54_stats_t *noxtls_nrf54_cracen_stats(void);

/**
 * @brief Clear the counters.
 */
void noxtls_nrf54_cracen_reset_stats(void);

/**
 * @brief Try to take the CRACEN ownership flag (shared by every Nordic NoxTLS
 *        accelerator user; never blocks).
 *
 * @return 1 when taken, 0 when CRACEN is in use.
 */
int noxtls_nordic_crypto_try_acquire(void);

/**
 * @brief Give the ownership flag back.
 */
void noxtls_nordic_crypto_release(void);

/**
 * @brief Overwrite a buffer with zeros through a volatile pointer (key material,
 *        intermediate state).
 *
 * @param[out] buf Buffer.
 * @param[in]  len Bytes.
 */
void noxtls_nrf54_wipe(void *buf, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_NRF54_CRACEN_H */
