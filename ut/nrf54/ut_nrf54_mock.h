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
* File:    ut_nrf54_mock.h
* Summary: Functional CRACEN / KMU / NVIC register mock for the backend host tests
*
*****************************************************************************/

/**
 * @file ut_nrf54_mock.h
 * @brief Register-level mock of CRACEN (wrapper, CryptoMaster DMA, BA411, BA413,
 *        BA414EP, TRNG), the KMU and the NVIC, with a functional engine model.
 * @ingroup noxtls_nrf54_ut
 *
 * On START the mock walks the fetch descriptor chain as laid out by the
 * backend (address, next, length, tag), routes configuration words and data by
 * DMA tag, runs the reference AES / SHA-2 / GCM / CCM (ut_nrf54_ref.c) and
 * writes the result through the push chain. Any violation of the descriptor
 * rules the backend relies on (config word first, LAST only on the final
 * descriptor except the hash state, REALIGN on configuration descriptors,
 * whole AES blocks, padded AEAD segments, push space equal to the engine
 * output, ...) is recorded in g_ut.err and reported as a DMA bus error, so a
 * test that checks results also checks the descriptor format.
 *
 * BA414EP: START snapshots COMMAND and the operand memory; the math is not
 * modelled, the command ends with the error flags chosen by the test. A point
 * multiplication returns R = P XOR k (both coordinates) so the backend's
 * double-check and result read-back can be verified. The nRF54L15 model
 * reports a microcode error unless the code RAM holds the image; the
 * nRF54LM20 model has read-only code memory and implements the clear-memory
 * command.
 */

#ifndef UT_NRF54_MOCK_H
#define UT_NRF54_MOCK_H

#include <stdint.h>

#include "noxtls_nrf54_accel.h"
#include "noxtls_nrf54_ba414ep_ucode.h"

/** Words of the mocked CRACEN wrapper. */
#define UT_WRAP_WORDS     0x400U
/** Words of the mocked CRACENCORE (64 KiB). */
#define UT_CORE_WORDS     0x4000U
/** Words of the mocked KMU. */
#define UT_KMU_WORDS      0x400U
/** Words of the mocked NVIC (0xE000E000..). */
#define UT_NVIC_WORDS     0x200U
/** Mocked KMU slots. */
#define UT_KMU_SLOTS      250U
/** Word index of a byte offset. */
#define UT_IDX(off)       ((off) / 4U)

/** One KMU slot of the model. */
typedef struct {
    uint32_t value[4];   /**< Key material. */
    uint32_t dest;       /**< Push destination. */
    uint32_t md;         /**< Metadata. */
    uint32_t rpolicy;    /**< Revoke policy. */
    uint8_t state;       /**< 0 empty, 1 provisioned, 2 revoked. */
    uint8_t pushblocked; /**< Push blocked. */
    uint8_t blocked;     /**< All operations blocked. */
} ut_kmu_slot_t;

/** Mock state (zeroed by ut_mock_reset()). */
typedef struct {
    uint32_t wrap[UT_WRAP_WORDS];   /**< Wrapper registers. */
    uint32_t core[UT_CORE_WORDS];   /**< CRACENCORE registers and memories. */
    uint32_t kmu[UT_KMU_WORDS];     /**< KMU registers. */
    uint32_t nvic[UT_NVIC_WORDS];   /**< NVIC registers. */
    uint32_t inten;                 /**< Wrapper INTEN. */
    uint32_t nvic_enabled;          /**< Non-zero once CRACEN_IRQn is enabled. */
    uint32_t irqn;                  /**< CRACEN_IRQn of the model. */
    uint8_t l15;                    /**< Non-zero: nRF54L15 model. */
    uint8_t in_isr;                 /**< Value returned by the CPU-context probe. */
    /* CryptoMaster. */
    uint32_t ctr_bits;              /**< BA411 counter width. */
    uint32_t delay_reads;           /**< STATUS reads before a job completes. */
    uint32_t busy_after_stop;       /**< STATUS reads still busy after PUSHSTOPPED. */
    uint32_t pending;               /**< Remaining delay of the job in flight. */
    uint32_t busy_left;             /**< Remaining busy-after-stop reads. */
    uint32_t softrst_busy_reads;    /**< SOFTRSTBUSY reads after a soft reset. */
    uint32_t softrst_left;          /**< Remaining SOFTRSTBUSY reads. */
    uint32_t starts;                /**< Jobs started. */
    uint32_t softresets;            /**< Soft resets. */
    uint32_t max_enable;            /**< OR of every ENABLE value. */
    uint32_t last_cfg;              /**< Config word of the last job. */
    uint32_t last_fetch_descs;      /**< Fetch descriptors of the last job. */
    uint32_t last_data_len;         /**< Payload bytes of the last job. */
    uint32_t last_keylen;           /**< Key bytes of the last AES job. */
    uint32_t last_key_addr;         /**< Key address of the last AES job. */
    uint32_t last_aad_len;          /**< AAD bytes of the last AEAD job. */
    uint8_t last_had_state;         /**< Last hash job resumed a state. */
    uint8_t hang;                   /**< 1: jobs never complete. */
    uint8_t stuck;                  /**< 1: busy forever after PUSHSTOPPED. */
    uint8_t inject_error;           /**< Jobs left to fail with a bus error. */
    uint8_t fail_skip;              /**< Jobs that still succeed before inject_error applies. */
    char err[128];                  /**< First rule violation. */
    /* TRNG. */
    uint32_t rng_state;             /**< STATUS.STATE. */
    uint32_t rng_status_bits;       /**< Failure bits with STATE == ERROR. */
    uint32_t rng_level;             /**< FIFO words. */
    uint32_t rng_head;              /**< Next FIFO word. */
    uint32_t rng_fifo[16];          /**< FIFO. */
    uint32_t rng_counter;           /**< Word generator. */
    uint32_t rng_startup_reads;     /**< STATUS reads spent in STARTUP. */
    uint32_t rng_startup_left;      /**< Remaining STARTUP reads. */
    uint32_t rng_key_writes;        /**< KEY register writes. */
    uint32_t rng_softresets;        /**< SOFTRST writes. */
    uint32_t rng_fail_starts;       /**< Starts that end in ERROR. */
    uint32_t rng_fail_bits;         /**< STATUS bits of injected failures. */
    uint8_t rng_never_ready;        /**< 1: stays in STARTUP. */
    /* KMU. */
    ut_kmu_slot_t kslot[UT_KMU_SLOTS]; /**< Slots. */
    uint32_t kmu_busy_reads;        /**< STATUS busy reads before the next task. */
    uint8_t kmu_never_ready;        /**< 1: STATUS stays busy. */
    uint8_t kmu_no_event;           /**< 1: tasks produce no event. */
    uint32_t kmu_tasks;             /**< Tasks triggered. */
    /* BA414EP. */
    uint32_t pk_status;             /**< Current STATUS. */
    uint32_t pk_status_bits;        /**< Error flags of the next command. */
    uint32_t pk_delay;              /**< STATUS reads a command stays busy. */
    uint32_t pk_pending;            /**< Remaining busy reads. */
    uint32_t pk_starts;             /**< Commands started (clear-memory included). */
    uint32_t pk_clears;             /**< Clear-memory commands. */
    uint32_t pk_cmd;                /**< COMMAND of the last non-clear command. */
    uint32_t pk_ptrs;               /**< POINTERS at the last non-clear START. */
    uint32_t ikg_busy_reads;        /**< IKG busy reads after power-up. */
    uint32_t pk_ptmul_runs;         /**< Point multiplications run. */
    uint32_t pk_ptmul_corrupt;      /**< Bit mask: corrupt the result of run n (bit n). */
    uint8_t pk_hang;                /**< 1: commands never complete. */
    uint8_t pk_clear_hang;          /**< 1: the clear-memory command never completes. */
    uint8_t ikg_never_ready;        /**< 1: IKG stays busy. */
    uint8_t pk_irq_at_power;        /**< 1: power-up latches a stale PKE completion. */
    uint8_t pk_snap[NOXTLS_NRF54_PK_DATA_SIZE]; /**< Operand memory at the last non-clear START. */
} ut_mock_t;

/** Mock state. */
extern ut_mock_t g_ut;

/** Test data RAM: the DMA window of most tests covers exactly this object. */
typedef struct {
    uint8_t in[4096];        /**< Input. */
    uint8_t out[4096];       /**< Output. */
    uint8_t aad[0xFF10];     /**< Long AAD. */
    uint8_t key[32];         /**< Key / IV scratch. */
    uint8_t prot[64];        /**< Stand-in for CRACEN protected RAM. */
    noxtls_nrf54_kmu_slot_data_t kdata; /**< KMU provisioning source. */
} ut_ram_t;

/** Test data RAM. */
extern ut_ram_t g_ut_ram;

/** Signals received by the test port. */
extern volatile uint32_t g_ut_signals;
/** Wait-hook calls of the test port. */
extern uint32_t g_ut_waits;
/** Lock / unlock calls of the test port. */
extern uint32_t g_ut_locks;
/** Unlock calls of the test port. */
extern uint32_t g_ut_unlocks;

/**
 * @brief Reset the mock for a chip and install it (registers, instance, DMA window = g_ut_ram).
 *
 * @param[in] l15 Non-zero for the nRF54L15 model, zero for the nRF54LM20 (CRACEN Lite).
 */
void ut_setup(uint8_t l15);

/**
 * @brief Install the interrupt-driven test port (wait runs the mocked interrupt; lock counts).
 */
void ut_port_irq(void);

/**
 * @brief Run CRACEN_IRQn when an enabled event is pending (advances the TRNG model).
 *
 * @return 1 when the handler ran.
 */
uint8_t ut_mock_run_irq(void);

/**
 * @brief Rebuild a host pointer from a 32-bit DMA address.
 *
 * @param[in] lo 32-bit address.
 *
 * @return Host pointer.
 */
uint8_t *ut_ptr(uint32_t lo);

/**
 * @brief Big-endian 32-byte operand of a slot in the last START snapshot.
 *
 * @param[in] slot Slot.
 *
 * @return Pointer into g_ut.pk_snap.
 */
const uint8_t *ut_pk_be(uint32_t slot);

/**
 * @brief Little-endian operand (start of a slot) in the last START snapshot.
 *
 * @param[in] slot Slot.
 *
 * @return Pointer into g_ut.pk_snap.
 */
const uint8_t *ut_pk_le(uint32_t slot);

/**
 * @brief Whether every byte of the live operand memory is zero.
 *
 * @return 1 when wiped.
 */
uint8_t ut_pk_wiped(void);

#endif /* UT_NRF54_MOCK_H */
