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
* File:    ut_efr32_mock.h
* Summary: Functional RADIOAES / SEMAILBOX / CMU register mock for the backend host tests
*
*****************************************************************************/

/**
 * @file ut_efr32_mock.h
 * @brief Register-level mock of the EFR32xG2x RADIOAES (BA411E), SEMAILBOX_HOST and CMU
 *        with a functional engine model.
 * @ingroup noxtls_efr32_ut
 *
 * On CMD the AES mock walks the fetch descriptor chain as laid out by the
 * backend (address, next, length, tag), routes configuration words and data by
 * DMA tag, computes the result with the NoxTLS software implementation and
 * writes it through the push chain. The SE mock decodes a mailbox message
 * (TX_HEADER, FIFO words), runs the command with the NoxTLS software
 * implementation and answers through RX_HEADER. While a mock engine runs, the
 * backend still owns its lock, so the software implementation called by the
 * model is served by the software path of NoxTLS (the engine looks busy):
 * results through the hardware path are therefore checked against the same
 * software that the FIPS / NIST vectors validate.
 *
 * Any violation of the descriptor or message rules the backend relies on (config
 * word first, key length equal to the key-size bits, IV with context load for
 * CBC / CTR, LAST on the final data descriptor, whole AES blocks, push space
 * equal to the engine output, parameter counts of the SE commands, ...) is
 * recorded in g_ut.err and reported as a bus error / invalid-parameter response,
 * so a test that checks results also checks the wire format.
 */

#ifndef UT_EFR32_MOCK_H
#define UT_EFR32_MOCK_H

#include <stdint.h>

#include "noxtls_efr32_accel.h"
#include "noxtls_aes.h"
#include "noxtls_aes_accel.h"
#include "noxtls_aes_ccm.h"
#include "noxtls_ecc.h"
#include "noxtls_ecdsa.h"
#include "noxtls_sha.h"
#include "sha512/noxtls_sha512.h"
#include "sha256/noxtls_sha256_accel_port.h"
#include "noxtls_ecc_accel_port.h"
#include "noxtls_ecdsa_accel_port.h"

/** Words of the mocked RADIOAES (0x440 bytes). */
#define UT_AES_WORDS      0x120U
/** Words of the mocked SEMAILBOX_HOST. */
#define UT_SEM_WORDS      0x20U
/** Words of the mocked CMU (0x1400 bytes). */
#define UT_CMU_WORDS      0x500U
/** Word index of a byte offset. */
#define UT_IDX(off)       ((off) / 4U)
/** Bytes of the RAM the DMA windows cover in the tests. */
#define UT_RAM_BYTES      0x48000U

/** Mock state (zeroed by ut_setup()). */
typedef struct {
    uint32_t aes[UT_AES_WORDS];      /**< RADIOAES registers. */
    uint32_t sem[UT_SEM_WORDS];      /**< SEMAILBOX_HOST registers. */
    uint32_t cmu[UT_CMU_WORDS];      /**< CMU registers. */
    uint32_t aes_if;                 /**< Interrupt flags. */
    uint32_t sem_words[16];          /**< Words written to the FIFO. */
    uint32_t sem_nwords;             /**< Words written. */
    uint32_t sem_expect;             /**< Words announced by TX_HEADER. */
    uint32_t sem_rx_header;          /**< Pending response. */
    uint32_t sem_tx_polls;           /**< TX_STATUS reads left before room is offered. */
    uint32_t sem_rx_polls;           /**< RX_STATUS reads left before the response is offered. */
    uint8_t sem_rx_ready;            /**< A response is pending. */
    uint8_t aes_hang;                /**< Knob: the engine never finishes. */
    uint8_t aes_bus_error;           /**< Knob: the job ends with a bus error. */
    uint8_t aes_softrst_stuck;       /**< Knob: SOFTRSTBSY never clears. */
    uint8_t aes_no_start;            /**< Knob: ignore CMD. */
    uint8_t sem_tx_never;            /**< Knob: the mailbox never offers room. */
    uint8_t sem_rx_never;            /**< Knob: the SE never answers. */
    uint8_t se_force;                /**< Knob: answer with se_force_resp instead of executing. */
    uint32_t se_force_resp;          /**< Forced response code. */
    uint32_t se_fail_first;          /**< Knob: answer the first n commands with an internal error. */
    uint32_t se_fail_at;             /**< Knob: answer command number n (1-based, counted from the last reset) with an internal error. */
    uint8_t se_wrong_mul;            /**< Knob: DH returns a wrong (but non-zero) point. */
    uint8_t se_infinity;             /**< Knob: DH returns the point (0, 0). */
    uint8_t se_trng_zero;            /**< Knob: the TRNG returns zeros. */
    uint8_t se_no_ecdsa_sign_check;  /**< Knob: reserved. */
    uint8_t aes_jobs_fail_after;     /**< Knob: fail the job number given (1-based, 0 = none). */
    uint32_t aes_jobs;               /**< Jobs executed. */
    uint32_t aes_resets;             /**< Soft resets seen. */
    uint32_t aes_last_cfg;           /**< Configuration word of the last job. */
    uint32_t aes_fetch_descs;        /**< Fetch descriptors of the last job. */
    uint32_t aes_push_descs;         /**< Push descriptors of the last job. */
    uint32_t aes_mask_seen;          /**< Mask word of the last job (0: none). */
    uint32_t se_cmds;                /**< SE commands executed. */
    uint32_t se_last_cmd;            /**< Command word of the last SE command. */
    uint32_t se_last_params[5];      /**< Parameters of the last SE command. */
    uint32_t se_last_nparams;        /**< Parameter count of the last SE command. */
    uint32_t se_hash_blocks;         /**< Blocks compressed by the SE mock. */
    uint32_t rng_state;              /**< TRNG generator state. */
    uint32_t sw_calls;               /**< Reserved. */
    char err[160];                   /**< First rule violation (empty: none). */
} ut_mock_t;

/** RAM the DMA windows cover (descriptors and module buffers live in the image; test buffers here). */
typedef struct {
    uint8_t in[UT_RAM_BYTES / 4U];   /**< Input buffer. */
    uint8_t out[UT_RAM_BYTES / 4U];  /**< Output buffer. */
    uint8_t aux[UT_RAM_BYTES / 4U];  /**< Auxiliary buffer (AAD, IV, tag, keys). */
    uint8_t aux2[UT_RAM_BYTES / 4U]; /**< Second auxiliary buffer. */
} ut_ram_t;

/** The mock. */
extern ut_mock_t g_ut;
/** Test buffers inside the DMA windows. */
extern ut_ram_t g_ut_ram;

/**
 * @brief Reset the mock, the backend state and the windows to the defaults of the EFR32MG26.
 *
 * Hardware configuration: AES only (no hash), ECB / CBC / CTR / CCM / CMAC, 128- and 256-bit keys,
 * 128-bit CTR counter, no masking (reset values of the RM, INCL_IPS_HW_CFG = 1, BA411E_HW_CFG_1 =
 * 0x05010127, BA411E_HW_CFG_2 = 0x80).
 */
void ut_setup(void);

/**
 * @brief Replace the hardware configuration registers.
 *
 * @param[in] incl INCL_IPS_HW_CFG.
 * @param[in] cfg1 BA411E_HW_CFG_1.
 * @param[in] cfg2 BA411E_HW_CFG_2.
 */
void ut_set_caps(uint32_t incl, uint32_t cfg1, uint32_t cfg2);

/**
 * @brief Whether the mock saw no rule violation.
 *
 * @return 1 when g_ut.err is empty.
 */
uint8_t ut_clean(void);

/**
 * @brief Convert an upper-case hex string to bytes.
 *
 * @param[in]  hex Hex digits (even count).
 * @param[out] out Receives the bytes.
 *
 * @return Bytes written.
 */
uint32_t ut_hex(const char *hex, uint8_t *out);

/**
 * @brief Make the backend think both engines are owned, so NoxTLS runs its software implementation.
 */
void ut_sw_begin(void);

/** @brief Give both engines back after ut_sw_begin(). */
void ut_sw_end(void);

/** @brief Lock-binding spy: AES try-acquire results to return, then 1. */
extern volatile uint32_t g_ut_bound_aes_busy;
/** @brief Lock-binding spy: SE try-acquire results to refuse. */
extern volatile uint32_t g_ut_bound_se_busy;
/** @brief Lock-binding spy: counts. */
extern volatile uint32_t g_ut_bound_calls[4];

/**
 * @brief Operations table whose functions refuse g_ut_bound_*_busy times then grant, and count calls.
 *
 * @return Pointer to a static table.
 */
const noxtls_efr32_engine_lock_t *ut_bound_lock(void);

#endif /* UT_EFR32_MOCK_H */
