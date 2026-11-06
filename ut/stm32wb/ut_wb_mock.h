/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    ut_wb_mock.h
* Summary: Register-level model of STM32WB55 AES1, PKA, RNG and HSEM for the host tests
*****************************************************************************/

/**
 * @file ut_wb_mock.h
 * @brief Functional register model of AES1, PKA, RNG and HSEM (replaces noxtls_stm32wb_bus.c).
 * @ingroup noxtls_stm32wb_ut
 *
 * AES1: ECB / CBC / CTR / GCM / CCM engines computed with the independent
 * reference in ut_wb_ref.c, following the register protocol of RM0434
 * (phases, 4-word blocks, CCF, NPBLB, 32-bit hardware counter). Any use that
 * a real device would reject (data written with EN clear, DOUT read with no
 * result, IV / key written while enabled, ...) is counted in proto_err.
 *
 * PKA: the RAM layout of the CMSIS header is checked operand by operand
 * (bit lengths, zero terminators, curve constants). Modular exponentiation
 * and the point check are computed; P-256 multiply / sign / verify answers
 * come from the generated known-answer tables.
 *
 * RNG and HSEM are scripted state machines. Every fault the driver must
 * survive can be injected through ut_wb_t.
 */

#ifndef UT_WB_MOCK_H
#define UT_WB_MOCK_H

#include <stdint.h>

#include "ut_wb_vectors.h"

/** Words of the scripted RNG stream. */
#define UT_WB_RNG_WORDS     64U
/** Words of the PKA RAM. */
#define UT_WB_PKA_WORDS     894U

/** Peripheral model state (zeroed and defaulted by ut_wb_reset()). */
typedef struct {
    /* HSEM */
    uint32_t sem_owner[32];     /**< 0 free, otherwise the owning HSEM core id (4 = CPU1, 8 = CPU2). */
    uint32_t sem_takes;         /**< Successful one-step locks by CPU1. */
    uint32_t sem_releases;      /**< Releases by CPU1. */
    uint32_t sem_last_release;  /**< Last value written to a release register. */
    uint32_t sem_last_id;       /**< Last semaphore released. */
    /* AES1 */
    uint32_t aes_cr;            /**< CR as stored. */
    uint32_t aes_key[8];        /**< KEYR0..7. */
    uint32_t aes_iv[4];         /**< IVR0..3. */
    uint32_t aes_din[4];        /**< Input words collected. */
    uint32_t aes_din_n;         /**< Number of input words collected. */
    uint32_t aes_dout[4];       /**< Result words. */
    uint32_t aes_dout_pos;      /**< Next result word (4 = none pending). */
    uint32_t aes_ccf;           /**< SR.CCF. */
    uint32_t aes_rderr;         /**< SR.RDERR. */
    uint32_t aes_wrerr;         /**< SR.WRERR. */
    uint32_t aes_busy;          /**< Force SR.BUSY. */
    uint32_t aes_computations;  /**< Completed engine operations. */
    uint32_t aes_fault_at;      /**< 1-based operation that fails (0 = none). */
    uint32_t aes_fault_kind;    /**< 1 RDERR, 2 WRERR, 3 never completes. */
    uint32_t aes_active;        /**< GCM / CCM init phase done. */
    uint32_t aes_cr_writes;     /**< CR writes seen. */
    uint32_t aes_final_mode_ok; /**< Final phases seen in encryption mode. */
    uint32_t aes_final_mode_bad;/**< Final phases seen in another mode. */
    uint32_t aes_last_npblb;    /**< NPBLB at the last payload block. */
    uint8_t gcm_h[16];          /**< GCM hash subkey. */
    uint8_t gcm_s[16];          /**< GHASH accumulator. */
    uint8_t gcm_ekj0[16];       /**< E(K, J0). */
    uint8_t gcm_icb[16];        /**< Counter block of the next payload block. */
    uint8_t ccm_y[16];          /**< CBC-MAC state. */
    uint8_t ccm_ctr[16];        /**< Counter block A_i of the next payload block. */
    uint8_t ccm_a0[16];         /**< Counter block A_0. */
    /* RNG */
    uint32_t rng_cr;            /**< CR as stored. */
    uint32_t rng_words[UT_WB_RNG_WORDS]; /**< Scripted data words. */
    uint32_t rng_n;             /**< Scripted words. */
    uint32_t rng_pos;           /**< Next word. */
    uint32_t rng_seis;          /**< SR.SEIS. */
    uint32_t rng_secs;          /**< SR.SECS. */
    uint32_t rng_seis_rearm;    /**< Times SEIS is raised again right after the driver clears it. */
    uint32_t rng_ceis;          /**< SR.CEIS. */
    uint32_t rng_ceis_rearm;    /**< Times CEIS is raised again right after the driver clears it. */
    uint32_t rng_cecs;          /**< SR.CECS. */
    uint32_t rng_secs_clear_after; /**< DR reads after which SECS clears (0 = never). */
    uint32_t rng_underruns;     /**< DR reads with no scripted word. */
    uint32_t rng_cr_writes;     /**< CR writes seen. */
    uint32_t rng_drdy_block;    /**< Force DRDY low. */
    uint32_t rng_dr_reads;      /**< DR reads. */
    /* PKA */
    uint32_t pka_cr;            /**< CR as stored. */
    uint32_t pka_flags;         /**< SR flag bits (PROCEND, RAMERR, ADDRERR). */
    uint32_t pka_ram[UT_WB_PKA_WORDS]; /**< PKA RAM. */
    uint32_t pka_starts;        /**< Operations started. */
    uint32_t pka_last_mode;     /**< Mode of the last operation. */
    uint32_t pka_busy;          /**< Force SR.BUSY. */
    uint32_t pka_never_end;     /**< Operations never finish. */
    uint32_t pka_ramerr;        /**< Operations end with a RAM error. */
    uint32_t pka_addrerr;       /**< Operations end with an address error. */
    uint32_t pka_fault_start;   /**< 1-based start that ends with a RAM error (0 = none). */
    uint32_t pka_force_sign_err;/**< ECDSA sign error word is forced non-zero. */
    uint32_t pka_force_sign_zero;/**< ECDSA sign returns r = s = 0 with no error. */
    uint32_t pka_force_check;   /**< Point check: 0 computed, 1 force off-curve, 2 force on-curve. */
    uint32_t pka_force_verify;  /**< ECDSA verify: 0 table, 1 force invalid, 2 force valid. */
    uint32_t pka_exp_bits;      /**< Exponent bit length seen by the last modexp / scalar bits of a multiply. */
    uint32_t pka_op_bits;       /**< Operand bit length seen by the last operation. */
    uint32_t pka_wipe_checked;  /**< Non-zero RAM words observed at the last START (diagnostic). */
    const ut_wb_mul_vec_t *mul_tab;       /**< Scalar multiplication answers. */
    uint32_t mul_n;                       /**< Entries in mul_tab. */
    const ut_wb_sign_vec_t *sign_tab;     /**< Signing answers. */
    uint32_t sign_n;                      /**< Entries in sign_tab. */
    const ut_wb_verify_vec_t *verify_tab; /**< Valid signatures. */
    uint32_t verify_n;                    /**< Entries in verify_tab. */
    /* Model diagnostics */
    uint32_t proto_err;         /**< Uses a real device would reject. */
    uint32_t bad_access;        /**< Accesses outside every modelled register. */
} ut_wb_t;

/** The model. */
extern ut_wb_t g_wb;

/** Reset the model and every driver counter that tests depend on to its power-on state. */
void ut_wb_reset(void);

/**
 * @brief Make CPU2 hold a semaphore.
 *
 * @param[in] id Semaphore number.
 */
void ut_wb_cpu2_take(uint32_t id);

/**
 * @brief Script the RNG data stream.
 *
 * @param[in] words Words (copied).
 * @param[in] n     Count (at most UT_WB_RNG_WORDS).
 */
void ut_wb_rng_script(const uint32_t *words, uint32_t n);

/** Fill the RNG script with @p n distinct, non-repeating words. */
void ut_wb_rng_script_counter(uint32_t n);

/** @brief Read a big-endian operand out of the PKA RAM (little-endian words). */
void ut_wb_ram_get(uint32_t off, uint8_t *out, uint32_t len);

/** @brief Word at a PKA RAM offset. */
uint32_t ut_wb_ram_word(uint32_t off);

#endif /* UT_WB_MOCK_H */
