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
* File:    noxtls_nrf54_pke.c
* Summary: CRACEN BA414EP: ECDSA P-256 verify, Ed25519 verify, P-256 point multiply
*
*****************************************************************************/

/**
 * @file noxtls_nrf54_pke.c
 * @brief Public-key operations on the CRACEN BA414EP engine.
 * @ingroup noxtls_nrf54
 *
 * Command sequence (one command per call):
 *   1. power the PKE / IKG module and wait until neither reports busy;
 *   2. nRF54L15: load the microcode into the code RAM once and read it back;
 *   3. clear a completion interrupt latched by the power-up (CONTROL.CLEARIRQ,
 *      EVENTS_PKEIKG) before anything is armed;
 *   4. write COMMAND, then the operands (aligned 32-bit writes only), then the
 *      slot pointers when the command uses them;
 *   5. CONTROL = START | CLEARIRQ; the PKE interrupt is armed only after START
 *      and the CPU sleeps in the port wait hook until STATUS.BUSY clears;
 *   6. read the result, wipe the operand memory, power the module down.
 * STATUS error flags: point not on curve, operand out of range, invalid
 * signature, not invertible, not a quadratic residue and wrong order are
 * verification rejections; any other flag (or a timeout) makes the caller fall
 * back to software.
 */

#include <stddef.h>
#include <string.h>

#include "noxtls_nrf54_pke.h"
#include "noxtls_nrf54_ba414ep_ucode.h"

/** @brief Bytes per operand-memory word. */
#define NOXTLS_NRF54_PKE_WORD_BYTES     4U
/** @brief Bits per byte. */
#define NOXTLS_NRF54_PKE_BITS_PER_BYTE  8U
/** @brief Byte holding the x-parity bit of an encoded Edwards point (RFC 8032 §5.1.2). */
#define NOXTLS_NRF54_PKE_ED_SIGN_BYTE   31U
/** @brief x-parity bit of the last byte of an encoded Edwards point. */
#define NOXTLS_NRF54_PKE_ED_SIGN_BIT    0x80U
/** @brief Blinding factor: bits 63..62 must be clear (big-endian first byte mask). */
#define NOXTLS_NRF54_PKE_BLIND_TOP_MSK  0x3FU
/** @brief Blinding factor: bit 61 must be set. */
#define NOXTLS_NRF54_PKE_BLIND_TOP_SET  0x20U
/** @brief Blinding factor: must be odd. */
#define NOXTLS_NRF54_PKE_BLIND_ODD      0x01U
/** @brief Operand bytes - 1 field of a 32-byte command. */
#define NOXTLS_NRF54_PKE_OPSZ_32        ((NOXTLS_NRF54_PKE_OPERAND_BYTES - 1U) << NOXTLS_NRF54_PK_OPSZ_POS)
/** @brief Operand bytes - 1 field of the clear-memory command (operand size 1). */
#define NOXTLS_NRF54_PKE_OPSZ_1         0U
/** @brief Status value reported for a command that did not finish in time. */
#define NOXTLS_NRF54_PKE_ST_TIMEOUT     NOXTLS_NRF54_PK_ST_BUSY

/** Module state. */
typedef struct {
    uint32_t slot_size;              /**< Operand slot bytes. */
    uint8_t ucode_loaded;            /**< Non-zero once the nRF54L15 microcode is in place. */
    noxtls_nrf54_pke_stats_t stats;  /**< Counters. */
} noxtls_nrf54_pke_t;

/** Module state. */
static noxtls_nrf54_pke_t s_noxtls_nrf54_pke = { NOXTLS_NRF54_PK_SLOT_SMALL, 0U, { 0U, 0U, 0U, 0U, 0U } };

/**
 * @brief Whether the instance is CRACEN Lite (nRF54LM20).
 * @internal
 *
 * @return 1 on CRACEN Lite.
 */
static uint8_t noxtls_nrf54_pke_lite(void)
{
    return (noxtls_nrf54_cracen_hw()->variant == NOXTLS_NRF54_VARIANT_LITE) ? 1U : 0U;
}

/**
 * @brief Offset of a slot byte inside CRACENCORE.
 * @internal
 *
 * @param[in] slot Slot.
 * @param[in] off  Byte offset inside the slot (multiple of 4).
 *
 * @return CRACENCORE offset.
 */
static uint32_t noxtls_nrf54_pke_addr(uint32_t slot, uint32_t off)
{
    return NOXTLS_NRF54_PK_DATA + (slot * s_noxtls_nrf54_pke.slot_size) + off;
}

/**
 * @brief Write bytes to operand memory with aligned word stores.
 * @internal
 *
 * @param[in] slot Slot.
 * @param[in] off  Byte offset inside the slot (multiple of 4).
 * @param[in] src  Bytes (memory order).
 * @param[in] len  Bytes (multiple of 4).
 */
static void noxtls_nrf54_pke_put(uint32_t slot, uint32_t off, const uint8_t *src, uint32_t len)
{
    uint32_t i;

    for (i = 0U; i < len; i += NOXTLS_NRF54_PKE_WORD_BYTES) {
        uint32_t w = (uint32_t)src[i] | ((uint32_t)src[i + 1U] << NOXTLS_NRF54_PKE_BITS_PER_BYTE) |
                     ((uint32_t)src[i + 2U] << (2U * NOXTLS_NRF54_PKE_BITS_PER_BYTE)) |
                     ((uint32_t)src[i + 3U] << (3U * NOXTLS_NRF54_PKE_BITS_PER_BYTE));

        noxtls_nrf54_core_wr(noxtls_nrf54_pke_addr(slot, off + i), w);
    }
}

/**
 * @brief Read bytes from operand memory with aligned word loads.
 * @internal
 *
 * @param[in]  slot Slot.
 * @param[in]  off  Byte offset (multiple of 4).
 * @param[out] dst  Bytes.
 * @param[in]  len  Bytes (multiple of 4).
 */
static void noxtls_nrf54_pke_get(uint32_t slot, uint32_t off, uint8_t *dst, uint32_t len)
{
    uint32_t i;

    for (i = 0U; i < len; i += NOXTLS_NRF54_PKE_WORD_BYTES) {
        uint32_t w = noxtls_nrf54_core_rd(noxtls_nrf54_pke_addr(slot, off + i));

        dst[i] = (uint8_t)w;
        dst[i + 1U] = (uint8_t)(w >> NOXTLS_NRF54_PKE_BITS_PER_BYTE);
        dst[i + 2U] = (uint8_t)(w >> (2U * NOXTLS_NRF54_PKE_BITS_PER_BYTE));
        dst[i + 3U] = (uint8_t)(w >> (3U * NOXTLS_NRF54_PKE_BITS_PER_BYTE));
    }
}

/**
 * @brief Offset of a 32-byte big-endian operand (right-aligned in its slot).
 * @internal
 *
 * @return Byte offset inside the slot.
 */
static uint32_t noxtls_nrf54_pke_be_off(void)
{
    return s_noxtls_nrf54_pke.slot_size - NOXTLS_NRF54_PKE_OPERAND_BYTES;
}

/**
 * @brief Load the microcode into the nRF54L15 code RAM and read it back.
 * @internal
 *
 * @return 1 when the code RAM holds the image.
 */
static uint8_t noxtls_nrf54_pke_load_ucode(void)
{
    uint32_t i;
    uint8_t ok = 1U;

    for (i = 0U; i < NOXTLS_NRF54_BA414EP_UCODE_WORDS; i++) {
        noxtls_nrf54_core_wr(NOXTLS_NRF54_PK_CODE + (i * NOXTLS_NRF54_PKE_WORD_BYTES), noxtls_nrf54_ba414ep_ucode[i]);
    }
    /* The read-back both checks the image and orders the device writes before START. */
    for (i = 0U; (i < NOXTLS_NRF54_BA414EP_UCODE_WORDS) && (ok != 0U); i++) {
        if (noxtls_nrf54_core_rd(NOXTLS_NRF54_PK_CODE + (i * NOXTLS_NRF54_PKE_WORD_BYTES)) !=
            noxtls_nrf54_ba414ep_ucode[i]) {
            ok = 0U;
        }
    }
    s_noxtls_nrf54_pke.stats.ucode_loads++;
    s_noxtls_nrf54_pke.ucode_loaded = ok;
    return ok;
}

/**
 * @brief Whether the PKE or the IKG reports busy.
 * @internal
 *
 * @return Non-zero while busy.
 */
static uint32_t noxtls_nrf54_pke_engine_busy(void)
{
    return (noxtls_nrf54_core_rd(NOXTLS_NRF54_PK_STATUS) & NOXTLS_NRF54_PK_ST_BUSY) |
           (noxtls_nrf54_core_rd(NOXTLS_NRF54_IKG_PKESTATUS) & NOXTLS_NRF54_IKG_ST_BUSY_MSK);
}

/**
 * @brief Acquire CRACEN, power the PKE and prepare it for a command.
 * @internal
 *
 * @param[in] need_p256 Non-zero when the command needs the built-in P-256 curve.
 *
 * @return NOXTLS_RETURN_SUCCESS (CRACEN owned) or NOXTLS_RETURN_NOT_SUPPORTED (released).
 */
static noxtls_return_t noxtls_nrf54_pke_begin(uint8_t need_p256)
{
    noxtls_return_t rc = noxtls_nrf54_cracen_acquire(NOXTLS_NRF54_MOD_PKE);

    if (rc == NOXTLS_RETURN_SUCCESS) {
        uint32_t spins = (uint32_t)NOXTLS_NRF54_CONFIG_PKE_READY_SPINS;
        uint32_t hwconfig;

        if ((noxtls_nrf54_cracen_caps()->inclips & NOXTLS_NRF54_INCLIPS_BA414EP) == 0U) {
            rc = NOXTLS_RETURN_NOT_SUPPORTED;
        }
        while ((rc == NOXTLS_RETURN_SUCCESS) && (noxtls_nrf54_pke_engine_busy() != 0U) && (spins > 0U)) {
            spins--;
        }
        if ((rc == NOXTLS_RETURN_SUCCESS) && (noxtls_nrf54_pke_engine_busy() != 0U)) {
            rc = NOXTLS_RETURN_NOT_SUPPORTED;
        }
        if ((rc == NOXTLS_RETURN_SUCCESS) && (noxtls_nrf54_pke_lite() == 0U) &&
            (s_noxtls_nrf54_pke.ucode_loaded == 0U) && (noxtls_nrf54_pke_load_ucode() == 0U)) {
            rc = NOXTLS_RETURN_NOT_SUPPORTED;
        }
        if (rc == NOXTLS_RETURN_SUCCESS) {
            hwconfig = noxtls_nrf54_core_rd(NOXTLS_NRF54_PK_HWCONFIG);
            s_noxtls_nrf54_pke.slot_size = ((hwconfig & NOXTLS_NRF54_PK_HW_MAXOPSZ_MSK) > NOXTLS_NRF54_PK_SLOT_SMALL) ?
                                           NOXTLS_NRF54_PK_SLOT_LARGE : NOXTLS_NRF54_PK_SLOT_SMALL;
            if ((need_p256 != 0U) && ((hwconfig & NOXTLS_NRF54_PK_HW_P256) == 0U)) {
                rc = NOXTLS_RETURN_NOT_SUPPORTED;
            }
        }
        if (rc == NOXTLS_RETURN_SUCCESS) {
            /* A completion latched at power-up must not satisfy the first wait. */
            noxtls_nrf54_core_wr(NOXTLS_NRF54_PK_CONTROL, NOXTLS_NRF54_PK_CTRL_CLEARIRQ);
            noxtls_nrf54_event_clear(NOXTLS_NRF54_EVENTS_PKEIKG);
        } else {
            noxtls_nrf54_cracen_release();
        }
    }
    return rc;
}

/**
 * @brief Completion check: the engine no longer reports busy.
 * @internal
 *
 * @param[in] ctx Unused.
 *
 * @return Non-zero when idle.
 */
static uint8_t noxtls_nrf54_pke_done(void *ctx)
{
    (void)ctx;
    return ((noxtls_nrf54_core_rd(NOXTLS_NRF54_PK_STATUS) & NOXTLS_NRF54_PK_ST_BUSY) == 0U) ? 1U : 0U;
}

/**
 * @brief Start the programmed command and wait for it.
 * @internal
 *
 * @param[in] pointers POINTERS value, or 0 when the command does not use them.
 *
 * @return STATUS error flags, or NOXTLS_NRF54_PKE_ST_TIMEOUT.
 */
static uint32_t noxtls_nrf54_pke_run(uint32_t pointers)
{
    noxtls_nrf54_pke_t *pk = &s_noxtls_nrf54_pke;
    uint32_t status;

    if (pointers != 0U) {
        noxtls_nrf54_core_wr(NOXTLS_NRF54_PK_POINTERS, pointers);
    }
    noxtls_nrf54_core_wr(NOXTLS_NRF54_PK_CONTROL, NOXTLS_NRF54_PK_CTRL_START | NOXTLS_NRF54_PK_CTRL_CLEARIRQ);
    if (noxtls_nrf54_cracen_wait(NOXTLS_NRF54_MOD_PKE, noxtls_nrf54_pke_done, NULL,
                                 NOXTLS_NRF54_CONFIG_PKE_TIMEOUT_US) != NOXTLS_RETURN_SUCCESS) {
        status = NOXTLS_NRF54_PKE_ST_TIMEOUT;
        /* Powering the module down stops the command; reload the microcode next time. */
        pk->ucode_loaded = 0U;
    } else {
        status = noxtls_nrf54_core_rd(NOXTLS_NRF54_PK_STATUS) & NOXTLS_NRF54_PK_ST_ERR_MSK;
        if ((status & NOXTLS_NRF54_PK_ST_BAD_UCODE) != 0U) {
            pk->ucode_loaded = 0U;
        }
    }
    noxtls_nrf54_core_wr(NOXTLS_NRF54_PK_CONTROL, NOXTLS_NRF54_PK_CTRL_CLEARIRQ);
    pk->stats.commands++;
    pk->stats.last_status = status;
    return status;
}

/**
 * @brief Wipe the operand memory, then power down and release CRACEN.
 * @internal
 *
 * @param[in] slots Bit mask of the slots used (nRF54L15 word wipe).
 */
static void noxtls_nrf54_pke_end(uint32_t slots)
{
    if (noxtls_nrf54_pke_lite() != 0U) {
        uint32_t spins = (uint32_t)NOXTLS_NRF54_CONFIG_PKE_READY_SPINS;

        /* CRACEN Lite: the engine clears its whole operand memory. */
        noxtls_nrf54_core_wr(NOXTLS_NRF54_PK_COMMAND, NOXTLS_NRF54_PK_OP_CLEAR_MEM | NOXTLS_NRF54_PKE_OPSZ_1);
        noxtls_nrf54_core_wr(NOXTLS_NRF54_PK_CONTROL, NOXTLS_NRF54_PK_CTRL_START | NOXTLS_NRF54_PK_CTRL_CLEARIRQ);
        while ((noxtls_nrf54_pke_done(NULL) == 0U) && (spins > 0U)) {
            spins--;
        }
        noxtls_nrf54_core_wr(NOXTLS_NRF54_PK_CONTROL, NOXTLS_NRF54_PK_CTRL_CLEARIRQ);
    } else {
        uint32_t slot;

        /* The base CRACEN has no clear-memory command: word writes. */
        for (slot = 0U; slot < (uint32_t)(sizeof(slots) * NOXTLS_NRF54_PKE_BITS_PER_BYTE); slot++) {
            if ((slots & (UINT32_C(1) << slot)) != 0U) {
                uint32_t off;

                for (off = 0U; off < s_noxtls_nrf54_pke.slot_size; off += NOXTLS_NRF54_PKE_WORD_BYTES) {
                    noxtls_nrf54_core_wr(noxtls_nrf54_pke_addr(slot, off), 0U);
                }
            }
        }
    }
    noxtls_nrf54_event_clear(NOXTLS_NRF54_EVENTS_PKEIKG);
    noxtls_nrf54_cracen_release();
}

/**
 * @brief Map the status of a verification.
 * @internal
 *
 * @param[in] status Error flags or NOXTLS_NRF54_PKE_ST_TIMEOUT.
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_FAILED (rejected) or NOXTLS_RETURN_NOT_SUPPORTED.
 */
static noxtls_return_t noxtls_nrf54_pke_map(uint32_t status)
{
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if (status == 0U) {
        /* Valid. */
    } else if ((status & ~NOXTLS_NRF54_PK_ST_REJECT) == 0U) {
        s_noxtls_nrf54_pke.stats.rejects++;
        rc = NOXTLS_RETURN_FAILED;
    } else {
        s_noxtls_nrf54_pke.stats.errors++;
        rc = NOXTLS_RETURN_NOT_SUPPORTED;
    }
    return rc;
}

noxtls_return_t noxtls_nrf54_pke_ecdsa_p256_verify(const uint8_t *qx, const uint8_t *qy, const uint8_t *h,
                                                   const uint8_t *r, const uint8_t *s)
{
    noxtls_return_t rc;

    if ((qx == NULL) || (qy == NULL) || (h == NULL) || (r == NULL) || (s == NULL)) {
        rc = NOXTLS_RETURN_NULL;
    } else {
        rc = noxtls_nrf54_pke_begin(1U);
        if (rc == NOXTLS_RETURN_SUCCESS) {
            uint32_t off = noxtls_nrf54_pke_be_off();

            noxtls_nrf54_core_wr(NOXTLS_NRF54_PK_COMMAND, NOXTLS_NRF54_PK_OP_ECDSA_VERIFY | NOXTLS_NRF54_PK_FLAG_BIG_ENDIAN |
                                 NOXTLS_NRF54_PK_CURVE_P256 | NOXTLS_NRF54_PKE_OPSZ_32);
            noxtls_nrf54_pke_put(NOXTLS_NRF54_PK_SLOT_ECDSA_QX, off, qx, NOXTLS_NRF54_PKE_OPERAND_BYTES);
            noxtls_nrf54_pke_put(NOXTLS_NRF54_PK_SLOT_ECDSA_QY, off, qy, NOXTLS_NRF54_PKE_OPERAND_BYTES);
            noxtls_nrf54_pke_put(NOXTLS_NRF54_PK_SLOT_ECDSA_R, off, r, NOXTLS_NRF54_PKE_OPERAND_BYTES);
            noxtls_nrf54_pke_put(NOXTLS_NRF54_PK_SLOT_ECDSA_S, off, s, NOXTLS_NRF54_PKE_OPERAND_BYTES);
            noxtls_nrf54_pke_put(NOXTLS_NRF54_PK_SLOT_ECDSA_H, off, h, NOXTLS_NRF54_PKE_OPERAND_BYTES);
            rc = noxtls_nrf54_pke_map(noxtls_nrf54_pke_run(0U));
            noxtls_nrf54_pke_end((UINT32_C(1) << NOXTLS_NRF54_PK_SLOT_ECDSA_QX) | (UINT32_C(1) << NOXTLS_NRF54_PK_SLOT_ECDSA_QY) |
                                 (UINT32_C(1) << NOXTLS_NRF54_PK_SLOT_ECDSA_R) | (UINT32_C(1) << NOXTLS_NRF54_PK_SLOT_ECDSA_S) |
                                 (UINT32_C(1) << NOXTLS_NRF54_PK_SLOT_ECDSA_H));
        }
    }
    return rc;
}

/**
 * @brief Write the y-coordinate of an encoded Edwards point (x-parity bit cleared).
 * @internal
 *
 * @param[in] slot Slot.
 * @param[in] pt   Encoded point (32 bytes).
 */
static void noxtls_nrf54_pke_put_y(uint32_t slot, const uint8_t *pt)
{
    uint8_t y[NOXTLS_NRF54_PKE_OPERAND_BYTES];

    (void)memcpy(y, pt, sizeof(y));
    y[NOXTLS_NRF54_PKE_ED_SIGN_BYTE] &= (uint8_t)~NOXTLS_NRF54_PKE_ED_SIGN_BIT;
    noxtls_nrf54_pke_put(slot, 0U, y, NOXTLS_NRF54_PKE_OPERAND_BYTES);
}

noxtls_return_t noxtls_nrf54_pke_ed25519_verify(const uint8_t *pub, const uint8_t *sig, const uint8_t *k)
{
    noxtls_return_t rc;

    if ((pub == NULL) || (sig == NULL) || (k == NULL)) {
        rc = NOXTLS_RETURN_NULL;
    } else {
        rc = noxtls_nrf54_pke_begin(0U);
        if (rc == NOXTLS_RETURN_SUCCESS) {
            uint32_t cmd = NOXTLS_NRF54_PK_OP_EDDSA_VERIFY | NOXTLS_NRF54_PK_CURVE_ED25519 | NOXTLS_NRF54_PKE_OPSZ_32;

            /* RFC 8032 §5.1.3: the top bit of the last byte is the parity of x. */
            if ((pub[NOXTLS_NRF54_PKE_ED_SIGN_BYTE] & NOXTLS_NRF54_PKE_ED_SIGN_BIT) != 0U) {
                cmd |= NOXTLS_NRF54_PK_FLAG_ED_AX_ODD;
            }
            if ((sig[NOXTLS_NRF54_PKE_ED_SIGN_BYTE] & NOXTLS_NRF54_PKE_ED_SIGN_BIT) != 0U) {
                cmd |= NOXTLS_NRF54_PK_FLAG_ED_RX_ODD;
            }
            noxtls_nrf54_core_wr(NOXTLS_NRF54_PK_COMMAND, cmd);
            /* k is a 512-bit little-endian integer split over two slots; the engine reduces it mod L. */
            noxtls_nrf54_pke_put(NOXTLS_NRF54_PK_SLOT_ED_K, 0U, k, NOXTLS_NRF54_PKE_OPERAND_BYTES);
            noxtls_nrf54_pke_put(NOXTLS_NRF54_PK_SLOT_ED_K + 1U, 0U, &k[NOXTLS_NRF54_PKE_OPERAND_BYTES],
                                 NOXTLS_NRF54_PKE_OPERAND_BYTES);
            noxtls_nrf54_pke_put_y(NOXTLS_NRF54_PK_SLOT_ED_AY, pub);
            noxtls_nrf54_pke_put(NOXTLS_NRF54_PK_SLOT_ED_S, 0U, &sig[NOXTLS_NRF54_PKE_OPERAND_BYTES],
                                 NOXTLS_NRF54_PKE_OPERAND_BYTES);
            noxtls_nrf54_pke_put_y(NOXTLS_NRF54_PK_SLOT_ED_RY, sig);
            rc = noxtls_nrf54_pke_map(noxtls_nrf54_pke_run(0U));
            noxtls_nrf54_pke_end((UINT32_C(1) << NOXTLS_NRF54_PK_SLOT_ED_K) | (UINT32_C(1) << (NOXTLS_NRF54_PK_SLOT_ED_K + 1U)) |
                                 (UINT32_C(1) << NOXTLS_NRF54_PK_SLOT_ED_AY) | (UINT32_C(1) << NOXTLS_NRF54_PK_SLOT_ED_S) |
                                 (UINT32_C(1) << NOXTLS_NRF54_PK_SLOT_ED_RY));
        }
    }
    return rc;
}

noxtls_return_t noxtls_nrf54_pke_p256_mul(const uint8_t *k, const uint8_t *px, const uint8_t *py,
                                          const uint8_t *blind, uint8_t *rx, uint8_t *ry)
{
    noxtls_return_t rc;

    if ((k == NULL) || (px == NULL) || (py == NULL) || (blind == NULL) || (rx == NULL) || (ry == NULL)) {
        rc = NOXTLS_RETURN_NULL;
    } else {
        rc = noxtls_nrf54_pke_begin(1U);
        if (rc == NOXTLS_RETURN_SUCCESS) {
            uint32_t off = noxtls_nrf54_pke_be_off();
            uint8_t b[NOXTLS_NRF54_PK_BLIND_BYTES];
            uint32_t status;

            /* Blinding factor (big-endian): odd, bits 63..62 clear, bit 61 set (constant-time engine path). */
            (void)memcpy(b, blind, sizeof(b));
            b[0] = (uint8_t)((b[0] & NOXTLS_NRF54_PKE_BLIND_TOP_MSK) | NOXTLS_NRF54_PKE_BLIND_TOP_SET);
            b[NOXTLS_NRF54_PK_BLIND_BYTES - 1U] |= NOXTLS_NRF54_PKE_BLIND_ODD;
            noxtls_nrf54_core_wr(NOXTLS_NRF54_PK_COMMAND, NOXTLS_NRF54_PK_OP_ECC_PTMUL | NOXTLS_NRF54_PK_FLAG_BIG_ENDIAN |
                                 NOXTLS_NRF54_PK_CURVE_P256 | NOXTLS_NRF54_PK_FLAG_RESQUARE |
                                 NOXTLS_NRF54_PK_FLAG_RAND_SCALAR | NOXTLS_NRF54_PK_FLAG_RAND_PROJ | NOXTLS_NRF54_PKE_OPSZ_32);
            noxtls_nrf54_pke_put(NOXTLS_NRF54_PK_SLOT_PTMUL_PX, off, px, NOXTLS_NRF54_PKE_OPERAND_BYTES);
            noxtls_nrf54_pke_put(NOXTLS_NRF54_PK_SLOT_PTMUL_PY, off, py, NOXTLS_NRF54_PKE_OPERAND_BYTES);
            noxtls_nrf54_pke_put(NOXTLS_NRF54_PK_SLOT_PTMUL_K, off, k, NOXTLS_NRF54_PKE_OPERAND_BYTES);
            noxtls_nrf54_pke_put(NOXTLS_NRF54_PK_SLOT_BLIND, s_noxtls_nrf54_pke.slot_size - NOXTLS_NRF54_PK_BLIND_BYTES, b,
                                 NOXTLS_NRF54_PK_BLIND_BYTES);
            noxtls_nrf54_wipe(b, (uint32_t)sizeof(b));
            status = noxtls_nrf54_pke_run(NOXTLS_NRF54_PK_SLOT_PTMUL_PX |
                                          (NOXTLS_NRF54_PK_SLOT_PTMUL_K << NOXTLS_NRF54_PK_PTR_B_POS) |
                                          (NOXTLS_NRF54_PK_SLOT_PTMUL_RX << NOXTLS_NRF54_PK_PTR_C_POS));
            if (status == 0U) {
                noxtls_nrf54_pke_get(NOXTLS_NRF54_PK_SLOT_PTMUL_RX, off, rx, NOXTLS_NRF54_PKE_OPERAND_BYTES);
                noxtls_nrf54_pke_get(NOXTLS_NRF54_PK_SLOT_PTMUL_RY, off, ry, NOXTLS_NRF54_PKE_OPERAND_BYTES);
            } else {
                s_noxtls_nrf54_pke.stats.errors++;
                noxtls_nrf54_wipe(rx, NOXTLS_NRF54_PKE_OPERAND_BYTES);
                noxtls_nrf54_wipe(ry, NOXTLS_NRF54_PKE_OPERAND_BYTES);
                rc = NOXTLS_RETURN_NOT_SUPPORTED;
            }
            noxtls_nrf54_pke_end((UINT32_C(1) << NOXTLS_NRF54_PK_SLOT_PTMUL_K) | (UINT32_C(1) << NOXTLS_NRF54_PK_SLOT_PTMUL_RX) |
                                 (UINT32_C(1) << NOXTLS_NRF54_PK_SLOT_PTMUL_RY) | (UINT32_C(1) << NOXTLS_NRF54_PK_SLOT_PTMUL_PX) |
                                 (UINT32_C(1) << NOXTLS_NRF54_PK_SLOT_PTMUL_PY) | (UINT32_C(1) << NOXTLS_NRF54_PK_SLOT_BLIND));
        }
    }
    return rc;
}

const noxtls_nrf54_pke_stats_t *noxtls_nrf54_pke_stats(void)
{
    return &s_noxtls_nrf54_pke.stats;
}

void noxtls_nrf54_pke_invalidate_ucode(void)
{
    s_noxtls_nrf54_pke.ucode_loaded = 0U;
}
