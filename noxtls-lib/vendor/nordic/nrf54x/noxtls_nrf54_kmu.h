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
* File:    noxtls_nrf54_kmu.h
* Summary: nRF54L KMU key slots (provision, push, block, revoke, read metadata)
*
*****************************************************************************/

/**
 * @file noxtls_nrf54_kmu.h
 * @brief Key management unit: 250 slots of 128 bits pushed into CRACEN protected RAM.
 * @ingroup noxtls_nrf54
 *
 * A pushed AES key is used by address with noxtls_nrf54_aes_crypt_keyref()
 * (noxtls_nrf54_cracen_hw()->prot_key0 for key 0); the CPU never reads it.
 * A task completes when its event fires: the task event means success,
 * EVENTS_REVOKED that the slot is revoked, EVENTS_ERROR that the task failed
 * (for READMETADATA: the slot is empty). The KMU has no interrupt line, so
 * tasks are awaited with a bounded poll. PROVISION and REVOKE write RRAM and
 * are permanent: an optional hook enables RRAM writes around them.
 */

#ifndef NOXTLS_NRF54_KMU_H
#define NOXTLS_NRF54_KMU_H

#include <stdint.h>

#include "noxtls_nrf54_cracen.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Revoke policy: the slot can be rewritten after a revoke. */
#define NOXTLS_NRF54_KMU_RPOLICY_ROTATING UINT32_C(0x01)
/** Revoke policy: the slot can never be revoked. */
#define NOXTLS_NRF54_KMU_RPOLICY_LOCKED   UINT32_C(0x02)
/** Revoke policy: the slot is revoked for good when revoked. */
#define NOXTLS_NRF54_KMU_RPOLICY_REVOKED  UINT32_C(0x03)

/** Provisioning source read by the KMU (28 bytes, word aligned, in RAM). */
typedef struct {
    uint32_t value[NOXTLS_NRF54_KMU_SLOT_WORDS]; /**< 128-bit key material. */
    uint32_t revoke_policy;                      /**< NOXTLS_NRF54_KMU_RPOLICY_*. */
    uint32_t dest;                               /**< Push destination address. */
    uint32_t metadata;                           /**< Metadata stored with the slot. */
} noxtls_nrf54_kmu_slot_data_t;

/** State of a slot reported by noxtls_nrf54_kmu_read_metadata(). */
typedef enum {
    NOXTLS_NRF54_KMU_SLOT_EMPTY = 0,       /**< Not provisioned. */
    NOXTLS_NRF54_KMU_SLOT_PROVISIONED = 1, /**< Provisioned; metadata valid. */
    NOXTLS_NRF54_KMU_SLOT_REVOKED = 2      /**< Revoked. */
} noxtls_nrf54_kmu_state_t;

/**
 * @brief Enable or disable RRAM writes around PROVISION / REVOKE.
 *
 * @param[in] ctx    Hook context.
 * @param[in] enable 1 before the task, 0 after it.
 *
 * @return NOXTLS_RETURN_SUCCESS to proceed (an error aborts the operation).
 */
typedef noxtls_return_t (*noxtls_nrf54_kmu_nvm_fn_t)(void *ctx, uint8_t enable);

/**
 * @brief Install the RRAM write hook used by provision / revoke (NULL removes it).
 *
 * @param[in] fn  Hook.
 * @param[in] ctx Hook context.
 */
void noxtls_nrf54_kmu_set_nvm_hook(noxtls_nrf54_kmu_nvm_fn_t fn, void *ctx);

/**
 * @brief Read the metadata and state of a slot.
 *
 * @param[in]  slot     Slot (0..249).
 * @param[out] metadata Metadata (0 unless provisioned).
 * @param[out] state    Slot state.
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL, NOXTLS_RETURN_INVALID_PARAM or NOXTLS_RETURN_TIMEOUT.
 */
noxtls_return_t noxtls_nrf54_kmu_read_metadata(uint32_t slot, uint32_t *metadata, noxtls_nrf54_kmu_state_t *state);

/**
 * @brief Push @p count consecutive slots to their destinations.
 *
 * @param[in] slot  First slot.
 * @param[in] count Slots (>= 1).
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_INVALID_PARAM, NOXTLS_RETURN_FAILED
 *         (empty, blocked or revoked slot) or NOXTLS_RETURN_TIMEOUT.
 */
noxtls_return_t noxtls_nrf54_kmu_push(uint32_t slot, uint32_t count);

/**
 * @brief Block pushes of @p count slots until the next reset.
 *
 * @param[in] slot  First slot.
 * @param[in] count Slots.
 *
 * @return As noxtls_nrf54_kmu_push().
 */
noxtls_return_t noxtls_nrf54_kmu_push_block(uint32_t slot, uint32_t count);

/**
 * @brief Block every operation on @p count slots until the next reset (nRF54LM20 only).
 *
 * @param[in] slot  First slot.
 * @param[in] count Slots.
 *
 * @return As noxtls_nrf54_kmu_push(), or NOXTLS_RETURN_NOT_SUPPORTED on the nRF54L15.
 */
noxtls_return_t noxtls_nrf54_kmu_block(uint32_t slot, uint32_t count);

/**
 * @brief Provision one slot (permanent RRAM write).
 *
 * @param[in] slot Slot.
 * @param[in] data Source (RAM, word aligned).
 *
 * @return NOXTLS_RETURN_SUCCESS, NOXTLS_RETURN_NULL, NOXTLS_RETURN_INVALID_PARAM,
 *         NOXTLS_RETURN_FAILED (slot not empty or revoked), NOXTLS_RETURN_TIMEOUT
 *         or the RRAM hook error.
 */
noxtls_return_t noxtls_nrf54_kmu_provision(uint32_t slot, const noxtls_nrf54_kmu_slot_data_t *data);

/**
 * @brief Revoke @p count slots (permanent).
 *
 * @param[in] slot  First slot.
 * @param[in] count Slots.
 *
 * @return As noxtls_nrf54_kmu_push(), or the RRAM hook error.
 */
noxtls_return_t noxtls_nrf54_kmu_revoke(uint32_t slot, uint32_t count);

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_NRF54_KMU_H */
