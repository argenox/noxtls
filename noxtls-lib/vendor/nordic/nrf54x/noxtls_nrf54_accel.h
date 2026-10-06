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
* File:    noxtls_nrf54_accel.h
* Summary: Public header of the NoxTLS nRF54L CRACEN backend
*
*****************************************************************************/

/**
 * @file noxtls_nrf54_accel.h
 * @brief Everything an application needs from the nRF54L CRACEN backend.
 * @ingroup noxtls_nrf54
 *
 * Build with NOXTLS_CFG_FEATURE_NRF54_HW_ACCEL=ON (CMake) or define
 * NOXTLS_FEATURE_NRF54_HW_ACCEL=1 and compile the files of
 * noxtls-lib/vendor/nordic/nrf54x. NoxTLS then routes AES (block, ECB / CBC /
 * CTR, GCM, CCM), SHA-224/256/384/512, CTR-DRBG entropy, P-256 point
 * multiplication, ECDSA P-256 verification and Ed25519 verification to CRACEN,
 * with software fallback. An RTOS calls noxtls_nrf54_cracen_set_port() once
 * so that long operations sleep on CRACEN_IRQn instead of polling.
 */

#ifndef NOXTLS_NRF54_ACCEL_H
#define NOXTLS_NRF54_ACCEL_H

#include "noxtls_nrf54_cracen.h"
#include "noxtls_nrf54_aes.h"
#include "noxtls_nrf54_aead.h"
#include "noxtls_nrf54_hash.h"
#include "noxtls_nrf54_rng.h"
#include "noxtls_nrf54_pke.h"
#include "noxtls_nrf54_kmu.h"

#endif /* NOXTLS_NRF54_ACCEL_H */
