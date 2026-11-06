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
* File:    noxtls_efr32_accel.h
* Summary: Public header of the NoxTLS EFR32xG2x hardware backend
*
*****************************************************************************/

/**
 * @file noxtls_efr32_accel.h
 * @brief Everything an application needs from the EFR32xG2x hardware backend.
 * @ingroup noxtls_efr32
 *
 * Build with NOXTLS_CFG_FEATURE_EFR32XG2X_HW_ACCEL=ON (CMake) or define
 * NOXTLS_FEATURE_EFR32XG2X_HW_ACCEL=1 and compile the files of
 * noxtls-lib/vendor/silabs/efr32xg2x. NoxTLS then routes AES (block, ECB / CBC /
 * CTR, CCM), SHA-224/256/384/512 blocks, CTR-DRBG entropy, P-256 / P-384
 * point multiplication, ECDH and ECDSA to the chip, with software fallback.
 * An application that shares RADIOAES or the Secure Engine with another
 * driver (for example the BlueNox link layer) calls
 * noxtls_efr32_engine_lock_bind() once at start-up.
 */

#ifndef NOXTLS_EFR32_ACCEL_H
#define NOXTLS_EFR32_ACCEL_H

#include "noxtls_efr32_core.h"
#include "noxtls_efr32_engine_lock.h"
#include "noxtls_efr32_aes_engine.h"
#include "noxtls_efr32_semailbox.h"
#include "noxtls_efr32_se_ops.h"
#include "noxtls_efr32_selftest.h"

#endif /* NOXTLS_EFR32_ACCEL_H */
