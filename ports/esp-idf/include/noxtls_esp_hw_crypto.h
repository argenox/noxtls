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
* File:    noxtls_esp_hw_crypto.h
* Summary: ESP-IDF hardware crypto registration for NoxTLS.
*
*
*****************************************************************************/

#ifndef NOXTLS_ESP_HW_CRYPTO_H
#define NOXTLS_ESP_HW_CRYPTO_H

/**
 * @brief Register ESP hardware MPI hooks (P-256 mod / mod_exp) with NoxTLS bignum.
 *
 * Requires CONFIG_NOXTLS_ESP_HW_MPI and CONFIG_MBEDTLS_HARDWARE_MPI in sdkconfig.
 * Called from noxtls_esp_idf_init().
 */
void noxtls_esp_hw_mpi_register(void);

/**
 * @brief Non-zero if P-256 HW ECC point multiply was compiled into noxtls_pkc.
 */
int noxtls_esp_hw_ecc_compiled_in(void);

/**
 * @brief Human-readable HW ECC status for UI/logging (null-terminated).
 *
 * Examples: "active", "N/A (no periph)", "off (config)".
 */
void noxtls_esp_hw_ecc_status_str(char *buf, unsigned int buflen);

/**
 * @brief Non-zero if P-256 HW MPI mod/mod_exp was compiled into noxtls_pkc.
 */
int noxtls_esp_hw_mpi_compiled_in(void);

#endif /* NOXTLS_ESP_HW_CRYPTO_H */
