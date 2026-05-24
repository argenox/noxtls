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

#ifndef NOXTLS_ESP_IDF_H
#define NOXTLS_ESP_IDF_H

/**
 * @brief Register ESP hardware RNG with NoxTLS DRBG.
 * @return 0 on success, negative on failure.
 *
 * Called automatically via a GCC constructor when CONFIG_NOXTLS_USE_ESP_ENTROPY
 * is enabled. Applications may call this explicitly before using DRBG.
 */
int noxtls_esp_idf_init(void);

#endif /* NOXTLS_ESP_IDF_H */
