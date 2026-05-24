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
* File:    noxtls_config.h
* Summary: NoxTLS configuration for the ESP-IDF example only.
* Library features: menuconfig -> Component config -> NoxTLS.
*
*
* Feature flags and buffer sizes come from menuconfig (sdkconfig /
* sdkconfig.defaults) via noxtls_config_features.h generated at build time.
* Do not include the repository-root noxtls/noxtls_config.h in this project.
*
* Tune the library under: Component config -> NoxTLS
*
*
*****************************************************************************/

#ifndef _NOXTLS_CONFIG_H_
#define _NOXTLS_CONFIG_H_

#include "noxtls_config_features.h"
#include "noxtls_esp_hw_accel.h"

/* Example-only static workspace size (not controlled by Kconfig). */
#ifndef NOXTLS_APP_STATIC_BUFFER_SIZE
#define NOXTLS_APP_STATIC_BUFFER_SIZE (16U * 1024U)
#endif

/*
 * This example serves one connection at a time, so keeping the ECC fixed-base
 * precompute cache alive across handshakes is safe and removes repeated
 * generator-table rebuilds from ECDSA signing.
 */
#ifndef NOXTLS_ECC_GLOBAL_PRECOMPUTE_CACHE
#define NOXTLS_ECC_GLOBAL_PRECOMPUTE_CACHE 1
#endif

/*
 * On ESP32S3, secp256r1 currently outperforms X25519 by a wide margin.
 * Prefer it first for TLS 1.3 handshakes in this example until X25519 is
 * optimized further.
 */
#ifndef NOXTLS_CFG_TLS13_PREFER_SECP256R1_OVER_X25519
#define NOXTLS_CFG_TLS13_PREFER_SECP256R1_OVER_X25519 1
#endif

#include "noxtls_check_config.h"

#endif /* _NOXTLS_CONFIG_H_ */
