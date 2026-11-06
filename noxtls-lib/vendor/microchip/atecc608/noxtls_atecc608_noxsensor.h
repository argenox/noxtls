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
* File:    noxtls_atecc608_noxsensor.h
* Summary: NoxSensor ATECC608 driver binding for the NoxTLS ATECC608 provider
*
*****************************************************************************/

/**
 * @file noxtls_atecc608_noxsensor.h
 * @brief Backend that drives the chip with the NoxSensor ATECC608 driver.
 *
 * Compiled only with NOXTLS_CFG_ATECC608_NOXSENSOR=ON and the NoxSensor include directory
 * (NOXTLS_ATECC608_NOXSENSOR_INCLUDE_DIR). The core of NoxTLS never includes a NoxSensor header; this adapter is
 * the only file that does.
 */
#ifndef NOXTLS_ATECC608_NOXSENSOR_H_
#define NOXTLS_ATECC608_NOXSENSOR_H_

#include "noxtls_atecc608.h"

#ifdef __cplusplus
extern "C" {
#endif

#if NOXTLS_FEATURE_ATECC608 && defined(NOXTLS_ATECC608_NOXSENSOR)

/** Opaque NoxSensor driver instance type, declared by noxsensor_atecc608.h. */
struct noxsensor_atecc608;

/**
 * @brief Fill a backend that uses an initialised NoxSensor ATECC608 instance.
 * @param[out] backend Backend to fill.
 * @param[in] device NoxSensor driver instance (noxsensor_atecc608_init() done); must outlive the backend.
 */
void noxtls_atecc608_noxsensor_backend(noxtls_atecc608_backend_t *backend, struct noxsensor_atecc608 *device);

#endif

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_ATECC608_NOXSENSOR_H_ */
