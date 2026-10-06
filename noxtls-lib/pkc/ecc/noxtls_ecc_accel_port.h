/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_ecc_accel_port.h
* Summary: Platform ECC acceleration hook interface
*****************************************************************************/

#ifndef NOXTLS_ECC_ACCEL_PORT_H_
#define NOXTLS_ECC_ACCEL_PORT_H_

#include <stdint.h>
#include "noxtls_common.h"
#include "noxtls_ecc.h"

#ifdef __cplusplus
extern "C" {
#endif

noxtls_return_t noxtls_ecc_point_multiply_accel_port(ecc_point_t *result,
                                                      const uint8_t *scalar,
                                                      const ecc_point_t *point,
                                                      const ecc_curve_params_t *curve);

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_ECC_ACCEL_PORT_H_ */
