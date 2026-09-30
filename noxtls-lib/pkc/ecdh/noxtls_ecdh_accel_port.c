/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_ecdh_accel_port.c
* Summary: Platform ECDH acceleration hook (default software fallback).
*****************************************************************************/

#include <stdint.h>

#include "noxtls_ecdh.h"
#include "noxtls_common.h"

noxtls_return_t noxtls_ecdh_compute_shared_secret_accel_port(
    const ecc_key_t * private_key, const ecc_point_t * peer_public_key,
    uint8_t * shared_secret, uint32_t * shared_secret_len)
{
    (void)private_key;
    (void)peer_public_key;
    (void)shared_secret;
    (void)shared_secret_len;
    return NOXTLS_RETURN_NOT_SUPPORTED;
}
