/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
* File:    aes_accel_errors_fixture.h
* Summary: Test-only accelerator fault and mode admission boundaries
*****************************************************************************/
#ifndef AES_ACCEL_ERRORS_FIXTURE_H
#define AES_ACCEL_ERRORS_FIXTURE_H
#include "noxtls_aes.h"
/** @brief Direct mode API type, unchanged from the production AES functions. */
typedef noxtls_return_t (*aes_error_mode_t)(const uint8_t *, const uint8_t *,
    uint32_t, const uint8_t *, uint8_t *, noxtls_aes_type_t);
#define AES_ERROR_TEST_BYTES 32U
#endif
