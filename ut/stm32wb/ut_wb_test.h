/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    ut_wb_test.h
* Summary: Shared helpers of the STM32WB host tests
*****************************************************************************/

/**
 * @defgroup noxtls_stm32wb_ut STM32WB5x backend host tests
 * @brief UTNox tests of the STM32WB5x backend against a register-level peripheral model.
 */

/**
 * @file ut_wb_test.h
 * @brief Common includes, setup / teardown macros and scripted stubs of the STM32WB host tests.
 * @ingroup noxtls_stm32wb_ut
 */

#ifndef UT_WB_TEST_H
#define UT_WB_TEST_H

#include <stdint.h>
#include <string.h>

#include "runner.h"
#include "test_assert.h"

#include "noxtls_stm32wb_accel.h"
#include "ut_wb_mock.h"

/** Reset the peripheral model and the driver history. */
#define UT_SETUP() \
    do { \
        ut_wb_reset(); \
        noxtls_stm32wb_rng_reset_history(); \
        ut_wb_stub_reset(); \
    } while (0)

/** The model saw no illegal use and no stray access, and every semaphore is free again. */
#define UT_CLEAN() \
    do { \
        uint32_t _s; \
        UTNOX_EQUALS(g_wb.proto_err, 0U); \
        UTNOX_EQUALS(g_wb.bad_access, 0U); \
        for (_s = 0U; _s < 32U; _s++) { \
            UTNOX_EQUALS(g_wb.sem_owner[_s], 0U); \
        } \
    } while (0)

/** Key, IV and chaining registers hold no secret after an operation. */
#define UT_AES_WIPED() \
    do { \
        uint32_t _k; \
        for (_k = 0U; _k < 8U; _k++) { \
            UTNOX_EQUALS(g_wb.aes_key[_k], 0U); \
        } \
        for (_k = 0U; _k < 4U; _k++) { \
            UTNOX_EQUALS(g_wb.aes_iv[_k], 0U); \
        } \
        UTNOX_EQUALS(g_wb.aes_cr, 0U); \
    } while (0)

/** Reset the scripted NoxTLS stubs (PKC DRBG). */
void ut_wb_stub_reset(void);

/**
 * @brief Queue a 32-byte block the stubbed PKC DRBG returns.
 *
 * @param[in] block 32 bytes.
 */
void ut_wb_stub_rng_push(const uint8_t *block);

/** Make the stubbed PKC DRBG fail. */
void ut_wb_stub_rng_fail(void);

/** @brief Number of PKC DRBG requests served. */
uint32_t ut_wb_stub_rng_calls(void);

#endif /* UT_WB_TEST_H */
