/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    ut_wb_stubs.c
* Summary: Scripted NoxTLS dependencies of the STM32WB ECC port in the host tests
*****************************************************************************/

/**
 * @file ut_wb_stubs.c
 * @brief Scripted noxtls_pkc_rng_generate() for the ECDSA port tests.
 * @ingroup noxtls_stm32wb_ut
 */

#include <string.h>

#include "ut_wb_test.h"
#include "pkc/noxtls_pkc_rng.h"

/** Queued nonce blocks. */
#define UT_STUB_QUEUE   8U

static uint8_t s_queue[UT_STUB_QUEUE][32];
static uint32_t s_count;
static uint32_t s_next;
static uint32_t s_fail;
static uint32_t s_calls;

void ut_wb_stub_reset(void)
{
    memset(s_queue, 0, sizeof(s_queue));
    s_count = 0U;
    s_next = 0U;
    s_fail = 0U;
    s_calls = 0U;
}

void ut_wb_stub_rng_push(const uint8_t *block)
{
    memcpy(s_queue[s_count], block, 32U);
    s_count++;
}

void ut_wb_stub_rng_fail(void)
{
    s_fail = 1U;
}

uint32_t ut_wb_stub_rng_calls(void)
{
    return s_calls;
}

noxtls_return_t noxtls_pkc_rng_generate(noxtls_pkc_rng_slot_t slot, uint8_t *out, uint32_t requested_bits)
{
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    (void)slot;
    s_calls++;
    if ((s_fail == 0U) && (requested_bits == 256U) && (s_count != 0U)) {
        memcpy(out, s_queue[(s_next < s_count) ? s_next : (s_count - 1U)], 32U);
        s_next++;
        rc = NOXTLS_RETURN_SUCCESS;
    }
    return rc;
}
