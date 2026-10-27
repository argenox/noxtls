/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    psk_fail_step_test.c
* Summary: The external PSK binder's failing step stays readable after return
*****************************************************************************/

/**
 * @file psk_fail_step_test.c
 * @brief Read tls13_psk_compute_external_binder()'s fail step after the call.
 *
 * The step names were block-scope compound literals, whose storage ends with
 * the block that stores their address in the out parameter. Each case reads
 * the name back only after the call has returned and another call has reused
 * its stack, so a name that lived on the stack no longer reads back intact.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "noxtls_tls13_psk.h"

/** Failed checks. */
static unsigned s_failures;

/**
 * @brief Overwrite the stack below the caller with a fill pattern.
 * @param[in] fill Byte to write.
 * @return A byte of the buffer, so the writes are not removed.
 */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((noinline))
#endif
static uint8_t scribble_stack(uint8_t fill)
{
    volatile uint8_t buffer[8192];
    for (size_t i = 0U; i < sizeof(buffer); ++i) {
        buffer[i] = fill;
    }

    return buffer[sizeof(buffer) / 2U];
}

/**
 * @brief Run one failing call and check its step after return.
 * @param[in] name Case name.
 * @param[in] hash Hash algorithm.
 * @param[in] psk PSK or NULL.
 * @param[in] hello ClientHello bytes.
 * @param[in] hello_len ClientHello length.
 * @param[in] binder_offset Binder offset.
 * @param[in] binder_len Binder length.
 * @param[in] expected Expected step name.
 */
static void check_step(const char *name, noxtls_hash_algos_t hash, const uint8_t *psk,
                       const uint8_t *hello, uint32_t hello_len, uint32_t binder_offset,
                       uint16_t binder_len, const char *expected)
{
    uint8_t binder[64];
    const uint8_t *step = NULL;
    noxtls_return_t rc = tls13_psk_compute_external_binder(hash, psk, (psk != NULL) ? 32U : 0U,
                                                           hello, hello_len, binder_offset, binder_len,
                                                           binder, NULL, 0U, &step);
    (void)scribble_stack(0xA5U);
    (void)scribble_stack(0x5AU);
    if ((rc == NOXTLS_RETURN_SUCCESS) || (step == NULL) ||
        (strcmp((const char *)step, expected) != 0)) {
        ++s_failures;
        (void)printf("FAIL %s: rc=%d step=%s, expected %s\n", name, (int)rc,
                     (step != NULL) ? "(changed)" : "(null)", expected);
        return;
    }

    (void)printf("PASS %s: %s\n", name, (const char *)step);
}

/**
 * @brief Check each failing step that a malformed call reaches.
 * @return 0 when every step reads back after return.
 */
int main(void)
{
    static const uint8_t psk[32] = { 1U };
    static const uint8_t hello[96] = { 0U };

    check_step("null_psk", NOXTLS_HASH_SHA_256, NULL, hello, sizeof(hello), 64U, 32U, "null");
    check_step("binder_bounds", NOXTLS_HASH_SHA_256, psk, hello, sizeof(hello), 80U, 32U, "binder_bounds");
    check_step("hash_algo", NOXTLS_HASH_MD5, psk, hello, sizeof(hello), 64U, 32U, "hash_algo");
    check_step("binder_len", NOXTLS_HASH_SHA_256, psk, hello, sizeof(hello), 64U, 16U, "binder_len");
    check_step("binder_prefix", NOXTLS_HASH_SHA_256, psk, hello, sizeof(hello), 64U, 32U, "binder_prefix");
    return (s_failures == 0U) ? 0 : 1;
}
