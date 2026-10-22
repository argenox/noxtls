/* Copyright (c) 2026 Argenox Technologies LLC.
 * SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial */
/**
 * @file dtls13_epoch_policy_ut.c
 * @brief Check handshake epoch admission without constructing network records.
 * @ingroup noxtls_dtls13_recovery
 */
#include "tls/noxtls_dtls13_epoch_policy.h"
#include "runner.h"
#include "test_assert.h"

/**
 * @brief Cover initial, installed, wrapped and maximum epoch admission states.
 *
 * @return Zero when every admission decision matches the state contract.
 */
REGISTER_TEST(dtls13_initial_application_epoch_admission)
{
    const uint64_t epochs[] = {DTLS13_EPOCH_INITIAL, DTLS13_EPOCH_EARLY_DATA,
                              DTLS13_EPOCH_HANDSHAKE,
                              DTLS13_EPOCH_APPLICATION,
                              DTLS13_EPOCH_APPLICATION + 1U, UINT64_MAX};
    for(uint32_t i = 0U; i < (sizeof(epochs) / sizeof(epochs[0])); ++i) {
        for(uint8_t low = 0U; low <= DTLS13_UNIFIED_EPOCH_MASK; ++low) {
            bool expected = (epochs[i] < DTLS13_EPOCH_APPLICATION) &&
                            (low == DTLS13_EPOCH_APPLICATION);
            UTNOX_EQUALS(noxtls_dtls13_application_epoch_pending(true, epochs[i], low), expected);
            UTNOX_EQUALS(noxtls_dtls13_application_epoch_pending(false, epochs[i], low), false);
        }
    }

    return 0;
}

#if defined(_MSC_VER)
/** @brief Register the admission-state test on MSVC. */
void utnox_register_tests(void)
{
    register_test(__reg_dtls13_initial_application_epoch_admission.name,
                  __reg_dtls13_initial_application_epoch_admission.func);
}
#endif
