/* Copyright (c) 2026 Argenox Technologies LLC.
 * SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial */
/**
 * @file noxtls_dtls13_epoch_policy.h
 * @brief Internal admission of the initial application epoch during a handshake.
 * @ingroup noxtls_dtls
 */
#ifndef NOXTLS_DTLS13_EPOCH_POLICY_H
#define NOXTLS_DTLS13_EPOCH_POLICY_H

#include <stdbool.h>
#include <stdint.h>
#include "noxtls_dtls_common.h"

/**
 * @brief Defer initial application records until peer Finished is verified.
 * @internal
 *
 * RFC 9147 (DTLS 1.3, April 2022), Section 5.8.1 requires discarding or
 * buffering application records before the peer's Finished. This predicate
 * covers the initial application epoch only; it does not reconstruct epochs.
 *
 * @param[in] handshaking Whether the connection is completing its handshake.
 * @param[in] read_epoch Full epoch of the installed peer read keys.
 * @param[in] record_epoch_low Low epoch bits from a validated unified header.
 *
 * @return True when the initial application epoch must be deferred.
 */
static inline bool noxtls_dtls13_application_epoch_pending(bool handshaking,
                                                        uint64_t read_epoch,
                                                        uint8_t record_epoch_low)
{
    return handshaking &&
           (read_epoch < DTLS13_EPOCH_APPLICATION) &&
           (record_epoch_low == DTLS13_EPOCH_APPLICATION);
}

#endif
