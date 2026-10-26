/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* This file is part of the NoxTLS Library.
* Licensed under the GNU General Public License v2.0 or later,
* or alternatively under a commercial license from Argenox Technologies LLC.
* See the LICENSE file in the project root for full details.
* CONTACT: info@argenox.com
*
* File:    dtls13_record_discard_fixture.h
* Summary: Datagram fixture for DTLS 1.3 invalid-record and alert tests
*****************************************************************************/
/** @file dtls13_record_discard_fixture.h
 * @brief Test-only corruption kinds and limits for the RFC 9147 4.5.2 / 4.5.3 tests.
 * @ingroup noxtls_dtls13_recovery
 */
#ifndef NOXTLS_DTLS13_RECORD_DISCARD_FIXTURE_H
#define NOXTLS_DTLS13_RECORD_DISCARD_FIXTURE_H
#include "dtls13_recovery_fixture.h"

/** Virtual milliseconds the handshake and recovery loops may run. */
#define DISCARD_STEPS 20000U
/** Bytes of an all-zero TLSInnerPlaintext (no content type, RFC 8446 5.4). */
#define DISCARD_ZERO_INNER_BYTES 8U
/** Record number of the injected unprotected alert. */
#define DISCARD_PLAINTEXT_SEQUENCE 0xFFU
/** Unified header bit flipped to select another epoch. */
#define DISCARD_EPOCH_FLIP 0x01U
/** First-byte bits flipped to leave the DTLSCiphertext range 001xxxxx. */
#define DISCARD_FIXED_BITS_FLIP 0x40U
/** Unified header field sizes (RFC 9147 Section 4, Figure 3). */
#define DISCARD_FLAGS_BYTES 1U
#define DISCARD_SEQUENCE_SHORT 1U
#define DISCARD_SEQUENCE_LONG 2U
#define DISCARD_LENGTH_BYTES 2U
/** Expected limits from RFC 9147 Section 4.5.3 and Appendix B. */
#define DISCARD_LIMIT_GCM_CHACHA ((uint64_t)1U << 36U)
#define DISCARD_LIMIT_CCM ((uint64_t)11863283U)
#define DISCARD_LIMIT_CCM_8 ((uint64_t)1U << 7U)
/** A cipher suite value no TLS 1.3 build supports. */
#define DISCARD_UNKNOWN_SUITE 0xFFFFU

/** @brief Ways an application record is damaged before delivery. */
typedef enum {
    DISCARD_TAMPER_TAG = 0,        /**< Flip the last AEAD tag byte. */
    DISCARD_TAMPER_SAMPLE,         /**< Flip the first ciphertext byte (record number mask sample). */
    DISCARD_TAMPER_EPOCH,          /**< Change the epoch bits of the unified header. */
    DISCARD_TAMPER_CID,            /**< Set the CID bit with no connection ID negotiated. */
    DISCARD_TAMPER_LENGTH,         /**< Make the length field overrun the datagram. */
    DISCARD_TAMPER_TRUNCATE,       /**< Drop the last byte of the datagram. */
    DISCARD_TAMPER_FIXED_BITS,     /**< Leave the DTLSCiphertext first-byte range. */
    DISCARD_TAMPER_PLAINTEXT_ALERT,/**< Turn the first byte into an alert content type. */
    DISCARD_TAMPER_COUNT
} discard_tamper_t;
#endif
