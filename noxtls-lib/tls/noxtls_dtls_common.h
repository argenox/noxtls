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
* File:    noxtls_dtls_common.h
* Summary: DTLS Common Definitions
*
*
*****************************************************************************/

#ifndef NOXTLS_DTLS_COMMON_H_
#define NOXTLS_DTLS_COMMON_H_

#include <stdint.h>

#include "noxtls_common.h"
#include "noxtls_tls_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* DTLS Versions */
#define DTLS_VERSION_1_0           0xFEFFU  /* DTLS 1.0 (based on TLS 1.1) */
#define DTLS_VERSION_1_2           0xFEFDU  /* DTLS 1.2 (based on TLS 1.2) */
#define DTLS_VERSION_1_3           0xFEFCU  /* DTLS 1.3 (based on TLS 1.3) */
/* RFC 9147: legacy_record_version in DTLS 1.3 record header (MUST be 0xFEFD; 0xFEFF allowed for initial ClientHello only) */
#define DTLS_1_3_LEGACY_RECORD_VERSION  0xFEFDU

/* RFC 9147 Figure 3: DTLS 1.3 unified header (DTLSCiphertext) first-byte bits */
#define DTLS13_UNIFIED_FIXED_BITS   0x20U    /* bits 7-5 = 001 */
#define DTLS13_UNIFIED_CID_BIT      0x10U    /* C: Connection ID present */
#define DTLS13_UNIFIED_S_BIT        0x08U    /* S: 16-bit sequence number */
#define DTLS13_UNIFIED_L_BIT        0x04U    /* L: length present */
#define DTLS13_UNIFIED_EPOCH_MASK   0x03U    /* E: low 2 bits of epoch */
#define DTLS13_UNIFIED_MIN_HEADER   2U       /* minimal: 1 byte + 8-bit seq (no L) */
#define DTLS13_UNIFIED_HEADER_WITH_LEN  4U   /* 1 byte + 8-bit seq + 16-bit length */
#define DTLS13_RECORD_NUMBER_ENC_LEN    16U  /* mask length for record number encryption */

/* DTLS Record Header Structure (13 bytes) */
/* 
 * struct {
 *     ContentType type;
 *     ProtocolVersion version;
 *     uint16 epoch;            - DTLS epoch (0 for unencrypted, 1+ for encrypted)
 *     uint48 sequence_number;  - DTLS sequence number (48 bits)
 *     uint16 length;           - Record length
 *     opaque fragment[DTLSPlaintext.length];
 * } DTLSPlaintext;
 */

/* DTLS Record Header Offsets */
#define DTLS_RECORD_TYPE_OFFSET        0
#define DTLS_RECORD_VERSION_OFFSET     1
#define DTLS_RECORD_EPOCH_OFFSET       3
#define DTLS_RECORD_SEQUENCE_OFFSET    5
#define DTLS_RECORD_LENGTH_OFFSET      11
#define DTLS_RECORD_DATA_OFFSET        13
#define DTLS_RECORD_HEADER_SIZE        13U

/* DTLS Handshake Message Structure */
/*
 * struct {
 *     HandshakeType msg_type;
 *     uint24 length;
 *     uint16 message_seq;         - DTLS sequence number
 *     uint24 fragment_offset;     - Fragment offset
 *     uint24 fragment_length;     - Fragment length
 *     select (HandshakeType) {
 *         case hello_request:       HelloRequest;
 *         case client_hello:        ClientHello;
 *         case hello_verify_request: HelloVerifyRequest;
 *         case server_hello:       ServerHello;
 *         case certificate:        Certificate;
 *         case server_key_exchange: ServerKeyExchange;
 *         case certificate_request: CertificateRequest;
 *         case server_hello_done:   ServerHelloDone;
 *         case certificate_verify: CertificateVerify;
 *         case client_key_exchange: ClientKeyExchange;
 *         case finished:           Finished;
 *     } body;
 * } Handshake;
 */

/* DTLS Handshake Header Offsets */
#define DTLS_HANDSHAKE_TYPE_OFFSET          0U
#define DTLS_HANDSHAKE_LENGTH_OFFSET        1U
#define DTLS_HANDSHAKE_MESSAGE_SEQ_OFFSET   4U
#define DTLS_HANDSHAKE_FRAGMENT_OFFSET      6U
#define DTLS_HANDSHAKE_FRAGMENT_LEN_OFFSET  9U
#define DTLS_HANDSHAKE_BODY_OFFSET          12U
#define DTLS_HANDSHAKE_HEADER_SIZE          12U

/* DTLS Hello Verify Request (Cookie Exchange) */
#define DTLS_HANDSHAKE_HELLO_VERIFY_REQUEST    3U

/* DTLS Maximum Fragment Size */
#define DTLS_MAX_FRAGMENT_SIZE          1500U    /* Typical MTU size */
#define DTLS_MIN_FRAGMENT_SIZE          256U     /* Minimum fragment size */
#define DTLS_MAX_HANDSHAKE_SIZE         TLS_MAX_HANDSHAKE_SIZE

/* DTLS Replay Protection Window */
#define DTLS_REPLAY_WINDOW_SIZE         64U      /* Number of sequence numbers to track */

/* DTLS ACK Range Limits */
#define DTLS_MAX_ACK_RANGES             32U      /* Max ACK ranges to track */
#define DTLS_FINAL_ACK_RETENTION_MS      120000u /* RFC 9147: retain final ACK for 2 MSL */
#define DTLS_MAX_ACK_WIRE_LEN            (4U + 2U + 2U + (12U * DTLS_MAX_ACK_RANGES) + 2U)
#define DTLS_REASSEMBLY_QUEUE_SIZE      4U       /* Future handshake messages retained for reordering */
#define DTLS_RETRANSMIT_RECORD_BURST    10U      /* RFC 9147 Section 5.8.3 send burst cap */

/* DTLS Epochs */
#define DTLS_EPOCH_UNENCRYPTED          0U      /* Unencrypted handshake */
#define DTLS_EPOCH_ENCRYPTED            1       /* Encrypted handshake */
#define DTLS_EPOCH_APPLICATION          2       /* Application data */

/* RFC 9147 DTLS 1.3 epochs: 0=initial, 1=0-RTT, 2=handshake, 3=application. */
#define DTLS13_EPOCH_INITIAL            0U
#define DTLS13_EPOCH_EARLY_DATA         1U
#define DTLS13_EPOCH_HANDSHAKE          2U
#define DTLS13_EPOCH_APPLICATION        3U

/* DTLS Record Structure */
NOXTLS_MSVC_WARNING_PUSH
NOXTLS_MSVC_DISABLE_PADDING
typedef struct
{
    uint8_t type;               /* Record type */
    uint16_t version;           /* Protocol version */
    uint16_t epoch;             /* DTLS epoch */
    uint64_t sequence_number;   /* DTLS sequence number (48 bits, stored as 64) */
    uint16_t length;            /* Record length */
    uint8_t *data;              /* Record data */
} dtls_record_t;
NOXTLS_MSVC_WARNING_POP

/* DTLS Handshake Fragment Structure */
NOXTLS_MSVC_WARNING_PUSH
NOXTLS_MSVC_DISABLE_PADDING
typedef struct
{
    uint8_t msg_type;           /* Handshake noxtls_message type */
    uint32_t length;            /* Total noxtls_message length */
    uint16_t message_seq;       /* Message sequence number */
    uint32_t fragment_offset;   /* Fragment offset */
    uint32_t fragment_length;   /* Fragment length */
    uint8_t *data;              /* Fragment data */
} dtls_handshake_fragment_t;
NOXTLS_MSVC_WARNING_POP

/* DTLS Replay Protection Window */
NOXTLS_MSVC_WARNING_PUSH
NOXTLS_MSVC_DISABLE_PADDING
typedef struct
{
    uint64_t window_bitmap;     /* Bitmap of received sequence numbers */
    uint64_t last_seq;          /* Last received sequence number */
} dtls_replay_window_t;
NOXTLS_MSVC_WARNING_POP

/* DTLS future handshake reassembly slot */
NOXTLS_MSVC_WARNING_PUSH
NOXTLS_MSVC_DISABLE_PADDING
typedef struct
{
    uint8_t active;
    uint8_t msg_type;
    uint16_t message_seq;
    uint32_t length;
    uint8_t *buffer;
    uint8_t *received;
    uint32_t capacity;
    uint32_t received_len;
    uint32_t received_count;
} dtls_reassembly_slot_t;
NOXTLS_MSVC_WARNING_POP

/* DTLS 1.2 sequence numbers are 48 bits (RFC 6347 4.1). */
#define DTLS_SEQ_NUM_MASK               0x0000FFFFFFFFFFFFULL

/* DTLS 1.2: records examined by one noxtls_dtls_recv_record() call before it gives up with
 * NOXTLS_RETURN_TIMEOUT when all of them are discarded (wrong epoch, replayed, malformed). */
#define DTLS12_MAX_RECORDS_PER_READ     64U

/* Flight buffer entry flag: the stored record body is plaintext of a protected record
 * (DTLS 1.2 epoch >= 1); it is re-protected with a fresh sequence number when sent. */
#define DTLS_FLIGHT_ENTRY_PROTECT       0x01U

struct dtls_context_s;

/**
 * Record protection hook used to (re)protect DTLS 1.2 records of the current write epoch
 * (the encrypted Finished of a flight). Must encrypt @p in with the write keys of epoch
 * ctx->epoch and the sequence number ctx->write_seq_num, without advancing it.
 */
typedef noxtls_return_t (*dtls_protect_record_fn)(struct dtls_context_s *ctx, uint8_t type,
                                                  const uint8_t *in, uint32_t in_len,
                                                  uint8_t *out, uint32_t *out_len);

/* DTLS Context Base Structure */
NOXTLS_MSVC_WARNING_PUSH
NOXTLS_MSVC_DISABLE_PADDING
typedef struct dtls_context_s
{
    tls_context_t base;         /* Base TLS context (reused) */

    /* DTLS-specific fields */
    uint16_t epoch;             /* Current (write) epoch; DTLS 1.3 also uses it for reading */
    uint16_t read_epoch;        /* DTLS 1.2: epoch of records accepted for reading (RFC 6347 4.1) */
    uint64_t read_seq_num;      /* Read sequence number (48-bit record sequence of the last record) */
    uint64_t write_seq_num;     /* Write sequence number (next record of the current write epoch) */
    uint64_t prev_write_seq_num; /* DTLS 1.2: next sequence number of the previous write epoch */
    dtls_protect_record_fn protect_record; /* DTLS 1.2: protects records of the current write epoch */
    uint16_t last_rx_message_seq;  /* message_seq of the last handshake message delivered */
    uint8_t flight_final;       /* DTLS 1.2: buffered flight is our last flight (no retransmit timer) */
    uint8_t flight_peer_next;   /* DTLS 1.2: the peer's next flight started; ours is released when we send again */
    uint8_t *rx_datagram;       /* DTLS 1.2: unread records of the last datagram */
    uint32_t rx_datagram_len;   /* Length of rx_datagram */
    uint16_t send_message_seq;  /* DTLS handshake noxtls_message sequence */
    uint16_t mtu;               /* MTU for fragmentation */
    uint32_t max_fragment;      /* Max fragment size */
    uint8_t anti_amp_factor;    /* Anti-amplification factor */
    
    /* Replay protection */
    dtls_replay_window_t replay_window;  /* Replay protection window */
    dtls_replay_window_t replay_windows[4];  /* DTLS 1.3 per low-epoch replay windows */
    uint64_t highest_recv_seq[4];       /* DTLS 1.3 full record number reconstruction */
    uint8_t highest_recv_seq_valid[4];  /* DTLS 1.3 reconstruction state */
    uint64_t connection_epoch;          /* Full DTLS 1.3 write epoch */
    uint64_t read_connection_epoch;     /* Full DTLS 1.3 read epoch */
    
    /* Handshake fragmentation */
    uint8_t *handshake_buffer;  /* Buffer for reassembling fragmented handshake */
    uint32_t handshake_buffer_len;  /* Length of handshake buffer */
    uint32_t handshake_buffer_capacity;  /* Capacity of handshake buffer */
    uint16_t expected_message_seq;  /* Expected noxtls_message sequence number */
    uint32_t expected_fragment_offset;  /* Expected fragment offset */
    uint8_t *handshake_received;        /* Byte map of received fragments */
    uint32_t handshake_received_len;    /* Length of received map */
    uint32_t handshake_received_count;  /* Bytes received so far */
    dtls_reassembly_slot_t reassembly_queue[DTLS_REASSEMBLY_QUEUE_SIZE];
    
    /* Retransmission flight buffer (DTLS handshakes) */
    uint8_t *flight_buffer;     /* Concatenated DTLS records with 2-byte length prefix */
    uint32_t flight_buffer_len; /* Current flight buffer length */
    uint32_t flight_buffer_capacity; /* Capacity of flight buffer */
    uint8_t *flight_buffer_storage; /* Optional caller-managed flight buffer storage */
    uint32_t flight_buffer_storage_capacity; /* Capacity of caller-managed flight buffer storage */
    uint32_t retransmit_max_attempts; /* Max retransmission attempts per receive */
    uint64_t bytes_received;    /* Bytes received (for anti-amplification) */
    uint64_t bytes_sent;        /* Bytes sent (for anti-amplification) */
    uint8_t validated;          /* Peer address validated */
    uint64_t ack_epoch;         /* Latest epoch to acknowledge */
    uint64_t ack_seq;           /* Latest sequence number to acknowledge */
    uint8_t ack_pending;        /* ACK pending flag */
    uint64_t ack_range_min;     /* ACK range start */
    uint64_t ack_range_max;     /* ACK range end */
    uint8_t ack_range_valid;    /* ACK range valid */
    uint8_t ack_range_count;    /* ACK range count */
    uint8_t ack_range_capacity; /* ACK range capacity */
    uint8_t ack_range_limit;    /* ACK range limit */
    uint64_t *ack_ranges_min;   /* ACK ranges start */
    uint64_t *ack_ranges_max;   /* ACK ranges end */
    uint64_t last_ack_epoch;    /* Last ACKed epoch received */
    uint64_t last_ack_seq;      /* Last ACKed sequence number received */
    uint64_t last_ack_range_min; /* Last ACKed range start */
    uint64_t last_ack_range_max; /* Last ACKed range end */
    uint64_t *last_ack_ranges_min; /* Last ACKed ranges start */
    uint64_t *last_ack_ranges_max; /* Last ACKed ranges end */
    uint8_t last_ack_range_count;  /* Last ACKed range count */
    uint8_t last_ack_valid;        /* 1 once an ACK has been received (last_ack_* fields meaningful) */
    uint64_t flight_epoch;      /* Epoch for current flight */
    uint64_t flight_min_seq;    /* First seq in current flight */
    uint64_t flight_max_seq;    /* Last seq in current flight */
    uint8_t flight_has_range;   /* Flight range valid */
    uint32_t retransmit_timeout_ms; /* Retransmit timeout in ms */
    uint32_t retransmit_base_timeout_ms; /* Current base RTO before loss backoff */
    uint32_t retransmit_backoff_ms; /* Backoff multiplier in per-mille units (2000 = 2x) */
    uint32_t smoothed_rtt_ms;    /* RTT estimator SRTT */
    uint32_t rttvar_ms;          /* RTT estimator variation */
    uint8_t rtt_estimator_valid; /* RTT estimator has at least one sample */
    uint64_t last_flight_sent_ms;   /* Last flight send time (ms) */
    uint8_t final_ack_active;        /* Final-flight ACK retained for duplicate peer retransmits */
    uint64_t final_ack_until_ms;     /* Monotonic expiry for retained final ACK (0 if no time callback) */
    uint32_t final_ack_len;          /* Retained ACK wire length */
    uint8_t final_ack[DTLS_MAX_ACK_WIRE_LEN]; /* Retained ACK handshake message */

    /* Cookie (for Hello Verify Request) */
    uint8_t cookie[TLS_COOKIE_MAX_LEN]; /* Locally generated stateless cookie */
    uint32_t cookie_len;        /* Cookie length */
    uint8_t cookie_secret[32];  /* Per-context secret for DTLS cookie HMAC */
    uint8_t cookie_secret_valid; /* Cookie secret initialized */
    uint8_t *hrr_cookie;        /* Peer HelloRetryRequest cookie to echo */
    uint32_t hrr_cookie_len;    /* Peer HelloRetryRequest cookie length */
} dtls_context_t;
NOXTLS_MSVC_WARNING_POP

/* DTLS Functions */
noxtls_return_t noxtls_dtls_context_init(dtls_context_t *ctx, tls_role_t role, uint16_t version);
noxtls_return_t noxtls_dtls_context_free(dtls_context_t *ctx);
noxtls_return_t noxtls_dtls_set_mtu(dtls_context_t *ctx, uint16_t mtu);
noxtls_return_t noxtls_dtls_set_flight_buffer(dtls_context_t *ctx, uint8_t *buffer, uint32_t capacity);
noxtls_return_t dtls_set_retransmit(dtls_context_t *ctx, uint32_t timeout_ms,
                                    uint32_t backoff_ms, uint32_t max_attempts);
noxtls_return_t noxtls_dtls_set_anti_amplification_limit(dtls_context_t *ctx, uint8_t factor);
noxtls_return_t noxtls_dtls_set_ack_range_limit(dtls_context_t *ctx, uint8_t max_ranges);

/* DTLS Record Layer */
noxtls_return_t noxtls_dtls_send_record(dtls_context_t *ctx, uint8_t type, const uint8_t *data, uint32_t len);
noxtls_return_t noxtls_dtls_recv_record(dtls_context_t *ctx, dtls_record_t *record);

/* DTLS 1.2: protect @p plaintext with ctx->protect_record under the current write epoch and send
 * it as one record; the plaintext is kept in the flight so a retransmission is re-protected with a
 * fresh record sequence number (RFC 6347 4.2.4). */
noxtls_return_t noxtls_dtls_send_protected_record(dtls_context_t *ctx, uint8_t type,
                                                  const uint8_t *plaintext, uint32_t len);
/* DTLS 1.2 64-bit sequence number used in MAC/AEAD input: epoch(16) || sequence_number(48). */
uint64_t noxtls_dtls_record_seq64(uint16_t epoch, uint64_t sequence_number);
/* DTLS 1.2: switch the write / read state to the next epoch (ChangeCipherSpec sent / received). */
void noxtls_dtls_next_write_epoch(dtls_context_t *ctx);
void noxtls_dtls_next_read_epoch(dtls_context_t *ctx);
/* Retransmit the buffered flight now (peer retransmitted its previous flight). */
noxtls_return_t noxtls_dtls_retransmit_flight(dtls_context_t *ctx);
/* Forget the buffered flight (the peer's next flight has arrived). */
void noxtls_dtls_flight_reset(dtls_context_t *ctx);
/* A message of the peer's next flight arrived: the buffered flight is kept (and retransmitted on
 * timeout) until the peer's flight is complete, and is replaced when our next flight starts. */
void noxtls_dtls_flight_peer_progress(dtls_context_t *ctx);
/* Deliver a complete, previously queued handshake message whose message_seq is next. */
noxtls_return_t noxtls_dtls_take_queued_handshake(dtls_context_t *ctx, uint8_t *msg_type,
                                                  uint8_t **complete_msg, uint32_t *complete_len);

/* DTLS Handshake Fragmentation */
noxtls_return_t dtls_send_handshake_fragment(dtls_context_t *ctx, 
                                               uint8_t msg_type,
                                               const uint8_t *data,
                                               uint32_t len,
                                               uint16_t message_seq);
noxtls_return_t noxtls_dtls_recv_handshake_fragment(dtls_context_t *ctx, dtls_handshake_fragment_t *fragment);
noxtls_return_t noxtls_dtls_reassemble_handshake(dtls_context_t *ctx, dtls_handshake_fragment_t *fragment, uint8_t **complete_msg, uint32_t *complete_len);

/* DTLS Replay Protection */
noxtls_return_t noxtls_dtls_check_replay(const dtls_context_t *ctx, uint64_t sequence_number);
noxtls_return_t noxtls_dtls_update_replay_window(dtls_context_t *ctx, uint64_t sequence_number);

/* DTLS Cookie Functions */
noxtls_return_t noxtls_dtls_generate_cookie(dtls_context_t *ctx, const uint8_t *client_hello, uint32_t client_hello_len, uint8_t *cookie, uint32_t *cookie_len);
noxtls_return_t noxtls_dtls_verify_cookie(const dtls_context_t *ctx, const uint8_t *cookie, uint32_t cookie_len);
void noxtls_dtls_mark_validated(dtls_context_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_DTLS_COMMON_H_ */
