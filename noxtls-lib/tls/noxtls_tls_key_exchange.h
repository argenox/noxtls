/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
*
* NOTICE:  All information contained herein, source code, binaries and
* derived works is, and remains
* the property of Argenox Technologies and its suppliers,
* if any.  The intellectual and technical concepts contained
* herein are proprietary to Argenox Technologies
* and its suppliers may be covered by U.S. and Foreign Patents,
* patents in process, and are protected by trade secret or copyright law.
* Dissemination of this information or reproduction of this material
* is strictly forbidden unless prior written permission is obtained
* from Argenox Technologies.
*
* THIS SOFTWARE IS PROVIDED BY ARGENOX "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL ARGENOX TECHNOLOGIES LLC BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*
* CONTACT: info@argenox.com
* 
*
* File:    noxtls_tls_key_exchange.h
* Summary: TLS Key Exchange Implementation (ECDHE, etc.)
*
*/

#ifndef _NOXTLS_TLS_KEY_EXCHANGE_H_
#define _NOXTLS_TLS_KEY_EXCHANGE_H_

#include <stdint.h>

#include "noxtls_common.h"
#include "noxtls_tls_common.h"
#include "pkc/ecc/noxtls_ecc.h"
#include "pkc/ecdh/noxtls_ecdh.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations - actual types are defined in NOXTLS_tls12.h and NOXTLS_tls13.h */
typedef struct tls12_context_s tls12_context_t;
typedef struct tls13_context_s tls13_context_t;

/* TLS ECDHE Key Exchange Context */
NOXTLS_MSVC_WARNING_PUSH
NOXTLS_MSVC_DISABLE_PADDING
typedef struct
{
    uint16_t named_group;           /* TLS named group */
    ecc_curve_t curve_type;         /* ECC curve type */
    ecc_key_t ephemeral_key;        /* Ephemeral key pair (NIST curves) */
    uint8_t x25519_private_key[32]; /* X25519 private key (little-endian) */
    uint8_t x25519_public_key[32];  /* X25519 public key (little-endian) */
    uint8_t *premaster_secret;     /* Premaster secret (for TLS 1.2) */
    uint32_t premaster_secret_len;  /* Premaster secret length */
    uint8_t *shared_secret;         /* Shared secret (for TLS 1.3) */
    uint32_t shared_secret_len;     /* Shared secret length */
} tls_ecdhe_context_t;
NOXTLS_MSVC_WARNING_POP

/* TLS DHE (finite-field DH) Key Exchange Context - TLS 1.2 only */
#define TLS_DHE_MAX_P_BYTES 512
NOXTLS_MSVC_WARNING_PUSH
NOXTLS_MSVC_DISABLE_PADDING
typedef struct
{
    uint16_t named_group;           /* TLS named group: 256=ffdhe2048, 257=ffdhe3072, 258=ffdhe4096 */
    uint32_t p_len;                 /* Length of p in bytes */
    uint8_t *server_private;        /* Server ephemeral private (p_len bytes) */
    uint8_t *server_public;         /* Server ephemeral public (p_len bytes) */
    uint8_t *client_private;        /* Client ephemeral private (p_len bytes) */
    uint8_t *client_public;         /* Client ephemeral public (p_len bytes) */
    uint8_t premaster_secret[TLS_DHE_MAX_P_BYTES];  /* Z = shared secret, length p_len */
    uint32_t premaster_secret_len;
} tls_dhe_context_t;
NOXTLS_MSVC_WARNING_POP

/* Named Group to ECC Curve Mapping */
noxtls_return_t noxtls_tls_named_group_to_ecc_curve(uint16_t named_group, ecc_curve_t *curve_type);
noxtls_return_t noxtls_tls_ecc_curve_to_named_group(ecc_curve_t curve_type, uint16_t *named_group);

/* ECC Point Encoding/Decoding for TLS */
noxtls_return_t noxtls_tls_encode_ecc_point_uncompressed(const ecc_point_t *point, uint8_t *output, uint32_t *output_len);
noxtls_return_t noxtls_tls_decode_ecc_point_uncompressed(const uint8_t *encoded, uint32_t encoded_len, ecc_point_t *point, ecc_curve_t curve_type);

/* ECDHE Key Exchange */
noxtls_return_t noxtls_tls_ecdhe_context_init(tls_ecdhe_context_t *ctx, uint16_t named_group);
noxtls_return_t noxtls_tls_ecdhe_context_free(tls_ecdhe_context_t *ctx);
noxtls_return_t noxtls_tls_ecdhe_generate_ephemeral_key(tls_ecdhe_context_t *ctx);
noxtls_return_t noxtls_tls_ecdhe_compute_shared_secret(tls_ecdhe_context_t *ctx, const ecc_point_t *peer_public_key);
noxtls_return_t noxtls_tls_ecdhe_compute_shared_secret_x25519(tls_ecdhe_context_t *ctx, const uint8_t peer_public_key[32]);
noxtls_return_t noxtls_tls_ecdhe_get_public_key_encoded(tls_ecdhe_context_t *ctx, uint8_t *output, uint32_t *output_len);

/* TLS 1.2 ECDHE Functions */
noxtls_return_t noxtls_tls12_ecdhe_send_server_key_exchange(tls12_context_t *ctx, tls_ecdhe_context_t *ecdhe_ctx);
noxtls_return_t noxtls_tls12_ecdhe_recv_server_key_exchange(tls12_context_t *ctx, tls_ecdhe_context_t *ecdhe_ctx);
noxtls_return_t noxtls_tls12_ecdhe_send_client_key_exchange(tls12_context_t *ctx, tls_ecdhe_context_t *ecdhe_ctx);
noxtls_return_t noxtls_tls12_ecdhe_recv_client_key_exchange(tls12_context_t *ctx, tls_ecdhe_context_t *ecdhe_ctx);

/* TLS 1.2 DHE (FFDHE) Functions */
noxtls_return_t noxtls_tls_dhe_context_init(tls_dhe_context_t *ctx, uint16_t named_group);
noxtls_return_t noxtls_tls_dhe_context_free(tls_dhe_context_t *ctx);
/** If msg_out and msg_out_len are non-NULL, the built handshake noxtls_message is copied for handshake hash. */
noxtls_return_t noxtls_tls12_dhe_send_server_key_exchange(tls12_context_t *ctx, tls_dhe_context_t *dhe_ctx, uint8_t *msg_out, uint32_t msg_out_size, uint32_t *msg_out_len);
/** Parse Server Key Exchange (record already received by caller). Caller must append record to handshake messages. */
noxtls_return_t noxtls_tls12_dhe_recv_server_key_exchange(tls12_context_t *ctx, tls_dhe_context_t *dhe_ctx, const uint8_t *record_data, uint32_t record_len);
noxtls_return_t noxtls_tls12_dhe_send_client_key_exchange(tls12_context_t *ctx, tls_dhe_context_t *dhe_ctx);
/** Parse Client Key Exchange (record already received by caller). Caller must append record to handshake messages. */
noxtls_return_t noxtls_tls12_dhe_recv_client_key_exchange(tls12_context_t *ctx, tls_dhe_context_t *dhe_ctx, const uint8_t *record_data, uint32_t record_len);

/* TLS 1.3 Key Share Functions */
noxtls_return_t noxtls_tls13_key_share_encode(const tls_ecdhe_context_t *ecdhe_ctx, uint8_t *output, uint32_t *output_len);
noxtls_return_t noxtls_tls13_key_share_decode(const uint8_t *encoded, uint32_t encoded_len, uint16_t named_group, ecc_point_t *public_key);
noxtls_return_t noxtls_tls13_process_client_key_share(tls13_context_t *ctx, tls_ecdhe_context_t *ecdhe_ctx);
noxtls_return_t noxtls_tls13_process_server_key_share(const tls13_context_t *ctx, tls_ecdhe_context_t *ecdhe_ctx);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_TLS_KEY_EXCHANGE_H_ */

