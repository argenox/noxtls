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
* File:    noxtls_tls_common.h
* Summary: TLS Common Definitions and Structures
*
*
*****************************************************************************/

#ifndef NOXTLS_TLS_COMMON_H_
#define NOXTLS_TLS_COMMON_H_

#include <stdint.h>

#include "noxtls_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* TLS Versions */
#define TLS_VERSION_1_0    0x0301U
#define TLS_VERSION_1_1    0x0302U
#define TLS_VERSION_1_2    0x0303U
#define TLS_VERSION_1_3    0x0304U

/* TLS Record Types */
#define TLS_RECORD_CHANGE_CIPHER_SPEC   20U
#define TLS_RECORD_CCS_PAYLOAD          0x01U  /* Single byte payload of Change Cipher Spec record */
#define TLS_RECORD_ALERT                21U
#define TLS_RECORD_HANDSHAKE            22U
#define TLS_RECORD_APPLICATION_DATA     23U
#define TLS_RECORD_HEARTBEAT            24U   /* RFC 6520: Heartbeat protocol */
#define TLS_RECORD_ACK                  26U  /* RFC 9147: DTLS 1.3 ACK (plaintext) */

/* TLS Handshake Types */
#define TLS_HANDSHAKE_HELLO_REQUEST         0U
#define TLS_HANDSHAKE_CLIENT_HELLO           1U
#define TLS_HANDSHAKE_SERVER_HELLO           2U
#define TLS_HANDSHAKE_NEW_SESSION_TICKET     4U
#define TLS_HANDSHAKE_END_OF_EARLY_DATA      5U
#define TLS_HANDSHAKE_ENCRYPTED_EXTENSIONS   8U
#define TLS_HANDSHAKE_CERTIFICATE            11U
#define TLS_HANDSHAKE_SERVER_KEY_EXCHANGE     12U
#define TLS_HANDSHAKE_CERTIFICATE_REQUEST    13U
#define TLS_HANDSHAKE_SERVER_HELLO_DONE      14U
#define TLS_HANDSHAKE_CERTIFICATE_VERIFY     15U
#define TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE    16U
#define TLS_HANDSHAKE_FINISHED               20U
#define TLS_HANDSHAKE_CERTIFICATE_STATUS     22U
#define TLS_HANDSHAKE_KEY_UPDATE             24U
#define TLS_HANDSHAKE_ACK                    25U
#define TLS_HANDSHAKE_REQUEST_CONNECTION_ID   9U   /* RFC 9147 */
#define TLS_HANDSHAKE_NEW_CONNECTION_ID      10U   /* RFC 9147 */
#define TLS_HANDSHAKE_MESSAGE_HASH           254U

/* TLS protocol sizes (bytes) */
#define TLS_RANDOM_SIZE                      32U   /* ClientHello / ServerHello random length */
#define TLS_MASTER_SECRET_LEN                48   /* Master secret length (RFC 5246/8446) */
#define TLS_MAX_SECRET_LEN                   64U   /* Max HKDF/PRF output (e.g. SHA-512) */
#define TLS_KEY_BLOCK_MAX_LEN                256  /* Max key_block length (TLS 1.2) */
#define TLS_FINISHED_VERIFY_DATA_LEN_12      12   /* TLS 1.0/1.1 Finished verify_data length */
#define TLS_HANDSHAKE_HEADER_LEN             4U    /* Handshake type (1) + length (3) */
#define TLS_CLIENT_HELLO_BASE_SIZE           2048U /* Base size for ClientHello before extensions */
#define TLS_CLIENT_HELLO_EXTENSIONS_TAIL     2048U /* Tail buffer for building extensions */
#define TLS_CLIENT_HELLO_DEFAULT_SIZE       (TLS_CLIENT_HELLO_BASE_SIZE + TLS_CLIENT_HELLO_EXTENSIONS_TAIL)
#define TLS_SERVER_HELLO_DEFAULT_SIZE        2048U
#define TLS_CLIENT_KEY_EXCHANGE_MAX_LEN      512U  /* Max ClientKeyExchange noxtls_message buffer */
#define TLS_HELLO_RETRY_REQUEST_MAX_SIZE     256
#define TLS_SERVER_KEY_EXCHANGE_WORKSPACE   (1024 + 320 + 512)  /* DHE/ECDHE params + sig buffer */
/*
 * RFC 5246 TLSCiphertext expansion is up to 2048 octets beyond 2^14 plaintext.
 * TLS 1.3 encrypted records are tighter (2^14+256) and enforced in decrypt.
 */
#define TLS_RECORD_WORKSPACE_OVERHEAD        2048U
#define TLS13_MAX_ENCRYPTED_RECORD_OVERHEAD  256U
#define TLS13_RECORD_WORKSPACE_SIZE         ((TLS_MAX_RECORD_SIZE + 32U) * 2U) /* TLS 1.3 record workspace size */
#define TLS_KEY_SHARE_ENTRY_MAX_LEN          2048 /* Encoded key share entry buffer */
#define TLS_SESSION_ID_MAX_LEN               32U
#define TLS_CERT_REQUEST_CONTEXT_MAX_LEN    32
#define TLS_NEW_SESSION_TICKET_NONCE_LEN     16
#define TLS_NST_TICKET_ID_LEN                16
#define TLS_PSK_BINDER_MAX_LEN               64
#define TLS_COOKIE_MAX_LEN                   32

/* EC point format and curve type (wire format) */
#define TLS_EC_POINT_UNCOMPRESSED            0x04U
#define TLS_EC_CURVE_TYPE_NAMED              0x03U

/* TLS 1.3 / RFC 8446 signature schemes */
#define TLS_SIGSCHEME_RSA_PSS_RSAE_SHA256 ((uint16_t)0x0804U)
#define TLS_SIGSCHEME_ECDSA_SECP256R1_SHA256 ((uint16_t)0x0403U)
#define TLS_SIGSCHEME_ECDSA_SECP384R1_SHA384 ((uint16_t)0x0503U)
#define TLS_SIGSCHEME_ECDSA_SECP521R1_SHA512 ((uint16_t)0x0603U)
#define TLS_SIGSCHEME_ECDSA_BRAINPOOLP256R1_TLS13_SHA256 ((uint16_t)0x081AU)
#define TLS_SIGSCHEME_ECDSA_BRAINPOOLP384R1_TLS13_SHA384 ((uint16_t)0x081BU)
#define TLS_SIGSCHEME_ECDSA_BRAINPOOLP512R1_TLS13_SHA512 ((uint16_t)0x081CU)
#define TLS_SIGSCHEME_ED25519 ((uint16_t)0x0807U)
#define TLS_SIGSCHEME_ED448 ((uint16_t)0x0808U) /* Private-use IDs for PQ/hybrid prototyping; switch to final IANA IDs when standardized. */
#define TLS_SIGSCHEME_MLDSA44 ((uint16_t)0xFEA0U)
#define TLS_SIGSCHEME_MLDSA65 ((uint16_t)0xFEA1U)
#define TLS_SIGSCHEME_MLDSA87 ((uint16_t)0xFEA2U)
#define TLS_SIGSCHEME_RSA_PSS_SHA256_MLDSA44 ((uint16_t)0xFEB0U)
#define TLS_SIGSCHEME_RSA_PSS_SHA256_MLDSA65 ((uint16_t)0xFEB1U)
#define TLS_SIGSCHEME_RSA_PSS_SHA384_MLDSA87 ((uint16_t)0xFEB2U)
#define TLS_SIGSCHEME_SLHDSA_SHA2_128S ((uint16_t)0xFEC0U)
#define TLS_SIGSCHEME_SLHDSA_SHA2_128F ((uint16_t)0xFEC1U)
#define TLS_SIGSCHEME_SLHDSA_SHA2_192S ((uint16_t)0xFEC2U)
#define TLS_SIGSCHEME_SLHDSA_SHA2_192F ((uint16_t)0xFEC3U)
#define TLS_SIGSCHEME_SLHDSA_SHA2_256S ((uint16_t)0xFEC4U)
#define TLS_SIGSCHEME_SLHDSA_SHA2_256F ((uint16_t)0xFEC5U)
#define TLS_SIGSCHEME_SLHDSA_SHAKE_128S ((uint16_t)0xFEC6U)
#define TLS_SIGSCHEME_SLHDSA_SHAKE_128F ((uint16_t)0xFEC7U)
#define TLS_SIGSCHEME_SLHDSA_SHAKE_192S ((uint16_t)0xFEC8U)
#define TLS_SIGSCHEME_SLHDSA_SHAKE_192F ((uint16_t)0xFEC9U)
#define TLS_SIGSCHEME_SLHDSA_SHAKE_256S ((uint16_t)0xFECAU)
#define TLS_SIGSCHEME_SLHDSA_SHAKE_256F ((uint16_t)0xFECBU)
#define TLS_SIGSCHEME_FALCON512 ((uint16_t)0xFECCU)
#define TLS_SIGSCHEME_FALCON1024 ((uint16_t)0xFECDU)
#define TLS_SIGSCHEME_LMS_HSS_SHA256 ((uint16_t)0xFECEU)
#define TLS_SIGSCHEME_XMSS_SHA256 ((uint16_t)0xFECFU)
#define TLS_SIGSCHEME_XMSSMT_SHA256 ((uint16_t)0xFED0U) /* TLS Named Groups (for key exchange) */
#define TLS_NAMED_GROUP_SECP256R1 ((uint16_t)23U) /* secp256r1 (NIST P-256) */
#define TLS_NAMED_GROUP_SECP384R1 ((uint16_t)24U) /* secp384r1 (NIST P-384) */
#define TLS_NAMED_GROUP_SECP521R1 ((uint16_t)25U) /* secp521r1 (NIST P-521) */
#define TLS_NAMED_GROUP_X25519 ((uint16_t)29U) /* x25519 (Curve25519) */
#define TLS_NAMED_GROUP_X448 ((uint16_t)30U) /* x448 (Curve448) */
/* Private-use IDs for PQ/hybrid prototyping plus current IANA assignment where available. */
#define TLS_NAMED_GROUP_MLKEM512 ((uint16_t)0xFE30U)
#define TLS_NAMED_GROUP_MLKEM768 ((uint16_t)0xFE31U)
#define TLS_NAMED_GROUP_MLKEM1024 ((uint16_t)0xFE32U)
#define TLS_NAMED_GROUP_X25519_MLKEM512 ((uint16_t)0xFE40U)
#define TLS_NAMED_GROUP_X25519_MLKEM768 ((uint16_t)0x11ECU)
#define TLS_NAMED_GROUP_X25519_MLKEM768_LEGACY ((uint16_t)0xFE41U)
#define TLS_NAMED_GROUP_X25519_MLKEM1024 ((uint16_t)0xFE42U) /* RFC 7919 FFDHE (finite-field DH) */
#define TLS_NAMED_GROUP_FFDHE2048 ((uint16_t)256U)
#define TLS_NAMED_GROUP_FFDHE3072 ((uint16_t)257U)
#define TLS_NAMED_GROUP_FFDHE4096 ((uint16_t)258U)
#define TLS_NAMED_GROUP_FFDHE6144 ((uint16_t)259U)
#define TLS_NAMED_GROUP_FFDHE8192 ((uint16_t)260U) /* TLS Cipher Suites */
#define TLS_CIPHER_SUITE_NULL_WITH_NULL_NULL ((uint16_t)0x0000U) /* RFC 5746 / RFC 7507: Signaling cipher suite value for empty renegotiation_info */
#define TLS_CIPHER_SUITE_EMPTY_RENEGOTIATION_INFO_SCSV ((uint16_t)0x00FFU)
#define TLS_CIPHER_SUITE_FALLBACK_SCSV ((uint16_t)0x5600U)
#define TLS_CIPHER_SUITE_RSA_WITH_3DES_EDE_CBC_SHA ((uint16_t)0x000AU)
#define TLS_CIPHER_SUITE_DHE_RSA_WITH_3DES_EDE_CBC_SHA ((uint16_t)0x0016U)
#define TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA ((uint16_t)0x002FU)
#define TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA ((uint16_t)0x0035U)
#define TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA256 ((uint16_t)0x003CU)
#define TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA256 ((uint16_t)0x003DU)
#define TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA ((uint16_t)0x0033U)
#define TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA ((uint16_t)0x0039U)
#define TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA256 ((uint16_t)0x0067U)
#define TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA256 ((uint16_t)0x006BU)
#define TLS_CIPHER_SUITE_RSA_WITH_AES_128_GCM_SHA256 ((uint16_t)0x009CU)
#define TLS_CIPHER_SUITE_RSA_WITH_AES_256_GCM_SHA384 ((uint16_t)0x009DU)
#define TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_GCM_SHA256 ((uint16_t)0x009EU)
#define TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_GCM_SHA384 ((uint16_t)0x009FU)
#define TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA ((uint16_t)0xC013U)
#define TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_CBC_SHA ((uint16_t)0xC014U)
#define TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA256 ((uint16_t)0xC027U)
#define TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_CBC_SHA384 ((uint16_t)0xC028U) /* TLS 1.2 ECDHE-ECDSA CBC/SHA and CBC/SHA256 (RFC 4492 / IANA) */
#define TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CBC_SHA ((uint16_t)0xC009U)
#define TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_CBC_SHA ((uint16_t)0xC00AU)
#define TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 ((uint16_t)0xC023U)
#define TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 ((uint16_t)0xC024U)
#define TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 ((uint16_t)0xC02BU)
#define TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 ((uint16_t)0xC02CU)
#define TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256 ((uint16_t)0xC02FU)
#define TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_GCM_SHA384 ((uint16_t)0xC030U) /* TLS 1.2 ChaCha20-Poly1305 (RFC 7905) */
#define TLS_CIPHER_SUITE_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 ((uint16_t)0xCCA8U)
#define TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 ((uint16_t)0xCCA9U)
#define TLS_CIPHER_SUITE_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 ((uint16_t)0xCCAAU)
#define TLS_CIPHER_SUITE_AES_128_GCM_SHA256 ((uint16_t)0x1301U)
#define TLS_CIPHER_SUITE_AES_256_GCM_SHA384 ((uint16_t)0x1302U)
#define TLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256 ((uint16_t)0x1303U)
#define TLS_CIPHER_SUITE_AES_128_CCM_SHA256 ((uint16_t)0x1304U)
#define TLS_CIPHER_SUITE_AES_128_CCM_8_SHA256 ((uint16_t)0x1305U) /* TLS 1.2 AES-CCM / AES-CCM_8 (RFC 6655) */
#define TLS_CIPHER_SUITE_RSA_WITH_AES_128_CCM ((uint16_t)0xC09CU)
#define TLS_CIPHER_SUITE_RSA_WITH_AES_256_CCM ((uint16_t)0xC09DU) /* RFC 6655: DHE_RSA CCM (16-byte tag) precedes RSA CCM_8 on the wire */
#define TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CCM ((uint16_t)0xC09EU)
#define TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CCM ((uint16_t)0xC09FU)
#define TLS_CIPHER_SUITE_RSA_WITH_AES_128_CCM_8 ((uint16_t)0xC0A0U)
#define TLS_CIPHER_SUITE_RSA_WITH_AES_256_CCM_8 ((uint16_t)0xC0A1U)
#define TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CCM_8 ((uint16_t)0xC0A2U)
#define TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CCM_8 ((uint16_t)0xC0A3U)
#define TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CCM ((uint16_t)0xC0ACU)
#define TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_CCM ((uint16_t)0xC0ADU)
#define TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_CCM_8 ((uint16_t)0xC0AEU)
#define TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_CCM_8 ((uint16_t)0xC0AFU) /* ARIA Cipher Suites (RFC 6209) */
#define TLS_CIPHER_SUITE_RSA_WITH_ARIA_128_CBC_SHA256 ((uint16_t)0xC03CU)
#define TLS_CIPHER_SUITE_RSA_WITH_ARIA_256_CBC_SHA384 ((uint16_t)0xC03DU)
#define TLS_CIPHER_SUITE_DH_DSS_WITH_ARIA_128_CBC_SHA256 ((uint16_t)0xC03EU)
#define TLS_CIPHER_SUITE_DH_DSS_WITH_ARIA_256_CBC_SHA384 ((uint16_t)0xC03FU)
#define TLS_CIPHER_SUITE_DH_RSA_WITH_ARIA_128_CBC_SHA256 ((uint16_t)0xC040U)
#define TLS_CIPHER_SUITE_DH_RSA_WITH_ARIA_256_CBC_SHA384 ((uint16_t)0xC041U)
#define TLS_CIPHER_SUITE_DHE_DSS_WITH_ARIA_128_CBC_SHA256 ((uint16_t)0xC042U)
#define TLS_CIPHER_SUITE_DHE_DSS_WITH_ARIA_256_CBC_SHA384 ((uint16_t)0xC043U)
#define TLS_CIPHER_SUITE_DHE_RSA_WITH_ARIA_128_CBC_SHA256 ((uint16_t)0xC044U)
#define TLS_CIPHER_SUITE_DHE_RSA_WITH_ARIA_256_CBC_SHA384 ((uint16_t)0xC045U)
#define TLS_CIPHER_SUITE_DHE_RSA_WITH_ARIA_128_GCM_SHA256 ((uint16_t)0xC07CU)
#define TLS_CIPHER_SUITE_DHE_RSA_WITH_ARIA_256_GCM_SHA384 ((uint16_t)0xC07DU)
#define TLS_CIPHER_SUITE_DH_anon_WITH_ARIA_128_CBC_SHA256    0xC046U
#define TLS_CIPHER_SUITE_DH_anon_WITH_ARIA_256_CBC_SHA384    0xC047U
#define TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256 ((uint16_t)0xC048U)
#define TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384 ((uint16_t)0xC049U)
#define TLS_CIPHER_SUITE_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256 ((uint16_t)0xC04AU)
#define TLS_CIPHER_SUITE_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384 ((uint16_t)0xC04BU)
#define TLS_CIPHER_SUITE_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256 ((uint16_t)0xC04CU)
#define TLS_CIPHER_SUITE_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384 ((uint16_t)0xC04DU)
#define TLS_CIPHER_SUITE_ECDH_RSA_WITH_ARIA_128_CBC_SHA256 ((uint16_t)0xC04EU)
#define TLS_CIPHER_SUITE_ECDH_RSA_WITH_ARIA_256_CBC_SHA384 ((uint16_t)0xC04FU)
#define TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256 ((uint16_t)0xC050U)
#define TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384 ((uint16_t)0xC051U)
#define TLS_CIPHER_SUITE_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256 ((uint16_t)0xC052U)
#define TLS_CIPHER_SUITE_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384 ((uint16_t)0xC053U)
#define TLS_CIPHER_SUITE_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256 ((uint16_t)0xC054U)
#define TLS_CIPHER_SUITE_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384 ((uint16_t)0xC055U)
#define TLS_CIPHER_SUITE_ECDH_RSA_WITH_ARIA_128_GCM_SHA256 ((uint16_t)0xC056U)
#define TLS_CIPHER_SUITE_ECDH_RSA_WITH_ARIA_256_GCM_SHA384 ((uint16_t)0xC057U) /* TLS Alert Levels */
#define TLS_ALERT_LEVEL_WARNING   1U
#define TLS_ALERT_LEVEL_FATAL     2U

/* TLS Extension Types */
#define TLS_EXTENSION_SERVER_NAME ((uint16_t)0U)
#define TLS_EXTENSION_MAX_FRAGMENT_LENGTH ((uint16_t)1U)
#define TLS_EXTENSION_STATUS_REQUEST ((uint16_t)5U)
#define TLS_EXTENSION_SUPPORTED_GROUPS ((uint16_t)10U)
#define TLS_EXTENSION_EC_POINT_FORMATS ((uint16_t)11U)
#define TLS_EXTENSION_SIGNATURE_ALGORITHMS ((uint16_t)13U)
#define TLS_EXTENSION_USE_SRTP ((uint16_t)14U)
#define TLS_EXTENSION_HEARTBEAT ((uint16_t)15U) /* TLS Heartbeat (RFC 6520) */
#define TLS_HEARTBEAT_MESSAGE_REQUEST               1U
#define TLS_HEARTBEAT_MESSAGE_RESPONSE              2U
#define TLS_HEARTBEAT_MODE_PEER_ALLOWED_TO_SEND    1U
#define TLS_HEARTBEAT_MODE_PEER_NOT_ALLOWED_TO_SEND 2U
#define TLS_HEARTBEAT_MIN_PADDING_LEN             16U

#define TLS_EXTENSION_APPLICATION_LAYER_PROTOCOL_NEGOTIATION ((uint16_t)16U)
#define TLS_EXTENSION_SIGNED_CERTIFICATE_TIMESTAMP ((uint16_t)18U)
#define TLS_EXTENSION_CLIENT_CERTIFICATE_TYPE ((uint16_t)19U)
#define TLS_EXTENSION_SERVER_CERTIFICATE_TYPE ((uint16_t)20U) /* RFC 7250 / IANA TLS Certificate Types */
#define TLS_CERT_TYPE_X509               0U
#define TLS_CERT_TYPE_OPENPGP            1
#define TLS_CERT_TYPE_RAW_PUBLIC_KEY     2U
#define TLS_EXTENSION_PADDING ((uint16_t)21U)
#define TLS_EXTENSION_ENCRYPT_THEN_MAC ((uint16_t)22U)
#define TLS_EXTENSION_EXTENDED_MASTER_SECRET ((uint16_t)23U)
#define TLS_EXTENSION_TOKEN_BINDING ((uint16_t)24U)
#define TLS_EXTENSION_CACHED_INFO ((uint16_t)25U)
#define TLS_EXTENSION_TLS_LTS ((uint16_t)27U)
#define TLS_EXTENSION_COMPRESS_CERTIFICATE ((uint16_t)27U)
#define TLS_EXTENSION_RECORD_SIZE_LIMIT ((uint16_t)28U)
#define TLS_EXTENSION_PWD_PROTECT ((uint16_t)29U)
#define TLS_EXTENSION_PWD_CLEAR ((uint16_t)30U)
#define TLS_EXTENSION_PASSWORD_SALT ((uint16_t)31U)
#define TLS_EXTENSION_TICKET_PINNING ((uint16_t)35U)
#define TLS_EXTENSION_TLS_CERT_WITH_EXTERN_PSK ((uint16_t)36U)
#define TLS_EXTENSION_DELEGATED_CREDENTIAL ((uint16_t)34U)
#define TLS_EXTENSION_SESSION_TICKET ((uint16_t)35U)
#define TLS_EXTENSION_PRE_SHARED_KEY ((uint16_t)41U)
#define TLS_EXTENSION_EARLY_DATA ((uint16_t)42U)
#define TLS_EXTENSION_SUPPORTED_VERSIONS ((uint16_t)43U)
#define TLS_EXTENSION_COOKIE ((uint16_t)44U)
#define TLS_EXTENSION_PSK_KEY_EXCHANGE_MODES ((uint16_t)45U)
#define TLS_EXTENSION_CERTIFICATE_AUTHORITIES ((uint16_t)47U)
#define TLS_EXTENSION_OID_FILTERS ((uint16_t)48U)
#define TLS_EXTENSION_POST_HANDSHAKE_AUTH ((uint16_t)49U)
#define TLS_EXTENSION_SIGNATURE_ALGORITHMS_CERT ((uint16_t)50U)
#define TLS_EXTENSION_KEY_SHARE ((uint16_t)51U)
#define TLS_EXTENSION_CONNECTION_ID ((uint16_t)54U) /* RFC 9146 / RFC 9147: DTLS Connection ID */
/* RFC 5746: Secure renegotiation */
#define TLS_EXTENSION_RENEGOTIATION_INFO ((uint16_t)0xFF01U) /* TLS Alert Types */
#define TLS_ALERT_CLOSE_NOTIFY               0U
#define TLS_ALERT_UNEXPECTED_MESSAGE         10
#define TLS_ALERT_BAD_RECORD_MAC             20
#define TLS_ALERT_DECRYPTION_FAILED           21
#define TLS_ALERT_RECORD_OVERFLOW             22
#define TLS_ALERT_DECOMPRESSION_FAILURE       30
#define TLS_ALERT_HANDSHAKE_FAILURE           40
#define TLS_ALERT_NO_CERTIFICATE              41
#define TLS_ALERT_BAD_CERTIFICATE             42
#define TLS_ALERT_UNSUPPORTED_CERTIFICATE     43
#define TLS_ALERT_CERTIFICATE_REVOKED         44
#define TLS_ALERT_CERTIFICATE_EXPIRED         45
#define TLS_ALERT_CERTIFICATE_UNKNOWN         46
#define TLS_ALERT_ILLEGAL_PARAMETER           47
#define TLS_ALERT_UNKNOWN_CA                  48
#define TLS_ALERT_ACCESS_DENIED               49
#define TLS_ALERT_DECODE_ERROR                50
#define TLS_ALERT_DECRYPT_ERROR               51
#define TLS_ALERT_TOO_MANY_CIDS_REQUESTED     52
#define TLS_ALERT_EXPORT_RESTRICTION          60
#define TLS_ALERT_PROTOCOL_VERSION            70
#define TLS_ALERT_INSUFFICIENT_SECURITY       71
#define TLS_ALERT_INTERNAL_ERROR              80
#define TLS_ALERT_INAPPROPRIATE_FALLBACK      86
#define TLS_ALERT_USER_CANCELED               90
#define TLS_ALERT_NO_RENEGOTIATION            100
#define TLS_ALERT_MISSING_EXTENSION           109
#define TLS_ALERT_UNSUPPORTED_EXTENSION       110
#define TLS_ALERT_CERTIFICATE_UNOBTAINABLE    111
#define TLS_ALERT_UNRECOGNIZED_NAME           112
#define TLS_ALERT_BAD_CERTIFICATE_STATUS_RESPONSE 113
#define TLS_ALERT_BAD_CERTIFICATE_HASH_VALUE  114
#define TLS_ALERT_UNKNOWN_PSK_IDENTITY        115
#define TLS_ALERT_CERTIFICATE_REQUIRED         116
#define TLS_ALERT_NO_APPLICATION_PROTOCOL     120

/* Maximum TLS record and handshake sizes.
 * Configure in noxtls_config.h: NOXTLS_TLS_MAX_RECORD_SIZE and
 * NOXTLS_TLS_MAX_HANDSHAKE_SIZE. Record size must fit the largest
 * handshake noxtls_message (typically the Certificate noxtls_message = chain size);
 * see noxtls_config.h for adjustment and certificate-size guidance. */
#define TLS_MAX_RECORD_SIZE       NOXTLS_TLS_MAX_RECORD_SIZE
#define TLS_MAX_WIRE_RECORD_LENGTH NOXTLS_TLS_MAX_WIRE_RECORD_LENGTH
#define TLS_MAX_HANDSHAKE_SIZE    NOXTLS_TLS_MAX_HANDSHAKE_SIZE

/**
 * Maximum reassembled ClientHello (full handshake message: type + 3-byte length + body).
 * tlsfuzzer test_large_hello sends ClientHellos well above 64 KiB; cap memory for DoS safety.
 */
#ifndef TLS_MAX_CLIENT_HELLO_BYTES
#define TLS_MAX_CLIENT_HELLO_BYTES (262144u)
#endif

/**
 * Absolute wire ceiling for a TLS record fragment (RFC 5246 TLSCiphertext).
 * TLS 1.3 still rejects ciphertext above 2^14+256 during decrypt.
 */
#define TLS_MAX_PROTECTED_RECORD_FRAGMENT (TLS_MAX_RECORD_SIZE + TLS_RECORD_WORKSPACE_OVERHEAD)
#define TLS13_MAX_ENCRYPTED_RECORD_SIZE \
    (TLS_MAX_RECORD_SIZE + TLS13_MAX_ENCRYPTED_RECORD_OVERHEAD)

/** BoringSSL-compatible consecutive empty record / warning alert limits. */
#define TLS_MAX_EMPTY_RECORDS    32U
#define TLS_MAX_WARNING_ALERTS   4U

/** Size of per-connection handshake workspace for building/parsing handshake messages (client_hello, certificate, etc.). Reused to reduce peak stack and heap. */
#ifndef NOXTLS_TLS_HANDSHAKE_WORKSPACE_SIZE
#define NOXTLS_TLS_HANDSHAKE_WORKSPACE_SIZE 8192U
#endif
#define TLS_HANDSHAKE_WORKSPACE_SIZE  NOXTLS_TLS_HANDSHAKE_WORKSPACE_SIZE

/* Network I/O modes (unsigned for Rule 10.3). */
typedef uint32_t tls_io_mode_t;
#define TLS_IO_MODE_BLOCKING     ((tls_io_mode_t)0U)  /* Blocking I/O */
#define TLS_IO_MODE_NON_BLOCKING ((tls_io_mode_t)1U)  /* Non-blocking I/O */

/** Callback result used by nonblocking transports when no progress is possible. */
#define TLS_IO_WOULD_BLOCK (-2)

/** Default upper bound for encrypted bytes accepted but not yet written. */
#ifndef NOXTLS_TLS_IO_TX_QUEUE_LIMIT
#define NOXTLS_TLS_IO_TX_QUEUE_LIMIT (256U * 1024U)
#endif

/* Network I/O Callback Functions */
/* These are placeholder functions that applications must implement */
/* 
 * tls_send_callback: Send data over the network
 * @param user_data: Application-specific context
 * @param data: Data to send
 * @param len: Length of data to send
 * @return: Number of bytes sent, or negative on error
 */
typedef int32_t (*tls_send_callback_t)(void *send_user_data, const uint8_t *send_data, uint32_t send_len);

/*
 * tls_recv_callback: Receive data from the network
 * @param user_data: Application-specific context
 * @param data: Buffer to receive data into
 * @param len: Maximum length to receive
 * @return: Number of bytes received, or negative on error
 */
typedef int32_t (*tls_recv_callback_t)(void *recv_user_data, uint8_t *recv_data, uint32_t recv_len);

/*
 * tls_time_callback: Monotonic time in milliseconds
 * @param user_data: Application-specific context
 * @return: Time in milliseconds
 */
typedef uint64_t (*tls_time_callback_t)(void *time_user_data);

/* TLS connection state (unsigned for Rule 10.3). */
typedef uint32_t tls_state_t;
#define TLS_STATE_INIT        ((tls_state_t)0U)
#define TLS_STATE_HANDSHAKING ((tls_state_t)1U)
#define TLS_STATE_CONNECTED   ((tls_state_t)2U)
#define TLS_STATE_CLOSING     ((tls_state_t)3U)
#define TLS_STATE_CLOSED      ((tls_state_t)4U)
#define TLS_STATE_ERROR       ((tls_state_t)5U)

/* TLS role (unsigned for Rule 10.3). */
typedef uint32_t tls_role_t;
#define TLS_ROLE_CLIENT ((tls_role_t)0U)
#define TLS_ROLE_SERVER ((tls_role_t)1U)

/* Wire-format headers (packed, byte-addressed fields) */
NOXTLS_PACK_BEGIN
typedef struct NOXTLS_PACKED
{
    uint8_t type;
    uint8_t version[2];
    uint8_t length[2];
} tls_record_header_t;
NOXTLS_PACK_END

NOXTLS_PACK_BEGIN
typedef struct NOXTLS_PACKED
{
    uint8_t type[2];
    uint8_t length[2];
} tls_extension_header_t;
NOXTLS_PACK_END

NOXTLS_PACK_BEGIN
typedef struct NOXTLS_PACKED
{
    uint8_t msg_type;
    uint8_t length[3];
} tls_handshake_header_t;
NOXTLS_PACK_END

/* TLS Record Structure (internal container; not wire packed) */
NOXTLS_MSVC_WARNING_PUSH
NOXTLS_MSVC_DISABLE_PADDING
typedef struct
{
    uint8_t type;           /* Record type */
    uint16_t version;       /* Protocol version */
    uint32_t length;        /* Payload length (single record <= 2^14; reassembled CH can be larger) */
    uint8_t *data;          /* Record data */
} tls_record_t;
NOXTLS_MSVC_WARNING_POP

/* TLS Context Base Structure */
NOXTLS_MSVC_WARNING_PUSH
NOXTLS_MSVC_DISABLE_PADDING
typedef struct
{
    tls_role_t role;                    /* Client or server */
    uint16_t version;                   /* TLS version */
    tls_state_t state;                  /* Connection state */
    void *user_data;                     /* Application-specific data */
    tls_send_callback_t send_callback;   /* Send callback */
    tls_recv_callback_t recv_callback;   /* Receive callback */
    tls_time_callback_t time_callback;   /* Time callback (ms) */
    tls_io_mode_t io_mode;               /* I/O mode */
    /* For version negotiation: stored Client Hello */
    uint8_t *pending_client_hello;       /* Pre-received Client Hello data */
    uint32_t pending_client_hello_len;   /* Length of pre-received Client Hello */
    /** Client: pre-read ServerHello handshake fragment (TLS 1.2 resume after TLS 1.3 ClientHello downgrade). */
    uint8_t *pending_server_hello;
    uint32_t pending_server_hello_len;
    /* Optional record send workspace (allocated by noxtls_dtls_context_init when using TLS/DTLS 1.2/1.3) */
    uint8_t *record_send_buf;
    /* Caller-polled stream I/O state. These buffers are owned by the context. */
    uint8_t *io_tx_pending;
    uint32_t io_tx_pending_len;
    uint32_t io_tx_pending_offset;
    uint32_t io_tx_queue_limit;
    uint8_t io_rx_header[5];
    uint32_t io_rx_header_len;
    uint8_t *io_rx_payload;
    uint32_t io_rx_payload_len;
    uint32_t io_rx_payload_offset;
} tls_context_t;
NOXTLS_MSVC_WARNING_POP

/* TLS Cipher Suite Information */
NOXTLS_MSVC_WARNING_PUSH
NOXTLS_MSVC_DISABLE_PADDING
typedef struct
{
    uint16_t suite;         /* Cipher suite ID */
    const uint8_t *name;       /* Cipher suite name */
    uint8_t key_size;       /* Key size in bytes */
    uint8_t iv_size;        /* IV size in bytes */
    uint8_t mac_size;       /* MAC size in bytes */
} tls_cipher_suite_t;
NOXTLS_MSVC_WARNING_POP

/* Function Prototypes */
noxtls_return_t noxtls_tls_context_init(tls_context_t *ctx, tls_role_t role, uint16_t version);
noxtls_return_t noxtls_tls_context_free(tls_context_t *ctx);
noxtls_return_t noxtls_tls_set_io_callbacks(tls_context_t *ctx, 
                                        tls_send_callback_t send_cb, 
                                        tls_recv_callback_t recv_cb, 
                                        void *user_data);
noxtls_return_t noxtls_tls_set_time_callback(tls_context_t *ctx, tls_time_callback_t time_cb);
/** Select blocking or caller-polled nonblocking stream behavior. */
noxtls_return_t noxtls_tls_set_io_mode(tls_context_t *ctx, tls_io_mode_t mode);
/** Override the encrypted-output queue limit used in nonblocking mode. */
noxtls_return_t noxtls_tls_set_io_tx_queue_limit(tls_context_t *ctx, uint32_t limit);
/** Attempt to flush encrypted output previously accepted by the record layer. */
noxtls_return_t noxtls_tls_flush(tls_context_t *ctx);
/** Return nonzero while encrypted output remains queued. */
int noxtls_tls_has_pending_output(const tls_context_t *ctx);
noxtls_return_t noxtls_tls_send_record(tls_context_t *ctx, uint8_t type, const uint8_t *data, uint32_t len);
noxtls_return_t noxtls_tls_recv_record(tls_context_t *ctx, tls_record_t *record);
noxtls_return_t noxtls_tls_send_alert(tls_context_t *ctx, uint8_t level, uint8_t description);
void noxtls_tls_set_record_dump_file(const uint8_t *path);

/* Version Detection */
noxtls_return_t noxtls_tls_detect_version(tls_context_t *base_ctx, uint16_t *detected_version, uint8_t **client_hello_data, uint32_t *client_hello_len);

/**
 * @brief Return 1 if ClientHello lists @p version in supported_versions (ext 43), else 0.
 * @param client_hello Full handshake message (type byte + 3-byte length + ClientHello body).
 */
int noxtls_tls_client_hello_supported_versions_has(const uint8_t *client_hello,
                                                   uint32_t client_hello_len,
                                                   uint16_t version);

/*
 * Algorithm availability (feature-reduced builds).
 *
 * NOXTLS_TLS_ALGORITHM_FILTER is 1 when an algorithm that a built-in cipher
 * suite, signature scheme or named group depends on is compiled out
 * (NOXTLS_FEATURE_* = 0). The helpers below then report whether a code point
 * is usable in this build: a client never offers, and a server never selects
 * or accepts, a code point whose algorithm is unavailable. Code points the
 * helpers do not classify are reported as available, so the existing
 * negotiation logic keeps deciding on them. With every such algorithm compiled
 * in, the filter is 0, the helpers are not built and negotiation is unchanged.
 */
#define NOXTLS_TLS_ALGORITHM_FILTER \
    (!(NOXTLS_FEATURE_RSA && NOXTLS_FEATURE_ECDSA && NOXTLS_FEATURE_ECDH && NOXTLS_FEATURE_DH && \
       NOXTLS_FEATURE_X25519 && NOXTLS_FEATURE_X448 && NOXTLS_FEATURE_ED25519 && \
       NOXTLS_FEATURE_MD5 && NOXTLS_FEATURE_SHA1 && NOXTLS_FEATURE_SHA224 && \
       NOXTLS_FEATURE_SHA384 && NOXTLS_FEATURE_SHA512 && \
       NOXTLS_FEATURE_AES_CBC && NOXTLS_FEATURE_AES_GCM && NOXTLS_FEATURE_AES_CCM && \
       NOXTLS_FEATURE_CHACHA20_POLY1305 && NOXTLS_FEATURE_DES && NOXTLS_FEATURE_ARIA))

#if NOXTLS_TLS_ALGORITHM_FILTER
/**
 * @brief Return 1 if every algorithm @p cipher_suite needs (key exchange, authentication,
 *        bulk cipher, record MAC / PRF hash) is compiled into this build, else 0.
 */
int noxtls_tls_cipher_suite_is_available(uint16_t cipher_suite);
/**
 * @brief Return 1 if the signature algorithm and hash of SignatureScheme / TLS 1.2
 *        SignatureAndHashAlgorithm @p sig_scheme are compiled into this build, else 0.
 */
int noxtls_tls_signature_scheme_is_available(uint16_t sig_scheme);
/**
 * @brief Return 1 if the key exchange of TLS named group @p named_group is compiled
 *        into this build, else 0.
 */
int noxtls_tls_named_group_is_available(uint16_t named_group);
#endif

/* TLS Certificate Verification Functions */
/* Note: These functions require including NOXTLS_x509.h */
noxtls_return_t noxtls_tls_verify_certificate_signature(const void *cert, const void *issuer);

/* TLS Record Encryption/Decryption Functions */
/* Note: These require including NOXTLS_tls12.h or NOXTLS_tls13.h */
/* Forward declarations to avoid circular dependencies */
#ifndef NOXTLS_TLS12_CONTEXT_T_DEFINED
#define NOXTLS_TLS12_CONTEXT_T_DEFINED
typedef struct tls12_context_s tls12_context_t;
#endif
#ifndef NOXTLS_TLS13_CONTEXT_T_DEFINED
#define NOXTLS_TLS13_CONTEXT_T_DEFINED
typedef struct tls13_context_s tls13_context_t;
#endif

noxtls_return_t noxtls_tls12_encrypt_record(tls12_context_t *ctx, 
                                       uint8_t type,
                                       const uint8_t *plaintext,
                                       uint32_t plaintext_len,
                                       uint8_t *encrypted_record,
                                       uint32_t *encrypted_record_len);
noxtls_return_t noxtls_tls12_decrypt_record(tls12_context_t *ctx,
                                      uint8_t type,
                                      const uint8_t *encrypted_record,
                                      uint32_t encrypted_record_len,
                                      uint8_t *plaintext,
                                      uint32_t *plaintext_len);
noxtls_return_t noxtls_tls13_encrypt_record(tls13_context_t *ctx,
                                       uint8_t type,
                                       const uint8_t *plaintext,
                                       uint32_t plaintext_len,
                                       uint8_t *encrypted_record,
                                       uint32_t *encrypted_record_len);
noxtls_return_t noxtls_tls13_encrypt_record_early(tls13_context_t *ctx,
                                       uint16_t cipher_suite,
                                       uint8_t type,
                                       const uint8_t *plaintext,
                                       uint32_t plaintext_len,
                                       uint8_t *encrypted_record,
                                       uint32_t *encrypted_record_len);
/* RFC 9147: send one DTLS 1.3 encrypted record (DTLSCiphertext with unified header + record number encryption).
 * omit_length: 1 = omit length field (L=0, record runs to end of datagram); 0 = include length (L=1). */
noxtls_return_t noxtls_tls13_send_dtls13_encrypted_record(tls13_context_t *ctx,
                                       int32_t use_handshake_keys,
                                       uint8_t content_type,
                                       const uint8_t *inner_plaintext,
                                       uint32_t inner_len,
                                       int32_t omit_length);
/* RFC 9147: decrypt one DTLS 1.3 DTLSCiphertext (unified header + record number decryption + AEAD). raw = full packet. */
noxtls_return_t noxtls_tls13_decrypt_dtls13_record(tls13_context_t *ctx,
                                       const uint8_t *raw, uint32_t raw_len,
                                       uint8_t *out_content_type, uint8_t *out_plaintext, uint32_t *out_plaintext_len);
/* RFC 9147: return byte length of first DTLSCiphertext record in raw (for multiple records per datagram). 0 if invalid. */
uint32_t noxtls_tls13_dtls13_record_size(const uint8_t *raw, uint32_t raw_len, uint8_t own_connection_id_len);
noxtls_return_t noxtls_tls13_decrypt_record(tls13_context_t *ctx,
                                       const uint8_t *encrypted_record,
                                       uint32_t encrypted_record_len,
                                       uint8_t *plaintext,
                                       uint32_t *plaintext_len);
noxtls_return_t noxtls_tls13_decrypt_record_early(tls13_context_t *ctx,
                                       uint16_t cipher_suite,
                                       const uint8_t *encrypted_record,
                                       uint32_t encrypted_record_len,
                                       uint8_t *plaintext,
                                       uint32_t *plaintext_len);

/* TLS Extension Structures */
NOXTLS_MSVC_WARNING_PUSH
NOXTLS_MSVC_DISABLE_PADDING
typedef struct
{
    uint16_t type;          /* Extension type */
    uint16_t length;       /* Extension length */
    uint8_t *data;         /* Extension data */
} tls_extension_t;
NOXTLS_MSVC_WARNING_POP

/* Server Name Indication (SNI) Extension */
NOXTLS_MSVC_WARNING_PUSH
NOXTLS_MSVC_DISABLE_PADDING
typedef struct
{
    uint8_t name_type;     /* Name type (0 = host_name) */
    uint16_t name_len;     /* Name length */
    uint8_t *hostname;        /* Hostname (null-terminated) */
} tls_sni_extension_t;
NOXTLS_MSVC_WARNING_POP

/* Supported Groups Extension */
NOXTLS_MSVC_WARNING_PUSH
NOXTLS_MSVC_DISABLE_PADDING
typedef struct
{
    uint16_t *groups;      /* Array of named group IDs */
    uint32_t count;        /* Number of groups */
} tls_supported_groups_extension_t;
NOXTLS_MSVC_WARNING_POP

/* Key Share Extension (TLS 1.3) */
NOXTLS_MSVC_WARNING_PUSH
NOXTLS_MSVC_DISABLE_PADDING
typedef struct
{
    uint16_t group;        /* Named group */
    uint16_t key_exchange_len; /* Key exchange data length */
    uint8_t *key_exchange; /* Key exchange data */
} tls_key_share_extension_t;
NOXTLS_MSVC_WARNING_POP

/* Key Share Extension List (TLS 1.3) */
NOXTLS_MSVC_WARNING_PUSH
NOXTLS_MSVC_DISABLE_PADDING
typedef struct
{
    tls_key_share_extension_t *entries; /* Array of key share entries */
    uint32_t count;                      /* Number of entries */
} tls_key_share_list_extension_t;
NOXTLS_MSVC_WARNING_POP

/* Signature Algorithms Extension */
NOXTLS_MSVC_WARNING_PUSH
NOXTLS_MSVC_DISABLE_PADDING
typedef struct
{
    uint16_t *algorithms;  /* Array of signature algorithm IDs */
    uint32_t count;        /* Number of algorithms */
} tls_signature_algorithms_extension_t;
NOXTLS_MSVC_WARNING_POP

/* Application Layer Protocol Negotiation (ALPN) Extension */
NOXTLS_MSVC_WARNING_PUSH
NOXTLS_MSVC_DISABLE_PADDING
typedef struct
{
    uint8_t **protocols;      /* Array of protocol strings */
    uint32_t count;        /* Number of protocols */
} tls_alpn_extension_t;
NOXTLS_MSVC_WARNING_POP

/* Supported Versions Extension (TLS 1.3) */
NOXTLS_MSVC_WARNING_PUSH
NOXTLS_MSVC_DISABLE_PADDING
typedef struct
{
    uint16_t *versions;    /* Array of TLS versions */
    uint32_t count;        /* Number of versions */
} tls_supported_versions_extension_t;
NOXTLS_MSVC_WARNING_POP

/* Parsed Extensions Container */
NOXTLS_MSVC_WARNING_PUSH
NOXTLS_MSVC_DISABLE_PADDING
typedef struct
{
    tls_extension_t *extensions;        /* Array of all extensions */
    uint32_t count;                     /* Number of extensions */
    
    /* Parsed extension data (if available) */
    tls_sni_extension_t *sni;           /* Server Name Indication */
    tls_supported_groups_extension_t *supported_groups;  /* Supported Groups */
    tls_key_share_list_extension_t *key_share;  /* Key Share (TLS 1.3) */
    tls_signature_algorithms_extension_t *signature_algorithms;  /* Signature Algorithms */
    tls_alpn_extension_t *alpn;         /* ALPN */
    tls_supported_versions_extension_t *supported_versions;  /* Supported Versions */
} tls_extensions_t;
NOXTLS_MSVC_WARNING_POP

/* Extension Parsing Functions */
noxtls_return_t noxtls_tls_parse_extensions(const uint8_t *data, uint32_t data_len, tls_extensions_t *extensions);
noxtls_return_t noxtls_tls_extensions_free(tls_extensions_t *extensions);
noxtls_return_t noxtls_tls_parse_extension_sni(const uint8_t *data, uint32_t data_len, tls_sni_extension_t *sni);
noxtls_return_t noxtls_tls_parse_extension_supported_groups(const uint8_t *data, uint32_t data_len, tls_supported_groups_extension_t *groups);
noxtls_return_t noxtls_tls_parse_extension_key_share(const uint8_t *data, uint32_t data_len, tls_key_share_list_extension_t *key_share);
noxtls_return_t noxtls_tls_parse_extension_signature_algorithms(const uint8_t *data, uint32_t data_len, tls_signature_algorithms_extension_t *algorithms);
noxtls_return_t noxtls_tls_parse_extension_alpn(const uint8_t *data, uint32_t data_len, tls_alpn_extension_t *alpn);
noxtls_return_t noxtls_tls_parse_extension_supported_versions(const uint8_t *data, uint32_t data_len, tls_supported_versions_extension_t *versions);
noxtls_return_t noxtls_tls_find_extension(tls_extensions_t *extensions, uint16_t type, tls_extension_t **extension);

/** Maximum stored negotiated ALPN protocol length (RFC 7301). */
#define NOXTLS_TLS_ALPN_MAX_PROTOCOL_LEN 255u

/** Result of server-side ALPN processing after ClientHello extension parse. */
typedef uint32_t noxtls_tls_alpn_status_t;
#define NOXTLS_TLS_ALPN_STATUS_NONE         ((noxtls_tls_alpn_status_t)0U) /**< Client did not offer ALPN. */
#define NOXTLS_TLS_ALPN_STATUS_NEGOTIATED   ((noxtls_tls_alpn_status_t)1U) /**< Protocol selected (server preference order). */
#define NOXTLS_TLS_ALPN_STATUS_DECODE_ERROR ((noxtls_tls_alpn_status_t)2U) /**< Malformed ALPN extension. */
#define NOXTLS_TLS_ALPN_STATUS_NO_OVERLAP   ((noxtls_tls_alpn_status_t)3U) /**< Client offered ALPN but no protocol overlap. */

/**
 * @brief Select ALPN protocol from ClientHello extensions (server role).
 * @param extensions Parsed ClientHello extensions.
 * @param server_protocols Server-supported protocol names (non-owning).
 * @param server_count Number of server protocols.
 * @param selected Output buffer for selected protocol bytes.
 * @param selected_cap Capacity of @p selected.
 * @param selected_len Output length of selected protocol.
 * @return ALPN processing status.
 */
noxtls_tls_alpn_status_t noxtls_tls_alpn_server_process(tls_extensions_t *extensions,
                                                        const uint8_t * const *server_protocols,
                                                        uint32_t server_count,
                                                        uint8_t *selected,
                                                        uint32_t selected_cap,
                                                        uint16_t *selected_len);

/**
 * @brief Write RFC 7301 ALPN extension (type 0x0010) for a single selected protocol.
 * @return Bytes written, or 0 on error.
 */
uint32_t noxtls_tls_alpn_write_selected_extension(const uint8_t *protocol,
                                                  uint16_t protocol_len,
                                                  uint8_t *buf,
                                                  uint32_t buf_cap);

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_TLS_COMMON_H_ */

