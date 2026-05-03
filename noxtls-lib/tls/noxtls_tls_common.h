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
* File:    noxtls_tls_common.h
* Summary: TLS Common Definitions and Structures
*
*/

#ifndef _NOXTLS_TLS_COMMON_H_
#define _NOXTLS_TLS_COMMON_H_

#include <stdint.h>

#include "noxtls_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* TLS Versions */
#define TLS_VERSION_1_0    0x0301
#define TLS_VERSION_1_1    0x0302
#define TLS_VERSION_1_2    0x0303
#define TLS_VERSION_1_3    0x0304

/* TLS Record Types */
#define TLS_RECORD_CHANGE_CIPHER_SPEC   20
#define TLS_RECORD_CCS_PAYLOAD          0x01  /* Single byte payload of Change Cipher Spec record */
#define TLS_RECORD_ALERT                21
#define TLS_RECORD_HANDSHAKE            22
#define TLS_RECORD_APPLICATION_DATA     23
#define TLS_RECORD_ACK                  26   /* RFC 9147: DTLS 1.3 ACK (plaintext) */

/* TLS Handshake Types */
#define TLS_HANDSHAKE_HELLO_REQUEST         0
#define TLS_HANDSHAKE_CLIENT_HELLO           1
#define TLS_HANDSHAKE_SERVER_HELLO           2
#define TLS_HANDSHAKE_NEW_SESSION_TICKET     4
#define TLS_HANDSHAKE_END_OF_EARLY_DATA      5
#define TLS_HANDSHAKE_ENCRYPTED_EXTENSIONS   8
#define TLS_HANDSHAKE_CERTIFICATE            11
#define TLS_HANDSHAKE_SERVER_KEY_EXCHANGE     12
#define TLS_HANDSHAKE_CERTIFICATE_REQUEST    13
#define TLS_HANDSHAKE_SERVER_HELLO_DONE      14
#define TLS_HANDSHAKE_CERTIFICATE_VERIFY     15
#define TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE    16
#define TLS_HANDSHAKE_FINISHED               20
#define TLS_HANDSHAKE_KEY_UPDATE             24
#define TLS_HANDSHAKE_ACK                    25
#define TLS_HANDSHAKE_MESSAGE_HASH           254

/* TLS protocol sizes (bytes) */
#define TLS_RANDOM_SIZE                      32   /* ClientHello / ServerHello random length */
#define TLS_MASTER_SECRET_LEN                48   /* Master secret length (RFC 5246/8446) */
#define TLS_MAX_SECRET_LEN                   64   /* Max HKDF/PRF output (e.g. SHA-512) */
#define TLS_KEY_BLOCK_MAX_LEN                256  /* Max key_block length (TLS 1.2) */
#define TLS_FINISHED_VERIFY_DATA_LEN_12      12   /* TLS 1.0/1.1 Finished verify_data length */
#define TLS_HANDSHAKE_HEADER_LEN             4    /* Handshake type (1) + length (3) */
#define TLS_CLIENT_HELLO_BASE_SIZE           1024 /* Base size for ClientHello before extensions */
#define TLS_CLIENT_HELLO_EXTENSIONS_TAIL     256  /* Tail buffer for building extensions */
#define TLS_CLIENT_HELLO_DEFAULT_SIZE       (TLS_CLIENT_HELLO_BASE_SIZE + TLS_CLIENT_HELLO_EXTENSIONS_TAIL)
#define TLS_SERVER_HELLO_DEFAULT_SIZE        512
#define TLS_CLIENT_KEY_EXCHANGE_MAX_LEN      512  /* Max ClientKeyExchange message buffer */
#define TLS_HELLO_RETRY_REQUEST_MAX_SIZE     256
#define TLS_SERVER_KEY_EXCHANGE_WORKSPACE   (1024 + 320 + 512)  /* DHE/ECDHE params + sig buffer */
#define TLS_RECORD_WORKSPACE_OVERHEAD        256  /* Extra bytes for record_workspace (IV/tag/etc.) */
#define TLS_KEY_SHARE_ENTRY_MAX_LEN          256  /* Encoded key share entry buffer */
#define TLS_SESSION_ID_MAX_LEN               32
#define TLS_CERT_REQUEST_CONTEXT_MAX_LEN    32
#define TLS_NEW_SESSION_TICKET_NONCE_LEN     16
#define TLS_NST_TICKET_ID_LEN                16
#define TLS_PSK_BINDER_MAX_LEN               64
#define TLS_COOKIE_MAX_LEN                   32

/* EC point format and curve type (wire format) */
#define TLS_EC_POINT_UNCOMPRESSED            0x04
#define TLS_EC_CURVE_TYPE_NAMED              0x03

/* TLS 1.3 / RFC 8446 signature schemes */
#define TLS_SIGSCHEME_RSA_PSS_RSAE_SHA256    0x0804
#define TLS_SIGSCHEME_ECDSA_SECP256R1_SHA256 0x0403
#define TLS_SIGSCHEME_ECDSA_SECP384R1_SHA384 0x0503
#define TLS_SIGSCHEME_ED25519                0x0807

/* TLS Named Groups (for key exchange) */
#define TLS_NAMED_GROUP_SECP256R1    23  /* secp256r1 (NIST P-256) */
#define TLS_NAMED_GROUP_SECP384R1    24  /* secp384r1 (NIST P-384) */
#define TLS_NAMED_GROUP_SECP521R1    25  /* secp521r1 (NIST P-521) */
#define TLS_NAMED_GROUP_X25519       29  /* x25519 (Curve25519) */
#define TLS_NAMED_GROUP_X448         30  /* x448 (Curve448) */
/* RFC 7919 FFDHE (finite-field DH) */
#define TLS_NAMED_GROUP_FFDHE2048   256
#define TLS_NAMED_GROUP_FFDHE3072   257
#define TLS_NAMED_GROUP_FFDHE4096   258

/* TLS Cipher Suites */
#define TLS_CIPHER_SUITE_NULL_WITH_NULL_NULL                 0x0000
#define TLS_CIPHER_SUITE_RSA_WITH_3DES_EDE_CBC_SHA           0x000A
#define TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA            0x002F
#define TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA            0x0035
#define TLS_CIPHER_SUITE_RSA_WITH_AES_128_CBC_SHA256         0x003C
#define TLS_CIPHER_SUITE_RSA_WITH_AES_256_CBC_SHA256         0x003D
#define TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_CBC_SHA256     0x0039
#define TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_CBC_SHA256     0x006B
#define TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_128_GCM_SHA256     0x009E
#define TLS_CIPHER_SUITE_DHE_RSA_WITH_AES_256_GCM_SHA384     0x009F
#define TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_CBC_SHA256   0xC027
#define TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_CBC_SHA384   0xC028
#define TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 0xC02B
#define TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 0xC02C
#define TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256   0xC02F
#define TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_256_GCM_SHA384   0xC030
#define TLS_CIPHER_SUITE_AES_128_GCM_SHA256                  0x1301
#define TLS_CIPHER_SUITE_AES_256_GCM_SHA384                  0x1302
#define TLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256            0x1303
#define TLS_CIPHER_SUITE_AES_128_CCM_SHA256                  0x1304
#define TLS_CIPHER_SUITE_AES_128_CCM_8_SHA256                0x1305

/* ARIA Cipher Suites (RFC 6209) */
#define TLS_CIPHER_SUITE_RSA_WITH_ARIA_128_CBC_SHA256        0xC03C
#define TLS_CIPHER_SUITE_RSA_WITH_ARIA_256_CBC_SHA384        0xC03D
#define TLS_CIPHER_SUITE_DH_DSS_WITH_ARIA_128_CBC_SHA256     0xC03E
#define TLS_CIPHER_SUITE_DH_DSS_WITH_ARIA_256_CBC_SHA384     0xC03F
#define TLS_CIPHER_SUITE_DH_RSA_WITH_ARIA_128_CBC_SHA256     0xC040
#define TLS_CIPHER_SUITE_DH_RSA_WITH_ARIA_256_CBC_SHA384     0xC041
#define TLS_CIPHER_SUITE_DHE_DSS_WITH_ARIA_128_CBC_SHA256    0xC042
#define TLS_CIPHER_SUITE_DHE_DSS_WITH_ARIA_256_CBC_SHA384    0xC043
#define TLS_CIPHER_SUITE_DHE_RSA_WITH_ARIA_128_CBC_SHA256    0xC044
#define TLS_CIPHER_SUITE_DHE_RSA_WITH_ARIA_256_CBC_SHA384    0xC045
#define TLS_CIPHER_SUITE_DHE_RSA_WITH_ARIA_128_GCM_SHA256    0xC07C
#define TLS_CIPHER_SUITE_DHE_RSA_WITH_ARIA_256_GCM_SHA384    0xC07D
#define TLS_CIPHER_SUITE_DH_anon_WITH_ARIA_128_CBC_SHA256    0xC046
#define TLS_CIPHER_SUITE_DH_anon_WITH_ARIA_256_CBC_SHA384    0xC047
#define TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256 0xC048
#define TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384 0xC049
#define TLS_CIPHER_SUITE_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256 0xC04A
#define TLS_CIPHER_SUITE_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384 0xC04B
#define TLS_CIPHER_SUITE_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256  0xC04C
#define TLS_CIPHER_SUITE_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384  0xC04D
#define TLS_CIPHER_SUITE_ECDH_RSA_WITH_ARIA_128_CBC_SHA256   0xC04E
#define TLS_CIPHER_SUITE_ECDH_RSA_WITH_ARIA_256_CBC_SHA384   0xC04F
#define TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256 0xC050
#define TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384 0xC051
#define TLS_CIPHER_SUITE_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256 0xC052
#define TLS_CIPHER_SUITE_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384 0xC053
#define TLS_CIPHER_SUITE_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256  0xC054
#define TLS_CIPHER_SUITE_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384  0xC055
#define TLS_CIPHER_SUITE_ECDH_RSA_WITH_ARIA_128_GCM_SHA256   0xC056
#define TLS_CIPHER_SUITE_ECDH_RSA_WITH_ARIA_256_GCM_SHA384   0xC057

/* TLS Alert Levels */
#define TLS_ALERT_LEVEL_WARNING   1
#define TLS_ALERT_LEVEL_FATAL    2

/* TLS Extension Types */
#define TLS_EXTENSION_SERVER_NAME              0
#define TLS_EXTENSION_MAX_FRAGMENT_LENGTH      1
#define TLS_EXTENSION_STATUS_REQUEST          5
#define TLS_EXTENSION_SUPPORTED_GROUPS         10
#define TLS_EXTENSION_SIGNATURE_ALGORITHMS     13
#define TLS_EXTENSION_USE_SRTP                 14
#define TLS_EXTENSION_HEARTBEAT                15
#define TLS_EXTENSION_APPLICATION_LAYER_PROTOCOL_NEGOTIATION 16
#define TLS_EXTENSION_SIGNED_CERTIFICATE_TIMESTAMP 18
#define TLS_EXTENSION_CLIENT_CERTIFICATE_TYPE  19
#define TLS_EXTENSION_SERVER_CERTIFICATE_TYPE  20
/* RFC 7250 / IANA TLS Certificate Types */
#define TLS_CERT_TYPE_X509               0
#define TLS_CERT_TYPE_OPENPGP            1
#define TLS_CERT_TYPE_RAW_PUBLIC_KEY     2
#define TLS_EXTENSION_PADDING                  21
#define TLS_EXTENSION_ENCRYPT_THEN_MAC         22
#define TLS_EXTENSION_EXTENDED_MASTER_SECRET   23
#define TLS_EXTENSION_TOKEN_BINDING            24
#define TLS_EXTENSION_CACHED_INFO              25
#define TLS_EXTENSION_TLS_LTS                  27
#define TLS_EXTENSION_COMPRESS_CERTIFICATE     27
#define TLS_EXTENSION_RECORD_SIZE_LIMIT        28
#define TLS_EXTENSION_PWD_PROTECT              29
#define TLS_EXTENSION_PWD_CLEAR                30
#define TLS_EXTENSION_PASSWORD_SALT            31
#define TLS_EXTENSION_TICKET_PINNING           35
#define TLS_EXTENSION_TLS_CERT_WITH_EXTERN_PSK 36
#define TLS_EXTENSION_DELEGATED_CREDENTIAL     34
#define TLS_EXTENSION_SESSION_TICKET           35
#define TLS_EXTENSION_PRE_SHARED_KEY           41
#define TLS_EXTENSION_EARLY_DATA               42
#define TLS_EXTENSION_SUPPORTED_VERSIONS       43
#define TLS_EXTENSION_COOKIE                   44
#define TLS_EXTENSION_PSK_KEY_EXCHANGE_MODES   45
#define TLS_EXTENSION_CERTIFICATE_AUTHORITIES  47
#define TLS_EXTENSION_OID_FILTERS              48
#define TLS_EXTENSION_POST_HANDSHAKE_AUTH      49
#define TLS_EXTENSION_SIGNATURE_ALGORITHMS_CERT 50
#define TLS_EXTENSION_KEY_SHARE                51
#define TLS_EXTENSION_CONNECTION_ID            54  /* RFC 9146 / RFC 9147: DTLS Connection ID */
/* RFC 5746: Secure renegotiation */
#define TLS_EXTENSION_RENEGOTIATION_INFO       0xFF01

/* TLS Alert Types */
#define TLS_ALERT_CLOSE_NOTIFY               0
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
 * handshake message (typically the Certificate message = chain size);
 * see noxtls_config.h for adjustment and certificate-size guidance. */
#define TLS_MAX_RECORD_SIZE       NOXTLS_TLS_MAX_RECORD_SIZE
#define TLS_MAX_HANDSHAKE_SIZE    NOXTLS_TLS_MAX_HANDSHAKE_SIZE

/** Size of per-connection handshake workspace for building/parsing handshake messages (client_hello, certificate, etc.). Reused to reduce peak stack and heap. */
#define TLS_HANDSHAKE_WORKSPACE_SIZE  4096

/* Network I/O Callback Types */
typedef enum
{
    TLS_IO_MODE_BLOCKING,      /* Blocking I/O */
    TLS_IO_MODE_NON_BLOCKING   /* Non-blocking I/O */
} tls_io_mode_t;

/* Network I/O Callback Functions */
/* These are placeholder functions that applications must implement */
/* 
 * tls_send_callback: Send data over the network
 * @param user_data: Application-specific context
 * @param data: Data to send
 * @param len: Length of data to send
 * @return: Number of bytes sent, or negative on error
 */
typedef int32_t (*tls_send_callback_t)(void *user_data, const uint8_t *data, uint32_t len);

/*
 * tls_recv_callback: Receive data from the network
 * @param user_data: Application-specific context
 * @param data: Buffer to receive data into
 * @param len: Maximum length to receive
 * @return: Number of bytes received, or negative on error
 */
typedef int32_t (*tls_recv_callback_t)(void *user_data, uint8_t *data, uint32_t len);

/*
 * tls_time_callback: Monotonic time in milliseconds
 * @param user_data: Application-specific context
 * @return: Time in milliseconds
 */
typedef uint64_t (*tls_time_callback_t)(void *user_data);

/* TLS Connection State */
typedef enum
{
    TLS_STATE_INIT,
    TLS_STATE_HANDSHAKING,
    TLS_STATE_CONNECTED,
    TLS_STATE_CLOSING,
    TLS_STATE_CLOSED,
    TLS_STATE_ERROR
} tls_state_t;

/* TLS Role */
typedef enum
{
    TLS_ROLE_CLIENT,
    TLS_ROLE_SERVER
} tls_role_t;

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
    uint16_t length;        /* Record length */
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
    /* Optional record send workspace (allocated by dtls_context_init when using TLS/DTLS 1.2/1.3) */
    uint8_t *record_send_buf;
} tls_context_t;
NOXTLS_MSVC_WARNING_POP

/* TLS Cipher Suite Information */
NOXTLS_MSVC_WARNING_PUSH
NOXTLS_MSVC_DISABLE_PADDING
typedef struct
{
    uint16_t suite;         /* Cipher suite ID */
    const char *name;       /* Cipher suite name */
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
noxtls_return_t noxtls_tls_send_record(tls_context_t *ctx, uint8_t type, const uint8_t *data, uint32_t len);
noxtls_return_t noxtls_tls_recv_record(tls_context_t *ctx, tls_record_t *record);
noxtls_return_t noxtls_tls_send_alert(tls_context_t *ctx, uint8_t level, uint8_t description);
void noxtls_tls_set_record_dump_file(const char *path);

/* Version Detection */
noxtls_return_t noxtls_tls_detect_version(tls_context_t *base_ctx, uint16_t *detected_version, uint8_t **client_hello_data, uint32_t *client_hello_len);

/* TLS Certificate Verification Functions */
/* Note: These functions require including NOXTLS_x509.h */
noxtls_return_t noxtls_tls_verify_certificate_signature(void *cert, void *issuer);

/* TLS Record Encryption/Decryption Functions */
/* Note: These require including NOXTLS_tls12.h or NOXTLS_tls13.h */
/* Forward declarations to avoid circular dependencies */
typedef struct tls12_context_s tls12_context_t;
typedef struct tls13_context_s tls13_context_t;

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
                                       int use_handshake_keys,
                                       uint8_t content_type,
                                       const uint8_t *inner_plaintext,
                                       uint32_t inner_len,
                                       int omit_length);
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
    char *hostname;        /* Hostname (null-terminated) */
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
    char **protocols;      /* Array of protocol strings */
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

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_TLS_COMMON_H_ */

