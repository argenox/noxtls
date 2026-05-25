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
* File:    noxtls_tls_unified.c
* Summary: Unified TLS API: single connection type for TLS 1.2/1.3
*
*
*****************************************************************************/

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "noxtls_common.h"
#include "common/noxtls_memory.h"
#include "noxtls_tls_common.h"
#include "noxtls_tls_unified.h"
#include "noxtls_tls12.h"
#include "noxtls_tls13.h"

#if !(NOXTLS_FEATURE_TLS12 || NOXTLS_FEATURE_TLS13)
#error "noxtls_tls_unified.c requires at least NOXTLS_FEATURE_TLS12 or NOXTLS_FEATURE_TLS13"
#endif

/**
 * @brief Copy the I/O callbacks and user data to a version context
 *
 * @param[in] conn The connection to copy the I/O callbacks and user data from
 * @param[out] version_base The version context to copy the I/O callbacks and user data to
 */
static void unified_copy_io_to_version_context(noxtls_tls_connection_t *conn, tls_context_t *version_base)
{
    if(version_base == NULL) return;
    version_base->send_callback = conn->base.send_callback;
    version_base->recv_callback = conn->base.recv_callback;
    version_base->user_data = conn->base.user_data;
    version_base->io_mode = conn->base.io_mode;
    version_base->time_callback = conn->base.time_callback;
}

/**
 * @brief Initialize a TLS connection
 *
 * @param[in] conn The connection to initialize
 * @param[in] role The role of the connection
 * @return NOXTLS_RETURN_SUCCESS on success, error code otherwise
 */
noxtls_return_t noxtls_tls_connection_init(noxtls_tls_connection_t *conn, tls_role_t role)
{
    if(conn == NULL) return NOXTLS_RETURN_NULL;

    memset(conn, 0, sizeof(noxtls_tls_connection_t));
    conn->fixed_version = 0;
#if NOXTLS_FEATURE_TLS13
    conn->config_offers_tls13 = 1;
#endif

    if(noxtls_tls_context_init(&conn->base, role, TLS_VERSION_1_2) != NOXTLS_RETURN_SUCCESS)
        return NOXTLS_RETURN_FAILED;

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Initialize a TLS connection for a specific version
 *
 * @param[in] conn The connection to initialize
 * @param[in] role The role of the connection
 * @param[in] version The version to initialize the connection for
 * @return NOXTLS_RETURN_SUCCESS on success, error code otherwise
 */
noxtls_return_t noxtls_tls_connection_init_version(noxtls_tls_connection_t *conn, tls_role_t role, uint16_t version)
{
    if(conn == NULL) return NOXTLS_RETURN_NULL;
    if(version != TLS_VERSION_1_2 && version != TLS_VERSION_1_3) return NOXTLS_RETURN_INVALID_PARAM;

    if(version == TLS_VERSION_1_2) {
#if !NOXTLS_FEATURE_TLS12
        return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
    }
    if(version == TLS_VERSION_1_3) {
#if !NOXTLS_FEATURE_TLS13
        return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
    }

    memset(conn, 0, sizeof(noxtls_tls_connection_t));
    conn->fixed_version = 1;
    conn->negotiated_version = version;
    conn->is_tls13 = (version == TLS_VERSION_1_3) ? 1 : 0;
#if NOXTLS_FEATURE_TLS13
    conn->config_offers_tls13 = (version == TLS_VERSION_1_3) ? 1U : 0U;
#endif

    if(noxtls_tls_context_init(&conn->base, role, version) != NOXTLS_RETURN_SUCCESS)
        return NOXTLS_RETURN_FAILED;

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Free a TLS connection
 *
 * @param[in] conn The connection to free
 * @return NOXTLS_RETURN_SUCCESS on success, error code otherwise
 */
noxtls_return_t noxtls_tls_connection_free(noxtls_tls_connection_t *conn)
{
    if(conn == NULL) return NOXTLS_RETURN_NULL;

    if(conn->negotiated_version != 0) {
        if(conn->is_tls13) {
#if NOXTLS_FEATURE_TLS13
            noxtls_tls13_context_free(&conn->u.tls13);
#endif
        } else {
#if NOXTLS_FEATURE_TLS12
            noxtls_tls12_context_free(&conn->u.tls12);
#endif
        }
    }

    noxtls_tls_context_free(&conn->base);
    memset(conn, 0, sizeof(noxtls_tls_connection_t));
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Set the I/O callbacks for a TLS connection
 *
 * @param[in] conn The connection to set the I/O callbacks for
 * @param[in] send_cb The send callback to set
 * @param[in] recv_cb The recv callback to set
 * @param[in] user_data The user data to set
 * @return NOXTLS_RETURN_SUCCESS on success, error code otherwise
 */
noxtls_return_t noxtls_tls_connection_set_io_callbacks(noxtls_tls_connection_t *conn,
                                                      tls_send_callback_t send_cb,
                                                      tls_recv_callback_t recv_cb,
                                                      void *user_data)
{
    if(conn == NULL) return NOXTLS_RETURN_NULL;
    return noxtls_tls_set_io_callbacks(&conn->base, send_cb, recv_cb, user_data);
}

/**
 * @brief Set the time callback for a TLS connection
 *
 * @param[in] conn The connection to set the time callback for
 * @param[in] time_cb The time callback to set
 * @return NOXTLS_RETURN_SUCCESS on success, error code otherwise
 */
noxtls_return_t noxtls_tls_connection_set_time_callback(noxtls_tls_connection_t *conn, tls_time_callback_t time_cb)
{
    if(conn == NULL) return NOXTLS_RETURN_NULL;
    return noxtls_tls_set_time_callback(&conn->base, time_cb);
}

/**
 * @brief Set the server certificate for a TLS connection
 *
 * @param[in] conn The connection to set the server certificate for
 * @param[in] cert The server certificate to set
 * @param[in] cert_len The length of the server certificate to set
 * @return NOXTLS_RETURN_SUCCESS on success, error code otherwise
 */
noxtls_return_t noxtls_tls_connection_set_server_cert(noxtls_tls_connection_t *conn, const uint8_t *cert, uint32_t cert_len)
{
    if(conn == NULL) return NOXTLS_RETURN_NULL;
    conn->server_cert = cert;
    conn->server_cert_len = cert_len;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Set the server certificate chain for a TLS connection
 *
 * @param[in] conn The connection to set the server certificate chain for
 * @param[in] certs The server certificate chain to set
 * @param[in] cert_lens The lengths of the server certificate chain to set
 * @param[in] cert_count The count of the server certificate chain to set
 * @return NOXTLS_RETURN_SUCCESS on success, error code otherwise
 */
noxtls_return_t noxtls_tls_connection_set_server_cert_chain(noxtls_tls_connection_t *conn,
                                                            const uint8_t **certs,
                                                            const uint32_t *cert_lens,
                                                            uint32_t cert_count)
{
    if(conn == NULL) return NOXTLS_RETURN_NULL;
    conn->server_cert_chain = certs;
    conn->server_cert_chain_len = cert_lens;
    conn->server_cert_chain_count = cert_count;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Set the server private key for a TLS connection
 *
 * @param[in] conn The connection to set the server private key for
 * @param[in] rsa_key The server private key to set
 * @return NOXTLS_RETURN_SUCCESS on success, error code otherwise
 */
noxtls_return_t noxtls_tls_connection_set_server_private_key(noxtls_tls_connection_t *conn, void *rsa_key)
{
    if(conn == NULL) return NOXTLS_RETURN_NULL;
    conn->server_private_rsa = rsa_key;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Set the server cipher suites for a TLS connection
 *
 * @param[in] conn The connection to set the server cipher suites for
 * @param[in] suites The server cipher suites to set
 * @param[in] count The count of the server cipher suites to set
 * @return NOXTLS_RETURN_SUCCESS on success, error code otherwise
 */
noxtls_return_t noxtls_tls_connection_set_server_cipher_suites(noxtls_tls_connection_t *conn,
                                                               const uint16_t *suites,
                                                               uint32_t count)
{
    if(conn == NULL) return NOXTLS_RETURN_NULL;
    conn->server_cipher_suites = suites;
    conn->server_cipher_suites_count = count;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Set the server ALPN protocols for a TLS connection
 *
 * @param[in] conn The connection to set the server ALPN protocols for
 * @param[in] protocols The server ALPN protocols to set
 * @param[in] count The count of the server ALPN protocols to set
 * @return NOXTLS_RETURN_SUCCESS on success, error code otherwise
 */
noxtls_return_t noxtls_tls_connection_set_server_alpn_protocols(noxtls_tls_connection_t *conn,
                                                                const char **protocols,
                                                                uint32_t count)
{
    if(conn == NULL) return NOXTLS_RETURN_NULL;
    conn->server_alpn_protocols = protocols;
    conn->server_alpn_count = count;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Set the server name for a TLS connection
 *
 * @param[in] conn The connection to set the server name for
 * @param[in] name The server name to set
 * @param[in] name_len The length of the server name to set
 * @return NOXTLS_RETURN_SUCCESS on success, error code otherwise
 */
noxtls_return_t noxtls_tls_connection_set_sni(noxtls_tls_connection_t *conn, const char *name, uint16_t name_len)
{
    if(conn == NULL) return NOXTLS_RETURN_NULL;
    conn->server_name = name;
    conn->server_name_len = name_len;
    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Accept a TLS connection
 *
 * @param[in] conn The connection to accept
 * @return NOXTLS_RETURN_SUCCESS on success, error code otherwise
 */
noxtls_return_t noxtls_tls_connection_accept(noxtls_tls_connection_t *conn)
{
    noxtls_return_t rc;
    uint16_t detected_version;
    uint8_t *client_hello_data = NULL;
    uint32_t client_hello_len = 0;

    if(conn == NULL) return NOXTLS_RETURN_NULL;
    if(conn->base.role != TLS_ROLE_SERVER) return NOXTLS_RETURN_FAILED;
    if(conn->base.recv_callback == NULL) return NOXTLS_RETURN_FAILED;

    rc = noxtls_tls_detect_version(&conn->base, &detected_version, &client_hello_data, &client_hello_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        if(conn->base.send_callback != NULL) {
            if(rc == NOXTLS_RETURN_NOT_SUPPORTED) {
                (void)noxtls_tls_send_alert(&conn->base, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_PROTOCOL_VERSION);
            } else if(rc == NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER) {
                (void)noxtls_tls_send_alert(&conn->base, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_ILLEGAL_PARAMETER);
            } else if(rc == NOXTLS_RETURN_TLS_ALERT_DECODE_ERROR) {
                (void)noxtls_tls_send_alert(&conn->base, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_DECODE_ERROR);
            } else if(rc == NOXTLS_RETURN_TLS_ERROR) {
                (void)noxtls_tls_send_alert(&conn->base, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_UNEXPECTED_MESSAGE);
            } else if(rc == NOXTLS_RETURN_BAD_DATA) {
                (void)noxtls_tls_send_alert(&conn->base, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_DECODE_ERROR);
            }
        }
        return rc;
    }

    if(detected_version == TLS_VERSION_1_3) {
#if NOXTLS_FEATURE_TLS13
        conn->negotiated_version = TLS_VERSION_1_3;
        conn->is_tls13 = 1;

        rc = noxtls_tls13_context_init(&conn->u.tls13, TLS_ROLE_SERVER);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            if(client_hello_data) noxtls_free(client_hello_data);
            return rc;
        }

        conn->u.tls13.base.base.pending_client_hello = client_hello_data;
        conn->u.tls13.base.base.pending_client_hello_len = client_hello_len;
        unified_copy_io_to_version_context(conn, &conn->u.tls13.base.base);

        if(conn->server_cert != NULL) {
            conn->u.tls13.server_cert = (uint8_t *)conn->server_cert;
            conn->u.tls13.server_cert_len = conn->server_cert_len;
        }
        if(conn->server_cert_chain != NULL && conn->server_cert_chain_len != NULL && conn->server_cert_chain_count > 0) {
            noxtls_tls13_set_server_certificate_chain(&conn->u.tls13,
                                                      conn->server_cert_chain,
                                                      conn->server_cert_chain_len,
                                                      conn->server_cert_chain_count);
        }
        if(conn->server_private_rsa != NULL)
            noxtls_tls13_set_server_private_rsa(&conn->u.tls13, conn->server_private_rsa);
        if(conn->server_cipher_suites != NULL && conn->server_cipher_suites_count > 0) {
            noxtls_tls13_set_server_cipher_suites(&conn->u.tls13, conn->server_cipher_suites,
                                                  conn->server_cipher_suites_count);
        }
        if(conn->server_alpn_protocols != NULL && conn->server_alpn_count > 0) {
            noxtls_tls13_set_server_alpn_protocols(&conn->u.tls13, conn->server_alpn_protocols,
                                                   conn->server_alpn_count);
        }

        rc = noxtls_tls13_accept(&conn->u.tls13);

        if(conn->u.tls13.base.base.pending_client_hello) {
            noxtls_free(conn->u.tls13.base.base.pending_client_hello);
            conn->u.tls13.base.base.pending_client_hello = NULL;
            conn->u.tls13.base.base.pending_client_hello_len = 0;
        }

        if(rc != NOXTLS_RETURN_SUCCESS) {
            noxtls_tls13_context_free(&conn->u.tls13);
            conn->negotiated_version = 0;
            conn->is_tls13 = 0;
        }
        return rc;
#else
        if(conn->base.send_callback != NULL) {
            (void)noxtls_tls_send_alert(&conn->base, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_PROTOCOL_VERSION);
        }
        if(client_hello_data) noxtls_free(client_hello_data);
        return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
    }

    /* TLS 1.2 (or TLS 1.0/1.1 via shared tls12 stack when detect_version requests it) */
#if NOXTLS_FEATURE_TLS12
    {
        uint16_t tls12_wire_version = (detected_version == TLS_VERSION_1_0 ||
                                       detected_version == TLS_VERSION_1_1)
                                          ? detected_version
                                          : TLS_VERSION_1_2;
        conn->negotiated_version = tls12_wire_version;
        conn->is_tls13 = 0;

        rc = noxtls_tls12_context_init_with_version(&conn->u.tls12, TLS_ROLE_SERVER, tls12_wire_version);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        if(client_hello_data) noxtls_free(client_hello_data);
        return rc;
    }

    conn->u.tls12.base.base.pending_client_hello = client_hello_data;
    conn->u.tls12.base.base.pending_client_hello_len = client_hello_len;
    unified_copy_io_to_version_context(conn, &conn->u.tls12.base.base);

    if(conn->server_cert != NULL) {
        conn->u.tls12.server_cert = (uint8_t *)conn->server_cert;
        conn->u.tls12.server_cert_len = conn->server_cert_len;
    }
    if(conn->server_cert_chain != NULL && conn->server_cert_chain_len != NULL && conn->server_cert_chain_count > 0) {
        noxtls_tls12_set_server_certificate_chain(&conn->u.tls12,
                                                  conn->server_cert_chain,
                                                  conn->server_cert_chain_len,
                                                  conn->server_cert_chain_count);
    }
    if(conn->server_private_rsa != NULL)
        noxtls_tls12_set_server_private_rsa(&conn->u.tls12, conn->server_private_rsa);
    if(conn->server_cipher_suites != NULL && conn->server_cipher_suites_count > 0) {
        noxtls_tls12_set_server_cipher_suites(&conn->u.tls12, conn->server_cipher_suites,
                                              conn->server_cipher_suites_count);
    }
    if(conn->server_alpn_protocols != NULL && conn->server_alpn_count > 0) {
        noxtls_tls12_set_server_alpn_protocols(&conn->u.tls12, conn->server_alpn_protocols,
                                               conn->server_alpn_count);
    }

#if NOXTLS_FEATURE_TLS13
        conn->u.tls12.rfc8446_tls13_downgrade_sh_random =
            (conn->config_offers_tls13 != 0 && tls12_wire_version == TLS_VERSION_1_2) ? 1U : 0U;
#endif

        rc = noxtls_tls12_accept(&conn->u.tls12);

        if(conn->u.tls12.base.base.pending_client_hello) {
            noxtls_free(conn->u.tls12.base.base.pending_client_hello);
            conn->u.tls12.base.base.pending_client_hello = NULL;
            conn->u.tls12.base.base.pending_client_hello_len = 0;
        }

        if(rc != NOXTLS_RETURN_SUCCESS) {
            noxtls_tls12_context_free(&conn->u.tls12);
            conn->negotiated_version = 0;
        }
        return rc;
    }
#else
    if(conn->base.send_callback != NULL) {
        (void)noxtls_tls_send_alert(&conn->base, TLS_ALERT_LEVEL_FATAL, TLS_ALERT_PROTOCOL_VERSION);
    }
    if(client_hello_data) noxtls_free(client_hello_data);
    return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
}

/**
 * @brief Connect a TLS connection
 *
 * @param[in] conn The connection to connect
 * @return NOXTLS_RETURN_SUCCESS on success, error code otherwise
 */
noxtls_return_t noxtls_tls_connection_connect(noxtls_tls_connection_t *conn)
{
    noxtls_return_t rc;

    if(conn == NULL) return NOXTLS_RETURN_NULL;
    if(conn->base.role != TLS_ROLE_CLIENT) return NOXTLS_RETURN_FAILED;
    if(conn->base.recv_callback == NULL || conn->base.send_callback == NULL) return NOXTLS_RETURN_FAILED;

    if(conn->fixed_version) {
        if(conn->is_tls13) {
#if NOXTLS_FEATURE_TLS13
            rc = noxtls_tls13_context_init(&conn->u.tls13, TLS_ROLE_CLIENT);
            if(rc != NOXTLS_RETURN_SUCCESS) return rc;
            unified_copy_io_to_version_context(conn, &conn->u.tls13.base.base);
            if(conn->server_name != NULL) {
                conn->u.tls13.server_name = conn->server_name;
                conn->u.tls13.server_name_len = conn->server_name_len;
            }
            return noxtls_tls13_connect(&conn->u.tls13);
#endif
        } else {
#if NOXTLS_FEATURE_TLS12
            rc = noxtls_tls12_context_init(&conn->u.tls12, TLS_ROLE_CLIENT);
            if(rc != NOXTLS_RETURN_SUCCESS) return rc;
            unified_copy_io_to_version_context(conn, &conn->u.tls12.base.base);
            if(conn->server_name != NULL) {
                conn->u.tls12.server_name = conn->server_name;
                conn->u.tls12.server_name_len = conn->server_name_len;
            }
            return noxtls_tls12_connect(&conn->u.tls12);
#endif
        }
    }

    /* Auto: try TLS 1.3 first, then TLS 1.2 */
#if NOXTLS_FEATURE_TLS13
    rc = noxtls_tls13_context_init(&conn->u.tls13, TLS_ROLE_CLIENT);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        unified_copy_io_to_version_context(conn, &conn->u.tls13.base.base);
        if(conn->server_name != NULL) {
            conn->u.tls13.server_name = conn->server_name;
            conn->u.tls13.server_name_len = conn->server_name_len;
        }
        rc = noxtls_tls13_connect(&conn->u.tls13);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            conn->negotiated_version = TLS_VERSION_1_3;
            conn->is_tls13 = 1;
            return NOXTLS_RETURN_SUCCESS;
        }
#if NOXTLS_FEATURE_TLS12
        if(rc == NOXTLS_RETURN_NEGOTIATED_TLS12) {
            uint8_t *stash_sh = conn->u.tls13.client_tls12_downgrade_server_hello;
            uint32_t stash_sh_len = conn->u.tls13.client_tls12_downgrade_server_hello_len;
            conn->u.tls13.client_tls12_downgrade_server_hello = NULL;
            conn->u.tls13.client_tls12_downgrade_server_hello_len = 0;

            uint32_t ch_len = conn->u.tls13.handshake_messages_len;
            uint8_t *ch_copy = NULL;

            if(stash_sh == NULL || stash_sh_len < 4U || ch_len < 4U || conn->u.tls13.handshake_messages == NULL) {
                if(stash_sh) {
                    free(stash_sh);
                }
                noxtls_tls13_context_free(&conn->u.tls13);
                return NOXTLS_RETURN_FAILED;
            }

            ch_copy = (uint8_t *)noxtls_malloc(ch_len);
            if(ch_copy == NULL) {
                free(stash_sh);
                noxtls_tls13_context_free(&conn->u.tls13);
                return NOXTLS_RETURN_NOT_ENOUGH_MEMORY;
            }
            memcpy(ch_copy, conn->u.tls13.handshake_messages, ch_len);

            noxtls_tls13_context_free(&conn->u.tls13);

            rc = noxtls_tls12_context_init(&conn->u.tls12, TLS_ROLE_CLIENT);
            if(rc != NOXTLS_RETURN_SUCCESS) {
                noxtls_free(ch_copy);
                free(stash_sh);
                return rc;
            }
            unified_copy_io_to_version_context(conn, &conn->u.tls12.base.base);
            if(conn->server_name != NULL) {
                conn->u.tls12.server_name = conn->server_name;
                conn->u.tls12.server_name_len = conn->server_name_len;
            }
            conn->u.tls12.rfc8446_tls13_downgrade_sh_random = (conn->config_offers_tls13 != 0U) ? 1U : 0U;

            rc = noxtls_tls12_client_resume_from_tls13_downgrade(&conn->u.tls12, ch_copy, ch_len, stash_sh, stash_sh_len);
            if(rc == NOXTLS_RETURN_SUCCESS) {
                conn->negotiated_version = TLS_VERSION_1_2;
                conn->is_tls13 = 0;
                return NOXTLS_RETURN_SUCCESS;
            }
            noxtls_tls12_context_free(&conn->u.tls12);
            return rc;
        }
#endif
        noxtls_tls13_context_free(&conn->u.tls13);
    }
#endif

#if NOXTLS_FEATURE_TLS12
    rc = noxtls_tls12_context_init(&conn->u.tls12, TLS_ROLE_CLIENT);
    if(rc != NOXTLS_RETURN_SUCCESS) return rc;
    unified_copy_io_to_version_context(conn, &conn->u.tls12.base.base);
    if(conn->server_name != NULL) {
        conn->u.tls12.server_name = conn->server_name;
        conn->u.tls12.server_name_len = conn->server_name_len;
    }
    rc = noxtls_tls12_connect(&conn->u.tls12);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        conn->negotiated_version = TLS_VERSION_1_2;
        conn->is_tls13 = 0;
        return NOXTLS_RETURN_SUCCESS;
    }
    noxtls_tls12_context_free(&conn->u.tls12);
    return rc;
#else
    return NOXTLS_RETURN_FAILED;
#endif
}

/**
 * @brief Send data on a TLS connection
 *
 * @param[in] conn The connection to send data on
 * @param[in] data The data to send
 * @param[in] len The length of the data to send
 * @return NOXTLS_RETURN_SUCCESS on success, error code otherwise
 */
noxtls_return_t noxtls_tls_connection_send(noxtls_tls_connection_t *conn, const uint8_t *data, uint32_t len)
{
    if(conn == NULL || data == NULL) return NOXTLS_RETURN_NULL;
    if(conn->negotiated_version == 0) return NOXTLS_RETURN_FAILED;

    if(conn->is_tls13) {
#if NOXTLS_FEATURE_TLS13
        return noxtls_tls13_send(&conn->u.tls13, data, len);
#else
        return NOXTLS_RETURN_FAILED;
#endif
    } else {
#if NOXTLS_FEATURE_TLS12
        return noxtls_tls12_send(&conn->u.tls12, data, len);
#else
        return NOXTLS_RETURN_FAILED;
#endif
    }
}

/**
 * @brief Receive data on a TLS connection
 *
 * @param[in] conn The connection to receive data on
 * @param[out] buf The buffer to receive the data into
 * @param[out] len The length of the data received
 * @return NOXTLS_RETURN_SUCCESS on success, error code otherwise
 */
noxtls_return_t noxtls_tls_connection_recv(noxtls_tls_connection_t *conn, uint8_t *buf, uint32_t *len)
{
    if(conn == NULL || buf == NULL || len == NULL) return NOXTLS_RETURN_NULL;
    if(conn->negotiated_version == 0) return NOXTLS_RETURN_FAILED;

    if(conn->is_tls13) {
#if NOXTLS_FEATURE_TLS13
        return noxtls_tls13_recv(&conn->u.tls13, buf, len);
#else
        return NOXTLS_RETURN_FAILED;
#endif
    } else {
#if NOXTLS_FEATURE_TLS12
        return noxtls_tls12_recv(&conn->u.tls12, buf, len);
#else
        return NOXTLS_RETURN_FAILED;
#endif
    }
}

/**
 * @brief Close a TLS connection
 *
 * @param[in] conn The connection to close
 * @return NOXTLS_RETURN_SUCCESS on success, error code otherwise
 */
noxtls_return_t noxtls_tls_connection_close(noxtls_tls_connection_t *conn)
{
    if(conn == NULL) return NOXTLS_RETURN_NULL;
    if(conn->negotiated_version == 0) return NOXTLS_RETURN_FAILED;

    if(conn->is_tls13) {
#if NOXTLS_FEATURE_TLS13
        return noxtls_tls13_close(&conn->u.tls13);
#else
        return NOXTLS_RETURN_FAILED;
#endif
    } else {
#if NOXTLS_FEATURE_TLS12
        return noxtls_tls12_close(&conn->u.tls12);
#else
        return NOXTLS_RETURN_FAILED;
#endif
    }
}

/**
 * @brief Get the version of a TLS connection
 *
 * @param[in] conn The connection to get the version of
 * @return The version of the connection
 */
uint16_t noxtls_tls_connection_get_version(const noxtls_tls_connection_t *conn)
{
    if(conn == NULL) return 0;
    return conn->negotiated_version;
}
