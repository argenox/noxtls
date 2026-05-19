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
* This file is part of the NoxTLS Library.
*
* File:    noxtls_tls_unified.c
* Summary: Unified TLS API: single connection type for TLS 1.2/1.3
*
*/

#if !(NOXTLS_FEATURE_TLS12 || NOXTLS_FEATURE_TLS13)
#error "noxtls_tls_unified.c requires at least NOXTLS_FEATURE_TLS12 or NOXTLS_FEATURE_TLS13"
#endif

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "noxtls_common.h"
#include "common/noxtls_memory.h"
#include "noxtls_tls_common.h"
#include "noxtls_tls_unified.h"
#include "noxtls_tls12.h"
#include "noxtls_tls13.h"

static void unified_copy_io_to_version_context(noxtls_tls_connection_t *conn, tls_context_t *version_base)
{
    if(version_base == NULL) return;
    version_base->send_callback = conn->base.send_callback;
    version_base->recv_callback = conn->base.recv_callback;
    version_base->user_data = conn->base.user_data;
    version_base->io_mode = conn->base.io_mode;
    version_base->time_callback = conn->base.time_callback;
}

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
    conn->config_offers_tls13 = (version == TLS_VERSION_1_3) ? 1u : 0u;
#endif

    if(noxtls_tls_context_init(&conn->base, role, version) != NOXTLS_RETURN_SUCCESS)
        return NOXTLS_RETURN_FAILED;

    return NOXTLS_RETURN_SUCCESS;
}

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

noxtls_return_t noxtls_tls_connection_set_io_callbacks(noxtls_tls_connection_t *conn,
                                                      tls_send_callback_t send_cb,
                                                      tls_recv_callback_t recv_cb,
                                                      void *user_data)
{
    if(conn == NULL) return NOXTLS_RETURN_NULL;
    return noxtls_tls_set_io_callbacks(&conn->base, send_cb, recv_cb, user_data);
}

noxtls_return_t noxtls_tls_connection_set_time_callback(noxtls_tls_connection_t *conn, tls_time_callback_t time_cb)
{
    if(conn == NULL) return NOXTLS_RETURN_NULL;
    return noxtls_tls_set_time_callback(&conn->base, time_cb);
}

noxtls_return_t noxtls_tls_connection_set_server_cert(noxtls_tls_connection_t *conn, const uint8_t *cert, uint32_t cert_len)
{
    if(conn == NULL) return NOXTLS_RETURN_NULL;
    conn->server_cert = cert;
    conn->server_cert_len = cert_len;
    return NOXTLS_RETURN_SUCCESS;
}

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

noxtls_return_t noxtls_tls_connection_set_server_private_key(noxtls_tls_connection_t *conn, void *rsa_key)
{
    if(conn == NULL) return NOXTLS_RETURN_NULL;
    conn->server_private_rsa = rsa_key;
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_tls_connection_set_server_cipher_suites(noxtls_tls_connection_t *conn,
                                                               const uint16_t *suites,
                                                               uint32_t count)
{
    if(conn == NULL) return NOXTLS_RETURN_NULL;
    conn->server_cipher_suites = suites;
    conn->server_cipher_suites_count = count;
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_tls_connection_set_server_alpn_protocols(noxtls_tls_connection_t *conn,
                                                                const char **protocols,
                                                                uint32_t count)
{
    if(conn == NULL) return NOXTLS_RETURN_NULL;
    conn->server_alpn_protocols = protocols;
    conn->server_alpn_count = count;
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_tls_connection_set_sni(noxtls_tls_connection_t *conn, const char *name, uint16_t name_len)
{
    if(conn == NULL) return NOXTLS_RETURN_NULL;
    conn->server_name = name;
    conn->server_name_len = name_len;
    return NOXTLS_RETURN_SUCCESS;
}

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
            (conn->config_offers_tls13 != 0 && tls12_wire_version == TLS_VERSION_1_2) ? 1u : 0u;
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

            if(stash_sh == NULL || stash_sh_len < 4u || ch_len < 4u || conn->u.tls13.handshake_messages == NULL) {
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
            conn->u.tls12.rfc8446_tls13_downgrade_sh_random = (conn->config_offers_tls13 != 0u) ? 1u : 0u;

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

uint16_t noxtls_tls_connection_get_version(const noxtls_tls_connection_t *conn)
{
    if(conn == NULL) return 0;
    return conn->negotiated_version;
}
