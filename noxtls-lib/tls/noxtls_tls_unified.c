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
    if (version_base == NULL) return;
    version_base->send_callback = conn->base.send_callback;
    version_base->recv_callback = conn->base.recv_callback;
    version_base->user_data = conn->base.user_data;
    version_base->io_mode = conn->base.io_mode;
    version_base->time_callback = conn->base.time_callback;
}

noxtls_return_t noxtls_tls_connection_init(noxtls_tls_connection_t *conn, tls_role_t role)
{
    if (conn == NULL) return NOXTLS_RETURN_NULL;

    memset(conn, 0, sizeof(noxtls_tls_connection_t));
    conn->fixed_version = 0;

    if (noxtls_tls_context_init(&conn->base, role, TLS_VERSION_1_2) != NOXTLS_RETURN_SUCCESS)
        return NOXTLS_RETURN_FAILED;

    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_tls_connection_init_version(noxtls_tls_connection_t *conn, tls_role_t role, uint16_t version)
{
    if (conn == NULL) return NOXTLS_RETURN_NULL;
    if (version != TLS_VERSION_1_2 && version != TLS_VERSION_1_3) return NOXTLS_RETURN_INVALID_PARAM;

    if (version == TLS_VERSION_1_2) {
#if !NOXTLS_FEATURE_TLS12
        return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
    } else {
#if !NOXTLS_FEATURE_TLS13
        return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
    }

    memset(conn, 0, sizeof(noxtls_tls_connection_t));
    conn->fixed_version = 1;
    conn->negotiated_version = version;
    conn->is_tls13 = (version == TLS_VERSION_1_3) ? 1 : 0;

    if (noxtls_tls_context_init(&conn->base, role, version) != NOXTLS_RETURN_SUCCESS)
        return NOXTLS_RETURN_FAILED;

    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_tls_connection_free(noxtls_tls_connection_t *conn)
{
    if (conn == NULL) return NOXTLS_RETURN_NULL;

    if (conn->negotiated_version != 0) {
        if (conn->is_tls13) {
#if NOXTLS_FEATURE_TLS13
            tls13_context_free(&conn->u.tls13);
#endif
        } else {
#if NOXTLS_FEATURE_TLS12
            tls12_context_free(&conn->u.tls12);
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
    if (conn == NULL) return NOXTLS_RETURN_NULL;
    return noxtls_tls_set_io_callbacks(&conn->base, send_cb, recv_cb, user_data);
}

noxtls_return_t noxtls_tls_connection_set_time_callback(noxtls_tls_connection_t *conn, tls_time_callback_t time_cb)
{
    if (conn == NULL) return NOXTLS_RETURN_NULL;
    return noxtls_tls_set_time_callback(&conn->base, time_cb);
}

noxtls_return_t noxtls_tls_connection_set_server_cert(noxtls_tls_connection_t *conn, const uint8_t *cert, uint32_t cert_len)
{
    if (conn == NULL) return NOXTLS_RETURN_NULL;
    conn->server_cert = cert;
    conn->server_cert_len = cert_len;
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_tls_connection_set_server_private_key(noxtls_tls_connection_t *conn, void *rsa_key)
{
    if (conn == NULL) return NOXTLS_RETURN_NULL;
    conn->server_private_rsa = rsa_key;
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_tls_connection_set_sni(noxtls_tls_connection_t *conn, const char *name, uint16_t name_len)
{
    if (conn == NULL) return NOXTLS_RETURN_NULL;
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

    if (conn == NULL) return NOXTLS_RETURN_NULL;
    if (conn->base.role != TLS_ROLE_SERVER) return NOXTLS_RETURN_FAILED;
    if (conn->base.recv_callback == NULL) return NOXTLS_RETURN_FAILED;

    rc = noxtls_tls_detect_version(&conn->base, &detected_version, &client_hello_data, &client_hello_len);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    if (detected_version == TLS_VERSION_1_3) {
#if NOXTLS_FEATURE_TLS13
        conn->negotiated_version = TLS_VERSION_1_3;
        conn->is_tls13 = 1;

        rc = tls13_context_init(&conn->u.tls13, TLS_ROLE_SERVER);
        if (rc != NOXTLS_RETURN_SUCCESS) {
            if (client_hello_data) noxtls_free(client_hello_data);
            return rc;
        }

        conn->u.tls13.base.base.pending_client_hello = client_hello_data;
        conn->u.tls13.base.base.pending_client_hello_len = client_hello_len;
        unified_copy_io_to_version_context(conn, &conn->u.tls13.base.base);

        if (conn->server_cert != NULL) {
            conn->u.tls13.server_cert = (uint8_t *)conn->server_cert;
            conn->u.tls13.server_cert_len = conn->server_cert_len;
        }
        if (conn->server_private_rsa != NULL)
            tls13_set_server_private_rsa(&conn->u.tls13, conn->server_private_rsa);

        rc = tls13_accept(&conn->u.tls13);

        if (conn->u.tls13.base.base.pending_client_hello) {
            noxtls_free(conn->u.tls13.base.base.pending_client_hello);
            conn->u.tls13.base.base.pending_client_hello = NULL;
            conn->u.tls13.base.base.pending_client_hello_len = 0;
        }

        if (rc != NOXTLS_RETURN_SUCCESS) {
            tls13_context_free(&conn->u.tls13);
            conn->negotiated_version = 0;
            conn->is_tls13 = 0;
        }
        return rc;
#else
        if (client_hello_data) noxtls_free(client_hello_data);
        return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
    }

    /* TLS 1.2 (and treat 1.0/1.1 as 1.2 for unified API) */
#if NOXTLS_FEATURE_TLS12
    conn->negotiated_version = TLS_VERSION_1_2;
    conn->is_tls13 = 0;

    rc = tls12_context_init(&conn->u.tls12, TLS_ROLE_SERVER);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        if (client_hello_data) noxtls_free(client_hello_data);
        return rc;
    }

    conn->u.tls12.base.base.pending_client_hello = client_hello_data;
    conn->u.tls12.base.base.pending_client_hello_len = client_hello_len;
    unified_copy_io_to_version_context(conn, &conn->u.tls12.base.base);

    if (conn->server_cert != NULL) {
        conn->u.tls12.server_cert = (uint8_t *)conn->server_cert;
        conn->u.tls12.server_cert_len = conn->server_cert_len;
    }
    if (conn->server_private_rsa != NULL)
        tls12_set_server_private_rsa(&conn->u.tls12, conn->server_private_rsa);

    rc = tls12_accept(&conn->u.tls12);

    if (conn->u.tls12.base.base.pending_client_hello) {
        noxtls_free(conn->u.tls12.base.base.pending_client_hello);
        conn->u.tls12.base.base.pending_client_hello = NULL;
        conn->u.tls12.base.base.pending_client_hello_len = 0;
    }

    if (rc != NOXTLS_RETURN_SUCCESS) {
        tls12_context_free(&conn->u.tls12);
        conn->negotiated_version = 0;
    }
    return rc;
#else
    if (client_hello_data) noxtls_free(client_hello_data);
    return NOXTLS_RETURN_NOT_SUPPORTED;
#endif
}

noxtls_return_t noxtls_tls_connection_connect(noxtls_tls_connection_t *conn)
{
    noxtls_return_t rc;

    if (conn == NULL) return NOXTLS_RETURN_NULL;
    if (conn->base.role != TLS_ROLE_CLIENT) return NOXTLS_RETURN_FAILED;
    if (conn->base.recv_callback == NULL || conn->base.send_callback == NULL) return NOXTLS_RETURN_FAILED;

    if (conn->fixed_version) {
        if (conn->is_tls13) {
#if NOXTLS_FEATURE_TLS13
            rc = tls13_context_init(&conn->u.tls13, TLS_ROLE_CLIENT);
            if (rc != NOXTLS_RETURN_SUCCESS) return rc;
            unified_copy_io_to_version_context(conn, &conn->u.tls13.base.base);
            if (conn->server_name != NULL) {
                conn->u.tls13.server_name = conn->server_name;
                conn->u.tls13.server_name_len = conn->server_name_len;
            }
            return tls13_connect(&conn->u.tls13);
#endif
        } else {
#if NOXTLS_FEATURE_TLS12
            rc = tls12_context_init(&conn->u.tls12, TLS_ROLE_CLIENT);
            if (rc != NOXTLS_RETURN_SUCCESS) return rc;
            unified_copy_io_to_version_context(conn, &conn->u.tls12.base.base);
            if (conn->server_name != NULL) {
                conn->u.tls12.server_name = conn->server_name;
                conn->u.tls12.server_name_len = conn->server_name_len;
            }
            return tls12_connect(&conn->u.tls12);
#endif
        }
    }

    /* Auto: try TLS 1.3 first, then TLS 1.2 */
#if NOXTLS_FEATURE_TLS13
    rc = tls13_context_init(&conn->u.tls13, TLS_ROLE_CLIENT);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        unified_copy_io_to_version_context(conn, &conn->u.tls13.base.base);
        if (conn->server_name != NULL) {
            conn->u.tls13.server_name = conn->server_name;
            conn->u.tls13.server_name_len = conn->server_name_len;
        }
        rc = tls13_connect(&conn->u.tls13);
        if (rc == NOXTLS_RETURN_SUCCESS) {
            conn->negotiated_version = TLS_VERSION_1_3;
            conn->is_tls13 = 1;
            return NOXTLS_RETURN_SUCCESS;
        }
        tls13_context_free(&conn->u.tls13);
    }
#endif

#if NOXTLS_FEATURE_TLS12
    rc = tls12_context_init(&conn->u.tls12, TLS_ROLE_CLIENT);
    if (rc != NOXTLS_RETURN_SUCCESS) return rc;
    unified_copy_io_to_version_context(conn, &conn->u.tls12.base.base);
    if (conn->server_name != NULL) {
        conn->u.tls12.server_name = conn->server_name;
        conn->u.tls12.server_name_len = conn->server_name_len;
    }
    rc = tls12_connect(&conn->u.tls12);
    if (rc == NOXTLS_RETURN_SUCCESS) {
        conn->negotiated_version = TLS_VERSION_1_2;
        conn->is_tls13 = 0;
        return NOXTLS_RETURN_SUCCESS;
    }
    tls12_context_free(&conn->u.tls12);
    return rc;
#else
    return NOXTLS_RETURN_FAILED;
#endif
}

noxtls_return_t noxtls_tls_connection_send(noxtls_tls_connection_t *conn, const uint8_t *data, uint32_t len)
{
    if (conn == NULL || data == NULL) return NOXTLS_RETURN_NULL;
    if (conn->negotiated_version == 0) return NOXTLS_RETURN_FAILED;

    if (conn->is_tls13) {
#if NOXTLS_FEATURE_TLS13
        return tls13_send(&conn->u.tls13, data, len);
#else
        return NOXTLS_RETURN_FAILED;
#endif
    } else {
#if NOXTLS_FEATURE_TLS12
        return tls12_send(&conn->u.tls12, data, len);
#else
        return NOXTLS_RETURN_FAILED;
#endif
    }
}

noxtls_return_t noxtls_tls_connection_recv(noxtls_tls_connection_t *conn, uint8_t *buf, uint32_t *len)
{
    if (conn == NULL || buf == NULL || len == NULL) return NOXTLS_RETURN_NULL;
    if (conn->negotiated_version == 0) return NOXTLS_RETURN_FAILED;

    if (conn->is_tls13) {
#if NOXTLS_FEATURE_TLS13
        return tls13_recv(&conn->u.tls13, buf, len);
#else
        return NOXTLS_RETURN_FAILED;
#endif
    } else {
#if NOXTLS_FEATURE_TLS12
        return tls12_recv(&conn->u.tls12, buf, len);
#else
        return NOXTLS_RETURN_FAILED;
#endif
    }
}

noxtls_return_t noxtls_tls_connection_close(noxtls_tls_connection_t *conn)
{
    if (conn == NULL) return NOXTLS_RETURN_NULL;
    if (conn->negotiated_version == 0) return NOXTLS_RETURN_FAILED;

    if (conn->is_tls13) {
#if NOXTLS_FEATURE_TLS13
        return tls13_close(&conn->u.tls13);
#else
        return NOXTLS_RETURN_FAILED;
#endif
    } else {
#if NOXTLS_FEATURE_TLS12
        return tls12_close(&conn->u.tls12);
#else
        return NOXTLS_RETURN_FAILED;
#endif
    }
}

uint16_t noxtls_tls_connection_get_version(const noxtls_tls_connection_t *conn)
{
    if (conn == NULL) return 0;
    return conn->negotiated_version;
}
