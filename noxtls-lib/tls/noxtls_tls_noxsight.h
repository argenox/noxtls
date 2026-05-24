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
* File:    noxtls_tls_noxsight.h
* Summary: TLS NoxSight Integration
*
*
*****************************************************************************/

#ifndef _NOXTLS_TLS_NOXSIGHT_H_
#define _NOXTLS_TLS_NOXSIGHT_H_

#include <stdint.h>
#include <stddef.h>
#include "noxtls_config.h"

#ifndef NOXTLS_CFG_ENABLE_NOXSIGHT
#define NOXTLS_CFG_ENABLE_NOXSIGHT 0
#endif

/* Module masks for filtering and grouping. */
#define NOXTLS_LOG_MOD_HANDSHAKE   (1U << 0)
#define NOXTLS_LOG_MOD_RECORD      (1U << 1)
#define NOXTLS_LOG_MOD_X509        (1U << 2)
#define NOXTLS_LOG_MOD_CRYPTO      (1U << 3)
#define NOXTLS_LOG_MOD_IO          (1U << 4)
#define NOXTLS_LOG_MOD_SESSION     (1U << 5)
#define NOXTLS_LOG_MOD_KEYSCHED    (1U << 6)
#define NOXTLS_LOG_MOD_ALERT       (1U << 7)

/* Module indices mapped to NoxSight module field semantics. */
typedef enum {
    NOXTLS_NS_MOD_HANDSHAKE = 0U,
    NOXTLS_NS_MOD_RECORD = 1U,
    NOXTLS_NS_MOD_X509 = 2U,
    NOXTLS_NS_MOD_CRYPTO = 3U,
    NOXTLS_NS_MOD_IO = 4U,
    NOXTLS_NS_MOD_SESSION = 5U,
    NOXTLS_NS_MOD_KEYSCHED = 6U,
    NOXTLS_NS_MOD_ALERT = 7U
} noxtls_ns_module_t;

typedef enum {
    NOXTLS_EVT_STATE_ENTER = 1,
    NOXTLS_EVT_STATE_EXIT,
    NOXTLS_EVT_CLIENT_HELLO_SENT,
    NOXTLS_EVT_SERVER_HELLO_RECV,
    NOXTLS_EVT_CERTIFICATE_RECV,
    NOXTLS_EVT_CERT_PARSE_FAIL,
    NOXTLS_EVT_CERT_VERIFY_FAIL,
    NOXTLS_EVT_ALERT_SENT,
    NOXTLS_EVT_ALERT_RECV,
    NOXTLS_EVT_KEY_SCHEDULE_STAGE,
    NOXTLS_EVT_RECORD_RX,
    NOXTLS_EVT_RECORD_TX,
    NOXTLS_EVT_DECRYPT_FAIL,
    NOXTLS_EVT_VERIFY_SIG_FAIL,
    NOXTLS_EVT_SESSION_RESUME,
    NOXTLS_EVT_INTERNAL_ERROR
} noxtls_event_id_t;

typedef enum {
    NOXTLS_STATE_START = 1,
    NOXTLS_STATE_SEND_CH,
    NOXTLS_STATE_RECV_SH,
    NOXTLS_STATE_RECV_ENC_EXT,
    NOXTLS_STATE_VERIFY_CERT,
    NOXTLS_STATE_RECV_CERT_VERIFY,
    NOXTLS_STATE_RECV_FINISHED,
    NOXTLS_STATE_KEY_SCHEDULE,
    NOXTLS_STATE_SEND_FINISHED,
    NOXTLS_STATE_CONNECTED,
    NOXTLS_STATE_ACCEPT_RECV_CH,
    NOXTLS_STATE_ACCEPT_SEND_SH,
    NOXTLS_STATE_ACCEPT_SEND_CERT,
    NOXTLS_STATE_ACCEPT_SEND_FINISHED,
    NOXTLS_STATE_ACCEPT_RECV_FINISHED,
    NOXTLS_STATE_CLOSED
} noxtls_state_id_t;

#if NOXTLS_CFG_ENABLE_NOXSIGHT
#include "../../../noxsight/noxsight.h"

/**
 * @brief Get the connection ID.
 * 
 * @param ctx_ptr The context pointer.
 * @return The connection ID.
 */
static inline uint32_t noxtls_ns_conn_id(const void *ctx_ptr)
{
    uintptr_t v = (uintptr_t)ctx_ptr;
    return (uint32_t)(v & 0xFFFFu);
}

#define NOXTLS_NS_EVENT(ctx_, module_, severity_, event_, arg0_, arg1_)                           \
    NOXSIGHT_EVENT((module_), (severity_), (event_), (uint32_t)(arg0_), (uint32_t)(arg1_),       \
                   noxtls_ns_conn_id((ctx_)))

#define NOXTLS_NS_EVENT_SENSITIVE(ctx_, module_, severity_, event_, arg0_, arg1_)                 \
    NOXSIGHT_EVENT_SENSITIVE((module_), (severity_), (event_), (uint32_t)(arg0_), (uint32_t)(arg1_), \
                             noxtls_ns_conn_id((ctx_)))

#define NOXTLS_STATE_ENTER(ctx_, state_)                                                           \
    NOXTLS_NS_EVENT((ctx_), NOXTLS_NS_MOD_HANDSHAKE, NOXSIGHT_SEVERITY_DEBUG,                     \
                    NOXTLS_EVT_STATE_ENTER, (state_), 0U)

#define NOXTLS_STATE_EXIT(ctx_, state_, result_)                                                   \
    NOXTLS_NS_EVENT((ctx_), NOXTLS_NS_MOD_HANDSHAKE,                                               \
                    ((result_) == 0 ? NOXSIGHT_SEVERITY_DEBUG : NOXSIGHT_SEVERITY_ERROR),         \
                    NOXTLS_EVT_STATE_EXIT, (state_), (uint32_t)(result_))

#else
#ifndef NOXSIGHT_SEVERITY_ERROR
#define NOXSIGHT_SEVERITY_ERROR 0U
#endif
#ifndef NOXSIGHT_SEVERITY_WARN
#define NOXSIGHT_SEVERITY_WARN 1U
#endif
#ifndef NOXSIGHT_SEVERITY_INFO
#define NOXSIGHT_SEVERITY_INFO 2U
#endif
#ifndef NOXSIGHT_SEVERITY_DEBUG
#define NOXSIGHT_SEVERITY_DEBUG 3U
#endif
#ifndef NOXSIGHT_SEVERITY_TRACE
#define NOXSIGHT_SEVERITY_TRACE 4U
#endif

#define NOXTLS_NS_EVENT(ctx_, module_, severity_, event_, arg0_, arg1_) \
    do { (void)(ctx_); (void)(module_); (void)(severity_); (void)(event_); (void)(arg0_); (void)(arg1_); } while(0)
#define NOXTLS_NS_EVENT_SENSITIVE(ctx_, module_, severity_, event_, arg0_, arg1_) \
    do { (void)(ctx_); (void)(module_); (void)(severity_); (void)(event_); (void)(arg0_); (void)(arg1_); } while(0)
#define NOXTLS_STATE_ENTER(ctx_, state_) do { (void)(ctx_); (void)(state_); } while (0)
#define NOXTLS_STATE_EXIT(ctx_, state_, result_) do { (void)(ctx_); (void)(state_); (void)(result_); } while (0)
#endif

#endif /* _NOXTLS_TLS_NOXSIGHT_H_ */
