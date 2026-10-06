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

#ifndef NOXTLS_TLS_NOXSIGHT_H_
#define NOXTLS_TLS_NOXSIGHT_H_

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

/* Module indices mapped to NoxSight module field semantics (unsigned for Rule 10.3). */
typedef uint32_t noxtls_ns_module_t;
#define NOXTLS_NS_MOD_HANDSHAKE ((noxtls_ns_module_t)0U)
#define NOXTLS_NS_MOD_RECORD    ((noxtls_ns_module_t)1U)
#define NOXTLS_NS_MOD_X509      ((noxtls_ns_module_t)2U)
#define NOXTLS_NS_MOD_CRYPTO    ((noxtls_ns_module_t)3U)
#define NOXTLS_NS_MOD_IO        ((noxtls_ns_module_t)4U)
#define NOXTLS_NS_MOD_SESSION   ((noxtls_ns_module_t)5U)
#define NOXTLS_NS_MOD_KEYSCHED  ((noxtls_ns_module_t)6U)
#define NOXTLS_NS_MOD_ALERT     ((noxtls_ns_module_t)7U)

typedef uint32_t noxtls_event_id_t;
#define NOXTLS_EVT_STATE_ENTER         ((noxtls_event_id_t)1U)
#define NOXTLS_EVT_STATE_EXIT          ((noxtls_event_id_t)2U)
#define NOXTLS_EVT_CLIENT_HELLO_SENT   ((noxtls_event_id_t)3U)
#define NOXTLS_EVT_SERVER_HELLO_RECV   ((noxtls_event_id_t)4U)
#define NOXTLS_EVT_CERTIFICATE_RECV    ((noxtls_event_id_t)5U)
#define NOXTLS_EVT_CERT_PARSE_FAIL     ((noxtls_event_id_t)6U)
#define NOXTLS_EVT_CERT_VERIFY_FAIL    ((noxtls_event_id_t)7U)
#define NOXTLS_EVT_ALERT_SENT          ((noxtls_event_id_t)8U)
#define NOXTLS_EVT_ALERT_RECV          ((noxtls_event_id_t)9U)
#define NOXTLS_EVT_KEY_SCHEDULE_STAGE  ((noxtls_event_id_t)10U)
#define NOXTLS_EVT_RECORD_RX           ((noxtls_event_id_t)11U)
#define NOXTLS_EVT_RECORD_TX           ((noxtls_event_id_t)12U)
#define NOXTLS_EVT_DECRYPT_FAIL        ((noxtls_event_id_t)13U)
#define NOXTLS_EVT_VERIFY_SIG_FAIL     ((noxtls_event_id_t)14U)
#define NOXTLS_EVT_SESSION_RESUME      ((noxtls_event_id_t)15U)
#define NOXTLS_EVT_INTERNAL_ERROR      ((noxtls_event_id_t)16U)

typedef uint32_t noxtls_state_id_t;
#define NOXTLS_STATE_START                 ((noxtls_state_id_t)1U)
#define NOXTLS_STATE_SEND_CH               ((noxtls_state_id_t)2U)
#define NOXTLS_STATE_RECV_SH               ((noxtls_state_id_t)3U)
#define NOXTLS_STATE_RECV_ENC_EXT          ((noxtls_state_id_t)4U)
#define NOXTLS_STATE_VERIFY_CERT           ((noxtls_state_id_t)5U)
#define NOXTLS_STATE_RECV_CERT_VERIFY      ((noxtls_state_id_t)6U)
#define NOXTLS_STATE_RECV_FINISHED         ((noxtls_state_id_t)7U)
#define NOXTLS_STATE_KEY_SCHEDULE          ((noxtls_state_id_t)8U)
#define NOXTLS_STATE_SEND_FINISHED         ((noxtls_state_id_t)9U)
#define NOXTLS_STATE_CONNECTED             ((noxtls_state_id_t)10U)
#define NOXTLS_STATE_ACCEPT_RECV_CH        ((noxtls_state_id_t)11U)
#define NOXTLS_STATE_ACCEPT_SEND_SH        ((noxtls_state_id_t)12U)
#define NOXTLS_STATE_ACCEPT_SEND_CERT      ((noxtls_state_id_t)13U)
#define NOXTLS_STATE_ACCEPT_SEND_FINISHED  ((noxtls_state_id_t)14U)
#define NOXTLS_STATE_ACCEPT_RECV_FINISHED  ((noxtls_state_id_t)15U)
#define NOXTLS_STATE_CLOSED                ((noxtls_state_id_t)16U)

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

static inline void noxtls_ns_event_stub(const void *ctx_, noxtls_ns_module_t module_, uint32_t severity_,
                                         noxtls_event_id_t event_, uint32_t arg0_, uint32_t arg1_)
{
    (void)ctx_;
    (void)module_;
    (void)severity_;
    (void)event_;
    (void)arg0_;
    (void)arg1_;
}

#define NOXTLS_NS_EVENT(ctx_, module_, severity_, event_, arg0_, arg1_) \
    noxtls_ns_event_stub((ctx_), (module_), (severity_), (event_), (uint32_t)(arg0_), (uint32_t)(arg1_))
#define NOXTLS_NS_EVENT_SENSITIVE(ctx_, module_, severity_, event_, arg0_, arg1_) \
    NOXTLS_NS_EVENT((ctx_), (module_), (severity_), (event_), (arg0_), (arg1_))
#define NOXTLS_STATE_ENTER(ctx_, state_) \
    NOXTLS_NS_EVENT((ctx_), NOXTLS_NS_MOD_HANDSHAKE, NOXSIGHT_SEVERITY_DEBUG, \
                    NOXTLS_EVT_STATE_ENTER, (uint32_t)(state_), 0U)
#define NOXTLS_STATE_EXIT(ctx_, state_, result_) \
    NOXTLS_NS_EVENT((ctx_), NOXTLS_NS_MOD_HANDSHAKE, NOXSIGHT_SEVERITY_DEBUG, \
                    NOXTLS_EVT_STATE_EXIT, (uint32_t)(state_), (uint32_t)(result_))
#endif

#endif /* NOXTLS_TLS_NOXSIGHT_H_ */
