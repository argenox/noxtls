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
* File:    main.c
* Summary: DTLS PSK Demo Application
* Demonstrates DTLS with Pre-Shared Key (PSK) authentication
*
*/

/**
 * @file main.c
 * @brief DTLS 1.2/1.3 PSK handshake demo.
 * @defgroup noxtls_app_dtls_psk_demo DTLS PSK demo
 * @details
 * Runs an in-process DTLS server and client with PSK. Optional arguments:
 * --chacha use ChaCha20-Poly1305; --aes use AES-GCM; 1.2 or 12 for DTLS 1.2;
 * 1.3 or 13 for DTLS 1.3. Default is AES-GCM and DTLS 1.2.
 * @example
 * dtls_psk_demo
 * dtls_psk_demo 1.3
 * dtls_psk_demo --chacha 1.2
 * dtls_psk_demo --aes 1.3
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
#else
#include <pthread.h>
#endif

#include "noxtls-lib/common/noxtls_memory.h"
#include "noxtls-lib/common/noxtls_memory_compat.h"
#include "noxtls_common.h"
#include "noxtls-lib/tls/noxtls_tls_common.h"
#include "noxtls-lib/tls/noxtls_dtls_common.h"
#include "noxtls-lib/tls/noxtls_tls13.h"
#include "noxtls-lib/tls/noxtls_tls12.h"
#include "noxtls-lib/mdigest/sha256/noxtls_sha256.h"
#include "noxtls-lib/mdigest/noxtls_hash.h"
#include "noxtls-lib/drbg/noxtls_drbg.h"

/* DTLS PSK Identity and Key (for demo purposes) */
#define DTLS_PSK_IDENTITY     "test-identity"
#define DTLS_PSK_KEY        "test-key-12345"
#define DTLS_PSK_KEY_LEN    15

/* Server certificate for full DTLS 1.2 handshake (from data/certs when built with cert source) */
#ifdef DTLS12_DEMO_USE_CERT_DATA
extern unsigned char ______certs_server__server_der[];
extern unsigned int ______certs_server__server_der_len;
#endif

/* Network Buffer for UDP Simulation */
typedef struct
{
    uint8_t *data;
    uint32_t len;
    uint32_t capacity;
} udp_buffer_t;

typedef struct
{
    udp_buffer_t server_to_client;
    udp_buffer_t client_to_server;
} udp_connection_t;

/* Thread-safe network for full DTLS 1.2 (client and server in separate threads) */
#if defined(_WIN32) || defined(_WIN64)
typedef struct
{
    udp_connection_t net;
    CRITICAL_SECTION cs;
    CONDITION_VARIABLE cv_client_to_server;
    CONDITION_VARIABLE cv_server_to_client;
} thread_safe_udp_t;
#else
typedef struct
{
    udp_connection_t net;
    pthread_mutex_t mutex;
    pthread_cond_t cond_client_to_server;
    pthread_cond_t cond_server_to_client;
} thread_safe_udp_t;
#endif

/* Initialize UDP buffer */
static void udp_buffer_init(udp_buffer_t *buf)
{
    buf->data = NULL;
    buf->len = 0;
    buf->capacity = 0;
}

/* Append data to UDP buffer */
static noxtls_return_t udp_buffer_append(udp_buffer_t *buf, const uint8_t *data, uint32_t len)
{
    if(buf == NULL || data == NULL)
    {
        return NOXTLS_RETURN_NULL;
    }
    
    if(buf->capacity < buf->len + len)
    {
        uint32_t new_capacity = (buf->len + len) * 2;
        if(new_capacity < 4096) new_capacity = 4096;
        
        uint8_t *new_data = (uint8_t*)noxtls_realloc(buf->data, new_capacity);
        if(new_data == NULL)
        {
            return NOXTLS_RETURN_FAILED;
        }
        buf->data = new_data;
        buf->capacity = new_capacity;
    }
    
    memcpy(buf->data + buf->len, data, len);
    buf->len += len;
    return NOXTLS_RETURN_SUCCESS;
}

/* Read data from UDP buffer (reads entire datagram) */
static int32_t udp_buffer_read(udp_buffer_t *buf, uint8_t *data, uint32_t len)
{
    if(buf == NULL || data == NULL)
    {
        return -1;
    }
    
    if(buf->len == 0)
    {
        return 0;  /* No data available */
    }
    
    /* UDP reads entire datagram at once */
    uint32_t to_read = (len < buf->len) ? len : buf->len;
    memcpy(data, buf->data, to_read);
    
    /* Clear buffer after reading */
    buf->len = 0;
    
    return (int32_t)to_read;
}

/* Free UDP buffer */
static void udp_buffer_free(udp_buffer_t *buf)
{
    if(buf && buf->data)
    {
        noxtls_free(buf->data);
        buf->data = NULL;
    }
    if(buf)
    {
        buf->len = 0;
        buf->capacity = 0;
    }
}

/* Server send callback */
static int32_t server_send_callback(void *user_data, const uint8_t *data, uint32_t len)
{
    udp_connection_t *conn = (udp_connection_t*)user_data;
    if(conn == NULL || data == NULL)
    {
        return -1;
    }
    
    if(udp_buffer_append(&conn->server_to_client, data, len) != NOXTLS_RETURN_SUCCESS)
    {
        return -1;
    }
    
    return (int32_t)len;
}

/* Server receive callback */
static int32_t server_recv_callback(void *user_data, uint8_t *data, uint32_t len)
{
    udp_connection_t *conn = (udp_connection_t*)user_data;
    if(conn == NULL || data == NULL)
    {
        return -1;
    }
    
    return udp_buffer_read(&conn->client_to_server, data, len);
}

/* Client send callback */
static int32_t client_send_callback(void *user_data, const uint8_t *data, uint32_t len)
{
    udp_connection_t *conn = (udp_connection_t*)user_data;
    if(conn == NULL || data == NULL)
    {
        return -1;
    }
    
    if(udp_buffer_append(&conn->client_to_server, data, len) != NOXTLS_RETURN_SUCCESS)
    {
        return -1;
    }
    
    return (int32_t)len;
}

/* Client receive callback */
static int32_t client_recv_callback(void *user_data, uint8_t *data, uint32_t len)
{
    udp_connection_t *conn = (udp_connection_t*)user_data;
    if(conn == NULL || data == NULL)
    {
        return -1;
    }
    
    return udp_buffer_read(&conn->server_to_client, data, len);
}

/* User data for thread-safe full DTLS 1.2 callbacks */
typedef struct
{
    thread_safe_udp_t *ts;
    int is_client;  /* 1 = client, 0 = server */
} ts_io_user_data_t;

/* Thread-safe client send: append to client_to_server, signal server */
static int32_t client_send_ts_callback(void *user_data, const uint8_t *data, uint32_t len)
{
    ts_io_user_data_t *ud = (ts_io_user_data_t*)user_data;
    if(ud == NULL || ud->ts == NULL || data == NULL || !ud->is_client)
        return -1;
    thread_safe_udp_t *ts = ud->ts;
#if defined(_WIN32) || defined(_WIN64)
    EnterCriticalSection(&ts->cs);
    if(udp_buffer_append(&ts->net.client_to_server, data, len) != NOXTLS_RETURN_SUCCESS) {
        LeaveCriticalSection(&ts->cs);
        return -1;
    }
    WakeConditionVariable(&ts->cv_client_to_server);
    LeaveCriticalSection(&ts->cs);
#else
    pthread_mutex_lock(&ts->mutex);
    if(udp_buffer_append(&ts->net.client_to_server, data, len) != NOXTLS_RETURN_SUCCESS) {
        pthread_mutex_unlock(&ts->mutex);
        return -1;
    }
    pthread_cond_signal(&ts->cond_client_to_server);
    pthread_mutex_unlock(&ts->mutex);
#endif
    return (int32_t)len;
}

/* Thread-safe client recv: wait for server_to_client, then read */
static int32_t client_recv_ts_callback(void *user_data, uint8_t *data, uint32_t len)
{
    ts_io_user_data_t *ud = (ts_io_user_data_t*)user_data;
    if(ud == NULL || ud->ts == NULL || data == NULL || !ud->is_client)
        return -1;
    thread_safe_udp_t *ts = ud->ts;
    int32_t ret;
#if defined(_WIN32) || defined(_WIN64)
    EnterCriticalSection(&ts->cs);
    while(ts->net.server_to_client.len == 0)
        SleepConditionVariableCS(&ts->cv_server_to_client, &ts->cs, INFINITE);
    ret = udp_buffer_read(&ts->net.server_to_client, data, len);
    LeaveCriticalSection(&ts->cs);
#else
    pthread_mutex_lock(&ts->mutex);
    while(ts->net.server_to_client.len == 0)
        pthread_cond_wait(&ts->cond_server_to_client, &ts->mutex);
    ret = udp_buffer_read(&ts->net.server_to_client, data, len);
    pthread_mutex_unlock(&ts->mutex);
#endif
    return ret;
}

/* Thread-safe server send: append to server_to_client, signal client */
static int32_t server_send_ts_callback(void *user_data, const uint8_t *data, uint32_t len)
{
    ts_io_user_data_t *ud = (ts_io_user_data_t*)user_data;
    if(ud == NULL || ud->ts == NULL || data == NULL || ud->is_client)
        return -1;
    thread_safe_udp_t *ts = ud->ts;
#if defined(_WIN32) || defined(_WIN64)
    EnterCriticalSection(&ts->cs);
    if(udp_buffer_append(&ts->net.server_to_client, data, len) != NOXTLS_RETURN_SUCCESS) {
        LeaveCriticalSection(&ts->cs);
        return -1;
    }
    WakeConditionVariable(&ts->cv_server_to_client);
    LeaveCriticalSection(&ts->cs);
#else
    pthread_mutex_lock(&ts->mutex);
    if(udp_buffer_append(&ts->net.server_to_client, data, len) != NOXTLS_RETURN_SUCCESS) {
        pthread_mutex_unlock(&ts->mutex);
        return -1;
    }
    pthread_cond_signal(&ts->cond_server_to_client);
    pthread_mutex_unlock(&ts->mutex);
#endif
    return (int32_t)len;
}

/* Thread-safe server recv: wait for client_to_server, then read */
static int32_t server_recv_ts_callback(void *user_data, uint8_t *data, uint32_t len)
{
    ts_io_user_data_t *ud = (ts_io_user_data_t*)user_data;
    if(ud == NULL || ud->ts == NULL || data == NULL || ud->is_client)
        return -1;
    thread_safe_udp_t *ts = ud->ts;
    int32_t ret;
#if defined(_WIN32) || defined(_WIN64)
    EnterCriticalSection(&ts->cs);
    while(ts->net.client_to_server.len == 0)
        SleepConditionVariableCS(&ts->cv_client_to_server, &ts->cs, INFINITE);
    ret = udp_buffer_read(&ts->net.client_to_server, data, len);
    LeaveCriticalSection(&ts->cs);
#else
    pthread_mutex_lock(&ts->mutex);
    while(ts->net.client_to_server.len == 0)
        pthread_cond_wait(&ts->cond_client_to_server, &ts->mutex);
    ret = udp_buffer_read(&ts->net.client_to_server, data, len);
    pthread_mutex_unlock(&ts->mutex);
#endif
    return ret;
}

/* Generate PSK key from identity (simplified - in real implementation, use proper key derivation) */
static noxtls_return_t dtls_psk_get_key(const char *identity, uint8_t *key, uint32_t *key_len)
{
    if(identity == NULL || key == NULL || key_len == NULL)
    {
        return NOXTLS_RETURN_NULL;
    }
    
    /* For demo: use fixed PSK key */
    if(strcmp(identity, DTLS_PSK_IDENTITY) == 0)
    {
        if(*key_len < DTLS_PSK_KEY_LEN)
        {
            return NOXTLS_RETURN_FAILED;
        }
        memcpy(key, DTLS_PSK_KEY, DTLS_PSK_KEY_LEN);
        *key_len = DTLS_PSK_KEY_LEN;
        return NOXTLS_RETURN_SUCCESS;
    }
    
    return NOXTLS_RETURN_FAILED;
}

/* Print hex data */
static void print_hex(const uint8_t *data, uint32_t len)
{
    uint32_t i;
    for(i = 0; i < len; i++)
    {
        printf("%02x", data[i]);
        if(((i + 1) & 15) == 0) printf("\n");
        else if((i + 1) % 8 == 0) printf(" ");
    }
    if((len & 15) != 0) printf("\n");
}

static noxtls_return_t dtls_roundtrip_record(dtls_context_t *sender,
                                             dtls_context_t *receiver,
                                             uint8_t type,
                                             const uint8_t *payload,
                                             uint32_t payload_len,
                                             const char *label)
{
    dtls_record_t record;
    noxtls_return_t rc;

    printf("[DTLS] Sending %s (%u bytes)\n", label, payload_len);
    rc = noxtls_dtls_send_record(sender, type, payload, payload_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("ERROR: Failed to send %s record (%d)\n", label, rc);
        return rc;
    }

    rc = noxtls_dtls_recv_record(receiver, &record);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("ERROR: Failed to receive %s record (%d)\n", label, rc);
        return rc;
    }

    if(record.type != type || record.length != payload_len ||
       (payload_len > 0 && memcmp(record.data, payload, payload_len) != 0)) {
        printf("ERROR: %s record mismatch\n", label);
        if(record.data) {
            noxtls_free(record.data);
        }
        return NOXTLS_RETURN_FAILED;
    }

    if(record.data) {
        noxtls_free(record.data);
    }

    printf("[DTLS] %s received OK\n", label);
    return NOXTLS_RETURN_SUCCESS;
}

static noxtls_return_t dtls_handshake_exchange(dtls_context_t *client,
                                               dtls_context_t *server,
                                               uint8_t msg_type,
                                               uint16_t message_seq,
                                               const uint8_t *payload,
                                               uint32_t payload_len,
                                               const char *label)
{
    dtls_handshake_fragment_t fragment;
    uint8_t *complete_msg = NULL;
    uint32_t complete_len = 0;
    noxtls_return_t rc;

    printf("[DTLS] Sending %s handshake (%u bytes)\n", label, payload_len);
    rc = dtls_send_handshake_fragment(client, msg_type,
                                      payload, payload_len, message_seq);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("ERROR: Failed to send %s handshake (%d)\n", label, rc);
        return rc;
    }

    rc = noxtls_dtls_recv_handshake_fragment(server, &fragment);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("ERROR: Failed to receive %s handshake (%d)\n", label, rc);
        return rc;
    }

    rc = noxtls_dtls_reassemble_handshake(server, &fragment, &complete_msg, &complete_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("ERROR: Failed to reassemble %s handshake (%d)\n", label, rc);
        if(fragment.data) {
            noxtls_free(fragment.data);
        }
        return rc;
    }

    if(complete_msg != NULL) {
        printf("[DTLS] %s handshake reassembled (%u bytes)\n", label, complete_len);
        noxtls_free(complete_msg);
    }

    if(fragment.data) {
        noxtls_free(fragment.data);
    }

    return NOXTLS_RETURN_SUCCESS;
}

#ifdef DTLS12_DEMO_USE_CERT_DATA
/* Full DTLS 1.2 handshake (ECDHE + server cert): client and server thread args */
typedef struct
{
    thread_safe_udp_t *ts;
    noxtls_return_t rc;
} dtls12_thread_args_t;

#if defined(_WIN32) || defined(_WIN64)
static DWORD WINAPI dtls12_client_thread_fn(LPVOID arg)
#else
static void *dtls12_client_thread_fn(void *arg)
#endif
{
    dtls12_thread_args_t *args = (dtls12_thread_args_t*)arg;
    thread_safe_udp_t *ts = args->ts;
    ts_io_user_data_t client_io = { ts, 1 };
    tls12_context_t ctx;
    const char *msg = "Hello from DTLS 1.2 client";
    uint8_t recv_buf[256];
    uint32_t recv_len;
    noxtls_return_t rc;

    args->rc = noxtls_dtls12_context_init(&ctx, TLS_ROLE_CLIENT);
    if(args->rc != NOXTLS_RETURN_SUCCESS)
#if defined(_WIN32) || defined(_WIN64)
        return 0;
#else
        return NULL;
#endif
    rc = noxtls_tls_set_io_callbacks(&ctx.base.base, client_send_ts_callback, client_recv_ts_callback, &client_io);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_tls12_context_free(&ctx);
        args->rc = rc;
#if defined(_WIN32) || defined(_WIN64)
        return 0;
#else
        return NULL;
#endif
    }
    rc = noxtls_tls12_connect(&ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_tls12_context_free(&ctx);
        args->rc = rc;
#if defined(_WIN32) || defined(_WIN64)
        return 0;
#else
        return NULL;
#endif
    }
    printf("[Client] DTLS 1.2 handshake complete (ClientHello -> ... -> Finished).\n");
    rc = noxtls_tls12_send(&ctx, (const uint8_t*)msg, (uint32_t)strlen(msg));
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_tls12_context_free(&ctx);
        args->rc = rc;
#if defined(_WIN32) || defined(_WIN64)
        return 0;
#else
        return NULL;
#endif
    }
    recv_len = sizeof(recv_buf);
    rc = noxtls_tls12_recv(&ctx, recv_buf, &recv_len);
    noxtls_tls12_context_free(&ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        args->rc = rc;
#if defined(_WIN32) || defined(_WIN64)
        return 0;
#else
        return NULL;
#endif
    }
    printf("[Client] Received encrypted app data: %.*s\n", (int)recv_len, (char*)recv_buf);
    args->rc = NOXTLS_RETURN_SUCCESS;
#if defined(_WIN32) || defined(_WIN64)
    return 0;
#else
    return NULL;
#endif
}

#if defined(_WIN32) || defined(_WIN64)
static DWORD WINAPI dtls12_server_thread_fn(LPVOID arg)
#else
static void *dtls12_server_thread_fn(void *arg)
#endif
{
    dtls12_thread_args_t *args = (dtls12_thread_args_t*)arg;
    thread_safe_udp_t *ts = args->ts;
    ts_io_user_data_t server_io = { ts, 0 };
    tls12_context_t ctx;
    uint8_t recv_buf[256];
    uint32_t recv_len;
    const char *reply = "Hello from DTLS 1.2 server";
    noxtls_return_t rc;

    args->rc = noxtls_dtls12_context_init(&ctx, TLS_ROLE_SERVER);
    if(args->rc != NOXTLS_RETURN_SUCCESS)
#if defined(_WIN32) || defined(_WIN64)
        return 0;
#else
        return NULL;
#endif
    ctx.server_cert = ______certs_server__server_der;
    ctx.server_cert_len = ______certs_server__server_der_len;
    rc = noxtls_tls_set_io_callbacks(&ctx.base.base, server_send_ts_callback, server_recv_ts_callback, &server_io);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_tls12_context_free(&ctx);
        args->rc = rc;
#if defined(_WIN32) || defined(_WIN64)
        return 0;
#else
        return NULL;
#endif
    }
    rc = noxtls_tls12_accept(&ctx);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_tls12_context_free(&ctx);
        args->rc = rc;
#if defined(_WIN32) || defined(_WIN64)
        return 0;
#else
        return NULL;
#endif
    }
    printf("[Server] DTLS 1.2 handshake complete (ClientHello, HelloVerifyRequest?, ServerHello, Certificate, ServerKeyExchange, ServerHelloDone, ClientKeyExchange, CCS, Finished, CCS, Finished).\n");
    recv_len = sizeof(recv_buf);
    rc = noxtls_tls12_recv(&ctx, recv_buf, &recv_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_tls12_context_free(&ctx);
        args->rc = rc;
#if defined(_WIN32) || defined(_WIN64)
        return 0;
#else
        return NULL;
#endif
    }
    printf("[Server] Received encrypted app data: %.*s\n", (int)recv_len, (char*)recv_buf);
    rc = noxtls_tls12_send(&ctx, (const uint8_t*)reply, (uint32_t)strlen(reply));
    noxtls_tls12_context_free(&ctx);
    args->rc = rc;
#if defined(_WIN32) || defined(_WIN64)
    return 0;
#else
    return NULL;
#endif
}
#endif

/* DTLS 1.2 Handshake Demo: full handshake when cert data available, else simplified */
static noxtls_return_t dtls12_psk_handshake_demo(udp_connection_t *network)
{
    (void)network;
    printf("========================================\n");
    printf("DTLS 1.2 Handshake Demo\n");
    printf("========================================\n\n");

#ifdef DTLS12_DEMO_USE_CERT_DATA
    {
        thread_safe_udp_t ts;
        dtls12_thread_args_t client_args = { &ts, NOXTLS_RETURN_FAILED };
        dtls12_thread_args_t server_args = { &ts, NOXTLS_RETURN_FAILED };
        noxtls_return_t rc;
#if defined(_WIN32) || defined(_WIN64)
        HANDLE th_client;
        HANDLE th_server;
        InitializeCriticalSection(&ts.cs);
        InitializeConditionVariable(&ts.cv_client_to_server);
        InitializeConditionVariable(&ts.cv_server_to_client);
#else
        pthread_t th_client;
        pthread_t th_server;
        pthread_mutex_init(&ts.mutex, NULL);
        pthread_cond_init(&ts.cond_client_to_server, NULL);
        pthread_cond_init(&ts.cond_server_to_client, NULL);
#endif
        udp_buffer_init(&ts.net.server_to_client);
        udp_buffer_init(&ts.net.client_to_server);

        printf("Running full DTLS 1.2 handshake (ECDHE + server certificate):\n");
        printf("  ClientHello, (optional HelloVerifyRequest), ServerHello, Certificate,\n");
        printf("  Server Key Exchange, Server Hello Done, Client Key Exchange,\n");
        printf("  Change Cipher Spec, Finished (both sides), then encrypted app data.\n\n");

#if defined(_WIN32) || defined(_WIN64)
        th_server = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)dtls12_server_thread_fn, &server_args, 0, NULL);
        th_client = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)dtls12_client_thread_fn, &client_args, 0, NULL);
        if(!th_server || !th_client) {
            printf("ERROR: CreateThread failed\n");
            rc = NOXTLS_RETURN_FAILED;
        } else {
            WaitForSingleObject(th_server, INFINITE);
            WaitForSingleObject(th_client, INFINITE);
            CloseHandle(th_server);
            CloseHandle(th_client);
            rc = (server_args.rc == NOXTLS_RETURN_SUCCESS && client_args.rc == NOXTLS_RETURN_SUCCESS)
                 ? NOXTLS_RETURN_SUCCESS : NOXTLS_RETURN_FAILED;
        }
#else
        if(pthread_create(&th_server, NULL, (void*(*)(void*))dtls12_server_thread_fn, &server_args) != 0 ||
           pthread_create(&th_client, NULL, (void*(*)(void*))dtls12_client_thread_fn, &client_args) != 0) {
            printf("ERROR: pthread_create failed\n");
            rc = NOXTLS_RETURN_FAILED;
        } else {
            pthread_join(th_server, NULL);
            pthread_join(th_client, NULL);
            rc = (server_args.rc == NOXTLS_RETURN_SUCCESS && client_args.rc == NOXTLS_RETURN_SUCCESS)
                 ? NOXTLS_RETURN_SUCCESS : NOXTLS_RETURN_FAILED;
        }
#endif
        udp_buffer_free(&ts.net.server_to_client);
        udp_buffer_free(&ts.net.client_to_server);
#if defined(_WIN32) || defined(_WIN64)
        DeleteCriticalSection(&ts.cs);
#else
        pthread_mutex_destroy(&ts.mutex);
        pthread_cond_destroy(&ts.cond_client_to_server);
        pthread_cond_destroy(&ts.cond_server_to_client);
#endif
        if(rc != NOXTLS_RETURN_SUCCESS) {
            printf("ERROR: Full DTLS 1.2 handshake failed (client=%d server=%d)\n", client_args.rc, server_args.rc);
            return rc;
        }
        printf("\nDTLS 1.2 complete handshake and encrypted application data exchange succeeded.\n\n");
        return NOXTLS_RETURN_SUCCESS;
    }
#else
    printf("PSK Configuration (simplified flow; no cert data linked):\n");
    printf("  Identity: %s\n", DTLS_PSK_IDENTITY);
    printf("  Key: %s\n", DTLS_PSK_KEY);
    printf("\n");
    printf("  Identity: %s\n", DTLS_PSK_IDENTITY);
    printf("  Key: %s\n", DTLS_PSK_KEY);
    printf("\n");
    
    dtls_context_t client_ctx;
    dtls_context_t server_ctx;
    uint8_t client_hello[] = "CLIENT_HELLO_DTLS12_PSK";
    uint8_t server_hello[] = "SERVER_HELLO_DTLS12_PSK";
    uint8_t app_data[] = "DTLS12_APP_DATA";
    uint8_t cookie[HASH_SHA256_OUT_LEN];
    uint32_t cookie_len = sizeof(cookie);
    noxtls_return_t rc;

    noxtls_dtls_context_init(&client_ctx, TLS_ROLE_CLIENT, DTLS_VERSION_1_2);
    noxtls_dtls_context_init(&server_ctx, TLS_ROLE_SERVER, DTLS_VERSION_1_2);
    noxtls_tls_set_io_callbacks(&client_ctx.base, client_send_callback, client_recv_callback, network);
    noxtls_tls_set_io_callbacks(&server_ctx.base, server_send_callback, server_recv_callback, network);

    printf("[Server] Generating HelloVerifyRequest cookie...\n");
    rc = noxtls_dtls_generate_cookie(&server_ctx, client_hello, (uint32_t)sizeof(client_hello) - 1,
                              cookie, &cookie_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("ERROR: Failed to generate cookie (%d)\n", rc);
        return rc;
    }
    printf("  Cookie: ");
    print_hex(cookie, cookie_len);

    rc = noxtls_dtls_verify_cookie(&server_ctx, cookie, cookie_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("ERROR: Failed to verify cookie (%d)\n", rc);
        return rc;
    }
    printf("[Server] Cookie verified\n");

    rc = dtls_handshake_exchange(&client_ctx, &server_ctx,
                                 TLS_HANDSHAKE_CLIENT_HELLO, 0,
                                 client_hello, (uint32_t)sizeof(client_hello) - 1,
                                 "ClientHello");
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    rc = dtls_handshake_exchange(&server_ctx, &client_ctx,
                                 TLS_HANDSHAKE_SERVER_HELLO, 1,
                                 server_hello, (uint32_t)sizeof(server_hello) - 1,
                                 "ServerHello");
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    rc = dtls_roundtrip_record(&server_ctx, &client_ctx, TLS_RECORD_APPLICATION_DATA,
                               app_data, (uint32_t)sizeof(app_data) - 1,
                               "ApplicationData");
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    
    printf("\nDTLS 1.2 simplified demo (no cert linked). For full handshake, build with cert data.\n\n");
    noxtls_dtls_context_free(&client_ctx);
    noxtls_dtls_context_free(&server_ctx);
    return NOXTLS_RETURN_SUCCESS;
#endif
}

/* DTLS 1.3 PSK Handshake Demo. prefer_chacha20: 0 = prefer AES-GCM, 1 = prefer ChaCha20-Poly1305 (for full handshake use noxtls_tls13_set_prefer_chacha20). */
static noxtls_return_t dtls13_psk_handshake_demo(udp_connection_t *network, int prefer_chacha20)
{
    printf("========================================\n");
    printf("DTLS 1.3 PSK Handshake Demo\n");
    printf("========================================\n\n");
    printf("Cipher preference: %s\n\n", prefer_chacha20 ? "ChaCha20-Poly1305" : "AES-GCM (default)");

    printf("DTLS 1.3 Key Differences from DTLS 1.2:\n");
    printf("  - Single round-trip handshake (0-RTT support)\n");
    printf("  - PSK can be used for 0-RTT data\n");
    printf("  - Simplified handshake with fewer messages\n");
    printf("  - Always uses AEAD encryption (ChaCha20-Poly1305 or AES-GCM)\n");
    printf("  - No Change Cipher Spec noxtls_message\n");
    printf("  - Handshake messages encrypted after Server Hello\n\n");
    
    printf("PSK Configuration:\n");
    printf("  Identity: %s\n", DTLS_PSK_IDENTITY);
    printf("  Key: %s\n", DTLS_PSK_KEY);
    printf("\n");
    
    dtls_context_t client_ctx;
    dtls_context_t server_ctx;
    uint8_t client_hello[] = "CLIENT_HELLO_DTLS13_PSK";
    uint8_t server_hello[] = "SERVER_HELLO_DTLS13_PSK";
    uint8_t app_data[] = "DTLS13_APP_DATA";
    noxtls_return_t rc;

    noxtls_dtls_context_init(&client_ctx, TLS_ROLE_CLIENT, DTLS_VERSION_1_3);
    noxtls_dtls_context_init(&server_ctx, TLS_ROLE_SERVER, DTLS_VERSION_1_3);
    noxtls_tls_set_io_callbacks(&client_ctx.base, client_send_callback, client_recv_callback, network);
    noxtls_tls_set_io_callbacks(&server_ctx.base, server_send_callback, server_recv_callback, network);

    printf("[Client] Sending Client Hello (DTLS 1.3)...\n");
    printf("  Handshake noxtls_message would include:\n");
    printf("    - Supported Versions extension (DTLS 1.3)\n");
    printf("    - PSK Key Exchange Modes extension\n");
    printf("    - Pre-Shared Key extension (PSK identity)\n");
    printf("    - Supported Cipher Suites (AEAD only)\n");

    rc = dtls_handshake_exchange(&client_ctx, &server_ctx,
                                 TLS_HANDSHAKE_CLIENT_HELLO, 0,
                                 client_hello, (uint32_t)sizeof(client_hello) - 1,
                                 "ClientHello");
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    rc = dtls_handshake_exchange(&server_ctx, &client_ctx,
                                 TLS_HANDSHAKE_SERVER_HELLO, 1,
                                 server_hello, (uint32_t)sizeof(server_hello) - 1,
                                 "ServerHello");
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    rc = dtls_roundtrip_record(&client_ctx, &server_ctx, TLS_RECORD_APPLICATION_DATA,
                               app_data, (uint32_t)sizeof(app_data) - 1,
                               "ApplicationData");
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    
    printf("\nDTLS 1.3 Handshake completed (simplified demo)\n");
    printf("In a full DTLS 1.3 implementation, this would continue with:\n");
    printf("  - Encrypted Extensions (encrypted after Server Hello)\n");
    printf("  - Finished noxtls_message (encrypted, includes handshake hash)\n");
    printf("  - Application Data (can use 0-RTT if PSK is available)\n");
    printf("  - All messages after Server Hello are encrypted with AEAD\n\n");
    
    noxtls_dtls_context_free(&client_ctx);
    noxtls_dtls_context_free(&server_ctx);
    return NOXTLS_RETURN_SUCCESS;
}

/* Main function */
int main(int argc, char **argv)
{
    udp_connection_t network;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    int demo_version = 0;  /* 0 = both, 1 = DTLS 1.2 only, 2 = DTLS 1.3 only */
    int prefer_chacha20 = 0;  /* 0 = AES-GCM first, 1 = ChaCha20-Poly1305 first (TLS/DTLS 1.3) */

    printf("========================================\n");
    printf("DTLS PSK Demo Application\n");
    printf("Supports DTLS 1.2 and DTLS 1.3\n");
    printf("========================================\n\n");

    /* Parse command line arguments: [--chacha|--aes] [1.2|1.3] */
    for(int i = 1; i < argc; i++) {
        if(strcmp(argv[i], "--chacha") == 0) {
            prefer_chacha20 = 1;
        } else if(strcmp(argv[i], "--aes") == 0) {
            prefer_chacha20 = 0;
        } else if(strcmp(argv[i], "1.2") == 0 || strcmp(argv[i], "12") == 0) {
            demo_version = 1;
        } else if(strcmp(argv[i], "1.3") == 0 || strcmp(argv[i], "13") == 0) {
            demo_version = 2;
        } else {
            printf("Usage: %s [--chacha|--aes] [1.2|1.3]\n", argv[0]);
            printf("  --chacha     Prefer ChaCha20-Poly1305 for TLS/DTLS 1.3 (call noxtls_tls13_set_prefer_chacha20(ctx,1) before handshake)\n");
            printf("  --aes       Prefer AES-GCM for TLS/DTLS 1.3 (default)\n");
            printf("  No argument: Run both DTLS 1.2 and DTLS 1.3 demos\n");
            printf("  1.2 or 12:   Run DTLS 1.2 demo only\n");
            printf("  1.3 or 13:   Run DTLS 1.3 demo only\n\n");
        }
    }
    
    /* Initialize network buffers */
    udp_buffer_init(&network.server_to_client);
    udp_buffer_init(&network.client_to_server);
    
    do {
        /* Run DTLS 1.2 PSK handshake demo */
        if(demo_version == 0 || demo_version == 1)
        {
            rc = dtls12_psk_handshake_demo(&network);
            if(rc != NOXTLS_RETURN_SUCCESS)
            {
                printf("ERROR: DTLS 1.2 handshake demo failed: %d\n", rc);
                break;
            }
            
            if(demo_version == 0)
            {
                printf("\n");
                printf("========================================\n");
                printf("Press Enter to continue to DTLS 1.3 demo...\n");
                printf("========================================\n");
                getchar();
                printf("\n");
            }
        }
        
        /* Run DTLS 1.3 PSK handshake demo */
        if(demo_version == 0 || demo_version == 2)
        {
            /* Reinitialize buffers for second demo */
            udp_buffer_free(&network.server_to_client);
            udp_buffer_free(&network.client_to_server);
            udp_buffer_init(&network.server_to_client);
            udp_buffer_init(&network.client_to_server);
            
            rc = dtls13_psk_handshake_demo(&network, prefer_chacha20);
            if(rc != NOXTLS_RETURN_SUCCESS)
            {
                printf("ERROR: DTLS 1.3 handshake demo failed: %d\n", rc);
                break;
            }
        }
        
        printf("========================================\n");
        printf("Demo completed successfully!\n");
        printf("========================================\n");
    } while(0);
    
    /* Cleanup */
    /* Cleanup */
    udp_buffer_free(&network.server_to_client);
    udp_buffer_free(&network.client_to_server);
    
    return (rc == NOXTLS_RETURN_SUCCESS) ? 0 : 1;
}

