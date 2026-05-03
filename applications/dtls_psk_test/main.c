/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
*
* NOTICE:  All information contained herein, source code, binaries and
* derived works is, and remains the property of Argenox Technologies and its
* suppliers. Dissemination of this information or reproduction of this
* material is strictly forbidden unless prior written permission is obtained
* from Argenox Technologies.
*
* File:    main.c
* Summary: DTLS PSK test application — server and client in one process,
*          exchange application data both ways and verify payloads.
*
*/

/**
 * @file main.c
 * @brief DTLS PSK test — server and client in one process, exchange data and verify payloads.
 * @defgroup noxtls_app_dtls_psk_test DTLS PSK test
 * @details
 * Single-process test: runs DTLS server and client, exchanges application data
 * both ways and verifies payloads. No required parameters; uses built-in PSK.
 * @example
 * dtls_psk_test
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "noxtls_common.h"
#include "noxtls_memory.h"
#include "noxtls_tls_common.h"
#include "noxtls_dtls_common.h"
#include "mdigest/sha256/noxtls_sha256.h"

/* PSK (same as dtls_psk_demo for compatibility) */
#define PSK_IDENTITY   "test-identity"
#define PSK_KEY        "test-key-12345"
#define PSK_KEY_LEN    15

/* Payloads we send and verify */
#define MSG_SERVER_TO_CLIENT   "ServerToClient_Payload_123"
#define MSG_CLIENT_TO_SERVER   "ClientToServer_Payload_456"

/* In-memory UDP simulation */
typedef struct
{
    uint8_t *data;
    uint32_t len;
    uint32_t capacity;
} udp_buf_t;

typedef struct
{
    udp_buf_t server_to_client;
    udp_buf_t client_to_server;
} udp_conn_t;

static void udp_buf_init(udp_buf_t *b)
{
    b->data = NULL;
    b->len = 0;
    b->capacity = 0;
}

static noxtls_return_t udp_buf_append(udp_buf_t *b, const uint8_t *data, uint32_t len)
{
    if (!b || !data) return NOXTLS_RETURN_NULL;
    if (b->capacity < b->len + len) {
        uint32_t cap = (b->len + len) * 2;
        if (cap < 4096) cap = 4096;
        uint8_t *p = (uint8_t *)noxtls_realloc(b->data, cap);
        if (!p) return NOXTLS_RETURN_FAILED;
        b->data = p;
        b->capacity = cap;
    }
    memcpy(b->data + b->len, data, len);
    b->len += len;
    return NOXTLS_RETURN_SUCCESS;
}

static int32_t udp_buf_read(udp_buf_t *b, uint8_t *data, uint32_t len)
{
    if (!b || !data) return -1;
    if (b->len == 0) return 0;
    uint32_t n = len < b->len ? len : b->len;
    memcpy(data, b->data, n);
    b->len = 0;
    return (int32_t)n;
}

static void udp_buf_free(udp_buf_t *b)
{
    if (b && b->data) {
        noxtls_free(b->data);
        b->data = NULL;
    }
    if (b) b->len = 0, b->capacity = 0;
}

static int32_t server_send(void *u, const uint8_t *data, uint32_t len)
{
    udp_conn_t *c = (udp_conn_t *)u;
    if (!c || !data) return -1;
    return udp_buf_append(&c->server_to_client, data, len) == NOXTLS_RETURN_SUCCESS ? (int32_t)len : -1;
}

static int32_t server_recv(void *u, uint8_t *data, uint32_t len)
{
    udp_conn_t *c = (udp_conn_t *)u;
    if (!c || !data) return -1;
    return udp_buf_read(&c->client_to_server, data, len);
}

static int32_t client_send(void *u, const uint8_t *data, uint32_t len)
{
    udp_conn_t *c = (udp_conn_t *)u;
    if (!c || !data) return -1;
    return udp_buf_append(&c->client_to_server, data, len) == NOXTLS_RETURN_SUCCESS ? (int32_t)len : -1;
}

static int32_t client_recv(void *u, uint8_t *data, uint32_t len)
{
    udp_conn_t *c = (udp_conn_t *)u;
    if (!c || !data) return -1;
    return udp_buf_read(&c->server_to_client, data, len);
}

/* Send one record from sender, receive and verify on receiver */
static noxtls_return_t exchange_and_verify(dtls_context_t *sender, dtls_context_t *receiver,
                                           const uint8_t *payload, uint32_t len,
                                           const char *direction)
{
    dtls_record_t record;
    noxtls_return_t rc;

    rc = dtls_send_record(sender, TLS_RECORD_APPLICATION_DATA, payload, len);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        printf("[FAIL] %s send failed: %d\n", direction, rc);
        return rc;
    }

    rc = dtls_recv_record(receiver, &record);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        printf("[FAIL] %s recv failed: %d\n", direction, rc);
        return rc;
    }

    if (record.type != TLS_RECORD_APPLICATION_DATA || record.length != len ||
        (len && memcmp(record.data, payload, len) != 0)) {
        printf("[FAIL] %s payload mismatch (type=%u len=%u)\n", direction, (unsigned)record.type, (unsigned)record.length);
        if (record.data) noxtls_free(record.data);
        return NOXTLS_RETURN_FAILED;
    }

    if (record.data) noxtls_free(record.data);
    printf("[PASS] %s verified (%u bytes)\n", direction, (unsigned)len);
    return NOXTLS_RETURN_SUCCESS;
}

/* Send handshake fragment from sender, receive and reassemble on receiver */
static noxtls_return_t handshake_exchange(dtls_context_t *sender, dtls_context_t *receiver,
                                           uint8_t msg_type, uint16_t msg_seq,
                                           const uint8_t *payload, uint32_t len)
{
    dtls_handshake_fragment_t frag;
    uint8_t *complete = NULL;
    uint32_t complete_len = 0;
    noxtls_return_t rc;

    rc = dtls_send_handshake_fragment(sender, msg_type, payload, len, msg_seq);
    if (rc != NOXTLS_RETURN_SUCCESS) return rc;

    rc = dtls_recv_handshake_fragment(receiver, &frag);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        if (frag.data) noxtls_free(frag.data);
        return rc;
    }

    rc = dtls_reassemble_handshake(receiver, &frag, &complete, &complete_len);
    if (frag.data) noxtls_free(frag.data);
    if (rc != NOXTLS_RETURN_SUCCESS) return rc;
    if (complete_len != len || (len && memcmp(complete, payload, len) != 0)) {
        if (complete) noxtls_free(complete);
        return NOXTLS_RETURN_FAILED;
    }
    if (complete) noxtls_free(complete);
    return NOXTLS_RETURN_SUCCESS;
}

static noxtls_return_t run_dtls_psk_test(udp_conn_t *conn)
{
    dtls_context_t client_ctx, server_ctx;
    uint8_t client_hello[] = "CLIENT_HELLO_PSK";
    uint8_t server_hello[] = "SERVER_HELLO_PSK";
    uint8_t cookie[HASH_SHA256_OUT_LEN];
    uint32_t cookie_len = sizeof(cookie);
    noxtls_return_t rc;
    const uint8_t *msg_s2c = (const uint8_t *)MSG_SERVER_TO_CLIENT;
    const uint8_t *msg_c2s = (const uint8_t *)MSG_CLIENT_TO_SERVER;
    uint32_t len_s2c = (uint32_t)strlen(MSG_SERVER_TO_CLIENT);
    uint32_t len_c2s = (uint32_t)strlen(MSG_CLIENT_TO_SERVER);

    memset(&client_ctx, 0, sizeof(client_ctx));
    memset(&server_ctx, 0, sizeof(server_ctx));

    rc = dtls_context_init(&client_ctx, TLS_ROLE_CLIENT, DTLS_VERSION_1_2);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        printf("[FAIL] client context init: %d\n", rc);
        return rc;
    }
    rc = dtls_context_init(&server_ctx, TLS_ROLE_SERVER, DTLS_VERSION_1_2);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        printf("[FAIL] server context init: %d\n", rc);
        dtls_context_free(&client_ctx);
        return rc;
    }

    noxtls_tls_set_io_callbacks(&client_ctx.base, client_send, client_recv, conn);
    noxtls_tls_set_io_callbacks(&server_ctx.base, server_send, server_recv, conn);

    /* Server cookie (for HelloVerifyRequest simulation) */
    rc = dtls_generate_cookie(&server_ctx, client_hello, (uint32_t)sizeof(client_hello) - 1, cookie, &cookie_len);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        printf("[FAIL] generate cookie: %d\n", rc);
        goto cleanup;
    }
    rc = dtls_verify_cookie(&server_ctx, cookie, cookie_len);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        printf("[FAIL] verify cookie: %d\n", rc);
        goto cleanup;
    }

    /* Handshake: ClientHello then ServerHello */
    rc = handshake_exchange(&client_ctx, &server_ctx, TLS_HANDSHAKE_CLIENT_HELLO, 0,
                            client_hello, (uint32_t)sizeof(client_hello) - 1);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        printf("[FAIL] ClientHello exchange: %d\n", rc);
        goto cleanup;
    }

    rc = handshake_exchange(&server_ctx, &client_ctx, TLS_HANDSHAKE_SERVER_HELLO, 1,
                            server_hello, (uint32_t)sizeof(server_hello) - 1);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        printf("[FAIL] ServerHello exchange: %d\n", rc);
        goto cleanup;
    }

    /* Server -> Client application data; client verifies */
    rc = exchange_and_verify(&server_ctx, &client_ctx, msg_s2c, len_s2c, "Server->Client");
    if (rc != NOXTLS_RETURN_SUCCESS) goto cleanup;

    /* Client -> Server application data; server verifies */
    rc = exchange_and_verify(&client_ctx, &server_ctx, msg_c2s, len_c2s, "Client->Server");
    if (rc != NOXTLS_RETURN_SUCCESS) goto cleanup;

cleanup:
    dtls_context_free(&client_ctx);
    dtls_context_free(&server_ctx);
    return rc;
}

int main(int argc, char **argv)
{
    udp_conn_t conn;
    noxtls_return_t rc;
    (void)argc;
    (void)argv;

    printf("DTLS PSK test: server and client exchange data (in-memory UDP)\n");
    printf("PSK identity: %s\n", PSK_IDENTITY);
    printf("Verify: Server->Client \"%s\" and Client->Server \"%s\"\n\n", MSG_SERVER_TO_CLIENT, MSG_CLIENT_TO_SERVER);

    udp_buf_init(&conn.server_to_client);
    udp_buf_init(&conn.client_to_server);

    rc = run_dtls_psk_test(&conn);

    udp_buf_free(&conn.server_to_client);
    udp_buf_free(&conn.client_to_server);

    if (rc == NOXTLS_RETURN_SUCCESS) {
        printf("\nAll checks passed. Exit 0.\n");
        return 0;
    }
    printf("\nTest failed. Exit 1.\n");
    return 1;
}
