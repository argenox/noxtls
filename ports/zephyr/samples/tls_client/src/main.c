/*****************************************************************************
 * Copyright (c) [2019] - [2026], Argenox Technologies LLC
 * SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
 *
 * Zephyr sample: NoxTLS TLS 1.3 client (init-only or optional network handshake).
 *****************************************************************************/

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/net/socket.h>

#include "noxtls_common.h"
#include "noxtls_tls_common.h"
#include "noxtls_tls13.h"

#define NOXTLS_SAMPLE_TLS_PORT (443U)

typedef struct {
	int sock;
} noxtls_sample_conn_t;

/**
 * @brief Send callback for NoxTLS I/O over Zephyr BSD sockets.
 * @param user_data Connection context.
 * @param data Bytes to send.
 * @param len Length.
 * @return Bytes sent, or negative on error.
 */
static int32_t sample_tls_send_cb(void *user_data, const uint8_t *data, uint32_t len)
{
	noxtls_sample_conn_t *conn;
	int sent;

	if(user_data == NULL || data == NULL) {
		return -1;
	}

	conn = (noxtls_sample_conn_t *)user_data;
	sent = send(conn->sock, data, len, 0);
	if(sent < 0) {
		return -1;
	}

	return (int32_t)sent;
}

/**
 * @brief Receive callback for NoxTLS I/O over Zephyr BSD sockets.
 * @param user_data Connection context.
 * @param data Receive buffer.
 * @param len Maximum bytes to read.
 * @return Bytes received, or negative on error.
 */
static int32_t sample_tls_recv_cb(void *user_data, uint8_t *data, uint32_t len)
{
	noxtls_sample_conn_t *conn;
	int received;

	if(user_data == NULL || data == NULL) {
		return -1;
	}

	conn = (noxtls_sample_conn_t *)user_data;
	received = recv(conn->sock, data, len, 0);
	if(received < 0) {
		return -1;
	}

	return (int32_t)received;
}

/**
 * @brief Open a TCP connection to host:port using Zephyr sockets.
 * @param host Hostname.
 * @param port TCP port.
 * @return Socket fd, or negative errno on failure.
 */
static int sample_tcp_connect(const char *host, uint16_t port)
{
	struct addrinfo hints;
	struct addrinfo *res;
	struct addrinfo *it;
	char port_str[8];
	int sock;
	int err;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	snprintf(port_str, sizeof(port_str), "%u", (unsigned int)port);

	err = getaddrinfo(host, port_str, &hints, &res);
	if(err != 0 || res == NULL) {
		return -EIO;
	}

	sock = -1;
	for(it = res; it != NULL; it = it->ai_next) {
		sock = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
		if(sock < 0) {
			continue;
		}
		if(connect(sock, it->ai_addr, it->ai_addrlen) == 0) {
			break;
		}
		close(sock);
		sock = -1;
	}

	freeaddrinfo(res);
	return sock;
}

/**
 * @brief Run TLS 1.3 client handshake when network connect is enabled.
 * @param host Server hostname.
 * @return 0 on success, negative on failure.
 */
static int sample_run_tls_connect(const char *host)
{
	noxtls_sample_conn_t conn;
	tls13_context_t tls_ctx;
	noxtls_return_t rc;
	size_t host_len;

	conn.sock = sample_tcp_connect(host, NOXTLS_SAMPLE_TLS_PORT);
	if(conn.sock < 0) {
		printf("ERROR: TCP connect to %s:%u failed\n", host, NOXTLS_SAMPLE_TLS_PORT);
		return -1;
	}

	rc = noxtls_tls13_context_init(&tls_ctx, TLS_ROLE_CLIENT);
	if(rc != NOXTLS_RETURN_SUCCESS) {
		printf("ERROR: noxtls_tls13_context_init failed: %d\n", rc);
		close(conn.sock);
		return -1;
	}

	host_len = strlen(host);
	if(host_len > UINT16_MAX) {
		noxtls_tls13_context_free(&tls_ctx);
		close(conn.sock);
		return -1;
	}

	tls_ctx.server_name = host;
	tls_ctx.server_name_len = (uint16_t)host_len;

	rc = noxtls_tls_set_io_callbacks(&tls_ctx.base.base, sample_tls_send_cb,
					 sample_tls_recv_cb, &conn);
	if(rc != NOXTLS_RETURN_SUCCESS) {
		printf("ERROR: noxtls_tls_set_io_callbacks failed: %d\n", rc);
		noxtls_tls13_context_free(&tls_ctx);
		close(conn.sock);
		return -1;
	}

	rc = noxtls_tls13_connect(&tls_ctx);
	if(rc != NOXTLS_RETURN_SUCCESS) {
		printf("ERROR: TLS 1.3 handshake failed: %d\n", rc);
		noxtls_tls13_context_free(&tls_ctx);
		close(conn.sock);
		return -1;
	}

	printf("TLS handshake complete\n");
	noxtls_tls13_context_free(&tls_ctx);
	close(conn.sock);
	return 0;
}

int main(void)
{
	noxtls_return_t rc;
	tls13_context_t tls_ctx;
	const char *host = CONFIG_NOXTLS_SAMPLE_TLS_HOST;

	printf("NoxTLS Zephyr TLS client sample\n");

#if IS_ENABLED(CONFIG_NOXTLS_SAMPLE_TLS_CONNECT)
	if(sample_run_tls_connect(host) != 0) {
		return 1;
	}
#else
	rc = noxtls_tls13_context_init(&tls_ctx, TLS_ROLE_CLIENT);
	if(rc != NOXTLS_RETURN_SUCCESS) {
		printf("ERROR: noxtls_tls13_context_init failed: %d\n", rc);
		return 1;
	}
	noxtls_tls13_context_free(&tls_ctx);
	printf("NoxTLS TLS sample ready\n");
#endif

	return 0;
}
