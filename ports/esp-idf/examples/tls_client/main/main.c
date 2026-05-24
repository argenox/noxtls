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
* File:    main.c
* Summary: TLS 1.3 client (init-only or optional network handshake).
*
*****************************************************************************/

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "esp_log.h"
#include "sdkconfig.h"

#include "lwip/netdb.h"
#include "lwip/sockets.h"

#include "noxtls_common.h"
#include "noxtls_esp_idf.h"
#include "noxtls_tls_common.h"
#include "noxtls_tls13.h"

#define NOXTLS_SAMPLE_TAG           "noxtls_tls_client"
#define NOXTLS_SAMPLE_TLS_PORT      (443U)

typedef struct {
	int sock;
} noxtls_sample_conn_t;

/**
 * @brief Send callback for NoxTLS I/O over lwIP BSD sockets.
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
 * @brief Receive callback for NoxTLS I/O over lwIP BSD sockets.
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
 * @brief Open a TCP connection to host:port using lwIP sockets.
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
		ESP_LOGE(NOXTLS_SAMPLE_TAG, "TCP connect to %s:%u failed", host,
			 (unsigned int)NOXTLS_SAMPLE_TLS_PORT);
		return -1;
	}

	rc = noxtls_tls13_context_init(&tls_ctx, TLS_ROLE_CLIENT);
	if(rc != NOXTLS_RETURN_SUCCESS) {
		ESP_LOGE(NOXTLS_SAMPLE_TAG, "noxtls_tls13_context_init failed: %d", rc);
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
		ESP_LOGE(NOXTLS_SAMPLE_TAG, "noxtls_tls_set_io_callbacks failed: %d", rc);
		noxtls_tls13_context_free(&tls_ctx);
		close(conn.sock);
		return -1;
	}

	rc = noxtls_tls13_connect(&tls_ctx);
	if(rc != NOXTLS_RETURN_SUCCESS) {
		ESP_LOGE(NOXTLS_SAMPLE_TAG, "TLS 1.3 handshake failed: %d", rc);
		noxtls_tls13_context_free(&tls_ctx);
		close(conn.sock);
		return -1;
	}

	ESP_LOGI(NOXTLS_SAMPLE_TAG, "TLS handshake complete");
	noxtls_tls13_context_free(&tls_ctx);
	close(conn.sock);
	return 0;
}

/**
 * @brief The main function
 * 
 * @return void
 */
void app_main(void)
{
	noxtls_return_t rc;
	tls13_context_t tls_ctx;

	ESP_LOGI(NOXTLS_SAMPLE_TAG, "NoxTLS ESP-IDF TLS client example");

	(void)noxtls_esp_idf_init();

#if defined(CONFIG_NOXTLS_SAMPLE_TLS_CONNECT) && CONFIG_NOXTLS_SAMPLE_TLS_CONNECT
	if(sample_run_tls_connect(CONFIG_NOXTLS_SAMPLE_TLS_HOST) != 0) {
		return;
	}
#else
	rc = noxtls_tls13_context_init(&tls_ctx, TLS_ROLE_CLIENT);
	if(rc != NOXTLS_RETURN_SUCCESS) {
		ESP_LOGE(NOXTLS_SAMPLE_TAG, "noxtls_tls13_context_init failed: %d", rc);
		return;
	}
	noxtls_tls13_context_free(&tls_ctx);
	ESP_LOGI(NOXTLS_SAMPLE_TAG, "NoxTLS TLS sample ready");
#endif
}
