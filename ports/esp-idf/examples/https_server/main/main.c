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
* File:    noxtls_config.h
* Summary: NoxTLS configuration for the ESP-IDF tls_client example only.
*
* Binds TCP on CONFIG_NOXTLS_HTTPS_SERVER_PORT, accepts one client at a time,
* runs a TLS 1.3 handshake using embedded PEM cert/key, then returns a small
* HTTP/1.0 page describing the negotiated connection.
*
 * Provide your own certificate and private key in:
 *   certs/server_cert.pem
 *   certs/server_key.pem
* See examples/https_server/README.md for the openssl one-liner.
*
*****************************************************************************/

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_event.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "nvs_flash.h"
#include "sdkconfig.h"

#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"

#include "lwip/inet.h"
#include "lwip/netdb.h"
#include "lwip/sockets.h"

#include "esp_system.h"
#include "esp_timer.h"

#include "noxtls_common.h"
#include "noxtls_debug_printf.h"
#include "noxtls_esp_hw_crypto.h"
#include "noxtls_esp_idf.h"
#include "noxtls-lib/certs/certificates.h"
#include "noxtls-lib/certs/noxtls_x509.h"
#include "noxtls-lib/pkc/ecdsa/noxtls_ecdsa.h"
#include "noxtls-lib/pkc/ecc/noxtls_ecc.h"
#include "noxtls-lib/pkc/rsa/noxtls_rsa.h"
#include "noxtls-lib/tls/noxtls_tls13.h"
#include "noxtls-lib/tls/noxtls_tls_common.h"

#define NOXTLS_HTTPS_TAG                "noxtls_https_server"
#define NOXTLS_HTTPS_WIFI_CONNECTED_BIT BIT0
#define NOXTLS_HTTPS_WIFI_FAILED_BIT    BIT1
#define NOXTLS_HTTPS_WIFI_RETRY_MAX     (5U)
#define NOXTLS_HTTPS_RX_CHUNK              (1024U)
#define NOXTLS_HTTPS_RESPONSE_MAX          (3072U)
/* TLS handshake + ECDSA run on a dedicated task (not main). */
#define NOXTLS_HTTPS_SESSION_TASK_STACK    (24576U)
#define NOXTLS_HTTPS_SESSION_TASK_PRIORITY (5U)

typedef struct {
	TaskHandle_t notify_task;
	int client_sock;
	const uint8_t *cert_der;
	uint32_t cert_der_len;
	x509_private_key_t *server_key;
	rsa_key_t *server_rsa;
	ecc_key_t *server_ecc;
} https_session_args_t;

/* Browsers send ALPN; server must advertise overlap or handshake fails (RFC 7301). */
static const char *const NOXTLS_HTTPS_ALPN_PROTOCOLS[] = { "http/1.1", "h2" };

extern const uint8_t g_server_cert_pem_start[] asm("_binary_server_cert_pem_start");
extern const uint8_t g_server_cert_pem_end[]   asm("_binary_server_cert_pem_end");
extern const uint8_t g_server_key_pem_start[]  asm("_binary_server_key_pem_start");
extern const uint8_t g_server_key_pem_end[]    asm("_binary_server_key_pem_end");

typedef struct {
	int sock;
} noxtls_https_conn_t;

/** Per-connection timing and TLS parameters shown on the status HTML page. */
typedef struct {
	int64_t handshake_us;
	int64_t request_recv_us;
	int64_t response_send_us;
	int64_t session_total_us;
	uint32_t request_bytes;
	uint32_t response_body_bytes;
	uint32_t free_heap;
	uint32_t min_free_heap;
	uint32_t cpu_mhz;
	uint16_t cipher_suite;
	char alpn[NOXTLS_TLS_ALPN_MAX_PROTOCOL_LEN + 1U];
	char key_type[16];
	char kex_group[24];
	char hw_ecc[24];
	char hw_mpi[12];
} https_session_metrics_t;

/**
 * @brief Human-readable NoxTLS return code for logging.
 *
 * @param[in] rc The NoxTLS return code
 * @return The human-readable NoxTLS return code
 */
static const char *https_noxtls_rc_name(noxtls_return_t rc)
{
	switch(rc) {
	case NOXTLS_RETURN_SUCCESS: return "SUCCESS";
	case NOXTLS_RETURN_FAILED: return "FAILED";
	case NOXTLS_RETURN_NULL: return "NULL_ARG";
	case NOXTLS_RETURN_INVALID_PARAM: return "INVALID_PARAM";
	case NOXTLS_RETURN_BAD_DATA: return "BAD_DATA";
	case NOXTLS_RETURN_TIMEOUT: return "TIMEOUT";
	case NOXTLS_RETURN_NOT_SUPPORTED: return "NOT_SUPPORTED";
	case NOXTLS_RETURN_NOT_ENOUGH_MEMORY: return "NOT_ENOUGH_MEMORY";
	case NOXTLS_RETURN_TLS_ERROR: return "TLS_ERROR";
	case NOXTLS_RETURN_TLS_RECORD_AUTH_FAILED: return "RECORD_AUTH_FAILED";
	case NOXTLS_RETURN_TLS_FINISHED_VERIFY_FAILED: return "FINISHED_VERIFY_FAILED";
	case NOXTLS_RETURN_TLS_ALERT_DECODE_ERROR: return "ALERT_DECODE_ERROR";
	case NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER: return "ALERT_ILLEGAL_PARAMETER";
	default: return "OTHER";
	}
}

/**
 * @brief Log TLS context fields after a failed server handshake.
 *
 * @param[in] ctx The TLS 1.3 context
 * @param[in] rc The NoxTLS return code
 * @return void
 */
static void https_log_handshake_failure(const tls13_context_t *ctx, noxtls_return_t rc)
{
	const char *state = "unknown";

	if(ctx == NULL) {
		ESP_LOGE(NOXTLS_HTTPS_TAG, "handshake failed: %s (%d), ctx=NULL",
			 https_noxtls_rc_name(rc), (int)rc);
		return;
	}

	switch(ctx->base.base.state) {
	case TLS_STATE_INIT: state = "INIT"; break;
	case TLS_STATE_HANDSHAKING: state = "HANDSHAKING"; break;
	case TLS_STATE_CONNECTED: state = "CONNECTED"; break;
	case TLS_STATE_CLOSING: state = "CLOSING"; break;
	case TLS_STATE_CLOSED: state = "CLOSED"; break;
	case TLS_STATE_ERROR: state = "ERROR"; break;
	default: break;
	}

	ESP_LOGE(NOXTLS_HTTPS_TAG,
		 "handshake failed: %s (%d) tls_state=%s cipher=0x%04x peer_alert=%u "
		 "ecdsa_key=%u rsa_key=%u ed25519_key=%u free_heap=%u min_free_heap=%u",
		 https_noxtls_rc_name(rc), (int)rc, state,
		 (unsigned int)ctx->cipher_suite,
		 (unsigned int)ctx->peer_alert_received,
		 (unsigned int)(ctx->server_private_ecdsa != NULL),
		 (unsigned int)(ctx->server_private_rsa != NULL),
		 (unsigned int)ctx->server_cert_use_ed25519,
		 (unsigned int)esp_get_free_heap_size(),
		 (unsigned int)esp_get_minimum_free_heap_size());

	if(ctx->peer_alert_received != 0U) {
		ESP_LOGW(NOXTLS_HTTPS_TAG,
			 "Peer closed this TCP connection with a TLS alert (common for extra "
			 "browser tabs/sockets; another accept() may still succeed).");
	} else if(rc == NOXTLS_RETURN_FAILED) {
		ESP_LOGE(NOXTLS_HTTPS_TAG,
			 "FAILED without peer alert: often CertificateVerify/sign or send; "
			 "enable NOXTLS_HTTPS_SERVER_HANDSHAKE_DEBUG in menuconfig for step logs");
	}
}

#if defined(CONFIG_NOXTLS_HTTPS_SERVER_USE_WIFI) && CONFIG_NOXTLS_HTTPS_SERVER_USE_WIFI
static EventGroupHandle_t g_wifi_event_group;
static uint32_t g_wifi_retry_count;
#endif

/**
 * @brief Warn when sdkconfig diverges from sdkconfig.defaults (common crash cause on ESP32).
 *
 * @return void
 */
static void https_log_build_config_hints(void)
{
#if CONFIG_ESP_MAIN_TASK_STACK_SIZE < 24576
	ESP_LOGW(NOXTLS_HTTPS_TAG,
		 "CONFIG_ESP_MAIN_TASK_STACK_SIZE=%u (< 24 KB). "
		 "Run: idf.py -C examples/https_server fullclean build",
		 (unsigned int)CONFIG_ESP_MAIN_TASK_STACK_SIZE);
#endif
#if CONFIG_ESP_TASK_WDT_TIMEOUT_S < 30
	ESP_LOGW(NOXTLS_HTTPS_TAG,
		 "CONFIG_ESP_TASK_WDT_TIMEOUT_S=%u (< 30 s). "
		 "ECDSA CertificateVerify can exceed 5 s; use sdkconfig.defaults or fullclean",
		 (unsigned int)CONFIG_ESP_TASK_WDT_TIMEOUT_S);
#endif
#if CONFIG_NOXTLS_TLS_MAX_RECORD_SIZE > 8192
	ESP_LOGW(NOXTLS_HTTPS_TAG,
		 "CONFIG_NOXTLS_TLS_MAX_RECORD_SIZE=%u is large for ESP32 RAM "
		 "(~%u bytes record workspace per connection). Prefer 4096; see sdkconfig.defaults",
		 (unsigned int)CONFIG_NOXTLS_TLS_MAX_RECORD_SIZE,
		 (unsigned int)((CONFIG_NOXTLS_TLS_MAX_RECORD_SIZE + 32U) * 2U));
#endif
}

/**
 * @brief NoxTLS send callback bridging to a blocking lwIP socket.
 * @param user_data Pointer to noxtls_https_conn_t.
 * @param data Bytes to send.
 * @param len Number of bytes.
 * @return Bytes sent on success, negative on error.
 */
static int32_t https_tls_send_cb(void *user_data, const uint8_t *data, uint32_t len)
{
	noxtls_https_conn_t *conn;
	uint32_t offset = 0U;

	if(user_data == NULL || data == NULL || len == 0U) {
		return -1;
	}
	conn = (noxtls_https_conn_t *)user_data;
	while(offset < len) {
		int sent = send(conn->sock, data + offset, len - offset, 0);
		if(sent < 0) {
			return -1;
		}
		if(sent == 0) {
			return -1;
		}
		offset += (uint32_t)sent;
	}
	return (int32_t)len;
}

/**
 * @brief NoxTLS receive callback bridging to a blocking lwIP socket.
 * @param user_data Pointer to noxtls_https_conn_t.
 * @param data Receive buffer.
 * @param len Buffer size.
 * @return Bytes received on success, negative on error.
 */
static int32_t https_tls_recv_cb(void *user_data, uint8_t *data, uint32_t len)
{
	noxtls_https_conn_t *conn;
	int received;

	if(user_data == NULL || data == NULL) {
		return -1;
	}
	conn = (noxtls_https_conn_t *)user_data;
	received = recv(conn->sock, data, len, 0);
	if(received < 0) {
		return -1;
	}
	return (int32_t)received;
}

#if defined(CONFIG_NOXTLS_HTTPS_SERVER_USE_WIFI) && CONFIG_NOXTLS_HTTPS_SERVER_USE_WIFI
/**
 * @brief WiFi station event handler: trigger connect, handle retries, capture IP.
 * @param arg Unused.
 * @param event_base Event base.
 * @param event_id Event id.
 * @param event_data Event-specific payload.
 */
static void https_wifi_event_handler(void *arg, esp_event_base_t event_base,
				     int32_t event_id, void *event_data)
{
	(void)arg;
	(void)event_data;

	if(event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
		esp_wifi_connect();
	} else if(event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
		if(g_wifi_retry_count < NOXTLS_HTTPS_WIFI_RETRY_MAX) {
			esp_wifi_connect();
			g_wifi_retry_count++;
			ESP_LOGI(NOXTLS_HTTPS_TAG, "retry to connect to AP");
		} else {
			xEventGroupSetBits(g_wifi_event_group, NOXTLS_HTTPS_WIFI_FAILED_BIT);
		}
	} else if(event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
		ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
		ESP_LOGI(NOXTLS_HTTPS_TAG, "got ip: " IPSTR, IP2STR(&event->ip_info.ip));
		g_wifi_retry_count = 0;
		xEventGroupSetBits(g_wifi_event_group, NOXTLS_HTTPS_WIFI_CONNECTED_BIT);
	}
}

/**
 * @brief Bring up the WiFi station and block until the IP is acquired.
 * @return 0 on success, negative on failure.
 */
static int https_wifi_start_station(void)
{
	esp_event_handler_instance_t any_id;
	esp_event_handler_instance_t got_ip;
	EventBits_t bits;
	wifi_config_t cfg;

	g_wifi_event_group = xEventGroupCreate();
	if(g_wifi_event_group == NULL) {
		return -1;
	}

	ESP_ERROR_CHECK(esp_netif_init());
	ESP_ERROR_CHECK(esp_event_loop_create_default());
	esp_netif_create_default_wifi_sta();

	wifi_init_config_t init_cfg = WIFI_INIT_CONFIG_DEFAULT();
	ESP_ERROR_CHECK(esp_wifi_init(&init_cfg));

	ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
							    &https_wifi_event_handler, NULL,
							    &any_id));
	ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
							    &https_wifi_event_handler, NULL,
							    &got_ip));

	memset(&cfg, 0, sizeof(cfg));
	strncpy((char *)cfg.sta.ssid, CONFIG_NOXTLS_HTTPS_SERVER_WIFI_SSID,
		sizeof(cfg.sta.ssid) - 1U);
	strncpy((char *)cfg.sta.password, CONFIG_NOXTLS_HTTPS_SERVER_WIFI_PASSWORD,
		sizeof(cfg.sta.password) - 1U);
	cfg.sta.threshold.authmode = WIFI_AUTH_OPEN;

#if CONFIG_NOXTLS_HTTPS_SERVER_LOG_WIFI_PASSWORD
	ESP_LOGI(NOXTLS_HTTPS_TAG, "WiFi SSID='%s' password='%s'",
		 (const char *)cfg.sta.ssid, (const char *)cfg.sta.password);
#else
	{
		size_t pw_len = strlen((const char *)cfg.sta.password);
		ESP_LOGI(NOXTLS_HTTPS_TAG,
			 "WiFi SSID='%s' password=<hidden, %u chars>",
			 (const char *)cfg.sta.ssid, (unsigned)pw_len);
	}
#endif

	ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
	ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &cfg));
	ESP_ERROR_CHECK(esp_wifi_start());

	bits = xEventGroupWaitBits(g_wifi_event_group,
				   NOXTLS_HTTPS_WIFI_CONNECTED_BIT | NOXTLS_HTTPS_WIFI_FAILED_BIT,
				   pdFALSE, pdFALSE, portMAX_DELAY);
	if((bits & NOXTLS_HTTPS_WIFI_CONNECTED_BIT) == 0U) {
		ESP_LOGE(NOXTLS_HTTPS_TAG, "failed to connect to AP");
		return -1;
	}
	/* Avoid WiFi PM beacon timers racing a long, CPU-heavy TLS handshake on main. */
	ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));
	return 0;
}
#endif /* CONFIG_NOXTLS_HTTPS_SERVER_USE_WIFI */

/**
 * @brief Open and listen on a TCP socket on the configured port.
 * @return Listening socket fd, or negative errno on failure.
 */
static int https_listen_socket(void)
{
	struct sockaddr_in addr;
	int sock;
	int yes;

	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(sock < 0) {
		ESP_LOGE(NOXTLS_HTTPS_TAG, "socket() failed: errno=%d", errno);
		return -1;
	}

	yes = 1;
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons((uint16_t)CONFIG_NOXTLS_HTTPS_SERVER_PORT);

	if(bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		ESP_LOGE(NOXTLS_HTTPS_TAG, "bind() failed: errno=%d", errno);
		close(sock);
		return -1;
	}
	if(listen(sock, CONFIG_NOXTLS_HTTPS_SERVER_BACKLOG) < 0) {
		ESP_LOGE(NOXTLS_HTTPS_TAG, "listen() failed: errno=%d", errno);
		close(sock);
		return -1;
	}

	ESP_LOGI(NOXTLS_HTTPS_TAG, "listening on TCP port %u",
		 (unsigned int)CONFIG_NOXTLS_HTTPS_SERVER_PORT);
	return sock;
}

/**
 * @brief Fill human-readable server key type for the status page.
 * @param ctx TLS server context after handshake.
 * @param out Output buffer.
 * @param out_len Size of out.
 */
static void https_metrics_key_type(const tls13_context_t *ctx, char *out, size_t out_len)
{
	if(ctx == NULL || out == NULL || out_len == 0U) {
		return;
	}
	if(ctx->server_private_ecdsa != NULL) {
		strncpy(out, "ECDSA P-256", out_len - 1U);
	} else if(ctx->server_private_rsa != NULL) {
		strncpy(out, "RSA", out_len - 1U);
#if NOXTLS_FEATURE_ED25519
	} else if(ctx->server_cert_use_ed25519) {
		strncpy(out, "Ed25519", out_len - 1U);
#endif
	} else {
		strncpy(out, "unknown", out_len - 1U);
	}
	out[out_len - 1U] = '\0';
}

/**
 * @brief Get the name of the TLS 1.3 group
 *
 * @param[in] group The group to get the name from
 * @return The name of the TLS 1.3 group
 */
static const char *https_tls13_group_name(uint16_t group)
{
	switch(group) {
	case TLS_NAMED_GROUP_X25519: return "X25519";
	case TLS_NAMED_GROUP_X448: return "X448";
	case TLS_NAMED_GROUP_SECP256R1: return "secp256r1";
	case TLS_NAMED_GROUP_SECP384R1: return "secp384r1";
	case TLS_NAMED_GROUP_SECP521R1: return "secp521r1";
	case TLS_NAMED_GROUP_FFDHE2048: return "ffdhe2048";
	case TLS_NAMED_GROUP_FFDHE3072: return "ffdhe3072";
	case TLS_NAMED_GROUP_FFDHE4096: return "ffdhe4096";
	case TLS_NAMED_GROUP_FFDHE6144: return "ffdhe6144";
	case TLS_NAMED_GROUP_FFDHE8192: return "ffdhe8192";
	default: return "unknown";
	}
}

/**
 * @brief Append a timing row to the buffer
 *
 * @param[in] buf The buffer to append the timing row to
 * @param[in] buf_len The length of the buffer
 * @param[in] used The number of bytes used in the buffer
 * @param[in] label The label to append to the buffer
 * @param[in] duration_us The duration in microseconds
 * @return The number of bytes appended to the buffer
 */
static int https_append_timing_row(char *buf, size_t buf_len, int used,
				       const char *label, uint64_t duration_us)
{
	int n;

	if(buf == NULL || label == NULL || used < 0 || (size_t)used >= buf_len) {
		return -1;
	}
	if(duration_us == 0U) {
		return used;
	}
	n = snprintf(buf + used, buf_len - (size_t)used,
		     "<tr><td>%s</td><td>%.2f ms</td></tr>\r\n",
		     label, (double)duration_us / 1000.0);
	if(n <= 0 || (size_t)n >= (buf_len - (size_t)used)) {
		return -1;
	}
	return used + n;
}

/**
 * @brief Log the accept timing
 *
 * @param[in] ctx The TLS 1.3 context
 * @return void
 */
static void https_log_accept_timing(const tls13_context_t *ctx)
{
	const tls13_accept_timing_t *timing;

	if(ctx == NULL) {
		return;
	}
	timing = &ctx->last_accept_timing;
	ESP_LOGI(NOXTLS_HTTPS_TAG,
		 "accept timing ms: CH=%.2f cert_select=%.2f SH=%.2f key_share=%.2f "
		 "cert=%.2f cert_verify=%.2f finished=%.2f recv_finished=%.2f total=%.2f",
		 (double)timing->recv_client_hello_us / 1000.0,
		 (double)(timing->pick_server_identity_us +
			  timing->select_certificate_sig_scheme_us +
			  timing->sni_check_us) / 1000.0,
		 (double)timing->send_server_hello_us / 1000.0,
		 (double)(timing->process_client_key_share_us +
			  timing->derive_handshake_keys_us) / 1000.0,
		 (double)timing->send_certificate_us / 1000.0,
		 (double)timing->send_certificate_verify_us / 1000.0,
		 (double)(timing->send_finished_us +
			  timing->derive_application_secrets_us +
			  timing->install_server_application_write_keys_us) / 1000.0,
		 (double)(timing->recv_finished_us +
			  timing->install_client_application_read_keys_us) / 1000.0,
		 (double)timing->total_us / 1000.0);
	if(timing->send_middlebox_compat_ccs_us != 0U ||
	   timing->send_encrypted_extensions_us != 0U ||
	   timing->send_new_session_ticket_us != 0U) {
		ESP_LOGI(NOXTLS_HTTPS_TAG,
			 "accept timing detail ms: ccs=%.2f ee=%.2f cert_req=%.2f "
			 "nst=%.2f",
			 (double)timing->send_middlebox_compat_ccs_us / 1000.0,
			 (double)timing->send_encrypted_extensions_us / 1000.0,
			 (double)timing->send_certificate_request_us / 1000.0,
			 (double)timing->send_new_session_ticket_us / 1000.0);
	}
	if(timing->send_server_hello_key_share_gen_us != 0U ||
	   timing->process_client_key_share_compute_secret_us != 0U ||
	   timing->send_certificate_verify_sign_us != 0U) {
		const noxtls_ecdsa_sign_timing_t *ecdsa_timing = noxtls_ecdsa_last_sign_timing();
		ESP_LOGI(NOXTLS_HTTPS_TAG,
			 "accept crypto detail ms: sh_keygen=%.2f sh_send=%.2f "
			 "x25519_shared=%.2f hs_keys=%.2f cv_prehash=%.2f cv_sign=%.2f "
			 "cv_der=%.2f cv_send=%.2f",
			 (double)timing->send_server_hello_key_share_gen_us / 1000.0,
			 (double)timing->send_server_hello_record_send_us / 1000.0,
			 (double)timing->process_client_key_share_compute_secret_us / 1000.0,
			 (double)timing->process_client_key_share_derive_keys_us / 1000.0,
			 (double)timing->send_certificate_verify_build_tosign_us / 1000.0,
			 (double)timing->send_certificate_verify_sign_us / 1000.0,
			 (double)timing->send_certificate_verify_der_encode_us / 1000.0,
			 (double)timing->send_certificate_verify_record_send_us / 1000.0);
		if(timing->send_certificate_verify_sign_us != 0U &&
		   ecdsa_timing->total_us != 0U) {
			ESP_LOGI(NOXTLS_HTTPS_TAG,
				 "ecdsa sign detail ms: hash=%.2f accel=%.2f nonce=%.2f "
				 "kG=%.2f r_reduce=%.2f k_inv=%.2f s=%.2f self_verify=%.2f "
				 "total=%.2f attempts=%u",
				 (double)ecdsa_timing->hash_prepare_us / 1000.0,
				 (double)ecdsa_timing->accel_port_us / 1000.0,
				 (double)ecdsa_timing->nonce_generate_us / 1000.0,
				 (double)ecdsa_timing->base_point_mul_us / 1000.0,
				 (double)ecdsa_timing->r_reduce_us / 1000.0,
				 (double)ecdsa_timing->nonce_inv_us / 1000.0,
				 (double)ecdsa_timing->s_compute_us / 1000.0,
				 (double)ecdsa_timing->self_verify_us / 1000.0,
				 (double)ecdsa_timing->total_us / 1000.0,
				 (unsigned int)ecdsa_timing->attempts);
		}
	}
}

/**
 * @brief Render the HTTP response body describing the TLS connection and timings.
 * @param ctx TLS 1.3 context with negotiated parameters.
 * @param metrics Session timing collected in https_serve_one().
 * @param buf Output buffer.
 * @param buf_len Buffer size.
 * @return Number of bytes written, or negative on error.
 */
static int https_render_response(const tls13_context_t *ctx,
				 https_session_metrics_t *metrics,
				 char *buf, uint32_t buf_len)
{
	char body[NOXTLS_HTTPS_RESPONSE_MAX];
	char accept_timing_rows[1400];
	int body_len;
	int accept_timing_len;
	int total;
	const char *alpn;
	double hs_ms;
	double recv_ms;
	double send_ms;
	double total_ms;
	const tls13_accept_timing_t *timing;

	if(ctx == NULL || metrics == NULL) {
		return -1;
	}

	alpn = (metrics->alpn[0] != '\0') ? metrics->alpn : "(none)";
	hs_ms = (double)metrics->handshake_us / 1000.0;
	recv_ms = (double)metrics->request_recv_us / 1000.0;
	send_ms = (double)metrics->response_send_us / 1000.0;
	total_ms = (double)metrics->session_total_us / 1000.0;
	timing = &ctx->last_accept_timing;
	accept_timing_len = 0;
	accept_timing_rows[0] = '\0';
	accept_timing_len = https_append_timing_row(accept_timing_rows, sizeof(accept_timing_rows),
						      accept_timing_len,
						      "Receive ClientHello",
						      timing->recv_client_hello_us);
	accept_timing_len = https_append_timing_row(accept_timing_rows, sizeof(accept_timing_rows),
						      accept_timing_len,
						      "Pick certificate identity",
						      timing->pick_server_identity_us);
	accept_timing_len = https_append_timing_row(accept_timing_rows, sizeof(accept_timing_rows),
						      accept_timing_len,
						      "Select certificate signature scheme",
						      timing->select_certificate_sig_scheme_us);
	accept_timing_len = https_append_timing_row(accept_timing_rows, sizeof(accept_timing_rows),
						      accept_timing_len,
						      "SNI check",
						      timing->sni_check_us);
	accept_timing_len = https_append_timing_row(accept_timing_rows, sizeof(accept_timing_rows),
						      accept_timing_len,
						      "Send ServerHello",
						      timing->send_server_hello_us);
	accept_timing_len = https_append_timing_row(accept_timing_rows, sizeof(accept_timing_rows),
						      accept_timing_len,
						      "Send compatibility CCS",
						      timing->send_middlebox_compat_ccs_us);
	accept_timing_len = https_append_timing_row(accept_timing_rows, sizeof(accept_timing_rows),
						      accept_timing_len,
						      "Process client key share / derive handshake secret",
						      timing->process_client_key_share_us +
						      timing->derive_handshake_keys_us);
	accept_timing_len = https_append_timing_row(accept_timing_rows, sizeof(accept_timing_rows),
						      accept_timing_len,
						      "Send EncryptedExtensions",
						      timing->send_encrypted_extensions_us);
	accept_timing_len = https_append_timing_row(accept_timing_rows, sizeof(accept_timing_rows),
						      accept_timing_len,
						      "Send CertificateRequest",
						      timing->send_certificate_request_us);
	accept_timing_len = https_append_timing_row(accept_timing_rows, sizeof(accept_timing_rows),
						      accept_timing_len,
						      "Send Certificate",
						      timing->send_certificate_us);
	accept_timing_len = https_append_timing_row(accept_timing_rows, sizeof(accept_timing_rows),
						      accept_timing_len,
						      "Send CertificateVerify",
						      timing->send_certificate_verify_us);
	accept_timing_len = https_append_timing_row(accept_timing_rows, sizeof(accept_timing_rows),
						      accept_timing_len,
						      "Send Finished",
						      timing->send_finished_us);
	accept_timing_len = https_append_timing_row(accept_timing_rows, sizeof(accept_timing_rows),
						      accept_timing_len,
						      "Derive application secrets",
						      timing->derive_application_secrets_us);
	accept_timing_len = https_append_timing_row(accept_timing_rows, sizeof(accept_timing_rows),
						      accept_timing_len,
						      "Install server app write keys",
						      timing->install_server_application_write_keys_us);
	accept_timing_len = https_append_timing_row(accept_timing_rows, sizeof(accept_timing_rows),
						      accept_timing_len,
						      "Receive client certificate",
						      timing->recv_client_certificate_us);
	accept_timing_len = https_append_timing_row(accept_timing_rows, sizeof(accept_timing_rows),
						      accept_timing_len,
						      "Receive client CertificateVerify",
						      timing->recv_client_certificate_verify_us);
	accept_timing_len = https_append_timing_row(accept_timing_rows, sizeof(accept_timing_rows),
						      accept_timing_len,
						      "Receive Finished",
						      timing->recv_finished_us);
	accept_timing_len = https_append_timing_row(accept_timing_rows, sizeof(accept_timing_rows),
						      accept_timing_len,
						      "Install client app read keys",
						      timing->install_client_application_read_keys_us);
	accept_timing_len = https_append_timing_row(accept_timing_rows, sizeof(accept_timing_rows),
						      accept_timing_len,
						      "Send NewSessionTicket",
						      timing->send_new_session_ticket_us);
	if(accept_timing_len < 0) {
		return -1;
	}

	body_len = snprintf(body, sizeof(body),
			    "<!DOCTYPE html>\r\n"
			    "<html><head><meta charset=\"utf-8\">"
			    "<title>NoxTLS ESP HTTPS</title>\r\n"
			    "<style>"
			    "body{font-family:system-ui,sans-serif;margin:1.5rem;max-width:42rem}"
			    "table{border-collapse:collapse;width:100%%}"
			    "th,td{border:1px solid #ccc;padding:.4rem .6rem;text-align:left}"
			    "th{background:#f4f4f4}"
			    "code{font-size:0.95em}"
			    "</style></head>\r\n"
			    "<body><h1>NoxTLS on ESP-IDF</h1>\r\n"
			    "<p>TLS 1.3 handshake completed successfully.</p>\r\n"
			    "<h2>Timing</h2>\r\n"
			    "<table>\r\n"
			    "<tr><th>Phase</th><th>Duration</th></tr>\r\n"
			    "<tr><td>TLS handshake (accept)</td><td>%.2f ms</td></tr>\r\n"
			    "<tr><td>HTTP request (TLS recv)</td><td>%.2f ms</td></tr>\r\n"
			    "<tr><td>HTTP response (TLS send)</td><td>%.2f ms</td></tr>\r\n"
			    "<tr><td><strong>Total (accept &rarr; response sent)</strong></td>"
			    "<td><strong>%.2f ms</strong></td></tr>\r\n"
			    "</table>\r\n"
			    "<h2>TLS Accept Breakdown</h2>\r\n"
			    "<table>\r\n"
			    "<tr><th>Step</th><th>Duration</th></tr>\r\n"
			    "%s"
			    "<tr><td><strong>Total accept()</strong></td><td><strong>%.2f ms</strong></td></tr>\r\n"
			    "</table>\r\n"
			    "<h2>Negotiated parameters</h2>\r\n"
			    "<table>\r\n"
			    "<tr><th>Parameter</th><th>Value</th></tr>\r\n"
			    "<tr><td>Cipher suite</td><td><code>0x%04X</code></td></tr>\r\n"
			    "<tr><td>ALPN</td><td><code>%s</code></td></tr>\r\n"
			    "<tr><td>Server key</td><td>%s</td></tr>\r\n"
			    "<tr><td>Key exchange group</td><td><code>%s</code></td></tr>\r\n"
			    "<tr><td>PSK mode</td><td>%s</td></tr>\r\n"
			    "</table>\r\n"
			    "<h2>Device / crypto</h2>\r\n"
			    "<table>\r\n"
			    "<tr><th>Parameter</th><th>Value</th></tr>\r\n"
			    "<tr><td>Target</td><td>%s</td></tr>\r\n"
			    "<tr><td>CPU clock</td><td>%u MHz</td></tr>\r\n"
			    "<tr><td>HW ECC (P-256)</td><td>%s</td></tr>\r\n"
			    "<tr><td>HW MPI (P-256)</td><td>%s</td></tr>\r\n"
			    "<tr><td>Free heap</td><td>%u bytes</td></tr>\r\n"
			    "<tr><td>Min free heap (session)</td><td>%u bytes</td></tr>\r\n"
			    "<tr><td>HTTP request size</td><td>%u bytes</td></tr>\r\n"
			    "<tr><td>HTML body size</td><td>%u bytes</td></tr>\r\n"
			    "</table>\r\n"
			    "</body></html>\r\n",
			    hs_ms, recv_ms, send_ms, total_ms,
			    accept_timing_rows, (double)timing->total_us / 1000.0,
			    (unsigned int)metrics->cipher_suite, alpn,
			    metrics->key_type,
			    metrics->kex_group,
			    ctx->psk_in_use ? "yes" : "no",
			    CONFIG_IDF_TARGET,
			    (unsigned int)metrics->cpu_mhz,
			    metrics->hw_ecc, metrics->hw_mpi,
			    (unsigned int)metrics->free_heap,
			    (unsigned int)metrics->min_free_heap,
			    (unsigned int)metrics->request_bytes,
			    (unsigned int)metrics->response_body_bytes);
	if(body_len <= 0 || (size_t)body_len >= sizeof(body)) {
		return -1;
	}
	metrics->response_body_bytes = (uint32_t)body_len;

	total = snprintf(buf, buf_len,
			 "HTTP/1.0 200 OK\r\n"
			 "Content-Type: text/html; charset=utf-8\r\n"
			 "Content-Length: %d\r\n"
			 "Connection: close\r\n"
			 "\r\n"
			 "%s",
			 body_len, body);
	if(total <= 0 || (uint32_t)total >= buf_len) {
		return -1;
	}
	return total;
}

/**
 * @brief Run one full client session: TLS handshake, request read, HTTP response, close.
 * @param client_sock Accepted client socket fd.
 * @param cert_der Server certificate DER bytes (leaf).
 * @param cert_der_len Length of cert_der.
 * @param key Parsed server private key (RSA or ECC).
 * @return 0 on success, negative on failure.
 */
static int https_serve_one(int client_sock,
			   const uint8_t *cert_der, uint32_t cert_der_len,
			   const x509_private_key_t *key,
			   rsa_key_t *server_rsa_key,
			   ecc_key_t *server_ecc_key)
{
	noxtls_https_conn_t conn;
	tls13_context_t *tls_ctx = NULL;
	noxtls_return_t rc;
	uint8_t request_buf[NOXTLS_HTTPS_RX_CHUNK];
	uint32_t request_len;
	char *response_buf = NULL;
	uint32_t response_buf_len = NOXTLS_HTTPS_RESPONSE_MAX + 256U;
	int response_len;
	rsa_key_t server_rsa;
	ecc_key_t server_ecc;
	int rsa_loaded;
	int ecc_loaded;
	int ret;
	https_session_metrics_t metrics;
	int64_t session_t0;

	conn.sock = client_sock;
	memset(&metrics, 0, sizeof(metrics));
	session_t0 = esp_timer_get_time();
	metrics.cpu_mhz = (uint32_t)CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ;
	noxtls_esp_hw_ecc_status_str(metrics.hw_ecc, (unsigned int)sizeof(metrics.hw_ecc));
	strncpy(metrics.hw_mpi,
		noxtls_esp_hw_mpi_compiled_in() ? "active" : "stub/off",
		sizeof(metrics.hw_mpi) - 1U);
	memset(&server_rsa, 0, sizeof(server_rsa));
	memset(&server_ecc, 0, sizeof(server_ecc));
	rsa_loaded = 0;
	ecc_loaded = 0;
	ret = -1;

	response_buf = (char *)malloc(response_buf_len);
	if(response_buf == NULL) {
		ESP_LOGE(NOXTLS_HTTPS_TAG, "malloc(response) failed");
		goto cleanup;
	}

	ESP_LOGI(NOXTLS_HTTPS_TAG, "session start free_heap=%u min_free_heap=%u",
		 (unsigned int)esp_get_free_heap_size(),
		 (unsigned int)esp_get_minimum_free_heap_size());

	/* tls13_context_t is multi-KB; keep it off the session task stack (see sdkconfig). */
	tls_ctx = (tls13_context_t *)calloc(1, sizeof(*tls_ctx));
	if(tls_ctx == NULL) {
		ESP_LOGE(NOXTLS_HTTPS_TAG, "calloc(tls13_context_t) failed");
		goto cleanup;
	}

	rc = noxtls_tls13_context_init(tls_ctx, TLS_ROLE_SERVER);
	if(rc != NOXTLS_RETURN_SUCCESS) {
		ESP_LOGE(NOXTLS_HTTPS_TAG, "noxtls_tls13_context_init failed: %d", rc);
		goto cleanup;
	}

	rc = noxtls_tls_set_io_callbacks(&tls_ctx->base.base, https_tls_send_cb,
					 https_tls_recv_cb, &conn);
	if(rc != NOXTLS_RETURN_SUCCESS) {
		ESP_LOGE(NOXTLS_HTTPS_TAG, "noxtls_tls_set_io_callbacks failed: %d", rc);
		goto cleanup;
	}

	if(server_rsa_key != NULL) {
		noxtls_tls13_set_server_private_rsa(tls_ctx, server_rsa_key);
	} else if(server_ecc_key != NULL) {
		noxtls_tls13_set_server_private_ecdsa(tls_ctx, server_ecc_key);
	} else if(key->key_type == X509_PRIVATE_KEY_RSA) {
		if(noxtls_x509_private_key_to_rsa_key(key, &server_rsa) != NOXTLS_RETURN_SUCCESS) {
			ESP_LOGE(NOXTLS_HTTPS_TAG, "convert to rsa_key_t failed");
			goto cleanup;
		}
		rsa_loaded = 1;
		noxtls_tls13_set_server_private_rsa(tls_ctx, &server_rsa);
	} else if(key->key_type == X509_PRIVATE_KEY_ECC) {
		if(noxtls_x509_private_key_to_ecc_key(key, &server_ecc) != NOXTLS_RETURN_SUCCESS) {
			ESP_LOGE(NOXTLS_HTTPS_TAG, "convert to ecc_key_t failed");
			goto cleanup;
		}
		ecc_loaded = 1;
		noxtls_tls13_set_server_private_ecdsa(tls_ctx, &server_ecc);
#if NOXTLS_FEATURE_ED25519
	} else if(key->key_type == X509_PRIVATE_KEY_ED25519) {
		uint32_t seed_len = 0;
		const uint8_t *seed = noxtls_x509_private_key_get_eddsa_seed(key, &seed_len);

		if(seed == NULL || seed_len != 32U) {
			ESP_LOGE(NOXTLS_HTTPS_TAG, "Ed25519 seed missing or invalid length");
			goto cleanup;
		}
		rc = noxtls_tls13_set_server_private_ed25519(tls_ctx, seed);
		if(rc != NOXTLS_RETURN_SUCCESS) {
			ESP_LOGE(NOXTLS_HTTPS_TAG, "noxtls_tls13_set_server_private_ed25519 failed: %d", rc);
			goto cleanup;
		}
#endif
	} else {
		ESP_LOGE(NOXTLS_HTTPS_TAG, "unsupported private key type: %d", key->key_type);
		goto cleanup;
	}

	tls_ctx->server_cert = (uint8_t *)cert_der;
	tls_ctx->server_cert_len = cert_der_len;

	noxtls_tls13_set_server_alpn_protocols(tls_ctx,
					     NOXTLS_HTTPS_ALPN_PROTOCOLS,
					     (uint32_t)(sizeof(NOXTLS_HTTPS_ALPN_PROTOCOLS) /
							sizeof(NOXTLS_HTTPS_ALPN_PROTOCOLS[0])));

#if defined(CONFIG_NOXTLS_HTTPS_SERVER_HANDSHAKE_DEBUG) && CONFIG_NOXTLS_HTTPS_SERVER_HANDSHAKE_DEBUG
	noxtls_debug_set_level(2);
	ESP_LOGW(NOXTLS_HTTPS_TAG, "handshake debug: NoxTLS UART logging enabled");
#endif

	{
		int64_t hs_t0 = esp_timer_get_time();
		rc = noxtls_tls13_accept(tls_ctx);
		metrics.handshake_us = esp_timer_get_time() - hs_t0;
	}

#if defined(CONFIG_NOXTLS_HTTPS_SERVER_HANDSHAKE_DEBUG) && CONFIG_NOXTLS_HTTPS_SERVER_HANDSHAKE_DEBUG
	noxtls_debug_set_level(0);
#endif

	if(rc != NOXTLS_RETURN_SUCCESS) {
		const char *fail_step = noxtls_tls13_last_accept_fail_step();

		if(tls_ctx->peer_alert_received != 0U &&
		   fail_step != NULL && strcmp(fail_step, "recv_finished") == 0) {
			ESP_LOGW(NOXTLS_HTTPS_TAG,
				 "handshake aborted after %lld ms at %s (peer alert; spare browser connection)",
				 (long long)(metrics.handshake_us / 1000LL), fail_step);
		} else {
			ESP_LOGE(NOXTLS_HTTPS_TAG, "handshake failed at step: %s (after %lld ms)",
				 (fail_step != NULL && fail_step[0] != '\0') ? fail_step : "(not recorded)",
				 (long long)(metrics.handshake_us / 1000LL));
		}
		https_log_accept_timing(tls_ctx);
		https_log_handshake_failure(tls_ctx, rc);
		goto cleanup;
	}

	ESP_LOGI(NOXTLS_HTTPS_TAG,
		 "TLS handshake OK in %lld ms cipher=0x%04x group=%s (free_heap=%u min_free_heap=%u)",
		 (long long)(metrics.handshake_us / 1000LL),
		 (unsigned int)tls_ctx->cipher_suite,
		 https_tls13_group_name((uint16_t)tls_ctx->selected_kex_group),
		 (unsigned int)esp_get_free_heap_size(),
		 (unsigned int)esp_get_minimum_free_heap_size());
	https_log_accept_timing(tls_ctx);

	metrics.cipher_suite = (uint16_t)tls_ctx->cipher_suite;
	if(tls_ctx->negotiated_alpn_len > 0U &&
	   tls_ctx->negotiated_alpn_len < sizeof(metrics.alpn)) {
		memcpy(metrics.alpn, tls_ctx->negotiated_alpn, tls_ctx->negotiated_alpn_len);
		metrics.alpn[tls_ctx->negotiated_alpn_len] = '\0';
	}
	https_metrics_key_type(tls_ctx, metrics.key_type, sizeof(metrics.key_type));
	strncpy(metrics.kex_group,
		https_tls13_group_name((uint16_t)tls_ctx->selected_kex_group),
		sizeof(metrics.kex_group) - 1U);
	metrics.kex_group[sizeof(metrics.kex_group) - 1U] = '\0';

	{
		int64_t recv_t0 = esp_timer_get_time();
		request_len = sizeof(request_buf);
		rc = noxtls_tls13_recv(tls_ctx, request_buf, &request_len);
		metrics.request_recv_us = esp_timer_get_time() - recv_t0;
		metrics.request_bytes = request_len;
	}
	if(rc != NOXTLS_RETURN_SUCCESS) {
		ESP_LOGW(NOXTLS_HTTPS_TAG, "noxtls_tls13_recv: %d", rc);
		/* still try to write a response anyway */
	} else {
		ESP_LOGI(NOXTLS_HTTPS_TAG, "received %u request bytes",
			 (unsigned int)request_len);
	}

	metrics.free_heap = (uint32_t)esp_get_free_heap_size();
	metrics.min_free_heap = (uint32_t)esp_get_minimum_free_heap_size();

	response_len = https_render_response(tls_ctx, &metrics, response_buf, response_buf_len);
	if(response_len < 0) {
		ESP_LOGE(NOXTLS_HTTPS_TAG, "render response failed");
		goto cleanup;
	}

	{
		int64_t send_t0 = esp_timer_get_time();
		rc = noxtls_tls13_send(tls_ctx, (const uint8_t *)response_buf, (uint32_t)response_len);
		metrics.response_send_us = esp_timer_get_time() - send_t0;
	}
	metrics.session_total_us = esp_timer_get_time() - session_t0;
	if(rc != NOXTLS_RETURN_SUCCESS) {
		ESP_LOGE(NOXTLS_HTTPS_TAG, "noxtls_tls13_send failed: %d", rc);
		goto cleanup;
	}

	noxtls_tls13_close(tls_ctx);
	ret = 0;

cleanup:
	if(rsa_loaded) noxtls_rsa_key_free(&server_rsa);
	if(ecc_loaded) noxtls_ecc_key_free(&server_ecc);
	if(tls_ctx != NULL) {
		noxtls_tls13_context_free(tls_ctx);
		free(tls_ctx);
	}
	if(response_buf != NULL) {
		free(response_buf);
	}
	close(client_sock);
	return ret;
}

/**
 * @brief FreeRTOS worker: one TLS+HTTP session (large stack, off the accept loop task).
 * @param arg Heap-allocated https_session_args_t (freed here).
 */
static void https_session_task(void *arg)
{
	https_session_args_t *session = (https_session_args_t *)arg;
	int rc;

	if(session == NULL) {
		vTaskDelete(NULL);
		return;
	}
	rc = https_serve_one(session->client_sock, session->cert_der, session->cert_der_len,
			     session->server_key, session->server_rsa, session->server_ecc);
	if(session->notify_task != NULL) {
		xTaskNotify(session->notify_task, (uint32_t)rc, eSetValueWithOverwrite);
	}
	free(session);
	vTaskDelete(NULL);
}

/**
 * @brief Run https_serve_one on a dedicated task and block until it finishes.
 * @return 0 on success, negative on failure to spawn the worker.
 */
static int https_run_session_task(int client_sock, const uint8_t *cert_der, uint32_t cert_der_len,
				  x509_private_key_t *server_key,
				  rsa_key_t *server_rsa,
				  ecc_key_t *server_ecc)
{
	https_session_args_t *session;
	BaseType_t created;
	uint32_t notify_rc = 1U;

	session = (https_session_args_t *)calloc(1, sizeof(*session));
	if(session == NULL) {
		close(client_sock);
		return -1;
	}
	session->notify_task = xTaskGetCurrentTaskHandle();
	session->client_sock = client_sock;
	session->cert_der = cert_der;
	session->cert_der_len = cert_der_len;
	session->server_key = server_key;
	session->server_rsa = server_rsa;
	session->server_ecc = server_ecc;

	created = xTaskCreate(https_session_task, "noxtls_https",
			      NOXTLS_HTTPS_SESSION_TASK_STACK, session,
			      NOXTLS_HTTPS_SESSION_TASK_PRIORITY, NULL);
	if(created != pdPASS) {
		ESP_LOGE(NOXTLS_HTTPS_TAG,
			 "xTaskCreate(https) failed (stack=%u); free_heap=%u",
			 (unsigned int)NOXTLS_HTTPS_SESSION_TASK_STACK,
			 (unsigned int)esp_get_free_heap_size());
		free(session);
		close(client_sock);
		return -1;
	}

	(void)xTaskNotifyWait(0U, 0U, &notify_rc, portMAX_DELAY);
	return (notify_rc == 0U) ? 0 : -1;
}

/**
 * @brief Length of an EMBED_TXTFILES blob (may include a trailing NUL).
 * @param start Embedded start symbol.
 * @param end Embedded end symbol (one past last byte).
 * @return Byte length excluding a single trailing NUL, if present.
 */
static uint32_t https_embedded_txt_len(const uint8_t *start, const uint8_t *end)
{
	uint32_t len = (uint32_t)(end - start);

	if(len > 0U && start[len - 1U] == 0U) {
		len--;
	}
	return len;
}

/**
 * @brief Convert PEM block to DER, allocating an output buffer of suitable size.
 * @param pem PEM bytes.
 * @param pem_len PEM length.
 * @param der_out Output: allocated DER buffer (caller frees with free()).
 * @param der_len_out Output: DER length.
 * @return 0 on success, negative on failure.
 */
static int https_pem_to_der_alloc(const uint8_t *pem, uint32_t pem_len,
				  uint8_t **der_out, uint32_t *der_len_out)
{
	uint8_t *der;
	uint32_t der_len;

	der = (uint8_t *)malloc(pem_len);
	if(der == NULL) return -1;

	der_len = pem_len;
	if(noxtls_certificate_pem_to_der((uint8_t *)pem, pem_len, der,
					 &der_len) != NOXTLS_RETURN_SUCCESS) {
		free(der);
		return -1;
	}
	*der_out = der;
	*der_len_out = der_len;
	return 0;
}

/**
 * @brief The main function.
 *
 * @return void
 */
void app_main(void)
{
	uint32_t cert_pem_len;
	uint32_t key_pem_len;
	uint8_t *cert_der = NULL;
	uint32_t cert_der_len = 0U;
	x509_private_key_t key;
	rsa_key_t server_rsa;
	ecc_key_t server_ecc;
	int key_inited = 0;
	int server_rsa_inited = 0;
	int server_ecc_inited = 0;
	int listen_sock = -1;

	memset(&server_rsa, 0, sizeof(server_rsa));
	memset(&server_ecc, 0, sizeof(server_ecc));

	ESP_LOGI(NOXTLS_HTTPS_TAG, "NoxTLS ESP-IDF HTTPS server example");
	https_log_build_config_hints();

	esp_err_t err = nvs_flash_init();
	if(err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
		ESP_ERROR_CHECK(nvs_flash_erase());
		err = nvs_flash_init();
	}
	ESP_ERROR_CHECK(err);

	(void)noxtls_esp_idf_init();
	{
		char ecc_status[sizeof(((https_session_metrics_t *)0)->hw_ecc)];

		noxtls_esp_hw_ecc_status_str(ecc_status, (unsigned int)sizeof(ecc_status));
		ESP_LOGI(NOXTLS_HTTPS_TAG,
			 "HW ECC (P-256): %s on %s (MPI for field math may still be active)",
			 ecc_status, CONFIG_IDF_TARGET);
	}

#if defined(CONFIG_NOXTLS_HTTPS_SERVER_USE_WIFI) && CONFIG_NOXTLS_HTTPS_SERVER_USE_WIFI
	if(https_wifi_start_station() != 0) {
		ESP_LOGE(NOXTLS_HTTPS_TAG, "WiFi bring-up failed");
		return;
	}
#endif

	cert_pem_len = https_embedded_txt_len(g_server_cert_pem_start, g_server_cert_pem_end);
	key_pem_len = https_embedded_txt_len(g_server_key_pem_start, g_server_key_pem_end);

	if(https_pem_to_der_alloc(g_server_cert_pem_start, cert_pem_len,
				  &cert_der, &cert_der_len) != 0) {
		ESP_LOGE(NOXTLS_HTTPS_TAG,
			 "failed to decode embedded server_cert.pem (placeholder?); "
			 "see certs/server_cert.pem header for the openssl command.");
		goto cleanup;
	}

	if(noxtls_x509_private_key_init(&key) != NOXTLS_RETURN_SUCCESS) {
		ESP_LOGE(NOXTLS_HTTPS_TAG, "private key init failed");
		goto cleanup;
	}
	key_inited = 1;

	if(noxtls_x509_private_key_parse_pem(&key, g_server_key_pem_start,
					     key_pem_len) != NOXTLS_RETURN_SUCCESS) {
		ESP_LOGE(NOXTLS_HTTPS_TAG,
			 "failed to parse embedded server_key.pem (placeholder?); "
			 "see certs/server_key.pem header for the openssl command.");
		goto cleanup;
	}

	if(key.key_type == X509_PRIVATE_KEY_RSA) {
		if(noxtls_x509_private_key_to_rsa_key(&key, &server_rsa) != NOXTLS_RETURN_SUCCESS) {
			ESP_LOGE(NOXTLS_HTTPS_TAG, "failed to pre-convert RSA private key");
			goto cleanup;
		}
		server_rsa_inited = 1;
	} else if(key.key_type == X509_PRIVATE_KEY_ECC) {
		if(noxtls_x509_private_key_to_ecc_key(&key, &server_ecc) != NOXTLS_RETURN_SUCCESS) {
			ESP_LOGE(NOXTLS_HTTPS_TAG, "failed to pre-convert ECC private key");
			goto cleanup;
		}
		server_ecc_inited = 1;
	}

	listen_sock = https_listen_socket();
	if(listen_sock < 0) goto cleanup;

	while(1) {
		struct sockaddr_in client_addr;
		socklen_t client_addr_len = sizeof(client_addr);
		int client_sock;
		char client_ip[16];

		client_sock = accept(listen_sock, (struct sockaddr *)&client_addr,
				     &client_addr_len);
		if(client_sock < 0) {
			ESP_LOGE(NOXTLS_HTTPS_TAG, "accept() failed: errno=%d", errno);
			vTaskDelay(pdMS_TO_TICKS(100));
			continue;
		}

		inet_ntoa_r(client_addr.sin_addr, client_ip, sizeof(client_ip));
		ESP_LOGI(NOXTLS_HTTPS_TAG, "accepted %s:%u (free_heap=%u)", client_ip,
			 (unsigned int)ntohs(client_addr.sin_port),
			 (unsigned int)esp_get_free_heap_size());

			(void)https_run_session_task(client_sock, cert_der, cert_der_len, &key,
						     server_rsa_inited ? &server_rsa : NULL,
						     server_ecc_inited ? &server_ecc : NULL);
	}

cleanup:
	if(listen_sock >= 0) close(listen_sock);
	if(server_rsa_inited) noxtls_rsa_key_free(&server_rsa);
	if(server_ecc_inited) noxtls_ecc_key_free(&server_ecc);
	if(key_inited) noxtls_x509_private_key_free(&key);
	if(cert_der != NULL) free(cert_der);
}
