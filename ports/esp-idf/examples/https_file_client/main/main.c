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
* Summary: Downloads a file over HTTPS using `noxtls_tls13_connect` + 
*          HTTP GET and stores the response body into SPIFFS.
*
*
*****************************************************************************/

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_spiffs.h"
#include "esp_wifi.h"
#include "nvs_flash.h"
#include "sdkconfig.h"

#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"

#include "lwip/netdb.h"
#include "lwip/sockets.h"

#include "noxtls_common.h"
#include "noxtls_esp_idf.h"
#include "noxtls-lib/certs/noxtls_x509.h"
#include "noxtls-lib/tls/noxtls_tls13.h"

#define NOXTLS_FILE_TAG                "noxtls_file_client"
#define NOXTLS_FILE_WIFI_CONNECTED_BIT BIT0
#define NOXTLS_FILE_WIFI_FAIL_BIT      BIT1
#define NOXTLS_FILE_WIFI_RETRY_MAX     (5U)
#define NOXTLS_FILE_RX_CHUNK           (2048U)
#define NOXTLS_FILE_PART_PATH          CONFIG_NOXTLS_FILE_CLIENT_OUTPUT_PATH ".part"

typedef struct {
    int sock;
} file_conn_t;

extern const uint8_t g_root_ca_pem_start[] asm("_binary_root_ca_pem_start");
extern const uint8_t g_root_ca_pem_end[]   asm("_binary_root_ca_pem_end");

static EventGroupHandle_t g_wifi_event_group;
static uint32_t g_wifi_retry_count;

/**
 * @brief Send callback for NoxTLS I/O over lwIP BSD sockets.
 * @param user_data Connection context.
 * @param data Bytes to send.
 * @param len Length.
 * @return Bytes sent, or negative on error.
 */
static int32_t file_tls_send_cb(void *user_data, const uint8_t *data, uint32_t len)
{
    file_conn_t *conn = (file_conn_t *)user_data;
    int sent;

    if(conn == NULL || data == NULL) return -1;
    sent = send(conn->sock, data, len, 0);
    if(sent < 0) return -1;
    return (int32_t)sent;
}

/**
 * @brief Receive callback for NoxTLS I/O over lwIP BSD sockets.
 * @param user_data Connection context.
 * @param data Receive buffer.
 * @param len Maximum bytes to read.
 * @return Bytes received, or negative on error.
 */
static int32_t file_tls_recv_cb(void *user_data, uint8_t *data, uint32_t len)
{
    file_conn_t *conn = (file_conn_t *)user_data;
    int received;

    if(conn == NULL || data == NULL) return -1;
    received = recv(conn->sock, data, len, 0);
    if(received < 0) return -1;
    return (int32_t)received;
}

/**
 * @brief WiFi event handler.
 * @param arg User data.
 * @param event_base Event base.
 * @param event_id Event ID.
 * @param event_data Event data.
 */
static void file_wifi_event_handler(void *arg, esp_event_base_t event_base,
                                    int32_t event_id, void *event_data)
{
    (void)arg;

    if(event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if(event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        if(g_wifi_retry_count < NOXTLS_FILE_WIFI_RETRY_MAX) {
            esp_wifi_connect();
            g_wifi_retry_count++;
        } else {
            xEventGroupSetBits(g_wifi_event_group, NOXTLS_FILE_WIFI_FAIL_BIT);
        }
    } else if(event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
        ESP_LOGI(NOXTLS_FILE_TAG, "got ip: " IPSTR, IP2STR(&event->ip_info.ip));
        g_wifi_retry_count = 0;
        xEventGroupSetBits(g_wifi_event_group, NOXTLS_FILE_WIFI_CONNECTED_BIT);
    }
}

/**
 * @brief Start the WiFi station.
 * @return 0 on success, -1 on failure.
 */
static int file_wifi_start_station(void)
{
    esp_event_handler_instance_t any_id;
    esp_event_handler_instance_t got_ip;
    EventBits_t bits;
    wifi_config_t cfg;

    g_wifi_event_group = xEventGroupCreate();
    if(g_wifi_event_group == NULL) return -1;

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t init_cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&init_cfg));

    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                                        &file_wifi_event_handler, NULL, &any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                                                        &file_wifi_event_handler, NULL, &got_ip));

    memset(&cfg, 0, sizeof(cfg));
    strncpy((char *)cfg.sta.ssid, CONFIG_NOXTLS_FILE_CLIENT_WIFI_SSID, sizeof(cfg.sta.ssid) - 1U);
    strncpy((char *)cfg.sta.password, CONFIG_NOXTLS_FILE_CLIENT_WIFI_PASSWORD,
            sizeof(cfg.sta.password) - 1U);
    cfg.sta.threshold.authmode = WIFI_AUTH_OPEN;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &cfg));
    ESP_ERROR_CHECK(esp_wifi_start());

    bits = xEventGroupWaitBits(g_wifi_event_group,
                               NOXTLS_FILE_WIFI_CONNECTED_BIT | NOXTLS_FILE_WIFI_FAIL_BIT,
                               pdFALSE, pdFALSE, portMAX_DELAY);
    if((bits & NOXTLS_FILE_WIFI_CONNECTED_BIT) == 0U) {
        return -1;
    }
    return 0;
}

/**
 * @brief Mount the SPIFFS filesystem.
 * @return 0 on success, -1 on failure.
 */
static int file_spiffs_mount(void)
{
    esp_vfs_spiffs_conf_t conf = {
        .base_path = "/spiffs",
        .partition_label = "storage",
        .max_files = 4,
        .format_if_mount_failed = true,
    };

    esp_err_t rc = esp_vfs_spiffs_register(&conf);
    if(rc != ESP_OK) {
        ESP_LOGE(NOXTLS_FILE_TAG, "SPIFFS mount failed: %s", esp_err_to_name(rc));
        return -1;
    }
    return 0;
}

/**
 * @brief Connect to a TCP server.
 * @param host Hostname or IP address.
 * @param port Port number.
 * @return 0 on success, -1 on failure.
 */
static int file_tcp_connect(const char *host, uint16_t port)
{
    struct addrinfo hints;
    struct addrinfo *res;
    struct addrinfo *it;
    char port_str[8];
    int sock;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);
    if(getaddrinfo(host, port_str, &hints, &res) != 0 || res == NULL) {
        return -1;
    }

    sock = -1;
    for(it = res; it != NULL; it = it->ai_next) {
        sock = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if(sock < 0) continue;
        if(connect(sock, it->ai_addr, it->ai_addrlen) == 0) break;
        close(sock);
        sock = -1;
    }

    freeaddrinfo(res);
    return sock;
}

/**
 * @brief Configure the trust anchor.
 * @return 0 on success, -1 on failure.
 */
static int file_configure_trust_anchor(void)
{
    noxtls_return_t rc;
    x509_certificate_t ca;
    x509_certificate_chain_t chain;
    uint32_t pem_len;

    pem_len = (uint32_t)(g_root_ca_pem_end - g_root_ca_pem_start);
    if(pem_len == 0U) return -1;

    rc = noxtls_x509_certificate_init(&ca);
    if(rc != NOXTLS_RETURN_SUCCESS) return -1;

    rc = noxtls_x509_certificate_parse_pem(&ca, g_root_ca_pem_start, pem_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_x509_certificate_free(&ca);
        return -1;
    }

    rc = noxtls_x509_certificate_chain_init(&chain);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_x509_certificate_free(&ca);
        return -1;
    }

    rc = noxtls_x509_certificate_chain_add(&chain, &ca);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_x509_trust_store_set(&chain);
    }

    noxtls_x509_certificate_chain_free(&chain);
    noxtls_x509_certificate_free(&ca);
    return (rc == NOXTLS_RETURN_SUCCESS) ? 0 : -1;
}

#define NOXTLS_FILE_HEADER_MAX (2048U)

/**
 * @brief Case-insensitive prefix match.
 * @return 1 when @p s starts with @p prefix ignoring ASCII case.
 */
static int file_prefix_ieq(const char *s, const char *prefix)
{
    while(*prefix != '\0') {
        char a = *s;
        char b = *prefix;
        if(a >= 'A' && a <= 'Z') {
            a = (char)(a - 'A' + 'a');
        }
        if(b >= 'A' && b <= 'Z') {
            b = (char)(b - 'A' + 'a');
        }
        if(a != b) {
            return 0;
        }
        s++;
        prefix++;
    }
    return 1;
}

/**
 * @brief Check the status line and read Content-Length from a NUL-terminated header block.
 * @param[in]  hdr            Header bytes up to and including the blank line.
 * @param[out] content_length Content-Length value, or -1 when absent.
 * @return 0 for a 200 response with a well-formed (or absent) Content-Length, -1 otherwise.
 */
static int file_parse_http_headers(const char *hdr, long long *content_length)
{
    const char *line = hdr;

    *content_length = -1;
    if(!(file_prefix_ieq(hdr, "HTTP/1.1 200") || file_prefix_ieq(hdr, "HTTP/1.0 200")) ||
       (hdr[12] != ' ' && hdr[12] != '\r')) {
        return -1;
    }
    while((line = strstr(line, "\r\n")) != NULL) {
        line += 2;
        if(file_prefix_ieq(line, "content-length:")) {
            const char *v = line + 15;
            long long n = 0;
            int digits = 0;

            if(*content_length >= 0) {
                return -1; /* duplicate Content-Length */
            }
            while(*v == ' ' || *v == '\t') {
                v++;
            }
            while(*v >= '0' && *v <= '9') {
                if(n > (LLONG_MAX - 9) / 10) {
                    return -1;
                }
                n = (n * 10) + (long long)(*v - '0');
                v++;
                digits++;
            }
            while(*v == ' ' || *v == '\t') {
                v++;
            }
            if(digits == 0 || v[0] != '\r') {
                return -1;
            }
            *content_length = n;
        }
    }
    return 0;
}

/**
 * @brief Download an HTTPS file.
 * @return 0 on success, -1 on failure.
 */
static int file_download_https(void)
{
    file_conn_t conn;
    tls13_context_t tls;
    noxtls_return_t rc;
    char request[1024];
    uint8_t rx[NOXTLS_FILE_RX_CHUNK];
    uint32_t rx_len;
    FILE *fp;
    uint32_t total_body;
    int header_done;
    char header_buf[NOXTLS_FILE_HEADER_MAX];
    uint32_t header_len;
    long long content_length;
    int download_ok;

    conn.sock = file_tcp_connect(CONFIG_NOXTLS_FILE_CLIENT_HOST,
                                 (uint16_t)CONFIG_NOXTLS_FILE_CLIENT_PORT);
    if(conn.sock < 0) {
        ESP_LOGE(NOXTLS_FILE_TAG, "TCP connect failed");
        return -1;
    }

    rc = noxtls_tls13_context_init(&tls, TLS_ROLE_CLIENT);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        close(conn.sock);
        return -1;
    }

    tls.server_name = CONFIG_NOXTLS_FILE_CLIENT_HOST;
    tls.server_name_len = (uint16_t)strlen(CONFIG_NOXTLS_FILE_CLIENT_HOST);
    rc = noxtls_tls_set_io_callbacks(&tls.base.base, file_tls_send_cb, file_tls_recv_cb, &conn);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_tls13_context_free(&tls);
        close(conn.sock);
        return -1;
    }

    rc = noxtls_tls13_connect(&tls);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        ESP_LOGE(NOXTLS_FILE_TAG, "TLS connect failed: %d", (int)rc);
        noxtls_tls13_context_free(&tls);
        close(conn.sock);
        return -1;
    }

    snprintf(request, sizeof(request),
             "GET %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "User-Agent: NoxTLS-ESP-file-client/1.0\r\n"
             "Accept: */*\r\n"
             "Connection: close\r\n\r\n",
             CONFIG_NOXTLS_FILE_CLIENT_PATH,
             CONFIG_NOXTLS_FILE_CLIENT_HOST);

    rc = noxtls_tls13_send(&tls, (const uint8_t *)request, (uint32_t)strlen(request));
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_tls13_context_free(&tls);
        close(conn.sock);
        return -1;
    }

    /* Write to a temporary file and only rename it into place once the
     * response is complete and authenticated (close_notify). */
    fp = fopen(NOXTLS_FILE_PART_PATH, "wb");
    if(fp == NULL) {
        ESP_LOGE(NOXTLS_FILE_TAG, "failed to open output path: %s", NOXTLS_FILE_PART_PATH);
        noxtls_tls13_context_free(&tls);
        close(conn.sock);
        return -1;
    }

    total_body = 0U;
    header_done = 0;
    header_len = 0U;
    content_length = -1;
    download_ok = 0;

    while(1) {
        uint32_t start = 0U;

        rx_len = sizeof(rx);
        rc = noxtls_tls13_recv(&tls, rx, &rx_len);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            /* TCP close without close_notify, a forged record or a fatal alert. */
            ESP_LOGE(NOXTLS_FILE_TAG, "download cut or not authenticated (recv rc=%d)", (int)rc);
            break;
        }
        if(rx_len == 0U) {
            if(tls.base.base.state == TLS_STATE_CLOSING) {
                download_ok = 1; /* authenticated close_notify */
                break;
            }
            continue; /* empty application record */
        }

        if(header_done == 0) {
            uint32_t i;

            for(i = 0U; i < rx_len; i++) {
                if(header_len >= (uint32_t)(sizeof(header_buf) - 1U)) {
                    break;
                }
                header_buf[header_len++] = (char)rx[i];
                if(header_len >= 4U && memcmp(&header_buf[header_len - 4U], "\r\n\r\n", 4U) == 0) {
                    header_done = 1;
                    start = i + 1U;
                    break;
                }
            }
            if(header_done == 0) {
                if(header_len >= (uint32_t)(sizeof(header_buf) - 1U)) {
                    ESP_LOGE(NOXTLS_FILE_TAG, "response headers too large");
                    break;
                }
                continue;
            }
            header_buf[header_len] = '\0';
            if(file_parse_http_headers(header_buf, &content_length) != 0) {
                ESP_LOGE(NOXTLS_FILE_TAG, "unexpected HTTP status or malformed Content-Length");
                break;
            }
            if(start >= rx_len) {
                continue;
            }
        }

        if(total_body + (rx_len - start) > (uint32_t)CONFIG_NOXTLS_FILE_CLIENT_MAX_DOWNLOAD_BYTES) {
            ESP_LOGE(NOXTLS_FILE_TAG, "download exceeds max size");
            break;
        }
        if(fwrite(rx + start, 1U, rx_len - start, fp) != (size_t)(rx_len - start)) {
            ESP_LOGE(NOXTLS_FILE_TAG, "write to %s failed", NOXTLS_FILE_PART_PATH);
            break;
        }
        total_body += (rx_len - start);
    }

    if(download_ok != 0 && header_done == 0) {
        ESP_LOGE(NOXTLS_FILE_TAG, "no complete HTTP response received");
        download_ok = 0;
    }
    if(download_ok != 0 && content_length >= 0 && (long long)total_body != content_length) {
        ESP_LOGE(NOXTLS_FILE_TAG, "body length %u does not match Content-Length %lu",
                 (unsigned)total_body, (unsigned long)content_length);
        download_ok = 0;
    }
    if(fclose(fp) != 0) {
        download_ok = 0;
    }
    if(download_ok != 0) {
        noxtls_tls13_close(&tls);
    }
    noxtls_tls13_context_free(&tls);
    close(conn.sock);

    if(download_ok == 0) {
        (void)remove(NOXTLS_FILE_PART_PATH);
        ESP_LOGE(NOXTLS_FILE_TAG, "download failed; nothing saved to %s", CONFIG_NOXTLS_FILE_CLIENT_OUTPUT_PATH);
        return -1;
    }
    (void)remove(CONFIG_NOXTLS_FILE_CLIENT_OUTPUT_PATH);
    if(rename(NOXTLS_FILE_PART_PATH, CONFIG_NOXTLS_FILE_CLIENT_OUTPUT_PATH) != 0) {
        ESP_LOGE(NOXTLS_FILE_TAG, "rename to %s failed", CONFIG_NOXTLS_FILE_CLIENT_OUTPUT_PATH);
        (void)remove(NOXTLS_FILE_PART_PATH);
        return -1;
    }

    ESP_LOGI(NOXTLS_FILE_TAG, "download complete: %u bytes saved to %s",
             (unsigned)total_body, CONFIG_NOXTLS_FILE_CLIENT_OUTPUT_PATH);
    return 0;
}

/**
 * @brief Main function.
 */
void app_main(void)
{
    esp_err_t err;

    ESP_LOGI(NOXTLS_FILE_TAG, "NoxTLS HTTPS file client example");
    (void)noxtls_esp_idf_init();

    err = nvs_flash_init();
    if(err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);

    if(file_wifi_start_station() != 0) {
        ESP_LOGE(NOXTLS_FILE_TAG, "WiFi bring-up failed");
        return;
    }

    if(file_spiffs_mount() != 0) {
        return;
    }

    if(file_configure_trust_anchor() != 0) {
        ESP_LOGE(NOXTLS_FILE_TAG, "trust anchor parse failed (replace main/certs/root_ca.pem)");
        return;
    }

    if(file_download_https() != 0) {
        ESP_LOGE(NOXTLS_FILE_TAG, "download failed");
    }

    noxtls_x509_trust_store_clear();
}
