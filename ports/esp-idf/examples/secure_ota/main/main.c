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
* Summary: Secure OTA flow over NoxTLS HTTPS: stream firmware into OTA partition,
*          hash while downloading, optional digest pin, switch boot partition on success.
*
* Replace `main/certs/root_ca.pem` with the CA for your OTA server.
* Set `NOXTLS_SECURE_OTA_EXPECTED_SHA256_HEX` for integrity pinning.
* Secure Boot and Flash Encryption are controlled by ESP-IDF bootloader/security 
* config; this app logs whether those configs are enabled.
*
*****************************************************************************/

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_ota_ops.h"
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
#include "noxtls-lib/mdigest/sha256/noxtls_sha256.h"
#include "noxtls-lib/tls/noxtls_tls13.h"

#define NOXTLS_OTA_TAG                "noxtls_secure_ota"
#define NOXTLS_OTA_WIFI_CONNECTED_BIT BIT0
#define NOXTLS_OTA_WIFI_FAIL_BIT      BIT1
#define NOXTLS_OTA_WIFI_RETRY_MAX     (5U)
#define NOXTLS_OTA_RX_CHUNK           (2048U)

typedef struct {
    int sock;
} ota_conn_t;

extern const uint8_t g_root_ca_pem_start[] asm("_binary_root_ca_pem_start");
extern const uint8_t g_root_ca_pem_end[]   asm("_binary_root_ca_pem_end");

static EventGroupHandle_t g_wifi_event_group;
static uint32_t g_wifi_retry_count;

/**
 * @brief Convert a hexadecimal character to a nibble
 *
 * @param[in] c The character to convert
 * @return The nibble value of the character
 */
static int hex_nibble(char c)
{
    if(c >= '0' && c <= '9') return c - '0';
    if(c >= 'a' && c <= 'f') return c - 'a' + 10;
    if(c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/**
 * @brief Parse a 32-byte hexadecimal string into a 32-byte array
 *
 * @param[in] hex The hexadecimal string to parse
 * @param[out] out The array to store the parsed bytes
 * @return 0 on success, -1 on failure
 */
static int parse_hex32(const char *hex, uint8_t out[32])
{
    uint32_t i;

    if(hex == NULL || out == NULL) return -1;
    if(strlen(hex) != 64U) return -1;

    for(i = 0U; i < 32U; i++) {
        int hi = hex_nibble(hex[i * 2U]);
        int lo = hex_nibble(hex[i * 2U + 1U]);
        if(hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

/**
 * @brief The callback function for sending data
 *
 * @param[in] user_data The user data
 * @param[in] data The data to send
 * @param[in] len The length of the data to send
 * @return The length of the data sent
 */
static int32_t ota_tls_send_cb(void *user_data, const uint8_t *data, uint32_t len)
{
    ota_conn_t *conn = (ota_conn_t *)user_data;
    int sent;

    if(conn == NULL || data == NULL) return -1;
    sent = send(conn->sock, data, len, 0);
    if(sent < 0) return -1;
    return (int32_t)sent;
}

/**
 * @brief The callback function for receiving data
 *
 * @param[in] user_data The user data
 * @param[in] data The data to receive
 * @param[in] len The length of the data to receive
 * @return The length of the data received
 */
static int32_t ota_tls_recv_cb(void *user_data, uint8_t *data, uint32_t len)
{
    ota_conn_t *conn = (ota_conn_t *)user_data;
    int received;

    if(conn == NULL || data == NULL) return -1;
    received = recv(conn->sock, data, len, 0);
    if(received < 0) return -1;
    return (int32_t)received;
}

/**
 * @brief The event handler for the WiFi connection
 *
 * @param[in] arg The argument to the event handler
 * @param[in] event_base The base event of the event
 * @param[in] event_id The ID of the event
 * @param[in] event_data The data of the event
 */
static void ota_wifi_event_handler(void *arg, esp_event_base_t event_base,
                                   int32_t event_id, void *event_data)
{
    (void)arg;

    if(event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if(event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        if(g_wifi_retry_count < NOXTLS_OTA_WIFI_RETRY_MAX) {
            esp_wifi_connect();
            g_wifi_retry_count++;
        } else {
            xEventGroupSetBits(g_wifi_event_group, NOXTLS_OTA_WIFI_FAIL_BIT);
        }
    } else if(event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
        ESP_LOGI(NOXTLS_OTA_TAG, "got ip: " IPSTR, IP2STR(&event->ip_info.ip));
        g_wifi_retry_count = 0;
        xEventGroupSetBits(g_wifi_event_group, NOXTLS_OTA_WIFI_CONNECTED_BIT);
    }
}

/**
 * @brief Start the WiFi station
 *
 * @return 0 on success, -1 on failure
 */
static int ota_wifi_start_station(void)
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
                                                        &ota_wifi_event_handler, NULL, &any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                                                        &ota_wifi_event_handler, NULL, &got_ip));

    memset(&cfg, 0, sizeof(cfg));
    strncpy((char *)cfg.sta.ssid, CONFIG_NOXTLS_SECURE_OTA_WIFI_SSID, sizeof(cfg.sta.ssid) - 1U);
    strncpy((char *)cfg.sta.password, CONFIG_NOXTLS_SECURE_OTA_WIFI_PASSWORD,
            sizeof(cfg.sta.password) - 1U);
    cfg.sta.threshold.authmode = WIFI_AUTH_OPEN;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &cfg));
    ESP_ERROR_CHECK(esp_wifi_start());

    bits = xEventGroupWaitBits(g_wifi_event_group,
                               NOXTLS_OTA_WIFI_CONNECTED_BIT | NOXTLS_OTA_WIFI_FAIL_BIT,
                               pdFALSE, pdFALSE, portMAX_DELAY);
    return ((bits & NOXTLS_OTA_WIFI_CONNECTED_BIT) != 0U) ? 0 : -1;
}

/**
 * @brief Connect to a TCP server
 *
 * @param[in] host The host to connect to
 * @param[in] port The port to connect to
 * @return 0 on success, -1 on failure
 */
static int ota_tcp_connect(const char *host, uint16_t port)
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
    if(getaddrinfo(host, port_str, &hints, &res) != 0 || res == NULL) return -1;

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
 * @brief Configure the trust anchor
 *
 * @return 0 on success, -1 on failure
 */
static int ota_configure_trust_anchor(void)
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

/**
 * @brief Download and stage the OTA image
 *
 * @return 0 on success, -1 on failure
 */
static int ota_download_and_stage(void)
{
    ota_conn_t conn;
    tls13_context_t tls;
    noxtls_return_t rc;
    char request[1024];
    uint8_t rx[NOXTLS_OTA_RX_CHUNK];
    uint32_t rx_len;
    uint8_t header_probe[8];
    uint32_t header_probe_len;
    int header_done;
    uint32_t total_body;
    const esp_partition_t *next_partition;
    esp_ota_handle_t ota_handle;
    noxtls_sha_ctx_t sha;
    uint8_t digest[32];
    uint8_t expected[32];
    int has_expected;

    next_partition = esp_ota_get_next_update_partition(NULL);
    if(next_partition == NULL) {
        ESP_LOGE(NOXTLS_OTA_TAG, "no OTA partition available");
        return -1;
    }

    if(esp_ota_begin(next_partition, OTA_SIZE_UNKNOWN, &ota_handle) != ESP_OK) {
        ESP_LOGE(NOXTLS_OTA_TAG, "esp_ota_begin failed");
        return -1;
    }

    conn.sock = ota_tcp_connect(CONFIG_NOXTLS_SECURE_OTA_HOST,
                                (uint16_t)CONFIG_NOXTLS_SECURE_OTA_PORT);
    if(conn.sock < 0) {
        esp_ota_end(ota_handle);
        return -1;
    }

    if(noxtls_sha256_init(&sha, NOXTLS_HASH_SHA_256) != NOXTLS_RETURN_SUCCESS) {
        close(conn.sock);
        esp_ota_end(ota_handle);
        return -1;
    }

    rc = noxtls_tls13_context_init(&tls, TLS_ROLE_CLIENT);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        close(conn.sock);
        esp_ota_end(ota_handle);
        return -1;
    }

    tls.server_name = CONFIG_NOXTLS_SECURE_OTA_HOST;
    tls.server_name_len = (uint16_t)strlen(CONFIG_NOXTLS_SECURE_OTA_HOST);
    rc = noxtls_tls_set_io_callbacks(&tls.base.base, ota_tls_send_cb, ota_tls_recv_cb, &conn);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_tls13_context_free(&tls);
        close(conn.sock);
        esp_ota_end(ota_handle);
        return -1;
    }

    rc = noxtls_tls13_connect(&tls);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        ESP_LOGE(NOXTLS_OTA_TAG, "TLS connect failed: %d", (int)rc);
        noxtls_tls13_context_free(&tls);
        close(conn.sock);
        esp_ota_end(ota_handle);
        return -1;
    }

    snprintf(request, sizeof(request),
             "GET %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "User-Agent: NoxTLS-ESP-secure-ota/1.0\r\n"
             "Accept: */*\r\n"
             "Connection: close\r\n\r\n",
             CONFIG_NOXTLS_SECURE_OTA_PATH,
             CONFIG_NOXTLS_SECURE_OTA_HOST);

    rc = noxtls_tls13_send(&tls, (const uint8_t *)request, (uint32_t)strlen(request));
    if(rc != NOXTLS_RETURN_SUCCESS) {
        noxtls_tls13_context_free(&tls);
        close(conn.sock);
        esp_ota_end(ota_handle);
        return -1;
    }

    header_probe_len = 0U;
    header_done = 0;
    total_body = 0U;

    while(1) {
        rx_len = sizeof(rx);
        rc = noxtls_tls13_recv(&tls, rx, &rx_len);
        if(rc != NOXTLS_RETURN_SUCCESS || rx_len == 0U) break;

        if(header_done == 0) {
            uint32_t i;
            uint32_t start = 0U;

            for(i = 0U; i < rx_len; i++) {
                if(header_probe_len < sizeof(header_probe)) {
                    header_probe[header_probe_len++] = rx[i];
                } else {
                    memmove(header_probe, header_probe + 1U, sizeof(header_probe) - 1U);
                    header_probe[sizeof(header_probe) - 1U] = rx[i];
                }

                if(header_probe_len >= 4U &&
                   header_probe[header_probe_len - 4U] == '\r' &&
                   header_probe[header_probe_len - 3U] == '\n' &&
                   header_probe[header_probe_len - 2U] == '\r' &&
                   header_probe[header_probe_len - 1U] == '\n') {
                    header_done = 1;
                    start = i + 1U;
                    break;
                }
            }

            if(header_done == 0) continue;
            if(start >= rx_len) continue;

            if(total_body + (rx_len - start) > (uint32_t)CONFIG_NOXTLS_SECURE_OTA_MAX_IMAGE_BYTES) {
                ESP_LOGE(NOXTLS_OTA_TAG, "image too large");
                noxtls_tls13_context_free(&tls);
                close(conn.sock);
                esp_ota_end(ota_handle);
                return -1;
            }

            if(esp_ota_write(ota_handle, rx + start, rx_len - start) != ESP_OK) {
                ESP_LOGE(NOXTLS_OTA_TAG, "esp_ota_write failed");
                noxtls_tls13_context_free(&tls);
                close(conn.sock);
                esp_ota_end(ota_handle);
                return -1;
            }
            if(noxtls_sha256_update(&sha, rx + start, rx_len - start) != NOXTLS_RETURN_SUCCESS) {
                noxtls_tls13_context_free(&tls);
                close(conn.sock);
                esp_ota_end(ota_handle);
                return -1;
            }
            total_body += (rx_len - start);
        } else {
            if(total_body + rx_len > (uint32_t)CONFIG_NOXTLS_SECURE_OTA_MAX_IMAGE_BYTES) {
                ESP_LOGE(NOXTLS_OTA_TAG, "image too large");
                noxtls_tls13_context_free(&tls);
                close(conn.sock);
                esp_ota_end(ota_handle);
                return -1;
            }

            if(esp_ota_write(ota_handle, rx, rx_len) != ESP_OK) {
                ESP_LOGE(NOXTLS_OTA_TAG, "esp_ota_write failed");
                noxtls_tls13_context_free(&tls);
                close(conn.sock);
                esp_ota_end(ota_handle);
                return -1;
            }
            if(noxtls_sha256_update(&sha, rx, rx_len) != NOXTLS_RETURN_SUCCESS) {
                noxtls_tls13_context_free(&tls);
                close(conn.sock);
                esp_ota_end(ota_handle);
                return -1;
            }
            total_body += rx_len;
        }
    }

    if(noxtls_sha256_finish(&sha, digest) != NOXTLS_RETURN_SUCCESS) {
        noxtls_tls13_context_free(&tls);
        close(conn.sock);
        esp_ota_end(ota_handle);
        return -1;
    }

    has_expected = (strlen(CONFIG_NOXTLS_SECURE_OTA_EXPECTED_SHA256_HEX) == 64U);
    if(has_expected && parse_hex32(CONFIG_NOXTLS_SECURE_OTA_EXPECTED_SHA256_HEX, expected) == 0) {
        if(memcmp(expected, digest, sizeof(expected)) != 0) {
            ESP_LOGE(NOXTLS_OTA_TAG, "firmware SHA-256 mismatch");
            noxtls_tls13_context_free(&tls);
            close(conn.sock);
            esp_ota_end(ota_handle);
            return -1;
        }
    }

    if(esp_ota_end(ota_handle) != ESP_OK) {
        ESP_LOGE(NOXTLS_OTA_TAG, "esp_ota_end failed");
        noxtls_tls13_context_free(&tls);
        close(conn.sock);
        return -1;
    }

    if(esp_ota_set_boot_partition(next_partition) != ESP_OK) {
        ESP_LOGE(NOXTLS_OTA_TAG, "esp_ota_set_boot_partition failed");
        noxtls_tls13_context_free(&tls);
        close(conn.sock);
        return -1;
    }

    noxtls_tls13_close(&tls);
    noxtls_tls13_context_free(&tls);
    close(conn.sock);

    ESP_LOGI(NOXTLS_OTA_TAG, "OTA image staged (%u bytes). Reboot to boot new image.", (unsigned)total_body);
    return 0;
}

/**
 * @brief Main function
 *
 * @return 0 on success, -1 on failure
 */
void app_main(void)
{
    esp_err_t err;

    ESP_LOGI(NOXTLS_OTA_TAG, "NoxTLS secure OTA example");

#if defined(CONFIG_SECURE_BOOT)
    ESP_LOGI(NOXTLS_OTA_TAG, "Secure Boot config: enabled");
#else
    ESP_LOGW(NOXTLS_OTA_TAG, "Secure Boot config: disabled (enable in menuconfig for production)");
#endif

#if defined(CONFIG_SECURE_FLASH_ENC_ENABLED)
    ESP_LOGI(NOXTLS_OTA_TAG, "Flash encryption config: enabled");
#else
    ESP_LOGW(NOXTLS_OTA_TAG, "Flash encryption config: disabled (recommended for production)");
#endif

    (void)noxtls_esp_idf_init();

    err = nvs_flash_init();
    if(err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);

    if(ota_wifi_start_station() != 0) {
        ESP_LOGE(NOXTLS_OTA_TAG, "WiFi bring-up failed");
        return;
    }

    if(ota_configure_trust_anchor() != 0) {
        ESP_LOGE(NOXTLS_OTA_TAG, "trust anchor parse failed (replace main/certs/root_ca.pem)");
        return;
    }

    if(ota_download_and_stage() != 0) {
        ESP_LOGE(NOXTLS_OTA_TAG, "secure OTA failed");
    }

    noxtls_x509_trust_store_clear();
}
