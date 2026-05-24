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
* Summary: SSH client flow using Argenox NoxSSH - WIP
*
*
*****************************************************************************/

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "nvs_flash.h"
#include "sdkconfig.h"

#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"

#include "lwip/netdb.h"
#include "lwip/sockets.h"

#if defined(__has_include)
#  if __has_include("noxssh_common.h")
#    include "noxssh_common.h"
#    define NOXTLS_HAVE_NOXSSH 1
#  else
#    define NOXTLS_HAVE_NOXSSH 0
#  endif
#else
#  define NOXTLS_HAVE_NOXSSH 0
#endif

#define NOXTLS_SSH_TAG                "noxtls_ssh_client"
#define NOXTLS_SSH_WIFI_CONNECTED_BIT BIT0
#define NOXTLS_SSH_WIFI_FAIL_BIT      BIT1
#define NOXTLS_SSH_WIFI_RETRY_MAX     (5U)

typedef struct {
    int sock;
} ssh_conn_t;

static EventGroupHandle_t g_wifi_event_group;
static uint32_t g_wifi_retry_count;

/**
 * @brief The event handler for the WiFi connection
 *
 * @param[in] arg The argument to the event handler
 * @param[in] event_base The base event of the event
 * @param[in] event_id The ID of the event
 * @param[in] event_data The data of the event
 */
static void ssh_wifi_event_handler(void *arg, esp_event_base_t event_base,
                                   int32_t event_id, void *event_data)
{
    (void)arg;

    if(event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if(event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        if(g_wifi_retry_count < NOXTLS_SSH_WIFI_RETRY_MAX) {
            esp_wifi_connect();
            g_wifi_retry_count++;
        } else {
            xEventGroupSetBits(g_wifi_event_group, NOXTLS_SSH_WIFI_FAIL_BIT);
        }
    } else if(event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
        ESP_LOGI(NOXTLS_SSH_TAG, "got ip: " IPSTR, IP2STR(&event->ip_info.ip));
        g_wifi_retry_count = 0;
        xEventGroupSetBits(g_wifi_event_group, NOXTLS_SSH_WIFI_CONNECTED_BIT);
    }
}

/**
 * @brief Start the WiFi station
 *
 * @return 0 on success, -1 on failure
 */
static int ssh_wifi_start_station(void)
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
                                                        &ssh_wifi_event_handler, NULL, &any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                                                        &ssh_wifi_event_handler, NULL, &got_ip));

    memset(&cfg, 0, sizeof(cfg));
    strncpy((char *)cfg.sta.ssid, CONFIG_NOXTLS_SSH_CLIENT_WIFI_SSID, sizeof(cfg.sta.ssid) - 1U);
    strncpy((char *)cfg.sta.password, CONFIG_NOXTLS_SSH_CLIENT_WIFI_PASSWORD,
            sizeof(cfg.sta.password) - 1U);
    cfg.sta.threshold.authmode = WIFI_AUTH_OPEN;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &cfg));
    ESP_ERROR_CHECK(esp_wifi_start());

    bits = xEventGroupWaitBits(g_wifi_event_group,
                               NOXTLS_SSH_WIFI_CONNECTED_BIT | NOXTLS_SSH_WIFI_FAIL_BIT,
                               pdFALSE, pdFALSE, portMAX_DELAY);
    return ((bits & NOXTLS_SSH_WIFI_CONNECTED_BIT) != 0U) ? 0 : -1;
}

/**
 * @brief Connect to a TCP server
 *
 * @param[in] host The host to connect to
 * @param[in] port The port to connect to
 * @return 0 on success, -1 on failure
 */
static int ssh_tcp_connect(const char *host, uint16_t port)
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

#if NOXTLS_HAVE_NOXSSH
/**
 * @brief The callback function for sending data
 *
 * @param[in] user_data The user data
 * @param[in] data The data to send
 * @param[in] len The length of the data to send
 * @return The length of the data sent
 */
static int32_t ssh_send_cb(void *user_data, const uint8_t *data, uint32_t len)
{
    ssh_conn_t *conn = (ssh_conn_t *)user_data;
    int sent;

    if(conn == NULL || data == NULL) return -1;
    sent = send(conn->sock, data, len, 0);
    return (sent >= 0) ? (int32_t)sent : -1;
}

/**
 * @brief The callback function for receiving data
 *
 * @param[in] user_data The user data
 * @param[in] data The data to receive
 * @param[in] len The length of the data to receive
 * @return The length of the data received
 */
static int32_t ssh_recv_cb(void *user_data, uint8_t *data, uint32_t len)
{
    ssh_conn_t *conn = (ssh_conn_t *)user_data;
    int received;

    if(conn == NULL || data == NULL) return -1;
    received = recv(conn->sock, data, len, 0);
    return (received >= 0) ? (int32_t)received : -1;
}

/**
 * @brief Run the NoxSSH client
 *
 * @return 0 on success, -1 on failure
 */
static int run_noxssh_client(void)
{
    ssh_conn_t conn;
    netnox_ssh_client_t client;
    netnox_return_t rc;
    int sock;
    uint8_t out[1024];
    uint32_t out_len;

    sock = ssh_tcp_connect(CONFIG_NOXTLS_SSH_CLIENT_HOST,
                           (uint16_t)CONFIG_NOXTLS_SSH_CLIENT_PORT);
    if(sock < 0) {
        ESP_LOGE(NOXTLS_SSH_TAG, "tcp connect failed");
        return -1;
    }

    conn.sock = sock;
    rc = netnox_ssh_client_init(&client, NULL, (uint16_t)CONFIG_NOXTLS_SSH_CLIENT_PORT);
    if(rc != NETNOX_RETURN_SUCCESS) {
        close(sock);
        return -1;
    }

    netnox_ssh_client_set_io_callbacks(&client, ssh_send_cb, ssh_recv_cb, &conn);
    rc = netnox_ssh_client_set_target(&client,
                                      CONFIG_NOXTLS_SSH_CLIENT_USERNAME,
                                      CONFIG_NOXTLS_SSH_CLIENT_HOST);
    if(rc != NETNOX_RETURN_SUCCESS) {
        close(sock);
        return -1;
    }

    rc = netnox_ssh_client_set_password(&client, CONFIG_NOXTLS_SSH_CLIENT_PASSWORD);
    if(rc != NETNOX_RETURN_SUCCESS) {
        close(sock);
        return -1;
    }

    rc = netnox_ssh_client_connect(&client);
    if(rc != NETNOX_RETURN_SUCCESS) {
        ESP_LOGE(NOXTLS_SSH_TAG, "ssh connect failed: %d", (int)rc);
        close(sock);
        return -1;
    }

    rc = netnox_ssh_client_authenticate(&client);
    if(rc != NETNOX_RETURN_SUCCESS) {
        ESP_LOGE(NOXTLS_SSH_TAG, "ssh auth failed: %d", (int)rc);
        netnox_ssh_client_close(&client);
        close(sock);
        return -1;
    }

    rc = netnox_ssh_client_open_session(&client);
    if(rc != NETNOX_RETURN_SUCCESS) {
        ESP_LOGE(NOXTLS_SSH_TAG, "open session failed: %d", (int)rc);
        netnox_ssh_client_close(&client);
        close(sock);
        return -1;
    }

    rc = netnox_ssh_client_exec(&client, CONFIG_NOXTLS_SSH_CLIENT_COMMAND);
    if(rc != NETNOX_RETURN_SUCCESS) {
        ESP_LOGE(NOXTLS_SSH_TAG, "exec failed: %d", (int)rc);
        netnox_ssh_client_close(&client);
        close(sock);
        return -1;
    }

    do {
        out_len = sizeof(out);
        rc = netnox_ssh_client_recv_data(&client, out, &out_len);
        if(rc == NETNOX_RETURN_SUCCESS && out_len > 0U) {
            fwrite(out, 1U, out_len, stdout);
        }
    } while(rc == NETNOX_RETURN_SUCCESS && out_len > 0U);

    netnox_ssh_client_close(&client);
    close(sock);
    return 0;
}
#endif

/**
 * @brief Main function
 *
 * @return 0 on success, -1 on failure
 */
void app_main(void)
{
    esp_err_t err;

    ESP_LOGI(NOXTLS_SSH_TAG, "NoxTLS SSH client example");

    err = nvs_flash_init();
    if(err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);

    if(ssh_wifi_start_station() != 0) {
        ESP_LOGE(NOXTLS_SSH_TAG, "WiFi bring-up failed");
        return;
    }

#if NOXTLS_HAVE_NOXSSH
    if(run_noxssh_client() != 0) {
        ESP_LOGE(NOXTLS_SSH_TAG, "SSH client flow failed");
    }
#else
    ESP_LOGW(NOXTLS_SSH_TAG,
             "noxssh_common.h not found. Add argenox/noxssh common module as an ESP-IDF component to enable this example.");
#endif
}
