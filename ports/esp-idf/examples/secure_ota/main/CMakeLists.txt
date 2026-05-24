# SPDX-License-Identifier: Apache-2.0

idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "."
    EMBED_TXTFILES
        "certs/root_ca.pem"
    REQUIRES
        esp-idf
        esp_timer
        nvs_flash
        esp_wifi
        esp_netif
        esp_event
        lwip
        app_update
)
