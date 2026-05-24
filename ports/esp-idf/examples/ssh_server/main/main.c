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
* Summary: SSH server Application (WIP)
*
*****************************************************************************/

#include "esp_log.h"
#include "sdkconfig.h"

#define NOXTLS_SSH_SERVER_TAG "noxtls_ssh_server"

void app_main(void)
{
    ESP_LOGI(NOXTLS_SSH_SERVER_TAG, "NoxTLS SSH server example scaffold");
    ESP_LOGW(NOXTLS_SSH_SERVER_TAG,
             "Current argenox/noxssh reference exposes SSH client APIs only. "
             "Server-side APIs are not available yet in noxssh_common.");
    ESP_LOGW(NOXTLS_SSH_SERVER_TAG,
             "Once noxssh server APIs are published, this example should bind TCP port %u and route transport callbacks into that server context.",
             (unsigned)CONFIG_NOXTLS_SSH_SERVER_PORT);
}
