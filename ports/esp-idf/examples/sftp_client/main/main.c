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
* Summary: SFTP integration scaffold (WIP)
*
*****************************************************************************/


#include "esp_log.h"
#include "sdkconfig.h"

#define NOXTLS_SFTP_TAG "noxtls_sftp_client"

void app_main(void)
{
    ESP_LOGI(NOXTLS_SFTP_TAG, "NoxTLS SFTP client example scaffold");
    ESP_LOGW(NOXTLS_SFTP_TAG,
             "SFTP subsystem requests are not yet exposed by argenox/noxssh common client API.");
    ESP_LOGW(NOXTLS_SFTP_TAG,
             "Planned flow: SSH transport/session via noxssh_common, subsystem=\"sftp\", then SFTP packet exchange for %s.",
             CONFIG_NOXTLS_SFTP_REMOTE_PATH);
}
