/*
 * SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
 *
 * Regression coverage for audit issue 105: debug level 1 must not print the
 * per-byte secret dumps that follow a [TLS13_DEBUG] label, nor any bare
 * hex-byte dump. Output is captured through the debug log file.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "noxtls_debug_printf.h"

#define LOG_PATH "debug_filter_test.log"

static const uint8_t secret[8] = { 0xDEU, 0xADU, 0xBEU, 0xEFU, 0xC0U, 0xFFU, 0xEEU, 0x11U };

/* Same call shape as the TLS 1.3 and key-exchange dumps. */
static void dump_like_library(void)
{
    uint32_t i;

    (void)noxtls_debug_printf((const uint8_t *)"[TLS13_DEBUG] shared_secret=");
    for(i = 0U; i < sizeof(secret); i += 1U) {
        (void)noxtls_debug_printf((const uint8_t *)"%02X", secret[i]);
    }
    (void)noxtls_debug_printf((const uint8_t *)"\n");
    (void)noxtls_debug_printf((const uint8_t *)"plain line %u\n", 7U);
    (void)noxtls_debug_printf((const uint8_t *)"unmarked dump: ");
    for(i = 0U; i < sizeof(secret); i += 1U) {
        (void)noxtls_debug_printf((const uint8_t *)"%02x ", secret[i]);
    }
    (void)noxtls_debug_printf((const uint8_t *)"\n");
}

static size_t read_log(char *buf, size_t cap)
{
    FILE *fp = fopen(LOG_PATH, "rb");
    size_t n = 0U;

    if(fp != NULL) {
        n = fread(buf, 1U, cap - 1U, fp);
        (void)fclose(fp);
    }
    buf[n] = '\0';
    return n;
}

int main(void)
{
    char log[4096];
    int ok = 1;

    (void)remove(LOG_PATH);
    if(noxtls_debug_set_log_file((const uint8_t *)LOG_PATH) != 0) {
        fprintf(stderr, "FAIL: cannot open log\n");
        return 1;
    }
    noxtls_debug_set_level(1U);
    dump_like_library();
    (void)noxtls_debug_set_log_file(NULL);
    (void)read_log(log, sizeof(log));
    if((strstr(log, "DEADBEEF") != NULL) || (strstr(log, "de ad be ef") != NULL) ||
       (strstr(log, "ADBE") != NULL) || (strstr(log, "shared_secret") != NULL)) {
        fprintf(stderr, "FAIL: level 1 printed secret bytes:\n%s\n", log);
        ok = 0;
    }
    if(strstr(log, "plain line 7") == NULL) {
        fprintf(stderr, "FAIL: level 1 dropped an ordinary line:\n%s\n", log);
        ok = 0;
    }

    (void)remove(LOG_PATH);
    (void)noxtls_debug_set_log_file((const uint8_t *)LOG_PATH);
    noxtls_debug_set_level(2U);
    dump_like_library();
    (void)noxtls_debug_set_log_file(NULL);
    noxtls_debug_set_level(0U);
    (void)read_log(log, sizeof(log));
    if(strstr(log, "DEADBEEFC0FFEE11") == NULL) {
        fprintf(stderr, "FAIL: level 2 no longer prints full debug output\n");
        ok = 0;
    }
    (void)remove(LOG_PATH);
    if(ok != 0) {
        printf("debug_filter_test: PASS\n");
    }
    return (ok != 0) ? 0 : 1;
}
