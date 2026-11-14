/*
 * SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
 *
 * Regression coverage for audit issue 106: noxtls_hex_string_to_bytes must
 * reject any non-hex character instead of decoding the pair as 0x00.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "string_common.h"

int main(void)
{
    static const char *const bad[] = {
        "zz", "0g", "g0", "00112233445566778899aabbccddeezz", "00 1", "0x00", "--",
        "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
    };
    uint8_t out[32];
    uint8_t expect[4] = { 0x0AU, 0x1BU, 0x2CU, 0xFFU };
    size_t i;
    int ok = 1;
    int rc;

    for(i = 0U; i < (sizeof(bad) / sizeof(bad[0])); i += 1U) {
        memset(out, 0x77, sizeof(out));
        rc = noxtls_hex_string_to_bytes((const uint8_t *)bad[i], out, sizeof(out));
        if(rc >= 0) {
            fprintf(stderr, "FAIL: \"%s\" accepted (%d)\n", bad[i], rc);
            ok = 0;
        }
        if((strlen(bad[i]) % 2U) == 0U) {
            if(rc != -5) {
                fprintf(stderr, "FAIL: \"%s\" returned %d, want -5\n", bad[i], rc);
                ok = 0;
            }
            if(out[0] != 0x77U) {
                fprintf(stderr, "FAIL: \"%s\" wrote output on error\n", bad[i]);
                ok = 0;
            }
        }
    }
    rc = noxtls_hex_string_to_bytes((const uint8_t *)"0a1B2cFf", out, sizeof(out));
    if((rc != 4) || (memcmp(out, expect, sizeof(expect)) != 0)) {
        fprintf(stderr, "FAIL: valid hex rejected or misparsed (%d)\n", rc);
        ok = 0;
    }
    rc = noxtls_hex_string_to_bytes((const uint8_t *)"", out, sizeof(out));
    if(rc != 0) {
        fprintf(stderr, "FAIL: empty string returned %d\n", rc);
        ok = 0;
    }
    if(ok != 0) {
        printf("hex_parse_test: PASS\n");
    }
    return (ok != 0) ? 0 : 1;
}
