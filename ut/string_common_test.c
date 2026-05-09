#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "common/string_common.h"

static int test_hex_string_to_bytes_success(void)
{
    static const char *hex = "0A1b2C";
    uint8_t out[3] = {0};
    int rc = noxtls_hex_string_to_bytes(hex, out, sizeof(out));

    if(rc != 3) {
        fprintf(stderr, "expected 3 output bytes, got %d\n", rc);
        return 1;
    }
    if(out[0] != 0x0A || out[1] != 0x1B || out[2] != 0x2C) {
        fprintf(stderr, "decoded bytes mismatch\n");
        return 1;
    }
    return 0;
}

static int test_hex_string_to_bytes_rejects_odd_length(void)
{
    uint8_t out[2] = {0};
    int rc = noxtls_hex_string_to_bytes("ABC", out, sizeof(out));

    if(rc != -3) {
        fprintf(stderr, "expected -3 for odd-length hex, got %d\n", rc);
        return 1;
    }
    return 0;
}

static int test_hex_string_to_bytes_rejects_small_buffer(void)
{
    uint8_t out[1] = {0};
    int rc = noxtls_hex_string_to_bytes("A1B2", out, sizeof(out));

    if(rc != -2) {
        fprintf(stderr, "expected -2 for too-small buffer, got %d\n", rc);
        return 1;
    }
    return 0;
}

static int test_hex_string_to_bytes_null_checks(void)
{
    uint8_t out[2] = {0};

    if(noxtls_hex_string_to_bytes(NULL, out, sizeof(out)) != -1) {
        fprintf(stderr, "NULL input should fail with -1\n");
        return 1;
    }
    if(noxtls_hex_string_to_bytes("00", NULL, 1) != -1) {
        fprintf(stderr, "NULL output should fail with -1\n");
        return 1;
    }
    return 0;
}

static int test_hex_string_to_bytes_large_even_input(void)
{
    size_t bytes_len = 4096;
    size_t hex_len = bytes_len * 2u;
    char *hex = (char *)malloc(hex_len + 1u);
    uint8_t *out = (uint8_t *)malloc(bytes_len);
    size_t i;
    int rc;

    if(hex == NULL || out == NULL) {
        free(hex);
        free(out);
        fprintf(stderr, "allocation failed in large-input test\n");
        return 1;
    }

    for(i = 0; i < bytes_len; i++) {
        hex[i * 2u] = 'A';
        hex[i * 2u + 1u] = 'B';
    }
    hex[hex_len] = '\0';

    rc = noxtls_hex_string_to_bytes(hex, out, bytes_len);
    if(rc != (int)bytes_len) {
        fprintf(stderr, "large-input decode length mismatch: expected %u got %d\n",
                (unsigned)bytes_len, rc);
        free(hex);
        free(out);
        return 1;
    }
    for(i = 0; i < bytes_len; i++) {
        if(out[i] != 0xAB) {
            fprintf(stderr, "large-input decode mismatch at index %u\n", (unsigned)i);
            free(hex);
            free(out);
            return 1;
        }
    }

    free(hex);
    free(out);
    return 0;
}

int main(void)
{
    if(test_hex_string_to_bytes_success() != 0) {
        return 1;
    }
    if(test_hex_string_to_bytes_rejects_odd_length() != 0) {
        return 1;
    }
    if(test_hex_string_to_bytes_rejects_small_buffer() != 0) {
        return 1;
    }
    if(test_hex_string_to_bytes_null_checks() != 0) {
        return 1;
    }
    if(test_hex_string_to_bytes_large_even_input() != 0) {
        return 1;
    }
    return 0;
}
