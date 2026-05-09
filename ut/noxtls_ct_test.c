#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "common/noxtls_ct.h"

static int test_ct_memcmp_basic(void)
{
    static const uint8_t a[] = {0x10, 0x20, 0x30, 0x40};
    static const uint8_t b[] = {0x10, 0x20, 0x30, 0x40};
    static const uint8_t c[] = {0x10, 0x20, 0x30, 0x41};

    if(noxtls_ct_memcmp(a, b, sizeof(a)) != 0) {
        fprintf(stderr, "noxtls_ct_memcmp equal-case failed\n");
        return 1;
    }
    if(noxtls_ct_memcmp(a, c, sizeof(a)) == 0) {
        fprintf(stderr, "noxtls_ct_memcmp diff-case failed\n");
        return 1;
    }
    return 0;
}

static int test_secret_memcmp_semantics(void)
{
    static const uint8_t x[] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
    static const uint8_t y[] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
    static const uint8_t z[] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEF};

    if(noxtls_secret_memcmp(x, y, sizeof(x)) != 0) {
        fprintf(stderr, "noxtls_secret_memcmp equal-case failed\n");
        return 1;
    }
    if(noxtls_secret_memcmp(x, z, sizeof(x)) == 0) {
        fprintf(stderr, "noxtls_secret_memcmp diff-case failed\n");
        return 1;
    }
    return 0;
}

static int test_secure_zero(void)
{
    uint8_t buf[32];
    size_t i;

    for(i = 0; i < sizeof(buf); i++) {
        buf[i] = (uint8_t)(i + 1u);
    }

    noxtls_secure_zero(buf, sizeof(buf));

    for(i = 0; i < sizeof(buf); i++) {
        if(buf[i] != 0) {
            fprintf(stderr, "noxtls_secure_zero failed at index %u\n", (unsigned)i);
            return 1;
        }
    }
    return 0;
}

int main(void)
{
    if(test_ct_memcmp_basic() != 0) {
        return 1;
    }
    if(test_secret_memcmp_semantics() != 0) {
        return 1;
    }
    if(test_secure_zero() != 0) {
        return 1;
    }
    return 0;
}
