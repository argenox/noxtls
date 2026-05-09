#include <string.h>
#include "noxtls_config.h"
#include "noxtls_ct.h"

int noxtls_ct_memcmp(const void *a, const void *b, size_t len)
{
    const uint8_t *pa;
    const uint8_t *pb;
    uint8_t diff = 0;
    size_t i;

    if(a == NULL || b == NULL) {
        return 1;
    }

    pa = (const uint8_t *)a;
    pb = (const uint8_t *)b;

    for(i = 0; i < len; i++) {
        diff |= (uint8_t)(pa[i] ^ pb[i]);
    }

    return (int)diff;
}

int noxtls_ct_equal(const void *a, const void *b, size_t len)
{
    return (noxtls_ct_memcmp(a, b, len) == 0);
}

int noxtls_secret_memcmp(const void *a, const void *b, size_t len)
{
#if NOXTLS_CT_COMPARE
    return noxtls_ct_memcmp(a, b, len);
#else
    return memcmp(a, b, len);
#endif
}

void noxtls_secure_zero(void *ptr, size_t len)
{
    volatile uint8_t *p;

    if(ptr == NULL || len == 0) {
        return;
    }

    p = (volatile uint8_t *)ptr;
    while(len > 0) {
        *p++ = 0;
        len--;
    }
}
