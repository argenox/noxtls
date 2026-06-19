#include <stddef.h>
#include <stdint.h>
#include <time.h>

void *memcpy(void *dst, const void *src, size_t n)
{
    size_t i;
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;

    for(i = 0U; i < n; ++i) {
        d[i] = s[i];
    }
    return dst;
}

void *memset(void *dst, int value, size_t n)
{
    size_t i;
    unsigned char *d = (unsigned char *)dst;

    for(i = 0U; i < n; ++i) {
        d[i] = (unsigned char)value;
    }
    return dst;
}

int memcmp(const void *lhs, const void *rhs, size_t n)
{
    size_t i;
    const unsigned char *l = (const unsigned char *)lhs;
    const unsigned char *r = (const unsigned char *)rhs;

    for(i = 0U; i < n; ++i) {
        if(l[i] != r[i]) {
            return (int)l[i] - (int)r[i];
        }
    }
    return 0;
}

void *memmove(void *dst, const void *src, size_t n)
{
    size_t i;
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;

    if(d == s || n == 0U) {
        return dst;
    }

    if(d < s) {
        for(i = 0U; i < n; ++i) {
            d[i] = s[i];
        }
    } else {
        for(i = n; i > 0U; --i) {
            d[i - 1U] = s[i - 1U];
        }
    }
    return dst;
}

size_t strlen(const char *s)
{
    size_t n = 0U;

    while(s[n] != '\0') {
        ++n;
    }
    return n;
}

time_t time(time_t *out)
{
    const time_t fixed_epoch = (time_t)1704067200;
    if(out != NULL) {
        *out = fixed_epoch;
    }
    return fixed_epoch;
}

/* ARM EABI aliases frequently emitted by arm-none-eabi builds. */
void __aeabi_memcpy(void *dst, const void *src, size_t n)
{
    (void)memcpy(dst, src, n);
}

void __aeabi_memcpy4(void *dst, const void *src, size_t n)
{
    (void)memcpy(dst, src, n);
}

void __aeabi_memcpy8(void *dst, const void *src, size_t n)
{
    (void)memcpy(dst, src, n);
}

void __aeabi_memset(void *dst, size_t n, int value)
{
    (void)memset(dst, value, n);
}

void __aeabi_memset4(void *dst, size_t n, int value)
{
    (void)memset(dst, value, n);
}

void __aeabi_memset8(void *dst, size_t n, int value)
{
    (void)memset(dst, value, n);
}
