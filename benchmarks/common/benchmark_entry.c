#include <stddef.h>
#include <stdint.h>

#include "drbg/noxtls_drbg.h"

#if defined(NOXTLS_BENCH_TLS12_TLS13)
#include "tls/noxtls_tls_unified.h"
#elif defined(NOXTLS_BENCH_TLS12_ONLY)
#include "tls/noxtls_tls12.h"
#elif defined(NOXTLS_BENCH_TLS13_ONLY)
#include "tls/noxtls_tls13.h"
#endif

int benchmark_entry(void)
{
#if defined(NOXTLS_BENCH_TLS12_TLS13)
    noxtls_tls_connection_t conn;
    uint8_t byte = 0U;
    uint32_t len = 1U;

    (void)noxtls_tls_connection_send(&conn, &byte, len);
#elif defined(NOXTLS_BENCH_TLS12_ONLY)
    tls12_context_t ctx;
    uint8_t byte = 0U;
    uint32_t len = 1U;

    (void)noxtls_tls12_send(&ctx, &byte, len);
#elif defined(NOXTLS_BENCH_TLS13_ONLY)
    tls13_context_t ctx;
    uint8_t byte = 0U;
    uint32_t len = 1U;

    (void)noxtls_tls13_send(&ctx, &byte, len);
#else
    (void)noxtls_drbg_get_entropy(NULL, 0U);
#endif
    return 0;
}
