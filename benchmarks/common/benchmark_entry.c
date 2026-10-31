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

#if defined(NOXTLS_BENCH_KEEP_ML_KEM)
#include "mlkem/noxtls_mlkem.h"
#endif
#if defined(NOXTLS_BENCH_KEEP_ML_DSA)
#include "mldsa/noxtls_mldsa.h"
#endif
#if defined(NOXTLS_BENCH_KEEP_SLH_DSA)
#include "slhdsa/noxtls_slhdsa.h"
#endif
#if defined(NOXTLS_BENCH_KEEP_FALCON)
#include "falcon/noxtls_falcon.h"
#endif
#if defined(NOXTLS_BENCH_KEEP_LMS_HSS)
#include "lms/noxtls_lms.h"
#endif
#if defined(NOXTLS_BENCH_KEEP_XMSS)
#include "xmss/noxtls_xmss.h"
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

    /*
     * Keep PQ archive members reachable if --whole-archive is mishandled.
     * Prefer keygen so multi-file algos (e.g. ML-DSA) pull more than the
     * size-query translation unit.
     */
#if defined(NOXTLS_BENCH_KEEP_ML_KEM)
    (void)noxtls_mlkem_keygen(NOXTLS_MLKEM_512, NULL, NULL);
#endif
#if defined(NOXTLS_BENCH_KEEP_ML_DSA)
    (void)noxtls_mldsa_keygen(NOXTLS_MLDSA_44, NULL, NULL);
#endif
#if defined(NOXTLS_BENCH_KEEP_SLH_DSA)
    (void)noxtls_slhdsa_keygen(NOXTLS_SLHDSA_SHA2_128S, NULL, NULL);
#endif
#if defined(NOXTLS_BENCH_KEEP_FALCON)
    (void)noxtls_falcon_keygen(NOXTLS_FALCON_512, NULL, 0U, NULL, 0U);
#endif
#if defined(NOXTLS_BENCH_KEEP_LMS_HSS)
    {
        /* Stateless (streaming) verification plus stateful keygen / signing. */
        noxtls_hss_key_t lms_key;
        uint32_t lms_sig_len = 0U;

        (void)noxtls_hss_verify(NOXTLS_LMS_FORMAT_HSS, NULL, 0U, NULL, 0U, NULL, 0U);
        (void)noxtls_hss_keygen(NULL, NULL, NULL, NULL, 0U, NULL, 0U);
        (void)noxtls_hss_key_load(&lms_key, NULL, 0U, NULL, 0U, 0U, 0U, NULL, NULL);
        (void)noxtls_hss_sign(&lms_key, NULL, 0U, NULL, 0U, &lms_sig_len);
        noxtls_hss_key_free(&lms_key);
    }
#endif
#if defined(NOXTLS_BENCH_KEEP_XMSS)
    /* Verification, key generation and stateful signing (with BDS traversal). */
    (void)noxtls_xmss_verify(NOXTLS_XMSS_SHA2_10_256, NULL, NULL, 0U, NULL, 0U);
    (void)noxtls_xmss_keygen(NOXTLS_XMSS_SHA2_10_256, NULL, 0U, NULL, 0U);
    (void)noxtls_xmss_signer_attach_traversal(NULL, NULL, 0U, 0U);
    (void)noxtls_xmss_sign_stateful(NULL, NULL, 0U, NULL, NULL);
#endif
    return 0;
}
