/*
 * Regression coverage for ECDH's non-secret failure provenance.  The result
 * must identify the branch without exposing any key material.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "pkc/ecdh/noxtls_ecdh.h"
#include "pkc/ecc/noxtls_ecc.h"
#include "drbg/noxtls_drbg.h"

/* PTS/SM failure diagnostics exported by the ECC implementation. */
extern volatile uint32_t noxtls_ecc_keygen_last_drbg_type;

static int expect(int condition, const char *message)
{
    if(!condition) {
        fprintf(stderr, "FAIL: %s\n", message);
        return 0;
    }
    return 1;
}

int main(void)
{
    ecc_key_t key;
    ecc_key_t generated_key;
    ecc_point_t invalid_peer;
    uint8_t secret[32];
    uint32_t secret_len;
    noxtls_ecdh_diagnostic_t diagnostic;
    noxtls_return_t rc;
    int ok = 1;

    /*
     * nRF52 ECB is AES-128 only.  Key generation must therefore choose the
     * enabled DRBG primitive rather than unconditionally requesting AES-256.
     * Configure this target with AES-256 disabled to exercise the nRF52-sized
     * build in CI.
     */
    memset(&generated_key, 0, sizeof(generated_key));
    rc = noxtls_ecc_key_generate(&generated_key, NOXTLS_ECC_SECP256R1);
    ok &= expect(rc == NOXTLS_RETURN_SUCCESS, "generate P-256 key");
#if NOXTLS_FEATURE_AES_256
    ok &= expect(noxtls_ecc_keygen_last_drbg_type == DRBG_AES256,
                 "AES-256 build selects AES-256 CTR-DRBG");
#else
    ok &= expect(noxtls_ecc_keygen_last_drbg_type == DRBG_AES128,
                 "AES-128-only build selects AES-128 CTR-DRBG");
#endif
    (void)noxtls_ecc_key_free(&generated_key);

    memset(&key, 0, sizeof(key));
    rc = noxtls_ecc_key_init(&key, NOXTLS_ECC_SECP256R1);
    if(!expect(rc == NOXTLS_RETURN_SUCCESS, "initialize P-256 key")) {
        return 1;
    }

    /* d = 1 makes the curve generator an inexpensive known-valid peer. */
    key.d[31] = 1u;
    secret_len = sizeof(secret);
    rc = noxtls_ecdh_compute_shared_secret_ex(&key, &key.curve->G, secret,
                                              &secret_len, &diagnostic);
    ok &= expect(rc == NOXTLS_RETURN_SUCCESS, "compute valid ECDH secret");
    ok &= expect(secret_len == sizeof(secret), "valid ECDH secret length");
    ok &= expect(diagnostic.stage == NOXTLS_ECDH_DIAGNOSTIC_NONE,
                 "successful ECDH has no diagnostic stage");
    ok &= expect(diagnostic.internal_rc == NOXTLS_RETURN_SUCCESS,
                 "successful ECDH has successful internal result");

    secret_len = sizeof(secret) - 1u;
    rc = noxtls_ecdh_compute_shared_secret_ex(&key, &key.curve->G, secret,
                                              &secret_len, &diagnostic);
    ok &= expect(rc == NOXTLS_RETURN_ECDH_OUTPUT_TOO_SMALL,
                 "return detailed short-output failure code");
    ok &= expect(diagnostic.stage == NOXTLS_ECDH_DIAGNOSTIC_OUTPUT_BUFFER,
                 "report output-buffer failure stage");
    ok &= expect(diagnostic.internal_rc == NOXTLS_RETURN_ECDH_OUTPUT_TOO_SMALL,
                 "report output-buffer failure code");
    rc = noxtls_ecdh_compute_shared_secret(&key, &key.curve->G, secret,
                                            &secret_len);
    ok &= expect(rc == NOXTLS_RETURN_ECDH_OUTPUT_TOO_SMALL,
                 "legacy ECDH API preserves detailed failure code");

    memset(&invalid_peer, 0, sizeof(invalid_peer));
    invalid_peer.size = key.curve->size;
    secret_len = sizeof(secret);
    rc = noxtls_ecdh_compute_shared_secret_ex(&key, &invalid_peer, secret,
                                              &secret_len, &diagnostic);
    ok &= expect(rc == NOXTLS_RETURN_ECDH_PEER_PUBLIC_KEY_INVALID,
                 "return detailed invalid-peer failure code");
    ok &= expect(diagnostic.stage == NOXTLS_ECDH_DIAGNOSTIC_PEER_PUBLIC_KEY,
                 "report peer validation failure stage");
    ok &= expect(diagnostic.internal_rc == NOXTLS_RETURN_FAILED,
                 "report peer validation failure code");

    key.d[31] = 0u;
    secret_len = sizeof(secret);
    rc = noxtls_ecdh_compute_shared_secret_ex(&key, &key.curve->G, secret,
                                              &secret_len, &diagnostic);
    ok &= expect(rc == NOXTLS_RETURN_ECDH_SHARED_POINT_INFINITY,
                 "return detailed shared-infinity failure code");
    ok &= expect(diagnostic.stage == NOXTLS_ECDH_DIAGNOSTIC_SHARED_POINT_INFINITY,
                 "report shared-infinity failure stage");
    key.d[31] = 1u;

    {
        ecc_curve_params_t *saved_curve = key.curve;
        key.curve = NULL;
        secret_len = sizeof(secret);
        rc = noxtls_ecdh_compute_shared_secret_ex(&key, &saved_curve->G,
                                                  secret, &secret_len,
                                                  &diagnostic);
        ok &= expect(rc == NOXTLS_RETURN_ECDH_PRIVATE_KEY_INVALID,
                     "return detailed invalid-private-key failure code");
        ok &= expect(diagnostic.stage == NOXTLS_ECDH_DIAGNOSTIC_PRIVATE_KEY,
                     "report invalid-private-key failure stage");
        key.curve = saved_curve;
    }

    rc = noxtls_ecdh_compute_shared_secret_ex(NULL, &key.curve->G, secret,
                                              &secret_len, &diagnostic);
    ok &= expect(rc == NOXTLS_RETURN_NULL, "reject null private key");
    ok &= expect(diagnostic.stage == NOXTLS_ECDH_DIAGNOSTIC_ARGUMENT,
                 "report null argument failure stage");
    ok &= expect(diagnostic.internal_rc == NOXTLS_RETURN_NULL,
                 "report null argument failure code");

    noxtls_ecc_key_free(&key);
    return ok ? 0 : 1;
}
