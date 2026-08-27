/*
 * Regression coverage for ECDH's non-secret failure provenance.  The result
 * must identify the branch without exposing any key material.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "pkc/ecdh/noxtls_ecdh.h"
#include "pkc/ecc/noxtls_ecc.h"
#include "tls/noxtls_tls_key_exchange.h"

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
    ecc_point_t invalid_peer;
    uint8_t secret[32];
    uint32_t secret_len;
    noxtls_ecdh_diagnostic_t diagnostic;
    noxtls_return_t rc;
    tls_ecdhe_context_t tls_ecdhe;
    int ok = 1;

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

    memset(&tls_ecdhe, 0, sizeof(tls_ecdhe));
    memset(&invalid_peer, 0, sizeof(invalid_peer));
    rc = noxtls_tls_ecdhe_compute_shared_secret(&tls_ecdhe, &invalid_peer);
    ok &= expect(rc == NOXTLS_RETURN_ECDH_PRIVATE_KEY_INVALID,
                 "TLS ECDHE returns detailed missing-private-key code");
    ok &= expect(tls_ecdhe.last_ecdh_diagnostic.stage ==
                     NOXTLS_ECDH_DIAGNOSTIC_PRIVATE_KEY,
                 "TLS ECDHE preserves missing-private-key stage");
    ok &= expect(tls_ecdhe.last_ecdh_diagnostic.internal_rc ==
                     NOXTLS_RETURN_ECDH_PRIVATE_KEY_INVALID,
                 "TLS ECDHE preserves missing-private-key code");

    rc = noxtls_tls_ecdhe_compute_shared_secret(&tls_ecdhe, NULL);
    ok &= expect(rc == NOXTLS_RETURN_NULL,
                 "TLS ECDHE returns null-argument code");
    ok &= expect(tls_ecdhe.last_ecdh_diagnostic.stage ==
                     NOXTLS_ECDH_DIAGNOSTIC_ARGUMENT,
                 "TLS ECDHE preserves null-argument stage");
    ok &= expect(tls_ecdhe.last_ecdh_diagnostic.internal_rc ==
                     NOXTLS_RETURN_NULL,
                 "TLS ECDHE preserves null-argument code");

    rc = noxtls_tls_ecdhe_context_init(&tls_ecdhe, TLS_NAMED_GROUP_SECP256R1);
    ok &= expect(rc == NOXTLS_RETURN_SUCCESS,
                 "initialize TLS ECDHE P-256 context");
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_tls_ecdhe_generate_ephemeral_key(&tls_ecdhe);
        ok &= expect(rc == NOXTLS_RETURN_SUCCESS,
                     "generate TLS ECDHE P-256 key");
        if(rc == NOXTLS_RETURN_SUCCESS) {
            memset(&invalid_peer, 0, sizeof(invalid_peer));
            invalid_peer.size = tls_ecdhe.ephemeral_key.curve->size;
            rc = noxtls_tls_ecdhe_compute_shared_secret(&tls_ecdhe,
                                                        &invalid_peer);
            ok &= expect(rc == NOXTLS_RETURN_ECDH_PEER_PUBLIC_KEY_INVALID,
                         "TLS ECDHE returns detailed invalid-peer code");
            ok &= expect(tls_ecdhe.last_ecdh_diagnostic.stage ==
                             NOXTLS_ECDH_DIAGNOSTIC_PEER_PUBLIC_KEY,
                         "TLS ECDHE preserves invalid-peer stage");
            ok &= expect(tls_ecdhe.last_ecdh_diagnostic.internal_rc ==
                             NOXTLS_RETURN_FAILED,
                         "TLS ECDHE preserves invalid-peer inner code");
        }
        (void)noxtls_tls_ecdhe_context_free(&tls_ecdhe);
    }

    return ok ? 0 : 1;
}
