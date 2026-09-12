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
    ecc_point_t captured_invalid_p256_point;
    uint8_t secret[32];
    uint32_t secret_len;
    noxtls_ecdh_diagnostic_t diagnostic;
    noxtls_return_t rc;
    tls_ecdhe_context_t tls_ecdhe;
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

    /*
     * Regression vector captured from a failed LE Secure Connections P-256
     * exchange.  Its coordinates are stored here in NoxTLS' big-endian
     * representation; the original SMP Pairing Public Key was little-endian
     * X || Y.  Independently checking the curve equation rejects this point.
     */
    {
        static const uint8_t captured_x[32] = {
            0x13u, 0x4Cu, 0x61u, 0xB5u, 0x52u, 0x97u, 0xB2u, 0x2Au,
            0xEDu, 0x5Fu, 0xB3u, 0xC7u, 0x85u, 0xE2u, 0xFCu, 0xEDu,
            0x8Fu, 0x69u, 0xE5u, 0xBCu, 0x65u, 0x22u, 0x30u, 0x7Eu,
            0xF9u, 0xCCu, 0xAFu, 0xE9u, 0x25u, 0x03u, 0xADu, 0xB7u,
        };
        static const uint8_t captured_y[32] = {
            0xB2u, 0x80u, 0x34u, 0x49u, 0x23u, 0x13u, 0x4Cu, 0x61u,
            0xB5u, 0x52u, 0x97u, 0xB2u, 0x2Au, 0xEDu, 0x5Fu, 0x94u,
            0x94u, 0xA5u, 0x88u, 0x92u, 0x9Fu, 0xA9u, 0x70u, 0xBDu,
            0xA8u, 0x30u, 0xEDu, 0xB2u, 0x80u, 0x34u, 0x49u, 0x23u,
        };

        memset(&captured_invalid_p256_point, 0,
               sizeof(captured_invalid_p256_point));
        memcpy(captured_invalid_p256_point.x, captured_x,
               sizeof(captured_x));
        memcpy(captured_invalid_p256_point.y, captured_y,
               sizeof(captured_y));
        captured_invalid_p256_point.size = key.curve->size;
        rc = noxtls_ecc_point_validate_public(&captured_invalid_p256_point,
                                              key.curve);
        ok &= expect(rc != NOXTLS_RETURN_SUCCESS,
                     "reject captured off-curve P-256 public key");
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
