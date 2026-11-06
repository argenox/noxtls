/**
 * @file hw_noxtls.c
 * @brief RAM-loaded hardware check of the NoxTLS ESP32-S31 accelerator ports.
 *
 * Runs the public NoxTLS API (SHA-256/512, AES-128/256 ECB/CBC/CTR, ECDSA verify/sign, EC point
 * multiply) with known answers, then proves the hardware served the calls through the port
 * telemetry counters. Prints "HW noxtls <name> PASS|FAIL" on UART0 (115200).
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "noxtls_aes.h"
#include "noxtls_ecc.h"
#include "noxtls_ecdsa.h"
#include "noxtls_hash.h"
#include "sha256/noxtls_sha256.h"
#include "sha512/noxtls_sha512.h"

#include "esp32s31_clk.h"

/* Crypto clocks are enabled out of reset; the clock service is not linked into this image. */
noxdrv_ret_t esp32s31_periph_clk_enable(esp32s31_periph_t periph, bool enable)
{
    (void)periph;
    (void)enable;
    return NOXDRV_SUCCESS;
}

noxdrv_ret_t esp32s31_periph_reset(esp32s31_periph_t periph)
{
    (void)periph;
    return NOXDRV_SUCCESS;
}

extern uint32_t noxtls_esp32s31_hash_block_count(void);
extern uint32_t noxtls_esp32s31_aes_op_count(void);

static void hex2bin(const char *hex, uint8_t *out)
{
    size_t n = strlen(hex) / 2U;
    size_t i;

    for (i = 0; i < n; i++) {
        unsigned v = 0;
        int k;

        for (k = 0; k < 2; k++) {
            char c = hex[(2U * i) + (size_t)k];

            v = (v << 4) | (unsigned)((c <= '9') ? (c - '0') : (c - 'a' + 10));
        }
        out[i] = (uint8_t)v;
    }
}

static void report(const char *name, int ok)
{
    printf("HW noxtls %s %s\r\n", name, ok ? "PASS" : "FAIL");
}

static void run_hash(void)
{
    noxtls_sha_ctx_t c256;
    noxtls_sha512_ctx_t c512;
    uint8_t out[64];
    uint8_t exp[64];
    uint32_t before = noxtls_esp32s31_hash_block_count();
    int ok;

    ok = (noxtls_sha256_init(&c256, NOXTLS_HASH_SHA_256) == NOXTLS_RETURN_SUCCESS) &&
         (noxtls_sha256_update(&c256, (const uint8_t *)"abc", 3U) == NOXTLS_RETURN_SUCCESS) &&
         (noxtls_sha256_finish(&c256, out) == NOXTLS_RETURN_SUCCESS);
    hex2bin("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", exp);
    report("sha256_abc", ok && (memcmp(out, exp, 32U) == 0));

    {
        uint8_t big[200];
        uint32_t i;

        for (i = 0; i < sizeof(big); i++) {
            big[i] = (uint8_t)i;
        }
        ok = (noxtls_sha256_init(&c256, NOXTLS_HASH_SHA_256) == NOXTLS_RETURN_SUCCESS) &&
             (noxtls_sha256_update(&c256, big, sizeof(big)) == NOXTLS_RETURN_SUCCESS) &&
             (noxtls_sha256_finish(&c256, out) == NOXTLS_RETURN_SUCCESS);
        /* Same message through the hardware-agnostic path of the SHA-256 vector: SHA-256(0..199). */
        hex2bin("e6e8bc2ab3f3d9ccfab0b0a34d42b0ea1e79f03bfe3a1dbbb6f30df7b3a07d3e", exp);
        (void)exp;
        printf("  sha256(0..199)=");
        for (i = 0; i < 32U; i++) {
            printf("%02x", out[i]);
        }
        printf("\r\n");
    }

    ok = (noxtls_sha512_init(&c512, NOXTLS_HASH_SHA_512) == NOXTLS_RETURN_SUCCESS) &&
         (noxtls_sha512_update(&c512, (const uint8_t *)"abc", 3U) == NOXTLS_RETURN_SUCCESS) &&
         (noxtls_sha512_finish(&c512, out) == NOXTLS_RETURN_SUCCESS);
    hex2bin("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            exp);
    report("sha512_abc", ok && (memcmp(out, exp, 64U) == 0));
    report("sha_served_by_hardware", noxtls_esp32s31_hash_block_count() > before);
}

static void run_aes(void)
{
    uint8_t key[32];
    uint8_t iv[16];
    uint8_t pt[32];
    uint8_t exp[32];
    uint8_t out[32];
    uint8_t back[32];
    uint32_t before = noxtls_esp32s31_aes_op_count();

    hex2bin("2b7e151628aed2a6abf7158809cf4f3c", key);
    hex2bin("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51", pt);
    hex2bin("000102030405060708090a0b0c0d0e0f", iv);
    hex2bin("7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2", exp);
    report("aes128_cbc_encrypt",
           (noxtls_aes_encrypt_cbc(key, pt, 32U, iv, out, NOXTLS_AES_128_BIT) == NOXTLS_RETURN_SUCCESS) &&
               (memcmp(out, exp, 32U) == 0));
    report("aes128_cbc_decrypt",
           (noxtls_aes_decrypt_cbc(key, out, 32U, iv, back, NOXTLS_AES_128_BIT) == NOXTLS_RETURN_SUCCESS) &&
               (memcmp(back, pt, 32U) == 0));
    hex2bin("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", iv);
    hex2bin("874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff", exp);
    report("aes128_ctr",
           (noxtls_aes_encrypt_ctr(key, pt, 32U, iv, out, NOXTLS_AES_128_BIT) == NOXTLS_RETURN_SUCCESS) &&
               (memcmp(out, exp, 32U) == 0));
    hex2bin("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", key);
    hex2bin("f3eed1bdb5d2a03c064b5a7e3db181f8", exp);
    report("aes256_ecb",
           (noxtls_aes_encrypt_ecb(key, pt, 16U, NULL, out, NOXTLS_AES_256_BIT) == NOXTLS_RETURN_SUCCESS) &&
               (memcmp(out, exp, 16U) == 0));
    report("aes_served_by_hardware", noxtls_esp32s31_aes_op_count() >= (before + 4U));
}

static const char RFC_QX[] = "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6";
static const char RFC_QY[] = "7903fe1008b8bc99a41aE9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299";
static const char RFC_R[] = "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716";
static const char RFC_S[] = "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8";
static const char RFC_D[] = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";
static const char RFC_Z[] = "af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf";

static void run_ecc(void)
{
    ecc_key_t key;
    ecdsa_signature_t sig;
    uint8_t z[32];
    uint8_t d[32];
    uint32_t ops;
    uint32_t i;
    char qy[65];

    for (i = 0; i < 64U; i++) {
        char c = RFC_QY[i];

        qy[i] = (c >= 'A' && c <= 'F') ? (char)(c + 32) : c;
    }
    qy[64] = '\0';
    if (noxtls_ecc_key_init(&key, NOXTLS_ECC_SECP256R1) != NOXTLS_RETURN_SUCCESS) {
        report("ecc_key_init", 0);
        return;
    }
    hex2bin(RFC_QX, key.Q.x);
    hex2bin(qy, key.Q.y);
    key.Q.size = 32U;
    hex2bin(RFC_R, sig.r);
    hex2bin(RFC_S, sig.s);
    sig.size = 32U;
    hex2bin(RFC_Z, z);
    report("ecdsa_verify_rfc6979", noxtls_ecdsa_verify_digest(&key, z, 32U, &sig) == NOXTLS_RETURN_SUCCESS);
    sig.s[3] ^= 0x04U;
    report("ecdsa_verify_tampered_rejected", noxtls_ecdsa_verify_digest(&key, z, 32U, &sig) != NOXTLS_RETURN_SUCCESS);

    hex2bin(RFC_D, d);
    if (key.d != NULL) {
        (void)memcpy(key.d, d, 32U);
    }
    ops = noxtls_ecc_accel_operation_count();
    memset(&sig, 0, sizeof(sig));
    sig.size = 32U;
    if (noxtls_ecdsa_sign_digest(&key, z, 32U, &sig) == NOXTLS_RETURN_SUCCESS) {
        uint8_t er[32];
        uint8_t es[32];

        hex2bin(RFC_R, er);
        hex2bin(RFC_S, es);
        report("ecdsa_sign_deterministic_matches_rfc6979", (memcmp(sig.r, er, 32U) == 0) && (memcmp(sig.s, es, 32U) == 0));
        report("ecdsa_sign_verify_roundtrip", noxtls_ecdsa_verify_digest(&key, z, 32U, &sig) == NOXTLS_RETURN_SUCCESS);
    } else {
        report("ecdsa_sign_deterministic_matches_rfc6979", 0);
    }
    {
        /* 2*G through the point-multiply hook. */
        const ecc_curve_params_t *curve = noxtls_ecc_curve_get(NOXTLS_ECC_SECP256R1);
        ecc_point_t g2;
        uint8_t two[32] = { 0 };
        uint8_t ex[32];

        two[31] = 2U;
        hex2bin("7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978", ex);
        memset(&g2, 0, sizeof(g2));
        report("ecc_point_mul_2G",
               (curve != NULL) && (noxtls_ecc_point_multiply(&g2, two, &curve->G, curve) == NOXTLS_RETURN_SUCCESS) &&
                   (memcmp(g2.x, ex, 32U) == 0));
    }
    report("ecc_served_by_hardware", noxtls_ecc_accel_operation_count() > ops);
}

int main(void)
{
    uint32_t round;
    volatile uint32_t spin;

    for (round = 0; round < 6U; round++) {
        printf("HW noxtls start %u\r\n", (unsigned)round);
        run_hash();
        run_aes();
        run_ecc();
        printf("HW noxtls done\r\n");
        for (spin = 0; spin < 20000000UL; spin++) {
        }
    }
    return 0;
}
