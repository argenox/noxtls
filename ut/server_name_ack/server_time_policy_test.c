/* Copyright (c) 2026 Argenox Technologies LLC.
 * SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial */
/** @file server_time_policy_test.c
 * @brief Explicit clockless bootstrap through the real TLS 1.3 Certificate path. */
#include <stdio.h>
#include <string.h>
#include "noxtls_tls13.h"
#include "noxtls_x509.h"
#include "common/noxtls_memory.h"
#include "../mtls_policy/mtls_test_pki.h"

#define CHECK(c) do { if(!(c)) { fprintf(stderr,"%s:%d: %s\n",__FILE__,__LINE__,#c); return 1; } } while(0)
#define TIME_NOW 1791158400LL
#define TIME_PAST 991353600LL
#define TIME_FUTURE 2556144000LL

static tls13_context_t client;
static x509_certificate_t ca, rogue, leaf;
static x509_certificate_chain_t anchors, rogue_anchors, empty;

/** @brief Write a TLS uint24. @param[out] out Bytes. @param[in] n Value. */
static void put24(uint8_t *out, uint32_t n)
{
    out[0]=(uint8_t)(n>>16U);out[1]=(uint8_t)(n>>8U);out[2]=(uint8_t)n;
}

/** @brief Deliver a real TLS Certificate with a configured verification policy.
 * @param[in] policy Borrowed policy, or NULL for existing defaults.
 * @param[in] der Test leaf DER. @param[in] length DER length.
 * @param[in] crl Context CRL, optionally configured independently.
 * @return Certificate receive/verification result. */
static noxtls_return_t receive_certificate(const noxtls_x509_verify_policy_t *policy,
    const uint8_t *der, uint32_t length, const noxtls_x509_crl_t *crl)
{
    noxtls_return_t rc=noxtls_tls13_context_init(&client,TLS_ROLE_CLIENT);
    if(rc!=NOXTLS_RETURN_SUCCESS) return rc;
    if(client.server_verify_policy!=NULL) return NOXTLS_RETURN_FAILED;
    noxtls_tls13_set_server_verify_policy(&client,policy);
    noxtls_tls13_set_verify_crl(&client,crl);
    uint32_t bytes=13U+length;
    uint8_t *msg=NOXTLS_MALLOC(bytes);
    if(msg==NULL) { (void)noxtls_tls13_context_free(&client);return NOXTLS_RETURN_NOT_ENOUGH_MEMORY; }
    memset(msg,0,bytes);
    msg[0]=TLS_HANDSHAKE_CERTIFICATE;
    put24(msg+1U,bytes-4U);
    put24(msg+5U,length+5U);
    put24(msg+8U,length);
    memcpy(msg+11U,der,length);
    client.hs->pending_handshake_msg=msg;
    client.hs->pending_handshake_len=bytes;
    rc=noxtls_tls13_recv_certificate(&client);
    (void)noxtls_tls13_context_free(&client);
    return rc;
}

/** @brief Check defaults, opt-in, trusted signatures, purpose and date enforcement. */
int main(void)
{
    noxtls_x509_verify_policy_t policy={0};
    CHECK(noxtls_x509_certificate_init(&ca)==NOXTLS_RETURN_SUCCESS);
    CHECK(noxtls_x509_certificate_init(&rogue)==NOXTLS_RETURN_SUCCESS);
    CHECK(noxtls_x509_certificate_init(&leaf)==NOXTLS_RETURN_SUCCESS);
    CHECK(noxtls_x509_certificate_parse_der(&ca,mtls_ca_cert,sizeof(mtls_ca_cert))==NOXTLS_RETURN_SUCCESS);
    CHECK(noxtls_x509_certificate_parse_der(&rogue,mtls_rogue_ca_cert,sizeof(mtls_rogue_ca_cert))==NOXTLS_RETURN_SUCCESS);
    CHECK(noxtls_x509_certificate_parse_der(&leaf,mtls_server_cert,sizeof(mtls_server_cert))==NOXTLS_RETURN_SUCCESS);
    CHECK(noxtls_x509_certificate_chain_init(&anchors)==NOXTLS_RETURN_SUCCESS);
    CHECK(noxtls_x509_certificate_chain_init(&rogue_anchors)==NOXTLS_RETURN_SUCCESS);
    CHECK(noxtls_x509_certificate_chain_init(&empty)==NOXTLS_RETURN_SUCCESS);
    CHECK(noxtls_x509_certificate_chain_add(&anchors,&ca)==NOXTLS_RETURN_SUCCESS);
    CHECK(noxtls_x509_certificate_chain_add(&rogue_anchors,&rogue)==NOXTLS_RETURN_SUCCESS);
    noxtls_x509_trust_store_clear();
    noxtls_tls13_set_server_verify_policy(NULL,NULL);
    CHECK(receive_certificate(NULL,mtls_server_cert,sizeof(mtls_server_cert),NULL)!=NOXTLS_RETURN_SUCCESS);
    policy.trust_anchors=&anchors;
    policy.time_mode=NOXTLS_X509_TIME_EXPLICIT;
    policy.verify_time=TIME_NOW;
    CHECK(receive_certificate(&policy,mtls_server_cert,sizeof(mtls_server_cert),NULL)==NOXTLS_RETURN_SUCCESS);
    policy.verify_time=TIME_FUTURE;
    CHECK(receive_certificate(&policy,mtls_server_cert,sizeof(mtls_server_cert),NULL)==NOXTLS_RETURN_CERT_EXPIRED);
    policy.verify_time=TIME_PAST;
    CHECK(receive_certificate(&policy,mtls_server_cert,sizeof(mtls_server_cert),NULL)==NOXTLS_RETURN_CERT_NOT_YET_VALID);
    policy.time_mode=NOXTLS_X509_TIME_DEFERRED;
    CHECK(receive_certificate(&policy,mtls_server_cert,sizeof(mtls_server_cert),NULL)==NOXTLS_RETURN_SUCCESS);
    CHECK(noxtls_x509_certificate_matches_hostname(&leaf,(const uint8_t *)"wrong.example",13U)!=NOXTLS_RETURN_SUCCESS);
    uint8_t tampered[sizeof(mtls_server_cert)];
    memcpy(tampered,mtls_server_cert,sizeof(tampered));tampered[sizeof(tampered)-1U]^=1U;
    CHECK(receive_certificate(&policy,tampered,sizeof(tampered),NULL)!=NOXTLS_RETURN_SUCCESS);
    CHECK(receive_certificate(&policy,mtls_client_cert,sizeof(mtls_client_cert),NULL)!=NOXTLS_RETURN_SUCCESS);
    policy.trust_anchors=&rogue_anchors;
    CHECK(receive_certificate(&policy,mtls_server_cert,sizeof(mtls_server_cert),NULL)!=NOXTLS_RETURN_SUCCESS);
    policy.trust_anchors=&empty;
    CHECK(receive_certificate(&policy,mtls_server_cert,sizeof(mtls_server_cert),NULL)!=NOXTLS_RETURN_SUCCESS);
    policy.trust_anchors=&anchors;
    noxtls_x509_crl_t crl={0};
    CHECK(receive_certificate(&policy,mtls_server_cert,sizeof(mtls_server_cert),&crl)==NOXTLS_RETURN_INVALID_PARAM);
    policy.crl=&crl;
    CHECK(receive_certificate(&policy,mtls_server_cert,sizeof(mtls_server_cert),NULL)==NOXTLS_RETURN_INVALID_PARAM);
    policy.crl=NULL;
    policy.required_eku=X509_EKU_CLIENT_AUTH;
    CHECK(receive_certificate(&policy,mtls_server_cert,sizeof(mtls_server_cert),NULL)==NOXTLS_RETURN_INVALID_PARAM);
    policy.required_eku=X509_EKU_SERVER_AUTH;
    /* Simulate a malformed notBefore (validity is decoded once at parse time). */
    leaf.validity_flags=(uint8_t)(leaf.validity_flags|X509_VALIDITY_NOT_BEFORE_BAD);
    CHECK(noxtls_x509_verify_cert_with_policy(&leaf,NULL,&policy,NULL)==NOXTLS_RETURN_BAD_DATA);
    policy.time_mode=(noxtls_x509_time_mode_t)99;
    CHECK(receive_certificate(&policy,mtls_server_cert,sizeof(mtls_server_cert),NULL)==NOXTLS_RETURN_INVALID_PARAM);
    CHECK(noxtls_x509_certificate_chain_free(&empty)==NOXTLS_RETURN_SUCCESS);
    CHECK(noxtls_x509_certificate_chain_free(&rogue_anchors)==NOXTLS_RETURN_SUCCESS);
    CHECK(noxtls_x509_certificate_chain_free(&anchors)==NOXTLS_RETURN_SUCCESS);
    CHECK(noxtls_x509_certificate_free(&leaf)==NOXTLS_RETURN_SUCCESS);
    CHECK(noxtls_x509_certificate_free(&rogue)==NOXTLS_RETURN_SUCCESS);
    CHECK(noxtls_x509_certificate_free(&ca)==NOXTLS_RETURN_SUCCESS);
    puts("Explicit server trust, clockless date deferral, strict dates and signature/purpose rejection PASS");
    return 0;
}
