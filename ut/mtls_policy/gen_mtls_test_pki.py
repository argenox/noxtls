#!/usr/bin/env python3
# Copyright (c) [2019] - [2026], Argenox Technologies LLC
# SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
#
# File:    gen_mtls_test_pki.py
# Summary: Generate the P-256 test PKI used by the mutual-TLS policy tests.
#
# Usage: python gen_mtls_test_pki.py > mtls_test_pki.h
# Requires the "cryptography" package. Output is committed so the tests do
# not depend on Python at build time. Private-use extension values follow
# the Thread TCAT certificate attribute layout (OID arc 1.3.6.1.4.1.44970).

import datetime
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

THREAD_ARC = "1.3.6.1.4.1.44970"
VALID_FROM = datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc)
VALID_TO = datetime.datetime(2049, 12, 31, 23, 59, 59, tzinfo=datetime.timezone.utc)
EXPIRED_FROM = datetime.datetime(2001, 1, 1, tzinfo=datetime.timezone.utc)
EXPIRED_TO = datetime.datetime(2002, 1, 1, tzinfo=datetime.timezone.utc)


def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NoxTLS Test"),
                      x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def key_usage(digital_signature=False, key_agreement=False, key_encipherment=False,
              cert_sign=False):
    return x509.KeyUsage(digital_signature=digital_signature, content_commitment=False,
                         key_encipherment=key_encipherment, data_encipherment=False,
                         key_agreement=key_agreement, key_cert_sign=cert_sign,
                         crl_sign=cert_sign, encipher_only=False, decipher_only=False)


def build(subject_cn, subject_key, issuer_cn, issuer_key, serial, ca=False,
          path_len=None, ku=None, eku=None, extra=(), not_before=VALID_FROM,
          not_after=VALID_TO):
    builder = (x509.CertificateBuilder()
               .subject_name(name(subject_cn))
               .issuer_name(name(issuer_cn))
               .public_key(subject_key.public_key())
               .serial_number(serial)
               .not_valid_before(not_before)
               .not_valid_after(not_after)
               .add_extension(x509.BasicConstraints(ca=ca, path_length=path_len), critical=True))
    if ku is not None:
        builder = builder.add_extension(ku, critical=True)
    if eku is not None:
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()), critical=False)
    for oid, der in extra:
        builder = builder.add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier(oid), der),
                                        critical=False)
    return builder.sign(issuer_key, hashes.SHA256())


def c_array(label, data):
    lines = ["static const uint8_t %s[] = {" % label]
    for i in range(0, len(data), 12):
        chunk = ", ".join("0x%02X" % b for b in data[i:i + 12])
        lines.append("    %s," % chunk)
    lines.append("};")
    return "\n".join(lines)


def key_der(key):
    return key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.TraditionalOpenSSL,
                             serialization.NoEncryption())


def main():
    curve = ec.SECP256R1()
    ca_key = ec.generate_private_key(curve)
    int_key = ec.generate_private_key(curve)
    rogue_key = ec.generate_private_key(curve)
    server_key = ec.generate_private_key(curve)
    client_key = ec.generate_private_key(curve)

    ca_ku = key_usage(cert_sign=True)
    leaf_ku = key_usage(digital_signature=True)
    auth_attr = (THREAD_ARC + ".3", bytes([0x04, 0x05, 0x21, 0x01, 0x01, 0x01, 0x01]))
    domain_attr = (THREAD_ARC + ".1", bytes([0x16, 0x0D]) + b"DefaultDomain")
    server_attr = (THREAD_ARC + ".3", bytes([0x04, 0x05, 0x20, 0x01, 0x01, 0x01, 0x01]))
    version_attr = (THREAD_ARC + ".2", bytes([0x02, 0x01, 0x05]))

    ca = build("Test Root CA", ca_key, "Test Root CA", ca_key, 1, ca=True, path_len=1, ku=ca_ku)
    inter = build("Test Intermediate CA", int_key, "Test Root CA", ca_key, 2, ca=True, path_len=0,
                  ku=ca_ku)
    rogue = build("Rogue Root CA", rogue_key, "Rogue Root CA", rogue_key, 3, ca=True, ku=ca_ku)
    server = build("Test Device", server_key, "Test Root CA", ca_key, 10, ku=leaf_ku,
                   extra=(version_attr, server_attr))
    client = build("Test Commissioner", client_key, "Test Intermediate CA", int_key, 20, ku=leaf_ku,
                   eku=[ExtendedKeyUsageOID.CLIENT_AUTH], extra=(domain_attr, auth_attr))
    client_direct = build("Test Commissioner Direct", client_key, "Test Root CA", ca_key, 21,
                          ku=leaf_ku, extra=(auth_attr,))
    client_expired = build("Test Commissioner Expired", client_key, "Test Root CA", ca_key, 22,
                           ku=leaf_ku, extra=(auth_attr,), not_before=EXPIRED_FROM,
                           not_after=EXPIRED_TO)
    client_key_agreement = build("Test Commissioner KeyAgreement", client_key, "Test Root CA", ca_key,
                                 23, ku=key_usage(key_agreement=True), extra=(auth_attr,))
    client_server_eku = build("Test Commissioner ServerAuth", client_key, "Test Root CA", ca_key, 24,
                              ku=leaf_ku, eku=[ExtendedKeyUsageOID.SERVER_AUTH], extra=(auth_attr,))
    client_rogue = build("Test Commissioner Rogue", client_key, "Rogue Root CA", rogue_key, 25,
                         ku=leaf_ku, extra=(auth_attr,))

    der = lambda c: c.public_bytes(serialization.Encoding.DER)
    out = []
    out.append("/* Generated by gen_mtls_test_pki.py - do not edit. P-256 / ecdsa-with-SHA256. */")
    out.append("#ifndef MTLS_TEST_PKI_H")
    out.append("#define MTLS_TEST_PKI_H")
    out.append("")
    out.append("#include <stdint.h>")
    out.append("")
    for label, data in (("mtls_ca_cert", der(ca)), ("mtls_intermediate_cert", der(inter)),
                        ("mtls_rogue_ca_cert", der(rogue)), ("mtls_server_cert", der(server)),
                        ("mtls_server_key", key_der(server_key)), ("mtls_client_cert", der(client)),
                        ("mtls_client_direct_cert", der(client_direct)),
                        ("mtls_client_expired_cert", der(client_expired)),
                        ("mtls_client_key_agreement_cert", der(client_key_agreement)),
                        ("mtls_client_server_eku_cert", der(client_server_eku)),
                        ("mtls_client_rogue_cert", der(client_rogue)),
                        ("mtls_client_key", key_der(client_key))):
        out.append(c_array(label, data))
        out.append("")
    out.append("#endif /* MTLS_TEST_PKI_H */")
    sys.stdout.write("\n".join(out) + "\n")


if __name__ == "__main__":
    main()
