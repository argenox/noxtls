#!/usr/bin/env python3
# Copyright (c) [2019] - [2026], Argenox Technologies LLC
# SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
#
# File:    gen_loopback_pki.py
# Summary: Generate the test PKI shared by the TLS loopback, X.509 parse and
#          RAM budget tests.
#
# Usage: python gen_loopback_pki.py <output_dir>
#   writes <output_dir>/loopback_pki.c and <output_dir>/loopback_pki.h
#
# Requires the "cryptography" package. The output is committed so the tests do
# not depend on Python at build time; re-running produces new keys, so commit
# both files together. Cross-check a certificate with e.g.
#   python -c "import loopback_pki" (n/a) or dump a PEM array and run
#   openssl x509 -noout -text -in cert.pem
#
# Contents
#   EC P-256 (ecdsa-with-SHA256):
#     ec_root (CA, pathLen 1) -> ec_client; ec_root -> ec_int (CA, pathLen 0) -> ec_server,
#     ec_revoked, ec_expired, ec_cn_only, ec_int2 (CA, violates pathLen 0) -> ec_deep
#     ec_root2, ec_root3 (unrelated anchors), ec_root3 -> ec_other_server
#     rogue_root -> rogue_server (same names as ec_server, untrusted)
#     ec_int CRL revoking ec_revoked plus two unrelated serials
#   RSA-2048 (sha256WithRSAEncryption): rsa_root -> rsa_server, rsa_client
#   Ed25519: ec_root -> ed_server (Ed25519 key, ECDSA-signed), ed_root (self-signed Ed25519)

import datetime
import os
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, ed25519
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

VALID_FROM = datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc)
VALID_TO = datetime.datetime(2049, 12, 31, 23, 59, 59, tzinfo=datetime.timezone.utc)
EXPIRED_FROM = datetime.datetime(2001, 1, 1, tzinfo=datetime.timezone.utc)
EXPIRED_TO = datetime.datetime(2002, 1, 1, tzinfo=datetime.timezone.utc)
CRL_THIS = datetime.datetime(2025, 1, 2, tzinfo=datetime.timezone.utc)
CRL_NEXT = datetime.datetime(2049, 12, 1, tzinfo=datetime.timezone.utc)

SERIAL_EC_ROOT = 0x01
SERIAL_EC_INT = 0x02
SERIAL_EC_SERVER = 0x1001
SERIAL_EC_CLIENT = 0x1002
SERIAL_EC_REVOKED = 0x1003
SERIAL_EC_EXPIRED = 0x1004
SERIAL_EC_CN_ONLY = 0x1005
SERIAL_EC_INT2 = 0x1006
SERIAL_EC_DEEP = 0x1007
SERIAL_CRL_EXTRA = (0x2001, 0x2002)


def name(cn, org="NoxTLS Test"):
    return x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
                      x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def key_usage(digital_signature=False, key_encipherment=False, cert_sign=False):
    return x509.KeyUsage(digital_signature=digital_signature, content_commitment=False,
                         key_encipherment=key_encipherment, data_encipherment=False,
                         key_agreement=False, key_cert_sign=cert_sign, crl_sign=cert_sign,
                         encipher_only=False, decipher_only=False)


def sig_hash(issuer_key):
    if isinstance(issuer_key, ed25519.Ed25519PrivateKey):
        return None
    return hashes.SHA256()


def build(subject, subject_key, issuer, issuer_key, serial, ca=False, path_len=None,
          ku=None, eku=None, san=None, not_before=VALID_FROM, not_after=VALID_TO, extra=()):
    pub = subject_key.public_key()
    builder = (x509.CertificateBuilder()
               .subject_name(subject)
               .issuer_name(issuer)
               .public_key(pub)
               .serial_number(serial)
               .not_valid_before(not_before)
               .not_valid_after(not_after)
               .add_extension(x509.BasicConstraints(ca=ca, path_length=path_len), critical=True)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(pub), critical=False)
               .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                   issuer_key.public_key()), critical=False))
    if ku is not None:
        builder = builder.add_extension(ku, critical=True)
    if eku is not None:
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    if san:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in san]), critical=False)
    for oid, value in extra:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(x509.ObjectIdentifier(oid), value), critical=False)
    return builder.sign(issuer_key, sig_hash(issuer_key))


def c_array(label, data):
    lines = ["const uint8_t %s[] = {" % label]
    for i in range(0, len(data), 12):
        chunk = ", ".join("0x%02X" % b for b in data[i:i + 12])
        lines.append("    %s," % chunk)
    lines.append("};")
    lines.append("const uint32_t %s_len = (uint32_t)sizeof(%s);" % (label, label))
    return "\n".join(lines)


def der(cert):
    return cert.public_bytes(serialization.Encoding.DER)


def pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


def trad_key_der(key):
    return key.private_bytes(serialization.Encoding.DER,
                             serialization.PrivateFormat.TraditionalOpenSSL,
                             serialization.NoEncryption())


def pkcs8_der(key):
    return key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def ski(cert):
    return cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest


def aki(cert):
    return cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier


def name_der(cert_name):
    return cert_name.public_bytes()


def main():
    out_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__))
    p256 = ec.SECP256R1()
    ec_root_key = ec.generate_private_key(p256)
    ec_int_key = ec.generate_private_key(p256)
    ec_int2_key = ec.generate_private_key(p256)
    ec_server_key = ec.generate_private_key(p256)
    ec_client_key = ec.generate_private_key(p256)
    ec_root2_key = ec.generate_private_key(p256)
    ec_root3_key = ec.generate_private_key(p256)
    rogue_key = ec.generate_private_key(p256)
    ec_csr_key = ec.generate_private_key(p256)
    rsa_root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ed_server_key = ed25519.Ed25519PrivateKey.generate()
    ed_root_key = ed25519.Ed25519PrivateKey.generate()

    ca_ku = key_usage(cert_sign=True)
    leaf_ku = key_usage(digital_signature=True)
    rsa_leaf_ku = key_usage(digital_signature=True, key_encipherment=True)
    server_eku = [ExtendedKeyUsageOID.SERVER_AUTH]
    client_eku = [ExtendedKeyUsageOID.CLIENT_AUTH]

    n_root = name("NoxTLS Test EC Root")
    n_int = name("NoxTLS Test EC Intermediate")
    n_int2 = name("NoxTLS Test EC Sub Intermediate")
    ec_root = build(n_root, ec_root_key, n_root, ec_root_key, SERIAL_EC_ROOT, ca=True,
                    path_len=1, ku=ca_ku)
    ec_int = build(n_int, ec_int_key, n_root, ec_root_key, SERIAL_EC_INT, ca=True, path_len=0,
                   ku=ca_ku)
    ec_server = build(name("server.test"), ec_server_key, n_int, ec_int_key, SERIAL_EC_SERVER,
                      ku=leaf_ku, eku=server_eku,
                      san=["server.test", "alt.test", "*.wild.test"])
    # Issued directly by the root: TLS clients send no intermediates for their own certificate.
    ec_client = build(name("client.test"), ec_client_key, n_root, ec_root_key, SERIAL_EC_CLIENT,
                      ku=leaf_ku, eku=client_eku)
    ec_revoked = build(name("revoked.test"), ec_server_key, n_int, ec_int_key, SERIAL_EC_REVOKED,
                       ku=leaf_ku, eku=server_eku, san=["revoked.test"])
    ec_expired = build(name("expired.test"), ec_server_key, n_int, ec_int_key, SERIAL_EC_EXPIRED,
                       ku=leaf_ku, eku=server_eku, san=["expired.test"],
                       not_before=EXPIRED_FROM, not_after=EXPIRED_TO)
    # For the OpenSSL interop test (clients connect to 127.0.0.1 as "localhost").
    ec_localhost = build(name("localhost"), ec_server_key, n_int, ec_int_key, 0x1009,
                         ku=leaf_ku, eku=server_eku, san=["localhost"])
    ec_cn_only = build(name("cnonly.test"), ec_server_key, n_int, ec_int_key, SERIAL_EC_CN_ONLY,
                       ku=leaf_ku, eku=server_eku)
    ec_int2 = build(n_int2, ec_int2_key, n_int, ec_int_key, SERIAL_EC_INT2, ca=True, ku=ca_ku)
    ec_deep = build(name("deep.test"), ec_server_key, n_int2, ec_int2_key, SERIAL_EC_DEEP,
                    ku=leaf_ku, eku=server_eku, san=["deep.test"])
    # Larger than the default NOXTLS_MAX_CERT_SIZE (16384) through one opaque extension.
    big_value = bytes([0x04, 0x82, 0x46, 0x50]) + bytes(range(256)) * 70
    ec_oversized = build(name("oversized.test"), ec_server_key, n_int, ec_int_key, 0x1008,
                         ku=leaf_ku, eku=server_eku, san=["oversized.test"],
                         extra=(("1.3.6.1.4.1.55555.1", big_value),))
    n_root2 = name("NoxTLS Test EC Root 2")
    n_root3 = name("NoxTLS Test EC Root 3")
    ec_root2 = build(n_root2, ec_root2_key, n_root2, ec_root2_key, 0x21, ca=True, ku=ca_ku)
    ec_root3 = build(n_root3, ec_root3_key, n_root3, ec_root3_key, 0x31, ca=True, ku=ca_ku)
    ec_other_server = build(name("other.test"), ec_server_key, n_root3, ec_root3_key, 0x3101,
                            ku=leaf_ku, eku=server_eku, san=["other.test"])
    n_rogue = name("NoxTLS Test EC Root", org="Rogue")
    rogue_root = build(n_rogue, rogue_key, n_rogue, rogue_key, 0x41, ca=True, ku=ca_ku)
    rogue_server = build(name("server.test"), ec_server_key, n_rogue, rogue_key, 0x4101,
                         ku=leaf_ku, eku=server_eku, san=["server.test"])

    n_rsa_root = name("NoxTLS Test RSA Root")
    rsa_root = build(n_rsa_root, rsa_root_key, n_rsa_root, rsa_root_key, 0x51, ca=True,
                     path_len=0, ku=ca_ku)
    rsa_server = build(name("rsa.test"), rsa_server_key, n_rsa_root, rsa_root_key, 0x5101,
                       ku=rsa_leaf_ku, eku=server_eku, san=["rsa.test", "server.test"])
    rsa_client = build(name("rsaclient.test"), rsa_client_key, n_rsa_root, rsa_root_key, 0x5102,
                       ku=leaf_ku, eku=client_eku)

    ed_server = build(name("ed.test"), ed_server_key, n_root, ec_root_key, 0x6101, ku=leaf_ku,
                      eku=server_eku, san=["ed.test", "server.test"])
    n_ed_root = name("NoxTLS Test Ed25519 Root")
    ed_root = build(n_ed_root, ed_root_key, n_ed_root, ed_root_key, 0x61, ca=True, ku=ca_ku)

    crl_builder = (x509.CertificateRevocationListBuilder()
                   .issuer_name(n_int)
                   .last_update(CRL_THIS)
                   .next_update(CRL_NEXT)
                   .add_extension(x509.CRLNumber(7), critical=False)
                   .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                       ec_int_key.public_key()), critical=False))
    for serial in (SERIAL_CRL_EXTRA[0], SERIAL_EC_REVOKED, SERIAL_CRL_EXTRA[1]):
        crl_builder = crl_builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder().serial_number(serial)
            .revocation_date(CRL_THIS).build())
    ec_int_crl = crl_builder.sign(ec_int_key, hashes.SHA256())

    ec_server_point = ec_server_key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    rsa_server_modulus = rsa_server_key.public_key().public_numbers().n.to_bytes(256, "big")
    ed_server_pub = ed_server_key.public_key().public_bytes(serialization.Encoding.Raw,
                                                            serialization.PublicFormat.Raw)
    ec_csr_point = ec_csr_key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)

    blobs = [
        ("lb_ec_root_cert", der(ec_root)), ("lb_ec_int_cert", der(ec_int)),
        ("lb_ec_server_cert", der(ec_server)), ("lb_ec_server_key", trad_key_der(ec_server_key)),
        ("lb_ec_client_cert", der(ec_client)), ("lb_ec_client_key", trad_key_der(ec_client_key)),
        ("lb_ec_revoked_cert", der(ec_revoked)), ("lb_ec_expired_cert", der(ec_expired)),
        ("lb_ec_cn_only_cert", der(ec_cn_only)), ("lb_ec_localhost_cert", der(ec_localhost)), ("lb_ec_int2_cert", der(ec_int2)),
        ("lb_ec_deep_cert", der(ec_deep)), ("lb_ec_oversized_cert", der(ec_oversized)),
        ("lb_ec_root2_cert", der(ec_root2)),
        ("lb_ec_root3_cert", der(ec_root3)), ("lb_ec_other_server_cert", der(ec_other_server)),
        ("lb_rogue_root_cert", der(rogue_root)), ("lb_rogue_server_cert", der(rogue_server)),
        ("lb_rsa_root_cert", der(rsa_root)), ("lb_rsa_server_cert", der(rsa_server)),
        ("lb_rsa_server_key", trad_key_der(rsa_server_key)),
        ("lb_rsa_client_cert", der(rsa_client)), ("lb_rsa_client_key", trad_key_der(rsa_client_key)),
        ("lb_ed_server_cert", der(ed_server)), ("lb_ed_server_key", pkcs8_der(ed_server_key)),
        ("lb_ed_root_cert", der(ed_root)),
        ("lb_ec_csr_key", trad_key_der(ec_csr_key)),
        ("lb_ec_int_crl", ec_int_crl.public_bytes(serialization.Encoding.DER)),
        # PEM encodings (NUL-free text; the _len excludes no terminator).
        ("lb_ec_root_pem", pem(ec_root)), ("lb_ec_int_pem", pem(ec_int)),
        ("lb_ec_server_pem", pem(ec_server)), ("lb_rsa_server_pem", pem(rsa_server)),
        ("lb_ec_int_crl_pem", ec_int_crl.public_bytes(serialization.Encoding.PEM)),
        # Expected values for field checks.
        ("lb_ec_root_ski", ski(ec_root)), ("lb_ec_int_ski", ski(ec_int)),
        ("lb_ec_int_aki", aki(ec_int)), ("lb_ec_server_ski", ski(ec_server)),
        ("lb_ec_server_aki", aki(ec_server)),
        ("lb_ec_int_subject_der", name_der(ec_int.subject)),
        ("lb_ec_server_subject_der", name_der(ec_server.subject)),
        ("lb_ec_server_point", ec_server_point), ("lb_rsa_server_modulus", rsa_server_modulus),
        ("lb_ed_server_pub", ed_server_pub), ("lb_ec_csr_point", ec_csr_point),
    ]

    header = []
    header.append("/* Generated by gen_loopback_pki.py - do not edit. */")
    header.append("#ifndef LOOPBACK_PKI_H")
    header.append("#define LOOPBACK_PKI_H")
    header.append("")
    header.append("#include <stdint.h>")
    header.append("")
    header.append("/* Validity of every non-expired certificate (seconds since the Unix epoch). */")
    header.append("#define LB_PKI_NOT_BEFORE %dLL" % int(VALID_FROM.timestamp()))
    header.append("#define LB_PKI_NOT_AFTER %dLL" % int(VALID_TO.timestamp()))
    header.append("#define LB_PKI_EXPIRED_NOT_AFTER %dLL" % int(EXPIRED_TO.timestamp()))
    header.append("#define LB_PKI_SERIAL_EC_SERVER 0x%XU" % SERIAL_EC_SERVER)
    header.append("#define LB_PKI_SERIAL_EC_CLIENT 0x%XU" % SERIAL_EC_CLIENT)
    header.append("#define LB_PKI_SERIAL_EC_REVOKED 0x%XU" % SERIAL_EC_REVOKED)
    header.append("#define LB_PKI_CRL_REVOKED_COUNT 3U")
    header.append("")
    for label, _ in blobs:
        header.append("extern const uint8_t %s[];" % label)
        header.append("extern const uint32_t %s_len;" % label)
    header.append("")
    header.append("#endif /* LOOPBACK_PKI_H */")

    source = []
    source.append("/* Generated by gen_loopback_pki.py - do not edit. */")
    source.append('#include "loopback_pki.h"')
    source.append("")
    for label, data in blobs:
        source.append(c_array(label, data))
        source.append("")

    with open(os.path.join(out_dir, "loopback_pki.h"), "w", newline="\n") as f:
        f.write("\n".join(header) + "\n")
    with open(os.path.join(out_dir, "loopback_pki.c"), "w", newline="\n") as f:
        f.write("\n".join(source))


if __name__ == "__main__":
    main()
