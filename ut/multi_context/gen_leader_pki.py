#!/usr/bin/env python3
# Copyright (c) [2019] - [2026], Argenox Technologies LLC
# SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
#
# File:    gen_leader_pki.py
# Summary: Generate the MQTT broker and device PKI of the leader use-case tests.
#
# Usage: python gen_leader_pki.py <output_dir>
#   writes <output_dir>/leader_pki.c and <output_dir>/leader_pki.h
#
# Requires the "cryptography" package. The output is committed so the tests do not
# depend on Python at build time; re-running produces new keys, so commit both files
# together.
#
# The certificates have the structure and sizes of a cloud MQTT broker's chains (AWS IoT
# Core ATS endpoints) and of its device certificates, under test names:
#   RSA:   broker leaf (RSA-2048, ten SAN names, AIA, CRL distribution point, policies,
#          three embedded SCTs) <- RSA intermediate <- Test Root CA 1 (trusted).
#          The broker also sends Test Root CA 1 cross-signed by an untrusted legacy root,
#          as such brokers do: leaf + intermediate + cross-signed root (3 certificates).
#          After an intermediate rotation: leaf4 <- M03 <- bridge CA <- Test Root CA 1,
#          sent with the cross-signed root (4 certificates, the profile's chain limit).
#          The same structure with every certificate padded to 2,040 bytes: the largest
#          chain the profile accepts (NOXTLS_STATIC_CERT_CHAIN_DEPTH_MAX x CERT_DER_MAX).
#   ECDSA: broker leaf (P-256, same extensions) <- P-256 intermediate <- Test Root CA 3.
#   Device: RSA-2048 and P-256 device certificates issued by the RSA device CA
#          (CN "Test IoT Certificate"), as a broker issues them (the P-256 one from a CSR).

import datetime
import os
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID, AuthorityInformationAccessOID

VALID_FROM = datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc)
VALID_TO = datetime.datetime(2049, 12, 31, 23, 59, 59, tzinfo=datetime.timezone.utc)
REGION = "iot.us-test-1.broker.test"
SCT_LIST_OID = "1.3.6.1.4.1.11129.2.4.2"


def name(cn, org="NoxTLS Test", ou=None, extra_locality=False):
    attrs = [x509.NameAttribute(NameOID.COUNTRY_NAME, "US")]
    if extra_locality:
        attrs.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Texas"))
        attrs.append(x509.NameAttribute(NameOID.LOCALITY_NAME, "Austin"))
    attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, org))
    if ou is not None:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou))
    attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))
    return x509.Name(attrs)


def key_usage(digital_signature=False, key_encipherment=False, cert_sign=False):
    return x509.KeyUsage(digital_signature=digital_signature, content_commitment=False,
                         key_encipherment=key_encipherment, data_encipherment=False,
                         key_agreement=False, key_cert_sign=cert_sign, crl_sign=cert_sign,
                         encipher_only=False, decipher_only=False)


def sct_list():
    """An embedded SCT list (RFC 6962 3.3) of three version-1 SCTs with ECDSA signatures."""
    scts = b""
    for i in range(3):
        log_id = bytes([0x10 + i]) * 32
        sig = bytes([0x30, 0x45, 0x02, 0x21, 0x00]) + bytes([0x40 + i]) * 32 + \
            bytes([0x02, 0x20]) + bytes([0x50 + i]) * 32
        body = bytes([0x00]) + log_id + (1735689600000 + i).to_bytes(8, "big") + b"\x00\x00" + \
            bytes([0x04, 0x03]) + len(sig).to_bytes(2, "big") + sig
        scts += len(body).to_bytes(2, "big") + body
    tls_list = len(scts).to_bytes(2, "big") + scts
    # extnValue holds an OCTET STRING with the TLS-encoded list.
    return bytes([0x04, 0x82]) + len(tls_list).to_bytes(2, "big") + tls_list


def build(subject, subject_key, issuer, issuer_key, serial, ca=False, path_len=None, ku=None,
          eku=None, san=None, aia=None, crl=None, policies=None, extra=()):
    pub = subject_key.public_key()
    builder = (x509.CertificateBuilder()
               .subject_name(subject)
               .issuer_name(issuer)
               .public_key(pub)
               .serial_number(serial)
               .not_valid_before(VALID_FROM)
               .not_valid_after(VALID_TO)
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
    if aia is not None:
        builder = builder.add_extension(x509.AuthorityInformationAccess([
            x509.AccessDescription(AuthorityInformationAccessOID.OCSP,
                                   x509.UniformResourceIdentifier(aia[0])),
            x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS,
                                   x509.UniformResourceIdentifier(aia[1]))]), critical=False)
    if crl is not None:
        builder = builder.add_extension(x509.CRLDistributionPoints([
            x509.DistributionPoint(full_name=[x509.UniformResourceIdentifier(crl)],
                                   relative_name=None, reasons=None, crl_issuer=None)]),
            critical=False)
    if policies is not None:
        builder = builder.add_extension(x509.CertificatePolicies([
            x509.PolicyInformation(x509.ObjectIdentifier(p), None) for p in policies]),
            critical=False)
    for oid, value in extra:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(x509.ObjectIdentifier(oid), value), critical=False)
    return builder.sign(issuer_key, hashes.SHA256())


PAD_OID = "1.3.6.1.4.1.55555.2"


def padded(target, make):
    """Rebuild a certificate with an opaque extension until its DER is target-8..target bytes."""
    pad = 0
    for _ in range(8):
        value = bytes([0x04, 0x82]) + pad.to_bytes(2, "big") + bytes([0x5A]) * pad
        cert = make(((PAD_OID, value),))
        size = len(der(cert))
        if target - 8 <= size <= target:
            return cert
        pad += target - 4 - size
    raise RuntimeError("cannot pad to %d bytes" % target)


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


def trad_key_der(key):
    return key.private_bytes(serialization.Encoding.DER,
                             serialization.PrivateFormat.TraditionalOpenSSL,
                             serialization.NoEncryption())


def broker_leaf(key, issuer, issuer_key, serial, ku, tag, pad=()):
    san = ["*." + REGION, REGION, "*.ats." + REGION, "*.jobs." + REGION,
           "*.credentials." + REGION, "*.data." + REGION, "*.data-ats." + REGION,
           "*.device-advisor." + REGION, "*.tunneling." + REGION, "*.fleethub." + REGION]
    return build(name("*." + REGION, org="NoxTLS Test Broker", extra_locality=True), key, issuer,
                 issuer_key, serial, ku=ku,
                 eku=[ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH], san=san,
                 aia=("http://ocsp.%s.trust.test" % tag, "http://crt.%s.trust.test/%s.cer" % (tag, tag)),
                 crl="http://crl.%s.trust.test/%s.crl" % (tag, tag), policies=["2.23.140.1.2.1"],
                 extra=((SCT_LIST_OID, sct_list()),) + tuple(pad))


def intermediate(cn, key, root_name, root_key, serial, tag, pad=(), path_len=0):
    return build(name(cn), key, root_name, root_key, serial, ca=True, path_len=path_len, extra=pad,
                 ku=key_usage(digital_signature=True, cert_sign=True),
                 eku=[ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH],
                 aia=("http://ocsp.root.trust.test", "http://crt.root.trust.test/%s.cer" % tag),
                 crl="http://crl.root.trust.test/%s.crl" % tag, policies=["2.23.140.1.2.1"])


def main():
    out_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__))
    p256 = ec.SECP256R1()

    def rsa2048():
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)

    root1_key = rsa2048()
    legacy_key = rsa2048()
    rsa_int_key = rsa2048()
    rsa_leaf_key = rsa2048()
    root3_key = ec.generate_private_key(p256)
    ec_int_key = ec.generate_private_key(p256)
    ec_leaf_key = ec.generate_private_key(p256)
    device_ca_key = rsa2048()
    device_rsa_key = rsa2048()
    device_ec_key = ec.generate_private_key(p256)

    ca_ku = key_usage(digital_signature=True, cert_sign=True)
    n_root1 = name("Test Root CA 1")
    n_legacy = name("Test Services Root Certificate Authority - G2", org="NoxTLS Test Legacy")
    n_root3 = name("Test Root CA 3")
    n_device_ca = name("Test IoT Device CA", org="NoxTLS Test Broker Inc.", ou="Test Web Services",
                       extra_locality=True)

    root1 = build(n_root1, root1_key, n_root1, root1_key, 0x0101, ca=True, ku=ca_ku)
    root1_cross = build(n_root1, root1_key, n_legacy, legacy_key, 0x0102, ca=True, ku=ca_ku,
                        aia=("http://ocsp.legacy.trust.test", "http://crt.legacy.trust.test/g2.cer"),
                        crl="http://crl.legacy.trust.test/g2.crl", policies=["2.5.29.32.0"])
    rsa_int = intermediate("Test RSA 2048 M01", rsa_int_key, n_root1, root1_key, 0x0103, "r2m01")
    rsa_leaf = broker_leaf(rsa_leaf_key, rsa_int.subject, rsa_int_key, 0x7A01,
                           key_usage(digital_signature=True, key_encipherment=True), "r2m01")

    # A rotated chain of four: leaf4 <- new intermediate <- bridge CA <- Test Root CA 1.
    bridge_key = rsa2048()
    rsa_int2_key = rsa2048()
    bridge = build(name("Test RSA 2048 Bridge CA"), bridge_key, n_root1, root1_key, 0x0104, ca=True,
                   path_len=1, ku=ca_ku,
                   aia=("http://ocsp.root.trust.test", "http://crt.root.trust.test/bridge.cer"),
                   crl="http://crl.root.trust.test/bridge.crl", policies=["2.23.140.1.2.1"])
    rsa_int2 = intermediate("Test RSA 2048 M03", rsa_int2_key, bridge.subject, bridge_key, 0x0105, "r2m03")
    rsa_leaf4 = broker_leaf(rsa_leaf_key, rsa_int2.subject, rsa_int2_key, 0x7A03,
                            key_usage(digital_signature=True, key_encipherment=True), "r2m03")

    # The profile's limit: four certificates of nearly NOXTLS_STATIC_CERT_DER_MAX (2,048).
    MAX_DER = 2040
    maxb = padded(MAX_DER, lambda pad: intermediate("Test RSA 2048 Bridge CA", bridge_key, n_root1,
                                                    root1_key, 0x0106, "bridge", pad=pad, path_len=1))
    maxi = padded(MAX_DER, lambda pad: intermediate("Test RSA 2048 M03", rsa_int2_key, maxb.subject,
                                                    bridge_key, 0x0107, "r2m03", pad=pad))
    maxl = padded(MAX_DER, lambda pad: broker_leaf(rsa_leaf_key, maxi.subject, rsa_int2_key, 0x7A04,
                                                   key_usage(digital_signature=True, key_encipherment=True),
                                                   "r2m03", pad=pad))
    maxc = padded(MAX_DER, lambda pad: build(n_root1, root1_key, n_legacy, legacy_key, 0x0108, ca=True,
                                             ku=ca_ku, extra=pad))

    root3 = build(n_root3, root3_key, n_root3, root3_key, 0x0301, ca=True, ku=ca_ku)
    ec_int = intermediate("Test ECDSA 256 M02", ec_int_key, n_root3, root3_key, 0x0302, "e2m02")
    ec_leaf = broker_leaf(ec_leaf_key, ec_int.subject, ec_int_key, 0x7A02,
                          key_usage(digital_signature=True), "e2m02")

    device_ca = build(n_device_ca, device_ca_key, n_device_ca, device_ca_key, 0x0401, ca=True,
                      ku=ca_ku)
    device_rsa = build(name("Test IoT Certificate"), device_rsa_key, n_device_ca, device_ca_key,
                       0x5EED01, ku=key_usage(digital_signature=True))
    device_ec = build(name("Test IoT Certificate"), device_ec_key, n_device_ca, device_ca_key,
                      0x5EED02, ku=key_usage(digital_signature=True))

    blobs = [
        ("lp_root1_cert", der(root1)), ("lp_root1_cross_cert", der(root1_cross)),
        ("lp_rsa_int_cert", der(rsa_int)), ("lp_rsa_leaf_cert", der(rsa_leaf)),
        ("lp_rsa_leaf_key", trad_key_der(rsa_leaf_key)),
        ("lp_rsa_bridge_cert", der(bridge)), ("lp_rsa_int2_cert", der(rsa_int2)),
        ("lp_rsa_leaf4_cert", der(rsa_leaf4)),
        ("lp_max_leaf_cert", der(maxl)), ("lp_max_int_cert", der(maxi)),
        ("lp_max_bridge_cert", der(maxb)), ("lp_max_cross_cert", der(maxc)),
        ("lp_root3_cert", der(root3)), ("lp_ec_int_cert", der(ec_int)),
        ("lp_ec_leaf_cert", der(ec_leaf)), ("lp_ec_leaf_key", trad_key_der(ec_leaf_key)),
        ("lp_device_ca_cert", der(device_ca)),
        ("lp_device_rsa_cert", der(device_rsa)), ("lp_device_rsa_key", trad_key_der(device_rsa_key)),
        ("lp_device_ec_cert", der(device_ec)), ("lp_device_ec_key", trad_key_der(device_ec_key)),
    ]
    for label, data in blobs:
        print("%-24s %5d bytes" % (label, len(data)))

    header = ["/* Generated by gen_leader_pki.py - do not edit. */",
              "#ifndef LEADER_PKI_H", "#define LEADER_PKI_H", "", "#include <stdint.h>", "",
              "#define LP_BROKER_HOST \"a1b2c3d4e5f6g7-ats.%s\"" % REGION, ""]
    for label, _ in blobs:
        header.append("extern const uint8_t %s[];" % label)
        header.append("extern const uint32_t %s_len;" % label)
    header += ["", "#endif /* LEADER_PKI_H */", ""]
    source = ["/* Generated by gen_leader_pki.py - do not edit. */", "#include \"leader_pki.h\"", ""]
    for label, data in blobs:
        source.append(c_array(label, data))
        source.append("")
    with open(os.path.join(out_dir, "leader_pki.h"), "w", newline="\n") as f:
        f.write("\n".join(header))
    with open(os.path.join(out_dir, "leader_pki.c"), "w", newline="\n") as f:
        f.write("\n".join(source))


if __name__ == "__main__":
    main()
