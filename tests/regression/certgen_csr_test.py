"""Check NoxTLS-generated PKCS#10 requests with an independent parser/verifier.

Usage: python tests/regression/certgen_csr_test.py --certgen binary/certgen
Requires cryptography >= 46. Generated keys are temporary test keys only.
"""
import argparse
import pathlib
import subprocess
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import serialization


def tlv(data, offset=0):
    start = offset
    tag = data[offset]
    size = data[offset + 1]
    offset += 2
    if size & 0x80:
        width = size & 0x7f
        assert 0 < width <= 4
        size = int.from_bytes(data[offset:offset + width], "big")
        offset += width
    assert offset + size <= len(data)
    return tag, data[offset:offset + size], offset + size, data[start:offset + size]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--certgen", required=True, type=pathlib.Path)
    exe = str(parser.parse_args().certgen.resolve())

    def run(*args, success=True):
        result = subprocess.run([exe, *map(str, args)], capture_output=True, text=True, timeout=60)
        assert (result.returncode == 0) == success, result.stdout + result.stderr

    with tempfile.TemporaryDirectory(prefix="noxtls-csr-") as tmp:
        root = pathlib.Path(tmp)
        cases = 0
        for curve, bits in [("prime256v1", 256), ("secp384r1", 384), ("secp521r1", 521)]:
            for key_format in ["PEM", "DER"]:
                base = root / f"{curve}-{key_format}"
                run("genec", "-curve", curve, "-outform", key_format, "-out", base)
                key_bytes = base.with_suffix(".key").read_bytes()
                loader = serialization.load_pem_private_key if key_format == "PEM" else serialization.load_der_private_key
                key = loader(key_bytes, password=None)
                for output_format in ["PEM", "DER"]:
                    output = root / "request.csr"
                    run("req", "-new", "-key", base.with_suffix(".key"), "-out", output,
                        "-outform", output_format, "-subj", "/CN=fleet-test-gateway")
                    load = x509.load_pem_x509_csr if output_format == "PEM" else x509.load_der_x509_csr
                    csr = load(output.read_bytes())
                    assert csr.is_signature_valid
                    assert csr.subject.rfc4514_string() == "CN=fleet-test-gateway"
                    assert csr.public_key().key_size == bits
                    assert csr.public_key().public_numbers() == key.public_key().public_numbers()
                    assert len(csr.attributes) == 0
                    # PKCS#10 attributes is mandatory, although the set may be empty.
                    der = csr.public_bytes(serialization.Encoding.DER)
                    tag, outer, end, _ = tlv(der)
                    assert tag == 0x30 and end == len(der)
                    tag, cri, _, _ = tlv(outer)
                    assert tag == 0x30
                    pos = 0
                    for expected in [0x02, 0x30, 0x30, 0xA0]:
                        tag, value, pos, _ = tlv(cri, pos)
                        assert tag == expected
                    assert value == b"" and pos == len(cri)
                    # Reject a signature with one byte changed, using the same parser.
                    damaged = bytearray(der)
                    damaged[-1] ^= 1
                    assert not x509.load_der_x509_csr(bytes(damaged)).is_signature_valid
                    cases += 1
                # Preserve the existing self-signed certificate operation.
                cert_path = root / "self.pem"
                run("req", "-new", "-x509", "-key", base.with_suffix(".key"),
                    "-out", cert_path, "-subj", "/CN=fleet-test-gateway")
                cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
                assert cert.public_key().public_numbers() == key.public_key().public_numbers()
                rejected = root / "rejected.csr"
                run("req", "-new", "-key", base.with_suffix(".key"), "-out", rejected,
                    "-outform", "invalid", success=False)
                assert not rejected.exists()
        print(f"PASS: {cases} CSR combinations, signature tampering, mandatory attributes, "
              "key matching, invalid formats and six self-signed certificate checks")


if __name__ == "__main__":
    main()
