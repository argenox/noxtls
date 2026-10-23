# Cert Application

Certificate parsing and verification utility using NoxTLS cert/X.509 support.

## Building

Built as part of the main project when `BUILD_APPLICATIONS` is ON. Target name: `cert`.

## Usage

Run the executable with certificate file(s) or options. See the source for details.

### Check a private key against a certificate

Use `keymatch` to verify that a private key belongs to the public key carried by
an X.509 certificate:

```bash
cert keymatch -i certificate.pem -k private-key.pem
```

The command accepts the certificate and private key formats supported by the
NoxTLS X.509 loaders. It uses NoxTLS to prove the key pair matches: RSA keys
sign and verify a check message, ECC and EdDSA keys derive and compare their
public components, and enabled ML-DSA, SLH-DSA, or Falcon keys sign and verify a
check message. It does not write out a public key. A successful match prints a
confirmation and exits with status 0; a mismatch exits nonzero. This checks the
key pair only; it does not verify the certificate chain or validity.
