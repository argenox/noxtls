# certgen – Key and Certificate Generation Utility

OpenSSL-like utility for generating keys and self-signed certificates using the
NoxTLS library. Self-signed certificate generation uses the certificate write
APIs which are now compiled in by default (`NOXTLS_HAVE_CERT_WRITE=ON`).

## Commands

### genrsa – Generate RSA key pair

Generates an RSA key pair and writes the private key to `<name>.key` and the
public key (SubjectPublicKeyInfo PEM) to `<name>.pub`.

**Options:**

- `-out <name>` – Base name for `<name>.key` and `<name>.pub`. If omitted, only
  the private key is written to stdout.
- `-outform DER|PEM` – Format for the private key file (default: PEM). The
  `.pub` file is always PEM.
- `-bits <n>` – Key size: 1024, 2048, 3072, 4096 (default: 2048).

**Examples:**

```bash
certgen genrsa -out server -bits 2048           # writes server.key and server.pub
certgen genrsa -out key -outform DER -bits 2048 # key.key (DER), key.pub (PEM)
```

### genec – Generate EC key pair

Generates an ECC key pair on one of the supported NIST, Brainpool or
secp-K1 curves and writes the private key to `<name>.key` and the public key
(SubjectPublicKeyInfo PEM) to `<name>.pub`.

**Options:**

- `-out <name>` – Base name for `<name>.key` and `<name>.pub`. If omitted, only
  the private key is written to stdout.
- `-outform DER|PEM` – Format for the private key file (default: PEM). The
  `.pub` file is always PEM.
- `-curve <name>` – One of:
  `secp192r1`, `secp224r1`, `prime256v1` (P-256), `secp384r1`, `secp521r1`,
  `brainpoolP256r1`, `brainpoolP384r1`, `brainpoolP512r1`,
  `secp192k1`, `secp224k1`, `secp256k1`. Default: `prime256v1`.

**Examples:**

```bash
certgen genec -out client -curve prime256v1
certgen genec -out eckey -outform DER -curve secp384r1
```

### gened25519 / gened448 – Generate EdDSA key pairs

`gened25519` is always available; `gened448` is available when both
`NOXTLS_FEATURE_ED448` and `NOXTLS_FEATURE_SHA3` are enabled at build time.
Writes a PKCS#8 private key (`<name>.key`) and an RFC 8410 SPKI public key
(`<name>.pub`).

```bash
certgen gened25519 -out ed25519key
certgen gened448   -out ed448key
```

### genmldsa / genslhdsa – Generate post-quantum key pairs (experimental)

Enabled by `NOXTLS_CFG_FEATURE_ML_DSA=ON` (FIPS 204 / ML-DSA) and
`NOXTLS_CFG_FEATURE_SLH_DSA=ON` (FIPS 205 / SLH-DSA). The PQC primitive
backends are work-in-progress in this distribution and `keygen`/`sign` may
return `NOXTLS_RETURN_NOT_SUPPORTED`; the X.509 SPKI/PKCS#8 plumbing is
already wired up so this command produces real certificates as soon as the
backends are completed.

```bash
certgen genmldsa  -out pq  -param ml-dsa-65
certgen genslhdsa -out pq2 -param slh-dsa-sha2-128s
```

### req – Self-signed X.509 certificate

`req -new -x509` produces a self-signed v3 certificate using the supplied
private key. Supported key types (the public key is derived from the private
key for asymmetric algorithms that allow it, or read from the companion
`.pub` SPKI file for ML-DSA / SLH-DSA):

| Private key                | Subject PK algorithm | Signature OID            |
|----------------------------|----------------------|--------------------------|
| RSA PKCS#1 / PKCS#8        | `rsaEncryption`      | `sha256WithRSAEncryption`|
| ECC SEC1 / PKCS#8          | `id-ecPublicKey`     | `ecdsa-with-SHA256/384/512` (sized to curve) |
| Ed25519 / Ed448 PKCS#8     | `id-Ed25519/Ed448`   | same OID (PureEdDSA)     |
| ML-DSA PKCS#8 (raw OCTET)  | `id-ml-dsa-{44,65,87}` | same OID                |
| SLH-DSA PKCS#8 (raw OCTET) | `id-slh-dsa-*`       | same OID                 |

**Options:**

- `-new -x509` – Create a self-signed certificate.
- `-key <file>` – Private key file (PEM or DER).
- `-out <file>` – Output certificate file.
- `-outform DER|PEM` – Output format (default: PEM).
- `-days <n>` – Validity in days (default: 365).
- `-subj <name>` – Subject, e.g. `/CN=localhost`.
- `-pub <file>` – (PQC only) Path to the companion SPKI public key file.
  Defaults to the basename of the private key file with the suffix replaced by
  `.pub`. PQC public keys cannot be derived from the secret key alone, so this
  file must exist for ML-DSA / SLH-DSA.

**Examples:**

```bash
# RSA — what used to fail in older builds now works:
certgen genrsa -out server -bits 2048
certgen req -new -x509 -key server.key -out server.pem -days 365 -subj /CN=esp32.local

# ECC P-256:
certgen genec  -out client -curve prime256v1
certgen req -new -x509 -key client.key -out cert.pem -days 365 -subj /CN=localhost

# Ed25519:
certgen gened25519 -out ed
certgen req -new -x509 -key ed.key -out ed.pem -days 365 -subj /CN=ed.local

# PQC (when ML-DSA/SLH-DSA backends are enabled and complete):
certgen genmldsa -out pq -param ml-dsa-65
certgen req -new -x509 -key pq.key -out pq.pem -days 365 -subj /CN=pq.local
```

If the build does not have `NOXTLS_HAVE_CERT_WRITE`, `req -new -x509` prints a
diagnostic and exits with a non-zero status.

## Build

From the project root:

```bash
mkdir build && cd build
cmake ..
cmake --build . --target certgen
```

`NOXTLS_HAVE_CERT_WRITE` defaults to `ON` for the `default`,
`tls_server_pki` and `fips_like_profile` profiles. To explicitly toggle it:

```bash
cmake -DNOXTLS_CFG_HAVE_CERT_WRITE=ON  ..
cmake -DNOXTLS_CFG_HAVE_CERT_WRITE=OFF ..  # strip out cert generation
```

To opt-in to the experimental post-quantum commands:

```bash
cmake -DNOXTLS_CFG_FEATURE_ML_DSA=ON -DNOXTLS_CFG_FEATURE_SLH_DSA=ON ..
```

The `certgen` executable is placed under `build/binary/Release/` (or
`build/applications/certgen/` when building standalone).

## Comparison with OpenSSL

| OpenSSL command                                                                    | certgen equivalent                                                                  |
|------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------|
| `openssl genrsa -out key.pem 2048`                                                 | `certgen genrsa -out key -bits 2048` (writes `key.key` + `key.pub`)                 |
| `openssl genrsa -out key.der -outform DER 2048`                                    | `certgen genrsa -out key -outform DER -bits 2048`                                   |
| `openssl ecparam -genkey -name prime256v1 -out key.pem`                            | `certgen genec -out key -curve prime256v1`                                          |
| `openssl genpkey -algorithm ED25519 -out ed.pem`                                   | `certgen gened25519 -out ed`                                                        |
| `openssl req -new -x509 -key key.pem -out cert.pem -days 365 -subj /CN=localhost`  | `certgen req -new -x509 -key key.key -out cert.pem -days 365 -subj /CN=localhost`   |
