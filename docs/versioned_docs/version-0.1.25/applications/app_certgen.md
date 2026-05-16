---
sidebar_position: 5
title: "Certgen utility"
---

# Certgen utility

Key and certificate generation (genrsa, req) using NoxTLS.

Commands: genrsa (generate RSA key), genec (generate EC key), req (certificate request / self-signed cert).
genrsa options: -out &lt;name&gt; (writes &lt;name&gt;.key and &lt;name&gt;.pub), -outform DER|PEM, -bits 1024|2048|3072|4096.
genec options: -out &lt;name&gt; (writes &lt;name&gt;.key and &lt;name&gt;.pub), -outform DER|PEM, -curve prime256v1|secp384r1|secp521r1.
req options (for -new -x509): -key &lt;file&gt;, -out &lt;file&gt;, -days &lt;n&gt;, -subj &lt;name&gt;.

OpenSSL-like utility for generating keys and self-signed certificates using the NOXTLS library. Uses the certificate write/generate APIs when built with `NOXTLS_HAVE_CERT_WRITE`.

## Commands

### genrsa – Generate RSA key pair

Generates an RSA key pair and writes the private key to `<name>.key` and the public key (SubjectPublicKeyInfo PEM) to `<name>.pub`.

**Options:**

- `-out <name>` – Base name for output files: private key `<name>.key`, public key `<name>.pub`. If omitted, only the private key is written to stdout.
- `-outform DER|PEM` – Format for the private key file (default: PEM). The `.pub` file is always PEM.
- `-bits <n>` – Key size: 1024, 2048, 3072, 4096 (default: 2048)

**Examples:**

```bash
certgen genrsa -out server -bits 2048       # writes server.key and server.pub
certgen genrsa -out key -outform DER -bits 2048   # key.key (DER), key.pub (PEM)
```

### genec – Generate EC key pair

Generates an ECC key pair (P-256, P-384, or P-521) and writes the private key to `<name>.key` and the public key (SubjectPublicKeyInfo PEM) to `<name>.pub`. Use the `.key` file with `req -new -x509 -key` for self-signed certificate generation.

**Options:**

- `-out <name>` – Base name for output files: private key `<name>.key`, public key `<name>.pub`. If omitted, only the private key is written to stdout.
- `-outform DER|PEM` – Format for the private key file (default: PEM). The `.pub` file is always PEM.
- `-curve <name>` – Curve: `prime256v1`, `secp384r1`, or `secp521r1` (default: prime256v1)

**Examples:**

```bash
certgen genec -out client -curve prime256v1   # writes client.key and client.pub
certgen genec -out eckey -outform DER -curve secp384r1
```

### req – Certificate request / self-signed certificate

When built with **`NOXTLS_HAVE_CERT_WRITE=ON`**, `req -new -x509` creates a self-signed X.509 certificate. It requires an **ECC private key** (e.g. P-256); RSA keys are not supported for cert generation by the library.

**Options:**

- `-new -x509` – Create self-signed certificate
- `-key <file>` – Private key file (ECC key, PEM or DER)
- `-out <file>` – Output certificate file
- `-outform DER|PEM` – Output format (default: PEM)
- `-days <n>` – Validity in days (default: 365)
- `-subj <name>` – Subject, e.g. `/CN=localhost`

**Examples:**

```bash
# Generate an ECC key with certgen, then create a self-signed cert
certgen genec -out client -curve prime256v1    # client.key, client.pub
certgen req -new -x509 -key client.key -out cert.pem -days 365 -subj /CN=localhost

certgen req -new -x509 -key client.key -out cert.der -outform DER -days 730 -subj /CN=myserver
```

If the build does not have `NOXTLS_HAVE_CERT_WRITE`, `req -new -x509` prints a message and exits; use OpenSSL to create the certificate in that case.

## Build

From the project root:

```bash
mkdir build && cd build
cmake ..
cmake --build . --target certgen
```

To enable self-signed certificate generation (ECC), configure with:

```bash
cmake -DNOXTLS_HAVE_CERT_WRITE=ON ..
cmake --build . --target certgen
```

The `certgen` executable will be in `build/binary/` (or `build/applications/certgen/` when building standalone).

## Comparison with OpenSSL

| OpenSSL command              | certgen equivalent                    |
|-----------------------------|--------------------------------------|
| `openssl genrsa -out key.pem 2048` | `certgen genrsa -out key -bits 2048` (writes key.key and key.pub) |
| `openssl genrsa -out key.der -outform DER 2048` | `certgen genrsa -out key -outform DER -bits 2048` |
| `openssl ecparam -genkey -name prime256v1 -out key.pem` | `certgen genec -out key -curve prime256v1` (writes key.key and key.pub) |
| `openssl req -new -x509 -key key.pem -out cert.pem -days 365 -subj /CN=localhost` | `certgen req -new -x509 -key key.key -out cert.pem -days 365 -subj /CN=localhost` (requires ECC key and `NOXTLS_HAVE_CERT_WRITE=ON`) |

## Examples

certgen genrsa -out server -bits 2048
certgen genec -out client -curve prime256v1
certgen req -new -x509 -key client.key -out cert.pem -days 365 -subj /CN=localhost

