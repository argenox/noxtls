---
sidebar_position: 6
title: Configure Certificates
description: Parse, convert, and verify X.509 certificates with NoxTLS for TLS and DTLS.
keywords:
  - x509
  - certificates
  - pki
  - tutorial
---

# Configure Certificates

TLS and DTLS servers (and mTLS clients) need **X.509 certificates**, private keys, and often a trust store. NoxTLS provides parsing, verification, and TLS integration through the [Certificates API](../api/certs).

## Tools you will use

| Tool | Purpose |
|------|---------|
| [Cert utility](../applications/app_cert) (`cert`) | Parse, convert, verify, inspect keys |
| [Certificate app](../applications/app_certificate) | Higher-level cert operations |
| [Certgen](../applications/app_certgen) | Generation (when enabled in your build) |

Build apps with `BUILD_APPLICATIONS=ON` (default in [Quickstart](./quickstart)).

## Inspect a certificate

```bash
./binary/cert info -i device.crt
./binary/cert read -i device.der
```

Human-readable summary includes subject, issuer, validity, and public key type.

## Convert PEM ↔ DER

Embedded firmware often stores **DER**; developers edit **PEM** on the host.

```bash
# DER to PEM
./binary/cert convert -i cert.der -o cert.pem -f pem

# PEM to DER
./binary/cert convert -i cert.pem -o cert.der -f der
```

Explicit input/output formats (also supported by the `noxtls` CLI cert subcommand):

```bash
noxtls cert convert -i cert.der -I der -o cert.pem -O pem
```

## Verify a chain

```bash
./binary/cert verify -i chain.pem
```

For TLS connections, verification also happens during the handshake when you configure trust anchors and hostname checks in the TLS context — do not rely on the utility alone in production.

## Private keys

Inspect key material (handle carefully — protect files on disk):

```bash
./binary/cert keyinfo -i server.key
./binary/cert keywrite -i key.der -o key.pem -f pem
```

Supported key types depend on your build profile (RSA, ECDSA, Ed25519, etc.). Server profile example:

```bash
cmake -S . -B build -D NOXTLS_PROFILE=tls_server_pki -D BUILD_TESTS=OFF
```

## Typical device layouts

| Store | Contents | Format |
|-------|----------|--------|
| Device cert | End-entity certificate | DER in flash |
| Private key | Server or client key | DER or protected secure element |
| Trust store | Root / intermediate CAs | One or more DER certs |

Keep flash usage small by storing only required intermediates, not entire public CT logs.

## TLS integration checklist

1. **Parse** DER/PEM into NoxTLS cert structures (or use pre-parsed blobs from your manufacturing flow).
2. **Configure server** — attach cert + key to `tls13_context_t` / accept path.
3. **Configure client trust** — load CA for server authentication; optional client cert for mTLS.
4. **SNI and names** — set server name on clients; ensure certificate SAN/CN matches.
5. **Time** — validity checks require a trustworthy clock (or disable time checks only in test builds via `NOXTLS_HAVE_TIME` — see [Configuration Guide](../configuration-guide)).

## Post-quantum signatures (optional)

With `NOXTLS_CFG_FEATURE_ML_DSA=ON`, ML-DSA keys and TLS 1.3 signature schemes are available. See [TLS 1.3 PQC](../api/tls13_pqc) and [ML-DSA API](../api/mldsa).

## Local HTTPS example

Combine with [Build Your First HTTPS Server](./https-server):

```bash
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=localhost"
./binary/https_server 8443 --cert server.crt --key server.key
```

## Next steps

- Client trust and hostname policy: [Build Your First TLS Client](./tls-client)
- UDP + certs: [Run DTLS on Embedded Devices](./dtls-embedded)
- API details: [Certificates](../api/certs)
