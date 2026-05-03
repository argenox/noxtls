# Client Certificate Authentication (Mutual TLS) in NoxTLS

This document describes how to use **client certificate authentication** (mutual TLS / mTLS) with NoxTLS TLS 1.3. When enabled, the server requests a certificate from the client and optionally verifies it; the client sends its certificate and proves possession of the private key via a CertificateVerify signature.

## Overview

- **Server**: Call `tls13_request_client_auth(ctx, 1)` before `tls13_accept`. The server will send a CertificateRequest after Encrypted Extensions and, after sending its own Certificate/CertificateVerify/Finished, will receive the client’s Certificate (possibly empty), optional CertificateVerify, and Finished.
- **Client**: Call `tls13_set_client_cert(ctx, cert_der, cert_len, rsa_key)` before `tls13_connect`. If the server sends a CertificateRequest and the client has a certificate and private key configured, the client sends Certificate and CertificateVerify before Finished; otherwise it sends only Finished (or an empty Certificate if required by policy).

Supported for **TLS 1.3** in NoxTLS. Client auth uses **RSA-PSS** (signature scheme 0x0804) for CertificateVerify; the client certificate must have an RSA public key.

---

## Server setup

1. Initialize the TLS 1.3 context as server and set the server certificate and private key as usual.
2. Optionally **request client authentication** before calling `tls13_accept`:

   ```c
   tls13_request_client_auth(ctx, 1);   /* request client cert */
   rc = tls13_accept(ctx);
   ```

3. After a successful handshake, if you requested client auth:
   - If the client sent a certificate: `ctx->client_cert` and `ctx->client_cert_len` hold the client certificate (DER). `ctx->client_cert_parsed` is the parsed X.509 structure (e.g. for subject/issuer checks).
   - If the client sent no certificate: `ctx->client_cert` is NULL and `ctx->client_cert_len` is 0.

You can use `ctx->client_cert_parsed` and the existing NoxTLS X.509 APIs to validate the client certificate (e.g. chain, validity, subject) as required by your policy.

---

## Client setup

1. Initialize the TLS 1.3 context as client.
2. Optionally configure a **client certificate and RSA private key** for mutual TLS (call before `tls13_connect`):

   ```c
   /* cert_der: DER-encoded X.509 certificate; rsa_key: pointer to rsa_key_t */
   rc = tls13_set_client_cert(ctx, cert_der, cert_len, rsa_key);
   rc = tls13_connect(ctx);
   ```

3. If the server sent a CertificateRequest and the client had a cert and key set, the library sends the client Certificate and CertificateVerify automatically during the handshake. If no cert was set (or the client chooses not to send one), only Finished is sent (or an empty Certificate as per TLS 1.3).

The client certificate must have an **RSA** public key; the private key is used to sign the handshake transcript for the CertificateVerify message (RSA-PSS with SHA-256).

---

## API summary

| Function | Role | Description |
|----------|------|-------------|
| `tls13_request_client_auth(ctx, request)` | Server | If `request` is non-zero, server sends CertificateRequest and expects client Certificate (possibly empty) and optionally CertificateVerify before Finished. Call before `tls13_accept`. |
| `tls13_set_client_cert(ctx, cert_der, cert_len, rsa_key)` | Client | Sets the client certificate (DER) and RSA private key (`rsa_key_t*`) for client auth. Call before `tls13_connect`. |

After the handshake, the server can inspect:

- `ctx->client_cert`, `ctx->client_cert_len` – raw client certificate (DER), or NULL/0 if none sent.
- `ctx->client_cert_parsed` – parsed `x509_certificate_t*` for the first certificate in the client’s list (if any).

---

## Protocol flow (TLS 1.3)

1. Client Hello → Server Hello (and optional Encrypted Extensions).
2. **Server** may send **CertificateRequest** (after Encrypted Extensions).
3. Server sends Certificate, CertificateVerify, Finished.
4. **Client** sends **Certificate** (optional or empty if no cert), **CertificateVerify** (only if a non-empty cert was sent), then **Finished**.
5. Application traffic.

NoxTLS implements this flow for TLS 1.3; the client automatically sends Certificate/CertificateVerify when the server requested auth and the client has a cert and key configured.

---

## Limitations

- **RSA only**: Client CertificateVerify is implemented with RSA-PSS (0x0804). ECDSA/EdDSA client auth is not implemented.
- **TLS 1.3**: This document and the described APIs apply to TLS 1.3. TLS 1.2 client auth may differ.
- **Verification**: The server receives and parses the client certificate and verifies the CertificateVerify signature. Additional checks (e.g. chain to a CA, revocation, subject name) are the application’s responsibility using NoxTLS X.509 APIs.

---

## See also

- RFC 8446 (TLS 1.3), Sections 4.3.2 (CertificateRequest), 4.4.2 (Certificate), 4.4.3 (Certificate Verify).
