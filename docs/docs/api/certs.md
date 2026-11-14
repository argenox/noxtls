---
sidebar_position: 27
title: Certificates
description: "NoxTLS X.509 certificate parsing, verification, chain validation, and TLS integration APIs."
keywords:
  - noxtls
  - x509
  - certificate verification
  - embedded pki
---

# Certificates

X.509 and certificate handling.

## Purpose

Certificate APIs cover:

- DER/PEM parse and conversion
- certificate/private-key load and transform helpers
- signature verification and chain verification
- hostname verification and failure introspection
- TLS-oriented certificate handling utilities

## Enablement

- Base support: `NOXTLS_CFG_FEATURE_CERT=ON`
- PKC dependency: `NOXTLS_CFG_FEATURE_PKC=ON`
- Post-quantum certificate signatures: `NOXTLS_CFG_FEATURE_ML_DSA=ON`

Dependency rules are validated in [Build Configuration Checks](/docs/api/build_config).

## Types

### `x509_certificate_t`

Parsed X.509 certificate object.

### `x509_certificate_chain_t`

Certificate chain container.

### `x509_private_key_t`

Parsed private key container.

## API

### `noxtls_parse_der`

```c
uint32_t noxtls_parse_der(uint8_t * data, uint32_t len);
```

Parse ASN.1 DER Data

**Parameters:**

- `data` — is a pointer to a pointer to the data to convert
- `length` — is a pointer to the length
- `output` — is a pointer to a buffer to place the DER data
- `out_len` — is the length of data placed in output

### `noxtls_parse_tag`

```c
uint32_t noxtls_parse_tag(uint8_t ** data, uint8_t * end);
```

Parse ASN.1 Tag

**Parameters:**

- `data` — is a pointer to a pointer to the data to convert
- `length` — is a pointer to the length
- `output` — is a pointer to a buffer to place the DER data
- `out_len` — is the length of data placed in output

### `noxtls_asn1_decode_integer`

```c
void noxtls_asn1_decode_integer(uint8_t ** data, uint32_t len);
```

Decodes object identifier

**Parameters:**

- `data` — is a pointer to the data to convert
- `length` — is the length of the PEM data
- `output` — is a pointer to a buffer to place the DER data
- `out_len` — is the length of data placed in output

### `noxtls_asn1_decode_bitstring`

```c
void noxtls_asn1_decode_bitstring(uint8_t ** data, uint32_t len);
```

Decodes ASN.1 Bit String

**Parameters:**

- `data` — is a pointer to  a pointer of the data to convert
- `len` — is the length of the data

### `noxtls_asn1_decode_obj_ident`

```c
void noxtls_asn1_decode_obj_ident(uint8_t ** data, uint32_t len);
```

Decodes object identifier

**Parameters:**

- `data` — is a pointer to the data to convert
- `length` — is the length of the PEM data
- `output` — is a pointer to a buffer to place the DER data
- `out_len` — is the length of data placed in output

### `noxtls_asn1_decode_print_string`

```c
void noxtls_asn1_decode_print_string(uint8_t ** data, uint32_t len);
```

Decodes object identifier

**Parameters:**

- `data` — is a pointer to the data to convert
- `length` — is the length of the PEM data
- `output` — is a pointer to a buffer to place the DER data
- `out_len` — is the length of data placed in output

### `noxtls_certificate_der_to_pem_ex`

```c
noxtls_return_t noxtls_certificate_der_to_pem_ex(const uint8_t *data, uint32_t length, uint8_t *output,
                                                 uint32_t out_max, uint32_t *out_len);
```

New in 0.3.0. Converts a DER certificate to PEM (`-----BEGIN CERTIFICATE-----` banners, 64-character Base64 lines) without writing past `output`. Header: `certs/certificates.h`.

The function computes the exact output size before it writes anything. If the PEM text plus its NUL terminator does not fit in `out_max` bytes, it returns `NOXTLS_RETURN_FAILED` and leaves `output` and `*out_len` unchanged.

**Parameters:**

- `data` — DER data to convert
- `length` — length of the DER data in bytes; must not be 0
- `output` — buffer that receives the NUL-terminated PEM text
- `out_max` — capacity of `output` in bytes, including the NUL terminator
- `out_len` — receives the length of the PEM text, not counting the NUL

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success; [NOXTLS_RETURN_INVALID_PARAM](/docs/api/return_codes) when `data`, `output`, or `out_len` is NULL or `length` is 0; [NOXTLS_RETURN_FAILED](/docs/api/return_codes) when `out_max` is too small (nothing is written) or encoding fails.

### `noxtls_csr_der_to_pem_ex`

```c
noxtls_return_t noxtls_csr_der_to_pem_ex(const uint8_t *data, uint32_t length, uint8_t *output,
                                         uint32_t out_max, uint32_t *out_len);
```

New in 0.3.0. Converts a DER Certificate Signing Request (PKCS#10) to PEM with `-----BEGIN CERTIFICATE REQUEST-----` banners. Same parameters, bounds check, and return codes as [`noxtls_certificate_der_to_pem_ex()`](#noxtls_certificate_der_to_pem_ex).

### `noxtls_certificate_der_to_pem`

```c
noxtls_return_t noxtls_certificate_der_to_pem(const uint8_t * data, uint32_t length, uint8_t * output, uint32_t * out_len);
```

Converts a DER certificate to PEM. This legacy form has no capacity parameter: `output` must hold the complete PEM text plus its NUL terminator, `noxtls_certificate_pem_buffer_size(length)` bytes. It is deprecated; prefer [`noxtls_certificate_der_to_pem_ex()`](#noxtls_certificate_der_to_pem_ex).

PEM output is not a fixed multiple of the DER size. Because of the banners, a short input needs more than twice its length, so a buffer sized as 2 × `length` overflows for inputs below about 85 bytes.

### `noxtls_certificate_pem_buffer_size`

```c
uint32_t noxtls_certificate_pem_buffer_size(uint32_t length);
```

Returns the exact capacity (PEM text plus NUL) that `noxtls_certificate_der_to_pem_ex()` needs for `length` DER bytes, or 0 when `length` is 0 or the size does not fit in `uint32_t`. Header: `certs/certificates.h`.

**Parameters:**

- `data` — DER data to convert
- `length` — length of the DER data in bytes
- `output` — buffer that receives the NUL-terminated PEM text; sized by the caller as above
- `out_len` — receives the length of the PEM text, not counting the NUL

**Returns:** [noxtls_return_t](/docs/api/return_codes): same as [`noxtls_certificate_der_to_pem_ex()`](#noxtls_certificate_der_to_pem_ex).

### `noxtls_csr_der_to_pem`

```c
noxtls_return_t noxtls_csr_der_to_pem(const uint8_t *data, uint32_t length, uint8_t *output, uint32_t *out_len);
```

Converts a DER Certificate Signing Request (PKCS#10) to PEM. Legacy form with no capacity parameter; the caller must size `output` as for [`noxtls_certificate_der_to_pem()`](#noxtls_certificate_der_to_pem). Prefer [`noxtls_csr_der_to_pem_ex()`](#noxtls_csr_der_to_pem_ex).

**Returns:** [noxtls_return_t](/docs/api/return_codes): same as [`noxtls_certificate_der_to_pem_ex()`](#noxtls_certificate_der_to_pem_ex).

### `noxtls_x509_certificate_write_pem`

```c
noxtls_return_t noxtls_x509_certificate_write_pem(const x509_certificate_t *cert, uint8_t *out, uint32_t out_max, uint32_t *out_len);
```

Writes a parsed or generated certificate as PEM. Requires certificate writing (`NOXTLS_HAVE_CERT_WRITE`). The certificate is encoded directly from its DER (`cert->raw_data`), with no temporary heap copy.

**Changed in 0.3.0:** earlier releases ignored `out_max` and could write past `out`. The function now returns `NOXTLS_RETURN_FAILED` without writing anything when `out_max` cannot hold the PEM text plus its NUL terminator.

**Parameters:**

- `cert` — [x509_certificate_t](#x509_certificate_t) with its DER encoding
- `out` — buffer that receives the NUL-terminated PEM text
- `out_max` — capacity of `out` in bytes, including the NUL terminator
- `out_len` — receives the length of the PEM text, not counting the NUL

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success; [NOXTLS_RETURN_NULL](/docs/api/return_codes) when `cert`, `out`, or `out_len` is NULL; [NOXTLS_RETURN_FAILED](/docs/api/return_codes) when the certificate has no DER data or `out_max` is too small.

### `noxtls_x509_csr_create_pem`

```c
noxtls_return_t noxtls_x509_csr_create_pem(
    const uint8_t *subject_der, uint32_t subject_len,
    const uint8_t *subject_pk_oid, uint32_t subject_pk_oid_len,
    const uint8_t *subject_pk, uint32_t subject_pk_len,
    const uint8_t *sig_oid, uint32_t sig_oid_len,
    const uint8_t *sign_key, uint32_t sign_key_len,
    noxtls_hash_algos_t hash_algo,
    uint8_t *out_pem, uint32_t out_max, uint32_t *out_len);
```

Creates a PKCS#10 certificate signing request, as `noxtls_x509_csr_create_der()` does, and encodes it as PEM. Requires certificate writing (`NOXTLS_HAVE_CERT_WRITE`). The signing key must be an ECC key.

**Changed in 0.3.0:** earlier releases ignored `out_max` when writing the PEM text. The function now returns `NOXTLS_RETURN_FAILED` without writing the PEM text when `out_max` cannot hold it plus its NUL terminator.

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success; [NOXTLS_RETURN_NULL](/docs/api/return_codes) when `out_pem` or `out_len` is NULL; [NOXTLS_RETURN_NOT_ENOUGH_MEMORY](/docs/api/return_codes) when the DER work buffer cannot be allocated; [NOXTLS_RETURN_FAILED](/docs/api/return_codes) when the request cannot be built or `out_max` is too small.

### `noxtls_certificate_pem_to_der`

```c
noxtls_return_t noxtls_certificate_pem_to_der(uint8_t * data, uint32_t length, uint8_t * output, uint32_t * out_len);
```

Converts PEM certificate to DER

**Parameters:**

- `data` — is a pointer to the data to convert
- `length` — is the length of the PEM data
- `output` — is a pointer to a buffer to place the DER data
- `out_len` — is the length of data placed in output

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success.

### `noxtls_x509_certificate_matches_hostname`

```c
noxtls_return_t noxtls_x509_certificate_matches_hostname(const x509_certificate_t *cert, const uint8_t *hostname, uint32_t hostname_len);
```

Check whether the certificate is valid for the given hostname (RFC 6125 style). Prefer SAN dNSName; if none, fall back to subject CN. Comparison is case-insensitive for DNS.

When `hostname` is an IPv4 literal (`10.0.0.1`) or an IPv6 literal (`::1`, `2001:db8::1`, optionally in brackets), it matches only an iPAddress SAN with the same address in binary form; dNSName entries, wildcards and the subject CN are never compared with it (RFC 6125 Section 6.2.1). Earlier releases compared IP literals with dNSName entries and the CN as text (so `*.0.0.1` matched `10.0.0.1`) and ignored iPAddress SANs.

**Changed in 0.3.0:**

- A SAN dNSName that contains a NUL byte is stored as an empty entry that never matches. It still counts as a SAN, so the subject-CN fallback stays disabled (RFC 6125 section 6.4.4). Earlier releases matched the part of the name before the NUL.
- The subject-CN fallback walks the DER subject and compares the hostname with every commonName attribute, including those in multi-valued RDNs. A value is used only if it is a PrintableString, UTF8String, IA5String, or TeletexString, contains no NUL, and is shorter than 256 bytes. Earlier releases searched the formatted `subject_dn` string for `CN=`, so another attribute whose value contained `CN=` could act as the common name.

**Parameters:**

- `cert` — [x509_certificate_t](#x509_certificate_t), normally from the parser. The CN fallback reads the DER subject (`cert->subject`), not `subject_dn`; code that fills in a certificate structure by hand must set the DER subject.
- `hostname` — Expected hostname as `uint8_t` text (need not be null-terminated). Since 0.3.0 this is `const uint8_t *`; cast string literals, e.g. `(const uint8_t *)"device.example.com"`.
- `hostname_len` — Length of hostname; 0 uses `noxtls_u8_strlen(hostname)`

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) if hostname matches a SAN dNSName or subject CN; [NOXTLS_RETURN_CERT_VERIFY_HOSTNAME_MISMATCH](/docs/api/return_codes) otherwise; [NOXTLS_RETURN_NULL](/docs/api/return_codes) if cert or hostname is NULL.

### `noxtls_x509_certificate_init`

```c
noxtls_return_t noxtls_x509_certificate_init(x509_certificate_t *cert);
```

Initialize X.509 certificate structure

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success.

### `noxtls_x509_certificate_free`

```c
noxtls_return_t noxtls_x509_certificate_free(x509_certificate_t *cert);
```

Free X.509 certificate structure

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success.

### `noxtls_x509_certificate_parse_der`

```c
noxtls_return_t noxtls_x509_certificate_parse_der(x509_certificate_t *cert, const uint8_t *data, uint32_t len);
```

Parse X.509 certificate from DER format

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success.

### `noxtls_x509_certificate_parse_pem`

```c
noxtls_return_t noxtls_x509_certificate_parse_pem(x509_certificate_t *cert, const uint8_t *data, uint32_t len);
```

Parse X.509 certificate from PEM format

### `noxtls_x509_certificate_load_file`

```c
noxtls_return_t noxtls_x509_certificate_load_file(x509_certificate_t *cert, const uint8_t *filename);
```

Load X.509 certificate from file. Returns `NOXTLS_RETURN_FAILED` when the library is built with `NOXTLS_HAVE_FILE_IO=0` (see [MISRA C:2025](../misra-c.md#host-stdio-is-opt-in)); use `noxtls_x509_certificate_parse_der()` / `_parse_pem()` instead.

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success.

### `noxtls_x509_certificate_verify_signature`

```c
noxtls_return_t noxtls_x509_certificate_verify_signature(x509_certificate_t *cert, const x509_certificate_t *issuer);
```

Verify certificate signature

ECDSA signatures must be the single DER encoding of `ECDSA-Sig-Value`: one SEQUENCE that spans the whole BIT STRING, exactly two minimal, non-negative INTEGERs and minimal lengths. Since the run-1 audit fixes, trailing bytes, extra elements, redundant leading zeros and negative values are rejected (the same check applies to CRL signatures), so a third party can no longer re-encode a valid signature into a certificate with different bytes.

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success.

### ML-DSA certificate signatures

When `NOXTLS_FEATURE_ML_DSA` is enabled, parser/verification paths include ML-DSA public keys and signature OIDs (ML-DSA-44/65/87). Certificate verification dispatches to ML-DSA verification where applicable.

Certificates are signed with pure ML-DSA (FIPS 204) over the DER TBSCertificate with an empty context string, as specified for X.509 in RFC 9881, and the signature OID must name the issuer key's parameter set. Earlier releases verified the signature over SHA-512(TBSCertificate), so they rejected standard ML-DSA certificates, including those written by NoxTLS itself, and accepted a non-standard signature over the digest. The certificate writer already signed the TBSCertificate directly and is unchanged.

Related APIs:

- [ML-DSA](/docs/api/mldsa)
- [TLS 1.3 PQC](/docs/api/tls13_pqc)

## CRL (Certificate Revocation List)

NoxTLS supports **offline** CRL loading and optional checks during X.509 trust verification (mbedTLS-style: separate CRL object, optional `_ex` verify APIs, and verification flags).

- CRL checks run **only when** you pass a non-NULL `noxtls_x509_crl_t *` (or a chain via `crl->next`) to `noxtls_x509_verify_server_cert_trust_ex` / `noxtls_x509_verify_client_cert_trust_ex`. If no CRL is supplied, behavior matches the non-`_ex` functions.
- For each non-anchor certificate in the chain, if a CRL’s **issuer** DN matches the **subject** DN of the certificate that signed that entity, the CRL **signature** is verified with that issuer’s public key, **thisUpdate** / **nextUpdate** are checked when `NOXTLS_HAVE_TIME` is enabled, and the entity’s **serial** is compared to revoked entries.
- When **nextUpdate** is present and the current time is past **nextUpdate**, verification fails with [NOXTLS_RETURN_CRL_EXPIRED](/docs/api/return_codes) and flag `NOXTLS_X509_VERIFY_FLAG_CRL_EXPIRED`.

**Changed by the run-1 audit fixes:**

- **Every applicable CRL is considered.** The whole list is walked; list order no longer matters. The certificate is revoked when any applicable CRL with a valid signature lists it. A CRL outside its thisUpdate/nextUpdate window does not establish status; verification fails with `NOXTLS_RETURN_CRL_EXPIRED` only when no applicable CRL for that issuer is current. A CRL with a bad signature still fails verification. Earlier releases stopped at the first CRL whose issuer matched, so an older CRL placed first hid a later one that listed the certificate.
- **CRL issuer matching uses the RFC 5280 Section 7.1 comparison used for path building** (string type, case and insignificant spaces ignored), followed by the signature check. Earlier releases compared the issuer DER byte for byte and skipped an equivalent CRL.
- **CRL extensions are processed.** A CRL with an unknown critical extension, a `deltaCRLIndicator` (delta CRLs are not supported), a critical CRL entry extension (for example `certificateIssuer` of an indirect CRL), or an `issuingDistributionPoint` with `indirectCRL`, `onlySomeReasons`, `onlyContainsAttributeCerts` or `nameRelativeToCRLIssuer` is refused at parse with `NOXTLS_RETURN_CRL_PARSE_FAILED`. An `issuingDistributionPoint` with `onlyContainsUserCerts`, `onlyContainsCACerts` or a `fullName` distribution point limits which certificates the CRL applies to: a distribution-point CRL applies only to certificates whose `cRLDistributionPoints` names the same point. A CRL outside its scope is ignored for that certificate.
- **Coverage.** When a CRL list is supplied and a chain level has no applicable CRL, `NOXTLS_X509_VERIFY_FLAG_CRL_LEVEL_UNCOVERED` is set. By default the level is still treated as not revoked (soft-fail, unchanged). To require a status for every level, call `noxtls_x509_set_crl_require_coverage(1)` (process-wide; applies to the TLS 1.2 and TLS 1.3 handshake paths, which pass no flags) or set `require_crl_coverage = 1` in a [`noxtls_x509_verify_policy_t`](#explicit-verification-policy). An uncovered level then fails with `NOXTLS_RETURN_CRL_VERIFY_FAILED`. The compile-time default is `NOXTLS_X509_CRL_REQUIRE_COVERAGE` (0). The default stays soft-fail so that existing configurations that load CRLs for only some issuers keep working.

### Verification flags (`noxtls_x509_verify_flags_t`)

When `flags_out` is non-NULL, `_ex` APIs clear it then OR in bits:

| Flag | Meaning |
|------|---------|
| `NOXTLS_X509_VERIFY_FLAG_CERT_REVOKED` | Serial matched a revoked entry on an applicable CRL. |
| `NOXTLS_X509_VERIFY_FLAG_CRL_EXPIRED` | CRL outside allowed time window (includes stale **nextUpdate**). |
| `NOXTLS_X509_VERIFY_FLAG_CRL_BAD_SIGNATURE` | CRL signature did not verify against the issuer. |
| `NOXTLS_X509_VERIFY_FLAG_CRL_NO_MATCH` | CRL(s) were supplied but none matched any issuer in the validated chain (informational on success). |
| `NOXTLS_X509_VERIFY_FLAG_CRL_USED` | At least one supplied CRL matched an issuer and was evaluated. |
| `NOXTLS_X509_VERIFY_FLAG_CRL_LEVEL_UNCOVERED` | A CRL list was supplied but at least one chain level had no applicable, current CRL (status unknown at that level). Fatal only when coverage is required. |

### CRL object and loaders

- `noxtls_x509_crl_init` / `noxtls_x509_crl_free` — `noxtls_x509_crl_free` also frees CRLs linked through `next`.
- `noxtls_x509_crl_parse_der`, `noxtls_x509_crl_parse_pem` (`-----BEGIN X509 CRL-----`), `noxtls_x509_crl_load_file`.

### Global trust store

```c
noxtls_return_t noxtls_x509_trust_store_set(const x509_certificate_chain_t *trust_anchors);
void noxtls_x509_trust_store_clear(void);
int noxtls_x509_trust_store_has_anchors(void);
```

`noxtls_x509_trust_store_set()` replaces the process-wide trust store, used by `noxtls_x509_verify_server_cert_trust*()`, `noxtls_x509_verify_client_cert_trust*()`, and TLS handshakes that verify against the global store, with a deep copy of `trust_anchors`. Pass NULL or an empty chain to clear it. The caller keeps ownership of `trust_anchors` and may free it right after the call. `noxtls_x509_trust_store_clear()` empties the store, and `noxtls_x509_trust_store_has_anchors()` returns 1 when at least one anchor is configured.

**Changed in 0.3.0:** the store owns exactly one copy of the anchors. Each `set` or `clear` frees the previous copy before a new one is allocated, so repeated calls no longer grow the heap. Earlier releases leaked every replaced copy. If the new copy cannot be allocated, the store is left empty (fail closed).

:::warning Threading

The library has no internal locking. Verification functions read the global store only for the duration of the call, and TLS contexts do not keep a pointer to it, but `set` and `clear` free the copy that a concurrent verification may be reading. Do not call `noxtls_x509_trust_store_set()` or `noxtls_x509_trust_store_clear()` while another thread verifies a certificate against the global store or runs a TLS handshake that does. Configure the store at start-up, serialize updates with your own lock, or pass anchors per call with [`noxtls_x509_verify_cert_with_policy()`](#explicit-verification-policy), whose anchor lifetime you control.

:::

### `noxtls_x509_verify_server_cert_trust_ex` / `noxtls_x509_verify_client_cert_trust_ex`

Optional `crl` and `flags_out` parameters; same trust path as `noxtls_x509_verify_server_cert_trust` / `noxtls_x509_verify_client_cert_trust` when `crl` is NULL.

### Path validation hardening (run-1 audit fixes)

These changes apply to `noxtls_x509_verify_server_cert_trust*()`, `noxtls_x509_verify_client_cert_trust*()`, `noxtls_x509_verify_cert_with_policy()` and the TLS handshakes that use them.

- **Trust anchor constraints apply.** When an anchor issues the next certificate, the constraints the anchor certificate carries are enforced as for intermediates: an anchor with `cA=FALSE` (for example a pinned end-entity certificate), an anchor whose Key Usage lacks `keyCertSign`, or an anchor whose `pathLenConstraint` is exceeded can no longer issue. An anchor without a basicConstraints extension (v1 roots, or v3 roots generated without it) is still accepted as an unconstrained legacy root. A pinned certificate still verifies itself by byte identity.
- **Name constraints are enforced.** `nameConstraints` in an intermediate or anchor, critical or not, is applied to every certificate below it: dNSName, iPAddress, rfc822Name (including subject `emailAddress`) and directoryName (subject and SAN). For the end-entity certificate without a dNSName SAN, host-name-like subject CN values are checked as dNSNames. Self-issued intermediates are exempt as in RFC 5280. A constraint on a name form NoxTLS cannot compare (URI, otherName, x400Address, ediPartyName, registeredID) fails the path only when a certificate below carries a name of that form. A `nameConstraints` with `minimum`/`maximum` fields or malformed syntax is refused at parse. Earlier releases refused critical `nameConstraints` at parse and silently ignored non-critical ones.
- **Extended Key Usage and Key Usage presence.** A present EKU that lists no recognized purpose (or is empty) now grants none of the `X509_EKU_*` purposes, and a present Key Usage with no bits set grants none of the usages. Earlier releases treated both as if the extension were absent. Presence is in `x509_certificate_t::ext_flags` (`X509_EXT_FLAG_KEY_USAGE`, `X509_EXT_FLAG_EXT_KEY_USAGE`, `X509_EXT_FLAG_NAME_CONSTRAINTS`). `noxtls_x509_verify_policy_t::require_key_usage_extension` now tests presence too.
- **Bounded path building.** A presented chain with more than `NOXTLS_X509_MAX_PRESENTED_CERTS` (16) certificates is rejected before any signature is verified, and one path validation performs at most `NOXTLS_X509_MAX_PATH_SIGNATURE_CHECKS` (24) signature verifications across all issuer candidates (anchors and presented). Both are compile-time overridable.

Stricter parsing:

- **Extensions.** A list element that is not an Extension SEQUENCE, a missing `extnValue`, trailing octets inside an Extension, a critical extension with an empty value, an Extensions field that is not a SEQUENCE, and duplicate or undecodable basicConstraints, Key Usage, EKU or nameConstraints extensions make `noxtls_x509_certificate_parse_der()` fail. Earlier releases stopped reading the list at a malformed element, which hid every later extension.
- **Validity.** `Validity` must hold exactly two `UTCTime`/`GeneralizedTime` values; an empty Validity or another tag fails the parse, and a missing bound is reported as `NOXTLS_RETURN_BAD_DATA` by the validity checks. Earlier releases treated such a certificate as never expiring.

### `noxtls_x509_set_crl_require_coverage` / `noxtls_x509_get_crl_require_coverage`

```c
void noxtls_x509_set_crl_require_coverage(int enabled);
int noxtls_x509_get_crl_require_coverage(void);
```

Process-wide switch: with 1, a verification that receives a CRL list fails with `NOXTLS_RETURN_CRL_VERIFY_FAILED` when a chain level has no applicable, current CRL. The default comes from `NOXTLS_X509_CRL_REQUIRE_COVERAGE` (0). Like the trust store, set it at start-up; there is no internal locking.

### `noxtls_x509_crl_serial_is_revoked`

Returns 1 if a parsed CRL lists the certificate serial as revoked.

### `noxtls_x509_certificate_check_validity`

```c
noxtls_return_t noxtls_x509_certificate_check_validity(const x509_certificate_t *cert);
```

Check certificate validity (not expired). `cert` is [x509_certificate_t](#x509_certificate_t).

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success.

### `noxtls_x509_certificate_check_validity_at`

```c
noxtls_return_t noxtls_x509_certificate_check_validity_at(const x509_certificate_t *cert, int64_t now);
```

New in 0.3.0. Checks notBefore/notAfter against an explicit time in seconds since the Unix epoch. Use it on devices whose clock comes from the application (for example after network time sync) rather than from `time()`. Returns `NOXTLS_RETURN_NOT_SUPPORTED` when `NOXTLS_HAVE_TIME` is 0.

### Explicit verification policy

New in 0.3.0. `noxtls_x509_verify_cert_with_policy()` verifies a certificate against trust anchors and leaf constraints **supplied per call**, instead of the process-wide trust store. This lets several trust domains coexist in one device, for example a commissioning CA and a web PKI. Chain building and issuer checks are the same as for the global-store APIs, whose behavior is unchanged.

```c
typedef enum
{
    NOXTLS_X509_TIME_SYSTEM = 0,   /* time(NULL) when NOXTLS_HAVE_TIME is 1; no time check when it is 0 */
    NOXTLS_X509_TIME_EXPLICIT = 1  /* check against policy.verify_time (needs NOXTLS_HAVE_TIME) */
} noxtls_x509_time_mode_t;

typedef struct noxtls_x509_verify_policy
{
    const x509_certificate_chain_t *trust_anchors; /* required, non-empty, non-owning */
    const noxtls_x509_crl_t *crl;                  /* optional CRL list, or NULL */
    uint32_t required_eku;                         /* X509_EKU_* purpose; 0 = no EKU constraint */
    uint16_t required_key_usage;                   /* X509_KEY_USAGE_* bits, all required when KU present; 0 = purpose default */
    uint8_t require_key_usage_extension;           /* 1 = reject a leaf without Key Usage */
    noxtls_x509_time_mode_t time_mode;
    int64_t verify_time;                           /* seconds since the Unix epoch (EXPLICIT mode) */
    uint8_t require_crl_coverage;                  /* 1 = every chain level needs an applicable CRL */
} noxtls_x509_verify_policy_t;

noxtls_return_t noxtls_x509_verify_cert_with_policy(const x509_certificate_t *leaf,
                                                    const x509_certificate_chain_t *presented_chain,
                                                    const noxtls_x509_verify_policy_t *policy,
                                                    noxtls_x509_verify_flags_t *flags_out);
```

- `presented_chain` holds the intermediates the peer presented, excluding the leaf. It may be empty.
- If the policy has no anchors, verification **fails closed** with `NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED`.
- `flags_out` is optional. It is cleared and then ORed with `NOXTLS_X509_VERIFY_FLAG_*` bits, as described in [Verification flags](#verification-flags-noxtls_x509_verify_flags_t).
- With `NOXTLS_X509_TIME_EXPLICIT`, CRL thisUpdate and nextUpdate are checked against `verify_time` as well, and a negative `verify_time` is rejected. Before the 0.3.0 fixes, CRL freshness used the system clock even in explicit mode.
- The TLS 1.2 server API [`noxtls_tls12_set_client_verify_policy()`](./tls12.md#noxtls_tls12_set_client_verify_policy) applies the same policy to client certificates.

### Raw extension lookup (`noxtls_x509_ext.h`)

New in 0.3.0. These functions read private or protocol-specific X.509 v3 extensions, such as the Thread TCAT attributes under 1.3.6.1.4.1.44970, without installing the global unknown-extension callback. They walk the raw Extensions DER of a parsed certificate. All returned pointers alias the certificate's storage.

```c
typedef struct
{
    const uint8_t *der;   uint32_t der_len;     /* complete Extension TLV */
    const uint8_t *oid;   uint32_t oid_len;     /* extnID content octets */
    const uint8_t *value; uint32_t value_len;   /* extnValue OCTET STRING contents */
    uint8_t critical;                            /* 1 when critical */
} noxtls_x509_extension_t;

noxtls_return_t noxtls_x509_certificate_find_extension(const x509_certificate_t *cert,
                                                       const uint8_t *oid, uint32_t oid_len,
                                                       noxtls_x509_extension_t *ext, int *found);
noxtls_return_t noxtls_x509_extensions_find_der(const uint8_t *extensions_der, uint32_t extensions_len,
                                                const uint8_t *oid, uint32_t oid_len,
                                                noxtls_x509_extension_t *ext, int *found);

noxtls_return_t noxtls_x509_extension_iter_init(noxtls_x509_extension_iter_t *iter,
                                                const x509_certificate_t *cert);
noxtls_return_t noxtls_x509_extension_iter_init_der(noxtls_x509_extension_iter_t *iter,
                                                    const uint8_t *extensions_der,
                                                    uint32_t extensions_len);
noxtls_return_t noxtls_x509_extension_iter_next(noxtls_x509_extension_iter_t *iter,
                                                noxtls_x509_extension_t *ext, int *has_ext);

int noxtls_x509_oid_is_under_arc(const uint8_t *oid, uint32_t oid_len,
                                 const uint8_t *arc, uint32_t arc_len);
```

- Decoding is **strict DER**. These all return `NOXTLS_RETURN_BAD_DATA`:
  - indefinite or non-minimal lengths
  - non-DER BOOLEANs
  - unterminated OIDs
  - trailing bytes
  - duplicate extensions (RFC 5280 section 4.2)
- The `find` functions validate the whole extension list, not just the match. `found` is set to 0 when the OID is absent.
- `noxtls_x509_oid_is_under_arc()` returns 1 when `oid` lies strictly below `arc`. Both are OID content octets, and `arc` must end on a sub-identifier boundary.

### `noxtls_x509_certificate_get_public_key`

```c
noxtls_return_t noxtls_x509_certificate_get_public_key(const x509_certificate_t *cert, void **key, uint32_t *key_type);
```

Get public key from certificate (noxtls_ namespace). `cert` is [x509_certificate_t](#x509_certificate_t). For ECC: key is set to an allocated [ecc_key_t](/docs/api/ecc#ecc_key_t) (caller must noxtls_ecc_key_free then free). key_type: 1 = RSA, 2 = ECC.

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success.

### Raw Public Keys (RFC 7250)

TLS 1.2 and DTLS 1.2 support **Raw Public Keys (RPK)** via the `client_certificate_type` and `server_certificate_type` extensions. The server can send a **SubjectPublicKeyInfo** (DER) in the Certificate message instead of an X.509 chain; the client receives it in `server_cert` and sets `server_cert_is_rpk` to 1. Verification is **out-of-band** (e.g. compare to a pinned key or use DANE). Use **tls12** APIs: `noxtls_tls12_set_server_use_rpk()` (server), `noxtls_tls12_set_client_accept_server_rpk()` / `noxtls_tls12_set_client_offer_client_rpk()` (client). Prefer ECDHE cipher suites with RPK.

### Detailed certificate failure information

When certificate parsing or verification fails, the library stores detailed failure information that you can retrieve to log or display the exact reason (time window, common name, expected hostname, chain index).

**Return codes:** Certificate APIs may return [NOXTLS_RETURN_CERT_PARSE_FAILED](/docs/api/return_codes), [NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED](/docs/api/return_codes), [NOXTLS_RETURN_CERT_VERIFY_HOSTNAME_MISMATCH](/docs/api/return_codes), [NOXTLS_RETURN_CERT_EXPIRED](/docs/api/return_codes), [NOXTLS_RETURN_CERT_NOT_YET_VALID](/docs/api/return_codes), [NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED](/docs/api/return_codes), [NOXTLS_RETURN_CERT_REVOKED](/docs/api/return_codes), [NOXTLS_RETURN_CRL_PARSE_FAILED](/docs/api/return_codes), [NOXTLS_RETURN_CRL_VERIFY_FAILED](/docs/api/return_codes), or [NOXTLS_RETURN_CRL_EXPIRED](/docs/api/return_codes). After any such failure, call `noxtls_cert_verify_failure_get()` to get a **noxtls_cert_verify_failure_info_t** with:

- **return_code** — The same code that was returned.
- **not_before** / **not_after** — Certificate validity times (e.g. for expired / not yet valid).
- **subject_dn** — Subject distinguished name of the certificate that failed.
- **expected_hostname** — The hostname that was checked (on hostname mismatch).
- **cert_index** — Index in chain (0-based) when chain verification fails.
- **populated** — 1 if the struct was filled by a failure; 0 otherwise.

```c
noxtls_cert_verify_failure_info_t info;
noxtls_cert_verify_failure_get(&info);
if (info.populated) {
    /* Text fields are uint8_t arrays since 0.3.0, e.g.
       printf("Cert failure: %u, subject=%s, not_after=%s
", (unsigned)info.return_code,
              (const char *)info.subject_dn, (const char *)info.not_after); */
}
```

**Clear:** Call `noxtls_cert_verify_failure_clear()` before a new verification if you want to avoid reusing an older failure’s details. Storage is process-wide (not thread-safe).

### `noxtls_x509_get_attr_name_from_oid`

```c
/* Internal helper (static): attribute name from OID */ static const uint8_t *noxtls_x509_get_attr_name_from_oid(const uint8_t *attr_oid, uint32_t attr_oid_len);
```

Parse Distinguished Name

### `noxtls_x509_parse_time`

```c
noxtls_return_t noxtls_x509_parse_time(const uint8_t *time_data, uint32_t time_len, uint8_t *output, uint32_t output_size);
```

Parse ASN.1 time

### `noxtls_x509_set_unknown_extension_callback`

```c
void noxtls_x509_set_unknown_extension_callback(noxtls_x509_unknown_ext_cb_t cb, void *user_ctx);
```

Set a global callback for unknown/custom certificate extension OIDs encountered during parse. Pass `NULL` as callback to clear.

### `noxtls_x509_certificate_chain_init`

```c
noxtls_return_t noxtls_x509_certificate_chain_init(x509_certificate_chain_t *chain);
```

Initialize certificate chain

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success.

### `noxtls_x509_certificate_chain_free`

```c
noxtls_return_t noxtls_x509_certificate_chain_free(x509_certificate_chain_t *chain);
```

Free certificate chain

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success.

### `noxtls_x509_certificate_chain_add`

```c
noxtls_return_t noxtls_x509_certificate_chain_add(x509_certificate_chain_t *chain, const x509_certificate_t *cert);
```

Add certificate to chain. `chain` is [x509_certificate_chain_t](#x509_certificate_chain_t); `cert` is [x509_certificate_t](#x509_certificate_t).

### `noxtls_x509_certificate_chain_verify`

```c
noxtls_return_t noxtls_x509_certificate_chain_verify(x509_certificate_chain_t *chain);
```

Verify certificate chain

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success.

### `noxtls_x509_private_key_init`

```c
noxtls_return_t noxtls_x509_private_key_init(x509_private_key_t *key);
```

Initialize X.509 private key structure

### `noxtls_x509_private_key_free`

```c
noxtls_return_t noxtls_x509_private_key_free(x509_private_key_t *key);
```

Free X.509 private key structure

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success.

### `noxtls_x509_private_key_parse_der`

```c
noxtls_return_t noxtls_x509_private_key_parse_der(x509_private_key_t *key, const uint8_t *data, uint32_t len);
```

Parse X.509 private key from DER format

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success.

### `noxtls_x509_private_key_parse_pem`

```c
noxtls_return_t noxtls_x509_private_key_parse_pem(x509_private_key_t *key, const uint8_t *data, uint32_t len);
```

Parse X.509 private key from PEM format

### Encrypted private keys (PBES2/PBKDF2)

For PKCS#8 `EncryptedPrivateKeyInfo`, noxtls supports decryption through:

- `noxtls_x509_private_key_parse_der_with_password(...)`
- `noxtls_x509_private_key_parse_pem_with_password(...)`

Current support in the built-in parser is:

- PBES2 container
- PBKDF2 key derivation using HMAC-SHA1 (through the public [`noxtls_pbkdf2_hmac()`](./kdf.md#noxtls_pbkdf2_hmac) when `NOXTLS_CFG_FEATURE_PBKDF2=ON`, otherwise a private implementation)
- AES-CBC encryption schemes: AES-128-CBC and AES-256-CBC

Behavior notes:

- If an encrypted key is parsed without a password, parsing fails and `key->encrypted` is set.
- If a password is provided but decryption fails (wrong password or unsupported scheme), parsing fails.
- Iteration count must be greater than 0 (internally bounded to avoid unreasonable values).

For general-purpose password-based key derivation, use the [Key derivation API](./kdf.md) (`noxtls_pbkdf2_hmac()`, new in 0.3.0).

### `noxtls_x509_private_key_parse_der_with_password`

```c
noxtls_return_t noxtls_x509_private_key_parse_der_with_password(x509_private_key_t *key, const uint8_t *data, uint32_t len,
                                                                  const uint8_t *password, uint32_t password_len);
```

Parse DER private key. If the input is PKCS#8 `EncryptedPrivateKeyInfo`, decrypt using password then parse.

### `noxtls_x509_private_key_parse_pem_with_password`

```c
noxtls_return_t noxtls_x509_private_key_parse_pem_with_password(x509_private_key_t *key, const uint8_t *data, uint32_t len,
                                                                  const uint8_t *password, uint32_t password_len);
```

Parse PEM private key. If the input is encrypted PKCS#8, decrypt using password then parse.

### `noxtls_x509_private_key_load_file`

```c
noxtls_return_t noxtls_x509_private_key_load_file(x509_private_key_t *key, const uint8_t *filename);
```

Load X.509 private key from file. Returns `NOXTLS_RETURN_FAILED` when built with `NOXTLS_HAVE_FILE_IO=0`.

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success.

### `noxtls_x509_private_key_to_rsa_key`

```c
noxtls_return_t noxtls_x509_private_key_to_rsa_key(const x509_private_key_t *key, void *rsa_key);
```

Convert X.509 private key to RSA key structure

### `noxtls_x509_private_key_to_ecc_key`

```c
noxtls_return_t noxtls_x509_private_key_to_ecc_key(const x509_private_key_t *key, ecc_key_t *ecc_key);
```

Convert X.509 private key to [ecc_key_t](/docs/api/ecc#ecc_key_t) (noxtls_ namespace). `key` is [x509_private_key_t](#x509_private_key_t). Caller provides ecc_key; it is filled and must be freed with noxtls_ecc_key_free.

The private scalar d must be in the range [1, n - 1] for the curve order n; this is checked in constant time. Earlier releases accepted d = 0 and d ≥ n, which `noxtls_x509_private_key_sign_data()` then used for signing.

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success; [NOXTLS_RETURN_BAD_DATA](/docs/api/return_codes) when the scalar is out of range.

### `noxtls_x509_private_key_sign_data`

```c
noxtls_return_t noxtls_x509_private_key_sign_data(const uint8_t *key, uint32_t key_len, const uint8_t *data, uint32_t data_len, noxtls_hash_algos_t hash_algo, uint8_t *out_der, uint32_t out_max, uint32_t *out_len);
```

High-level sign data with X.509 private key; output DER signature.

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success.

### `noxtls_x509_debug_print_oid`

```c
void noxtls_x509_debug_print_oid(const uint8_t *label, const uint8_t *oid_bytes, uint32_t oid_bytes_len);
```

Print OID in readable format

### `noxtls_x509_debug_print_hex`

```c
void noxtls_x509_debug_print_hex(const uint8_t *label, const uint8_t *data, uint32_t len, uint8_t verbose);
```

Print hex data with formatting

### `noxtls_x509_certificate_debug_print`

```c
noxtls_return_t noxtls_x509_certificate_debug_print(x509_certificate_t *cert, uint8_t verbose);
```

Debug print certificate information

### `noxtls_x509_private_key_debug_print`

```c
noxtls_return_t noxtls_x509_private_key_debug_print(x509_private_key_t *key, uint8_t verbose);
```

Debug print private key information

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success.

