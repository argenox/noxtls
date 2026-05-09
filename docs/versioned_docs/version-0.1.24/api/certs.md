---
sidebar_position: 27
title: "Certificates"
---

# Certificates

X.509 and certificate handling.

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

### `asn1_decode_integer`

```c
void asn1_decode_integer(uint8_t ** data, uint32_t len);
```

Decodes object identifier

**Parameters:**

- `data` — is a pointer to the data to convert
- `length` — is the length of the PEM data
- `output` — is a pointer to a buffer to place the DER data
- `out_len` — is the length of data placed in output

### `asn1_decode_bitstring`

```c
void asn1_decode_bitstring(uint8_t ** data, uint32_t len);
```

Decodes ASN.1 Bit String

**Parameters:**

- `data` — is a pointer to  a pointer of the data to convert
- `len` — is the length of the data

### `asn1_decode_obj_ident`

```c
void asn1_decode_obj_ident(uint8_t ** data, uint32_t len);
```

Decodes object identifier

**Parameters:**

- `data` — is a pointer to the data to convert
- `length` — is the length of the PEM data
- `output` — is a pointer to a buffer to place the DER data
- `out_len` — is the length of data placed in output

### `asn1_find_oid`

```c
void asn1_find_oid(char * oid);
```

Finds the OID description for an identifier

**Parameters:**

- `oid` — is the OID string

### `asn1_decode_print_string`

```c
void asn1_decode_print_string(uint8_t ** data, uint32_t len);
```

Decodes object identifier

**Parameters:**

- `data` — is a pointer to the data to convert
- `length` — is the length of the PEM data
- `output` — is a pointer to a buffer to place the DER data
- `out_len` — is the length of data placed in output

### `noxtls_certificate_der_to_pem`

```c
noxtls_return_t noxtls_certificate_der_to_pem(uint8_t * data, uint32_t length, uint8_t * output, uint32_t * out_len);
```

Converts DER certificate to PEM

**Parameters:**

- `data` — is a pointer to the DER data to convert
- `length` — is the length of the DER data
- `output` — is a pointer to a buffer to place the PEM data
- `out_len` — is the length of data placed in output

### `noxtls_csr_der_to_pem`

```c
noxtls_return_t noxtls_csr_der_to_pem(uint8_t *data, uint32_t length, uint8_t *output, uint32_t *out_len);
```

Converts DER Certificate Signing Request (PKCS#10) to PEM.

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success.

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
noxtls_return_t noxtls_x509_certificate_matches_hostname(const x509_certificate_t *cert, const char *hostname, uint32_t hostname_len);
```

Check whether the certificate is valid for the given hostname (RFC 6125 style). Prefer SAN dNSName; if none, fall back to subject CN. Comparison is case-insensitive for DNS.

**Parameters:**

- `cert` — [x509_certificate_t](#x509_certificate_t) (must have been parsed so subject_dn and optionally san_dns_ are set)
- `hostname` — Expected hostname (need not be null-terminated)
- `hostname_len` — Length of hostname

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
noxtls_return_t noxtls_x509_certificate_load_file(x509_certificate_t *cert, const char *filename);
```

Load X.509 certificate from file

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success.

### `noxtls_x509_certificate_verify_signature`

```c
noxtls_return_t noxtls_x509_certificate_verify_signature(x509_certificate_t *cert, const x509_certificate_t *issuer);
```

Verify certificate signature

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success.

### `noxtls_x509_certificate_check_validity`

```c
noxtls_return_t noxtls_x509_certificate_check_validity(const x509_certificate_t *cert);
```

Check certificate validity (not expired). `cert` is [x509_certificate_t](#x509_certificate_t).

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success.

### `noxtls_x509_certificate_get_public_key`

```c
noxtls_return_t noxtls_x509_certificate_get_public_key(const x509_certificate_t *cert, void **key, uint32_t *key_type);
```

Get public key from certificate (noxtls_ namespace). `cert` is [x509_certificate_t](#x509_certificate_t). For ECC: key is set to an allocated [ecc_key_t](/docs/api/ecc#ecc_key_t) (caller must noxtls_ecc_key_free then free). key_type: 1 = RSA, 2 = ECC.

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success.

### `x509_certificate_get_public_key`

```c
noxtls_return_t x509_certificate_get_public_key(const x509_certificate_t *cert, void **key, uint32_t *key_type);
```

Get public key from certificate (legacy wrapper)

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success.

### Raw Public Keys (RFC 7250)

TLS 1.2 and DTLS 1.2 support **Raw Public Keys (RPK)** via the `client_certificate_type` and `server_certificate_type` extensions. The server can send a **SubjectPublicKeyInfo** (DER) in the Certificate message instead of an X.509 chain; the client receives it in `server_cert` and sets `server_cert_is_rpk` to 1. Verification is **out-of-band** (e.g. compare to a pinned key or use DANE). Use **tls12** APIs: `tls12_set_server_use_rpk()` (server), `tls12_set_client_accept_server_rpk()` / `tls12_set_client_offer_client_rpk()` (client). Prefer ECDHE cipher suites with RPK.

### Detailed certificate failure information

When certificate parsing or verification fails, the library stores detailed failure information that you can retrieve to log or display the exact reason (time window, common name, expected hostname, chain index).

**Return codes:** Certificate APIs may return [NOXTLS_RETURN_CERT_PARSE_FAILED](/docs/api/return_codes), [NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED](/docs/api/return_codes), [NOXTLS_RETURN_CERT_VERIFY_HOSTNAME_MISMATCH](/docs/api/return_codes), [NOXTLS_RETURN_CERT_EXPIRED](/docs/api/return_codes), [NOXTLS_RETURN_CERT_NOT_YET_VALID](/docs/api/return_codes), or [NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED](/docs/api/return_codes). After any such failure, call `noxtls_cert_verify_failure_get()` to get a **noxtls_cert_verify_failure_info_t** with:

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
    /* e.g. printf("Cert failure: %d, subject=%s, not_after=%s\n", info.return_code, info.subject_dn, info.not_after); */
}
```

**Clear:** Call `noxtls_cert_verify_failure_clear()` before a new verification if you want to avoid reusing an older failure’s details. Storage is process-wide (not thread-safe).

### `noxtls_x509_get_attr_name_from_oid`

```c
/* Helper function to get attribute name from OID */ static const char* noxtls_x509_get_attr_name_from_oid(const uint8_t *oid, uint32_t oid_len);
```

Parse Distinguished Name

### `noxtls_x509_parse_time`

```c
noxtls_return_t noxtls_x509_parse_time(const uint8_t *time_data, uint32_t time_len, char *output, uint32_t output_size);
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
- PBKDF2 key derivation using HMAC-SHA1
- AES-CBC encryption schemes: AES-128-CBC and AES-256-CBC

Behavior notes:

- If an encrypted key is parsed without a password, parsing fails and `key->encrypted` is set.
- If a password is provided but decryption fails (wrong password or unsupported scheme), parsing fails.
- Iteration count must be greater than 0 (internally bounded to avoid unreasonable values).

This PBKDF2 path is used for encrypted private key import and is not a general-purpose KDF API.

### `noxtls_x509_private_key_parse_der_with_password`

```c
noxtls_return_t noxtls_x509_private_key_parse_der_with_password(x509_private_key_t *key, const uint8_t *data, uint32_t len, const char *password, uint32_t password_len);
```

Parse DER private key. If the input is PKCS#8 `EncryptedPrivateKeyInfo`, decrypt using password then parse.

### `noxtls_x509_private_key_parse_pem_with_password`

```c
noxtls_return_t noxtls_x509_private_key_parse_pem_with_password(x509_private_key_t *key, const uint8_t *data, uint32_t len, const char *password, uint32_t password_len);
```

Parse PEM private key. If the input is encrypted PKCS#8, decrypt using password then parse.

### `noxtls_x509_private_key_load_file`

```c
noxtls_return_t noxtls_x509_private_key_load_file(x509_private_key_t *key, const char *filename);
```

Load X.509 private key from file

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

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success.

### `noxtls_x509_private_key_sign_data`

```c
noxtls_return_t noxtls_x509_private_key_sign_data(const uint8_t *key, uint32_t key_len, const uint8_t *data, uint32_t data_len, noxtls_hash_algos_t hash_algo, uint8_t *out_der, uint32_t out_max, uint32_t *out_len);
```

High-level sign data with X.509 private key; output DER signature.

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success.

### `x509_private_key_to_ecc_key`

```c
noxtls_return_t x509_private_key_to_ecc_key(const x509_private_key_t *key, void *ecc_key);
```

Convert X.509 private key to ECC key structure (legacy wrapper)

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success.

### `noxtls_x509_debug_print_oid`

```c
void noxtls_x509_debug_print_oid(const char *label, const uint8_t *oid, uint32_t oid_len);
```

Print OID in readable format

### `noxtls_x509_debug_print_hex`

```c
void noxtls_x509_debug_print_hex(const char *label, const uint8_t *data, uint32_t len, uint8_t verbose);
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

