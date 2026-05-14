---
sidebar_position: 0
title: "Return codes (noxtls_return_t)"
---

# Return codes (noxtls_return_t)

Most NoxTLS API functions return **noxtls_return_t**, an enum type. Always check the return value: use [NOXTLS_RETURN_SUCCESS](#values) for success, or handle specific error codes for diagnostics.

The type and constants are defined in `noxtls_common.h`.

## Type

**noxtls_return_t** — Enumeration of success and error codes. Use it as the return type of API functions that report status.

## Values

| Constant | Value | Description |
|----------|-------|-------------|
| **NOXTLS_RETURN_SUCCESS** | 0 | Operation completed successfully. |
| **NOXTLS_RETURN_FAILED** | 1 | General failure (e.g. verification failed, crypto operation failed). |
| **NOXTLS_RETURN_NULL** | 2 | A required pointer argument was NULL. |
| **NOXTLS_RETURN_INVALID_PARAM** | 3 | An argument was invalid (e.g. out of range, inconsistent). |
| **NOXTLS_RETURN_INVALID_BLOCK_SIZE** | 4 | Block or buffer size invalid for the operation. |
| **NOXTLS_RETURN_INVALID_KEY_SIZE** | 5 | Key size invalid for the algorithm or mode. |
| **NOXTLS_RETURN_INVALID_MODE** | 6 | Cipher mode invalid or not supported for this operation. |
| **NOXTLS_RETURN_INVALID_ALGORITHM** | 7 | Requested algorithm not supported or invalid in this context. |
| **NOXTLS_RETURN_BAD_DATA** | 8 | Input data was malformed or invalid (e.g. auth tag mismatch). |
| **NOXTLS_RETURN_TIMEOUT** | 9 | Operation timed out. |
| **NOXTLS_RETURN_NOT_SUPPORTED** | 10 | Requested feature or option is not supported. |
| **NOXTLS_RETURN_NOT_INITIALIZED** | 11 | Context or module was not initialized. |
| **NOXTLS_RETURN_NOT_ENOUGH_MEMORY** | 12 | Memory allocation failed. |
| **NOXTLS_RETURN_NOT_ENOUGH_ENTROPY** | 13 | Insufficient entropy for random or key-generation. |
| **NOXTLS_RETURN_CERT_PARSE_FAILED** | 14 | Certificate parsing failed (malformed DER or invalid structure). |
| **NOXTLS_RETURN_CERT_VERIFY_FAILED** | 15 | Certificate verification failed (generic). |
| **NOXTLS_RETURN_TLS_ERROR** | 16 | TLS/protocol error (handshake, record, or unexpected message). |
| **NOXTLS_RETURN_CERT_VERIFY_SIGNATURE_FAILED** | 17 | Certificate signature verification failed (invalid or issuer key missing). |
| **NOXTLS_RETURN_CERT_VERIFY_HOSTNAME_MISMATCH** | 18 | Hostname does not match certificate SAN or subject CN. |
| **NOXTLS_RETURN_CERT_EXPIRED** | 19 | Certificate has expired (current time > notAfter). |
| **NOXTLS_RETURN_CERT_NOT_YET_VALID** | 20 | Certificate not yet valid (current time < notBefore). |
| **NOXTLS_RETURN_CERT_VERIFY_CHAIN_FAILED** | 21 | Certificate chain verification failed (signature or validity of a link). |

## Usage

- For **success**, check for `ret == NOXTLS_RETURN_SUCCESS` (or `!ret` when 0 is the only success value).
- For **verification-style** functions (e.g. hash verify), `NOXTLS_RETURN_SUCCESS` means the check passed; `NOXTLS_RETURN_FAILED` means it did not.
- Use specific codes (e.g. `NOXTLS_RETURN_NULL`, `NOXTLS_RETURN_BAD_DATA`) to narrow down errors in logs or handling.
- For **TLS** and **X.509** APIs, use the specific certificate return codes above to distinguish parse, signature, hostname, time, and chain failures. Use `NOXTLS_RETURN_TLS_ERROR` for protocol-level TLS/handshake errors.
- For **detailed certificate failure info** (notBefore, notAfter, subject DN, expected hostname, chain index), call [noxtls_cert_verify_failure_get](/docs/api/certs#detailed-certificate-failure-information) after any X.509 or TLS API that returns a `CERT_*` code.

## See also

- [Common](/docs/api/common) — Memory and debug utilities that also use noxtls_return_t.
