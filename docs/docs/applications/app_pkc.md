---
sidebar_position: 11
title: PKC utility
description: "NoxTLS PKC utility sample application: build, usage, and command-line options."
---

# PKC utility

Public key cryptography CLI: **RSA** (encrypt/decrypt/sign with ephemeral keys) and **EdDSA** (genkey, sign with a PKCS#8 file, verify with a raw public key hex).

See also the [EdDSA overview](../eddsa) and `applications/pkc/README.md` in the source tree.

## Building

The PKC utility is built as part of the main project:

```bash
cd build
ninja pkc
```

Or build all applications:

```bash
ninja
```

When built **inside the full NoxTLS CMake tree**, `pkc` links the X.509 library so **`-K`** can load PEM/DER PKCS#8 keys (for example keys from **certgen** `gened25519` / `gened448`). A minimal **standalone** `pkc` CMake project does not include that stack; use the main project build for EdDSA file signing.

## Usage

### General Syntax

```
pkc [operation] [algorithm] [options] [data...]
```

### Operations

- `encrypt` — Encrypt data (RSA only)
- `decrypt` — Decrypt data (RSA only)
- `sign` — Sign data
- `verify` — Verify a signature
- `genkey` — Generate a key pair

### Algorithms

- `rsa` — RSA
- `ed25519`, `ed25519ctx`, `ed25519ph` — Ed25519 variants (see `NOXTLS_FEATURE_ED25519`)
- `ed448`, `ed448ctx`, `ed448ph` — Ed448 variants (requires Ed448 + SHA-3 in the build)

### Options

- `-k <size>` — RSA key size in bits (1024, 2048, 3072, 4096). Default: 2048
- `-K <file>` — Private key PEM/DER (PKCS#8) for **EdDSA sign**
- `-P <hex>` — Raw public key hex (32 bytes Ed25519, 57 bytes Ed448) for **EdDSA verify**
- `-C <hex>` — Context bytes as hex for **ed25519ctx** / **ed448ctx** (sign and verify)
- `-h <algo>` — Hash for **RSA** signatures: `md5`, `sha1`, `sha256` (default: sha256). **Note:** use `--help` for help; `-h` selects RSA hash.
- `-d` — Debug
- `-x` — Interpret message input as hexadecimal
- `-v` — Version
- `--help` — Usage

## Examples

### Generate RSA key pair

```bash
pkc genkey rsa -k 2048
```

### Encrypt (RSA)

```bash
pkc encrypt rsa "Hello World"
```

### Sign (RSA)

```bash
pkc sign rsa "Message to sign" -h sha256
```

### Ed25519 (full tree build)

```bash
certgen gened25519 -out mykey
pkc sign ed25519 -K mykey.key "hello"
pkc genkey ed25519
pkc verify ed25519 -P <64-char-hex-pub> "hello" <128-char-hex-sig>
```

For `ed25519ctx`, pass the same `-C <hex>` to **sign** and **verify** (context length 1–255 bytes per RFC 8032).

### Decrypt / RSA verify

RSA **decrypt** and **verify** with externally supplied keys are not fully implemented on the CLI (ephemeral RSA demo paths only). Use **EdDSA verify** with `-P` for real verification, or OpenSSL for RSA with persisted keys.

## Key sizes (RSA)

- 1024 — not recommended for production
- 2048 — recommended minimum
- 3072 / 4096 — higher security

## Hash algorithms (RSA signatures)

- `md5`, `sha1` — legacy only
- `sha256` — recommended

## Output

Binary outputs (ciphertext, signatures, generated key material) are printed in **hexadecimal**.

## Security notes

Use at least 2048-bit RSA keys; prefer SHA-256 or stronger for RSA signatures. For production, load keys from secure storage; the RSA demo paths generate ephemeral keys per run.
