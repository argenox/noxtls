# PKC (Public Key Cryptography) Utility

This utility supports **RSA** (encrypt/decrypt/sign with ephemeral keys) and **EdDSA** (`ed25519`, `ed25519ctx`, `ed25519ph`, `ed448`, `ed448ctx`, `ed448ph`) for **genkey**, **sign** (with `-K` PKCS#8 PEM/DER), and **verify** (with `-P` raw public key hex).

When building as part of the main NoxTLS tree, `pkc` links against the X.509 layer so PEM PKCS#8 keys from **certgen** (`gened25519`, `gened448`) can be used with `-K`. PEM-only **standalone** `pkc` builds do not include that stack; use the full project build for EdDSA file signing.

For PKCS#8 key generation, **certgen** remains the recommended tool (`gened25519`, `gened448` when `NOXTLS_CFG_FEATURE_ED448` and SHA-3 are enabled).

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

## Usage

### General Syntax

```
pkc [operation] [algorithm] [options] [data...]
```

### Operations

- `encrypt` - Encrypt data using public key
- `decrypt` - Decrypt data using private key
- `sign` - Sign data using private key
- `verify` - Verify signature using public key
- `genkey` - Generate key pair (RSA or Ed25519 / Ed448)

### Algorithms

- `rsa` - RSA
- `ed25519`, `ed25519ctx`, `ed25519ph` - Ed25519 variants (library feature flags)
- `ed448`, `ed448ctx`, `ed448ph` - Ed448 variants (requires Ed448 + SHA-3 in the build)

### Options

- `-k <size>` - RSA key size in bits (1024, 2048, 3072, 4096). Default: 2048
- `-K <file>` - Private key PEM/DER (PKCS#8) for EdDSA **sign**
- `-P <hex>` - Raw public key hex (32 bytes Ed25519, 57 bytes Ed448) for EdDSA **verify**
- `-C <hex>` - Context bytes as hex for **ed25519ctx** / **ed448ctx** (sign and verify)
- `-h <algo>` - Hash algorithm for **RSA** signatures (md5, sha1, sha256). Default: sha256
- `-d` - Enable debug mode
- `-x` - Interpret noxtls_message input as hexadecimal string
- `-v` - Version information
- `--help` - Show help noxtls_message (do not use `-h` for help; `-h` selects RSA hash)

## Examples

### Generate RSA Key Pair

```bash
pkc genkey rsa -k 2048
```

This generates a 2048-bit RSA key pair and displays the public and private key components.

### Encrypt Data

```bash
pkc encrypt rsa "Hello World"
```

Encrypts the noxtls_message "Hello World" using a newly generated RSA key pair. The output includes:
- The ciphertext (hexadecimal)
- The public key (modulus n and exponent e) for decryption

### Sign Data

```bash
pkc sign rsa "Message to sign" -h sha256
```

Signs the noxtls_message using a newly generated RSA key pair with SHA-256 hashing. The output includes:
- The signature (hexadecimal)
- The public key (modulus n and exponent e) for verification

### Decrypt Data

```bash
pkc decrypt rsa <hex_ciphertext>
```

**Note:** Decryption with external keys is not yet fully implemented. The current implementation generates a new key pair for each operation.

### Verify Signature

```bash
pkc verify rsa "Message" <hex_signature>
```

RSA verify with external keys is still a placeholder.

### Ed25519 sign / verify (full project build)

```bash
certgen gened25519 -out mykey
pkc sign ed25519 -K mykey.key "hello"
pkc verify ed25519 -P <64-char-hex-pub> "hello" <128-char-hex-sig>
```

Use `pkc genkey ed25519` to print seed and public key hex for testing. For `ed25519ctx`, pass the same `-C` hex to sign and verify.

## Key Sizes

Supported RSA key sizes:
- 1024 bits (not recommended for production)
- 2048 bits (recommended minimum)
- 3072 bits
- 4096 bits (high security)

## Hash Algorithms for Signatures

Supported hash algorithms:
- `md5` - MD5 (not recommended for new applications)
- `sha1` - SHA-1 (deprecated, not recommended)
- `sha256` - SHA-256 (recommended)

## Output Format

All binary data (ciphertext, signatures, keys) is displayed in hexadecimal format.

## Security Notes

1. **Key Generation**: Key generation uses random number generation. For production use, ensure a cryptographically secure random number generator.

2. **Key Storage**: The current implementation does not persist keys. Keys are generated for each operation. In production, keys should be securely stored and loaded.

3. **Key Sizes**: Use at least 2048-bit keys for RSA. 1024-bit keys are considered insecure.

4. **Hash Algorithms**: Use SHA-256 or stronger for signatures. MD5 and SHA-1 are deprecated.

5. **Key Management**: Private keys should never be transmitted or stored insecurely.

## Future Enhancements

- Key import/export functionality
- Support for loading keys from files
- Support for ECC, ECDSA, and ECDH algorithms
- Key persistence and management
- More padding schemes (OAEP, PSS)


