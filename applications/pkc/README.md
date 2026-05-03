# PKC (Public Key Cryptography) Utility

This utility provides command-line access to public key cryptography operations, currently supporting RSA.

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
- `genkey` - Generate RSA key pair

### Algorithms

- `rsa` - RSA (Rivest-Shamir-Adleman) public key cryptography

### Options

- `-k <size>` - Key size in bits (1024, 2048, 3072, 4096). Default: 2048
- `-h <algo>` - Hash algorithm for signatures (md5, sha1, sha256). Default: sha256
- `-d` - Enable debug mode
- `-x` - Interpret input data as hexadecimal string
- `-v` - Version information
- `--help` or `-h` - Show help message

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

Encrypts the message "Hello World" using a newly generated RSA key pair. The output includes:
- The ciphertext (hexadecimal)
- The public key (modulus n and exponent e) for decryption

### Sign Data

```bash
pkc sign rsa "Message to sign" -h sha256
```

Signs the message using a newly generated RSA key pair with SHA-256 hashing. The output includes:
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

**Note:** Verification with external keys is not yet fully implemented. The current implementation requires the public key to be provided separately.

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


