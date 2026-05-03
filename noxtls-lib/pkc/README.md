# Public Key Cryptography (PKC)

This directory contains implementations of public key (asymmetric) cryptography algorithms.

## Structure

- `rsa/` - RSA (Rivest-Shamir-Adleman) public key cryptography
- `ecc/` - Elliptic Curve Cryptography base implementations
- `ecdsa/` - Elliptic Curve Digital Signature Algorithm
- `ecdh/` - Elliptic Curve Diffie-Hellman key exchange

## Algorithms

### RSA
- Key generation
- Encryption/Decryption
- Digital signatures
- Key sizes: 1024, 2048, 4096 bits

### ECC (Elliptic Curve Cryptography)
- Curve implementations (P-256, P-384, P-521, etc.)
- Point operations
- Scalar multiplication

### ECDSA (Elliptic Curve Digital Signature Algorithm)
- Signature generation
- Signature verification
- Various curve support

### ECDH (Elliptic Curve Diffie-Hellman)
- Key exchange protocol
- Shared secret generation

## Dependencies

- `mdigest` - For hash functions used in signatures
- `common` - Common utilities and definitions


