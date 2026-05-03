MD4 is a 128-bit cryptographic hash (RFC 1320). It is **cryptographically broken** and should not be used for security-sensitive applications; prefer SHA-256, SHA-3, or BLAKE2. This module is provided for compatibility with legacy systems only.

##What is MD4?

MD4 is a cryptographic hash function designed by Ron Rivest in 1990. It produces a 128-bit (16-byte) hash value from input data of arbitrary length.

**Design Goals:**
- Very fast in software
- Simple to implement
- Suitable for 32-bit processors

**How MD4 Works:**
- Processes input in 512-bit message blocks
- Uses 3 rounds of nonlinear functions
- Operates on 32-bit words with addition, rotation, and XOR operations

MD4 was one of the earliest widely-adopted hash functions and influenced later designs such as MD5 and the SHA-1 family.

MD4 is now considered **cryptographically obsolete** and should not be used as it has trivial collision attacks.
It is included in the NoxTLS to maintain compatibility with protocls which may still use it.

You should instead use SHA-256 / SHA-384 or better