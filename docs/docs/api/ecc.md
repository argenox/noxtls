---
sidebar_position: 26
title: "ECC (Elliptic curve crypto)"
---

# ECC (Elliptic curve crypto)

Elliptic curve cryptography: curves, points, keys, ECDH, ECDSA, and supporting bignum API.

## Algorithm overview

ECC uses arithmetic on elliptic curves over finite fields to provide public-key operations with smaller keys than classic finite-field or RSA systems. This module covers curve/key primitives and underpins ECDH key agreement and ECDSA signatures.

## Pros and cons

**Pros**

- Strong security-per-bit with compact keys/signatures.
- Typically faster than RSA/FFDHE at comparable security levels.
- Widely used in TLS and modern authentication stacks.

**Cons**

- Implementation complexity is higher than many symmetric primitives.
- Curve and parameter choices matter; weak/custom choices can create risk.
- Side-channel hardening and constant-time behavior are critical.

## When to use

- Use for modern public-key cryptography where performance and size matter.
- Good default for key exchange and signatures in network protocols.
- Prefer well-known curves and vetted parameter sets.

## Types

### ecc_curve_params_t

Opaque ECC curve parameters (prime, order, generator, etc.). Initialized with [noxtls_ecc_curve_init](#noxtls_ecc_curve_init), freed with [noxtls_ecc_curve_free](#noxtls_ecc_curve_free). Pass to point and key operations.

### ecc_point_t

ECC point (affine x, y or equivalent). Used for public keys and intermediate results. Initialized with [noxtls_ecc_point_init](#noxtls_ecc_point_init).

### ecc_key_t

ECC key pair (private scalar and public point). Initialized with [noxtls_ecc_key_init](#noxtls_ecc_key_init), generated with [noxtls_ecc_key_generate](#noxtls_ecc_key_generate), freed with [noxtls_ecc_key_free](#noxtls_ecc_key_free).

### ecc_curve_t

Enumeration of supported ECC curves (e.g. SECP256R1, SECP384R1). Used when initializing [ecc_curve_params_t](#ecc_curve_params_t) or [ecc_key_t](#ecc_key_t).

### ecdsa_signature_t

ECDSA signature (r, s). Initialized with [noxtls_ecdsa_signature_init](#noxtls_ecdsa_signature_init), freed with [noxtls_ecdsa_signature_free](#noxtls_ecdsa_signature_free).

## API

### `noxtls_ecc_curve_init`

```c
noxtls_return_t noxtls_ecc_curve_init(ecc_curve_params_t *curve, ecc_curve_t curve_type);
```

Initialize ECC curve parameters

**Parameters:**

- `curve` — [ecc_curve_params_t](#ecc_curve_params_t) to initialize
- `curve_type` — [ecc_curve_t](#ecc_curve_t): curve identifier

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success, [NOXTLS_RETURN_NULL](/docs/api/return_codes) if curve is NULL

### `noxtls_ecc_curve_free`

```c
noxtls_return_t noxtls_ecc_curve_free(ecc_curve_params_t *curve);
```

Free ECC curve parameters

**Parameters:**

- `curve` — [ecc_curve_params_t](#ecc_curve_params_t) to free

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success, [NOXTLS_RETURN_NULL](/docs/api/return_codes) if curve is NULL

### `noxtls_ecc_point_init`

```c
noxtls_return_t noxtls_ecc_point_init(ecc_point_t *point, uint32_t size);
```

Initialize ECC point

**Parameters:**

- `point` — [ecc_point_t](#ecc_point_t) to initialize
- `size` — Size of the point (coordinate size in bytes)

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success, [NOXTLS_RETURN_NULL](/docs/api/return_codes) if point is NULL

### `noxtls_ecc_point_add`

```c
noxtls_return_t noxtls_ecc_point_add(ecc_point_t *result, const ecc_point_t *p1, const ecc_point_t *p2, const ecc_curve_params_t *curve);
```

Add two points on the selected curve.

### `noxtls_ecc_point_double`

```c
noxtls_return_t noxtls_ecc_point_double(ecc_point_t *result, ecc_point_t *p, ecc_curve_params_t *curve);
```

Double a point on the selected curve.

### `noxtls_ecc_point_multiply`

```c
noxtls_return_t noxtls_ecc_point_multiply(ecc_point_t *result, const uint8_t *scalar, const ecc_point_t *point, const ecc_curve_params_t *curve);
```

Scalar multiplication (`result = scalar * point`).

### `noxtls_ecc_point_is_on_curve`

```c
noxtls_return_t noxtls_ecc_point_is_on_curve(const ecc_point_t *point, const ecc_curve_params_t *curve);
```

Validate that a point lies on the selected curve.

### `noxtls_ecc_point_multiply_uses_ref`

```c
int noxtls_ecc_point_multiply_uses_ref(void);
```

Return whether point multiplication currently uses a reference implementation path.

### `noxtls_ecc_point_mul_window_size`

```c
int noxtls_ecc_point_mul_window_size(void);
```

Return configured point-multiplication window size (`0` means ladder-only).

### `noxtls_ecc_key_init`

```c
noxtls_return_t noxtls_ecc_key_init(ecc_key_t *key, ecc_curve_t curve_type);
```

Initialize ECC key

**Parameters:**

- `key` — [ecc_key_t](#ecc_key_t) to initialize
- `curve_type` — [ecc_curve_t](#ecc_curve_t)

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success, [NOXTLS_RETURN_NULL](/docs/api/return_codes) if key is NULL

### `noxtls_ecc_key_generate`

```c
noxtls_return_t noxtls_ecc_key_generate(ecc_key_t *key, ecc_curve_t curve_type);
```

Generate ECC key pair  Generates a random private key d in range [1, n-1] using DRBG, then computes the public key Q = d G

**Parameters:**

- `key` — [ecc_key_t](#ecc_key_t) to initialize
- `curve_type` — [ecc_curve_t](#ecc_curve_t)

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success, [NOXTLS_RETURN_NULL](/docs/api/return_codes) if key is NULL

### `noxtls_ecc_key_free`

```c
noxtls_return_t noxtls_ecc_key_free(ecc_key_t *key);
```

Free ECC key

**Parameters:**

- `key` — [ecc_key_t](#ecc_key_t) to free

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success, [NOXTLS_RETURN_NULL](/docs/api/return_codes) if key is NULL

### `noxtls_ecdh_compute_shared_secret`

```c
noxtls_return_t noxtls_ecdh_compute_shared_secret(ecc_key_t *private_key, const ecc_point_t *peer_public_key, uint8_t *shared_secret, uint32_t *shared_secret_len);
```

ECDH Compute Shared Secret  Computes the shared secret from our private key and peer's public key. Shared secret = d Q_peer, where d is our private key and Q_peer is peer's public point.

**Parameters:**

- `private_key` — Our private key
- `peer_public_key` — Peer's public key point
- `shared_secret` — Output buffer for shared secret
- `shared_secret_len` — Input: buffer size, Output: actual shared secret length

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success

### `noxtls_ecdsa_signature_init`

```c
noxtls_return_t noxtls_ecdsa_signature_init(ecdsa_signature_t *sig, uint32_t size);
```

Initialize ECDSA signature structure

**Parameters:**

- `sig` — [ecdsa_signature_t](#ecdsa_signature_t)
- `size` — Size of the signature

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success, [NOXTLS_RETURN_NULL](/docs/api/return_codes) if sig is NULL

### `noxtls_ecdsa_signature_free`

```c
noxtls_return_t noxtls_ecdsa_signature_free(ecdsa_signature_t *sig);
```

Free ECDSA signature structure

**Parameters:**

- `sig` — [ecdsa_signature_t](#ecdsa_signature_t)

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success, [NOXTLS_RETURN_NULL](/docs/api/return_codes) if sig is NULL

### `noxtls_ecdsa_signature_parse_der`

```c
noxtls_return_t noxtls_ecdsa_signature_parse_der(const uint8_t *der, uint32_t der_len, ecdsa_signature_t *out, uint32_t coord_size);
```

Parse DER-encoded ECDSA signature (SEQUENCE of two INTEGERs r, s) into ecdsa_signature_t

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success.

### `noxtls_ecdsa_sign`

```c
noxtls_return_t noxtls_ecdsa_sign(ecc_key_t *key, const uint8_t *message, uint32_t message_len, ecdsa_signature_t *signature, noxtls_hash_algos_t hash_algo);
```

ECDSA Signature Generation  Algorithm: 1. Hash the message: h = HASH(message) 2. Generate random nonce k in [1, n-1] 3. Compute (x, y) = k G 4. r = x mod n (if r == 0, go to step 2) 5. s = k^-1 (h + r d) mod n (if s == 0, go to step 2) 6. Signature is (r, s)

**Parameters:**

- `key` — [ecc_key_t](#ecc_key_t)
- `message` — Message to sign
- `message_len` — Length of the message
- `signature` — [ecdsa_signature_t](#ecdsa_signature_t)
- `hash_algo` — [noxtls_hash_algos_t](/docs/api/hash#noxtls_hash_algos_t)

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success, [NOXTLS_RETURN_NULL](/docs/api/return_codes) if key is NULL

### `noxtls_ecdsa_verify`

```c
noxtls_return_t noxtls_ecdsa_verify(ecc_key_t *key, const uint8_t *message, uint32_t message_len, const ecdsa_signature_t *signature, noxtls_hash_algos_t hash_algo);
```

ECDSA Signature Verification  Algorithm: 1. Verify r and s are in [1, n-1] 2. Hash the message: h = HASH(message) 3. u1 = s^-1 h mod n 4. u2 = s^-1 r mod n 5. Compute (x, y) = u1 G + u2 Q 6. v = x mod n 7. Accept if v == r

**Parameters:**

- `key` — [ecc_key_t](#ecc_key_t)
- `message` — Message to verify
- `message_len` — Length of the message
- `signature` — [ecdsa_signature_t](#ecdsa_signature_t)
- `hash_algo` — [noxtls_hash_algos_t](/docs/api/hash#noxtls_hash_algos_t)

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success, [NOXTLS_RETURN_NULL](/docs/api/return_codes) if key is NULL

## Bignum (for ECC)

Low-level big-integer helpers used by ECC operations. Big-endian byte arrays.

### `noxtls_bn_cmp`

```c
int noxtls_bn_cmp(const uint8_t *a, const uint8_t *b, uint32_t len);
```

Compare two big integers (byte arrays, big-endian)

**Parameters:**

- `a` — First big integer
- `b` — Second big integer
- `len` — Length of the big integers

**Returns:** int 1 if a &gt; b, -1 if a &lt; b, 0 if a == b

### `noxtls_bn_is_zero`

```c
int noxtls_bn_is_zero(const uint8_t *a, uint32_t len);
```

Check if big integer is zero

**Parameters:**

- `a` — Big integer
- `len` — Length of the big integer

**Returns:** int 1 if the big integer is zero, 0 otherwise

### `noxtls_bn_is_one`

```c
int noxtls_bn_is_one(const uint8_t *a, uint32_t len);
```

Check if big integer is one

**Parameters:**

- `a` — Big integer
- `len` — Length of the big integer

**Returns:** int 1 if the big integer is one, 0 otherwise

### `noxtls_bn_copy`

```c
noxtls_return_t noxtls_bn_copy(uint8_t *dst, const uint8_t *src, uint32_t len);
```

Copy big integer

**Parameters:**

- `dst` — Destination big integer
- `src` — Source big integer
- `len` — Length of the big integer

### `noxtls_bn_add`

```c
noxtls_return_t noxtls_bn_add(uint8_t *result, const uint8_t *a, const uint8_t *b, uint32_t len);
```

Add two big integers: result = a + b

**Parameters:**

- `result` — Result big integer
- `a` — First big integer
- `b` — Second big integer
- `len` — Length of the big integers

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success.

### `noxtls_bn_sub`

```c
noxtls_return_t noxtls_bn_sub(uint8_t *result, const uint8_t *a, const uint8_t *b, uint32_t len);
```

Subtract two big integers: result = a - b (assumes a &gt;= b)

**Parameters:**

- `result` — Result big integer
- `a` — First big integer
- `b` — Second big integer
- `len` — Length of the big integers

### `noxtls_bn_mul`

```c
noxtls_return_t noxtls_bn_mul(uint8_t *result, const uint8_t *a, uint32_t a_len, const uint8_t *b, uint32_t b_len);
```

Multiply two big integers: result = a b (limb-based schoolbook)  Uses 32-bit limbs and 64-bit multiply-accumulate (MULADDC-style). Converts BE bytes to LE limbs, runs one pass per limb of b (multiply a by b[i], add into result at offset i), then converts result limbs back to BE bytes.

**Parameters:**

- `result` — Result big integer (a_len + b_len bytes, big-endian)
- `a` — First big integer (big-endian)
- `a_len` — Length of the first big integer
- `b` — Second big integer (big-endian)
- `b_len` — Length of the second big integer

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success.

### `noxtls_bn_rshift1`

```c
noxtls_return_t noxtls_bn_rshift1(uint8_t *a, uint32_t len);
```

Right shift big integer by one bit (divide by 2)

**Parameters:**

- `a` — Big integer
- `len` — Length of the big integer

### `noxtls_bn_mod`

```c
noxtls_return_t noxtls_bn_mod(uint8_t *result, const uint8_t *a, uint32_t a_len, const uint8_t *mod, uint32_t mod_len);
```

Modulus operation: result = a mod mod

**Parameters:**

- `result` — Result big integer
- `a` — First big integer
- `a_len` — Length of the first big integer
- `mod` — Modulus big integer
- `mod_len` — Length of the modulus big integer

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success.

### `noxtls_bn_mod_exp`

```c
noxtls_return_t noxtls_bn_mod_exp(uint8_t *result, const uint8_t *base, const uint8_t *exp, uint32_t exp_len, const uint8_t *mod, uint32_t mod_len);
```

Modular exponentiation: result = base ^ exp mod mod

**Parameters:**

- `result` — Result big integer
- `base` — Base big integer
- `exp` — Exponent big integer
- `exp_len` — Length of the exponent big integer
- `mod` — Modulus big integer
- `mod_len` — Length of the modulus big integer

### `noxtls_bn_mod_inv`

```c
noxtls_return_t noxtls_bn_mod_inv(uint8_t *result, const uint8_t *a, uint32_t a_len, const uint8_t *m, uint32_t m_len);
```

Binary Extended Euclidean Algorithm: compute a^-1 mod m (much faster - no division!)

**Parameters:**

- `result` — Result big integer
- `a` — First big integer
- `a_len` — Length of the first big integer
- `m` — Modulus big integer
- `m_len` — Length of the modulus big integer

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success.
