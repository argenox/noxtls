---
sidebar_position: 28
title: "DSA"
---

# DSA

Digital Signature Algorithm (DSA) per FIPS 186-4: key management, signing, and verification.

## Types

### dsa_key_t

DSA domain parameters and key. Holds prime modulus **p**, prime order **q**, generator **g**, public key **y**, and optional private key **x**. Initialized with [noxtls_dsa_key_init](#noxtls_dsa_key_init), freed with [noxtls_dsa_key_free](#noxtls_dsa_key_free). For verification-only, **x** may be left unset (or set to zero); **y** must be set with [noxtls_dsa_key_set_public](#noxtls_dsa_key_set_public).

### dsa_signature_t

DSA signature **(r, s)**. **r** and **s** are each **q_len** bytes (big-endian). Initialized with [noxtls_dsa_signature_init](#noxtls_dsa_signature_init), cleared with [noxtls_dsa_signature_free](#noxtls_dsa_signature_free).

### Constants

- **DSA_MAX_Q_BYTES** — Maximum length of **q** (and of **r**, **s**) in bytes (32 for 256-bit q).
- **DSA_MAX_P_BYTES** — Maximum length of **p** (and **g**, **y**) in bytes (384 for 3072-bit p).

## API

### `noxtls_dsa_key_init`

```c
noxtls_return_t noxtls_dsa_key_init(dsa_key_t *key, const uint8_t *p, uint32_t p_len, const uint8_t *q, uint32_t q_len, const uint8_t *g, uint32_t g_len);
```

Initialize DSA key with domain parameters **p**, **q**, **g** (all big-endian). Copies parameters into **key** and allocates storage for **y** and **x**. **g_len** must equal **p_len**.

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success.

### `noxtls_dsa_key_set_public`

```c
noxtls_return_t noxtls_dsa_key_set_public(dsa_key_t *key, const uint8_t *y);
```

Set the public key **y** (**p_len** bytes, big-endian). Use for verification-only keys.

### `noxtls_dsa_key_set_private`

```c
noxtls_return_t noxtls_dsa_key_set_private(dsa_key_t *key, const uint8_t *x);
```

Set the private key **x** (**q_len** bytes, big-endian). Required for signing.

### `noxtls_dsa_key_generate`

```c
noxtls_return_t noxtls_dsa_key_generate(dsa_key_t *key);
```

Generate a random private key **x** in [1, q−1] and compute **y = g^x mod p**. Domain parameters **p**, **q**, **g** must already be set (e.g. via [noxtls_dsa_key_init](#noxtls_dsa_key_init)).

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success.

### `noxtls_dsa_key_free`

```c
noxtls_return_t noxtls_dsa_key_free(dsa_key_t *key);
```

Free storage held by **key**. **key** is a [dsa_key_t](#dsa_key_t).

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success.

### `noxtls_dsa_signature_init`

```c
noxtls_return_t noxtls_dsa_signature_init(dsa_signature_t *sig, uint32_t q_len);
```

Initialize signature structure for the given **q_len** (subgroup size in bytes).

### `noxtls_dsa_signature_free`

```c
noxtls_return_t noxtls_dsa_signature_free(dsa_signature_t *sig);
```

Clear sensitive fields of **sig**.

### `noxtls_dsa_sign`

```c
noxtls_return_t noxtls_dsa_sign(const dsa_key_t *key, const uint8_t *message, uint32_t message_len, dsa_signature_t *signature, noxtls_hash_algos_t hash_algo);
```

Compute DSA signature **(r, s)** of **message** using **key** (must have private **x**) and **hash_algo**. Supported hashes: MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512. The hash is truncated to **q_len** bytes (leftmost bits) per FIPS 186-4.

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success.

### `noxtls_dsa_verify`

```c
noxtls_return_t noxtls_dsa_verify(const dsa_key_t *key, const uint8_t *message, uint32_t message_len, const dsa_signature_t *signature, noxtls_hash_algos_t hash_algo);
```

Verify DSA **signature** over **message** using **key** (must have public **y**) and **hash_algo**.

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) if the signature is valid, [NOXTLS_RETURN_FAILED](/docs/api/return_codes) otherwise.
