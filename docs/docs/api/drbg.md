---
sidebar_position: 24
title: "DRBG"
---

# DRBG

Deterministic Random Bit Generator (AES-CTR-DRBG) per NIST SP 800-90A. Header: `noxtls_drbg.h`.

## Types

### `drbg_aes_type_t`

DRBG security strength:

- `DRBG_AES128`
- `DRBG_AES192`
- `DRBG_AES256`

### `noxtls_entropy_source_t`

Entropy source selection:

- `NOXTLS_ENTROPY_SOURCE_AUTO`
- `NOXTLS_ENTROPY_SOURCE_WINDOWS_CSPRNG`
- `NOXTLS_ENTROPY_SOURCE_UNIX_URANDOM`
- `NOXTLS_ENTROPY_SOURCE_CUSTOM`
- `NOXTLS_ENTROPY_SOURCE_DUMMY`

### `noxtls_entropy_cb_t`

```c
typedef noxtls_return_t (*noxtls_entropy_cb_t)(uint8_t *entropy_buffer, uint32_t entropy_len);
```

Custom entropy callback type.

### `drbg_state_t`

DRBG runtime state (`V`, `Key`, reseed counter, AES variant, lengths, instantiated flag).

## API

### `drbg_get_entropy`

```c
noxtls_return_t drbg_get_entropy(uint8_t *entropy_buffer, uint32_t entropy_len);
```

Fill buffer with entropy from the configured source.

### `drbg_set_entropy_source`

```c
void drbg_set_entropy_source(noxtls_entropy_source_t source);
```

Select entropy source backend.

### `drbg_get_entropy_source`

```c
noxtls_entropy_source_t drbg_get_entropy_source(void);
```

Get current entropy source backend.

### `drbg_set_entropy_callback`

```c
void drbg_set_entropy_callback(noxtls_entropy_cb_t cb);
```

Set custom entropy callback.

### `drbg_get_entropy_callback`

```c
noxtls_entropy_cb_t drbg_get_entropy_callback(void);
```

Get custom entropy callback.

### `drbg_instantiate`

```c
noxtls_return_t drbg_instantiate(drbg_state_t *state,
                                 drbg_aes_type_t aes_type,
                                 const uint8_t *entropy_input,
                                 uint32_t entropy_len,
                                 const uint8_t *nonce,
                                 uint32_t nonce_len,
                                 const uint8_t *personalization_string,
                                 uint32_t pers_len);
```

Instantiate DRBG state. Entropy/nonce/personalization inputs are optional depending on the calling model.

### `drbg_generate`

```c
noxtls_return_t drbg_generate(drbg_state_t *state,
                              uint8_t *output_buffer,
                              uint32_t requested_bits,
                              const uint8_t *additional_input,
                              uint32_t add_input_len);
```

Generate pseudo-random output bits. Additional input is optional.

### `drbg_reseed`

```c
noxtls_return_t drbg_reseed(drbg_state_t *state,
                            const uint8_t *entropy_input,
                            uint32_t entropy_len,
                            const uint8_t *additional_input,
                            uint32_t add_input_len);
```

Reseed DRBG state.

### `drbg_update`

```c
noxtls_return_t drbg_update(drbg_state_t *state,
                            const uint8_t *provided_data,
                            uint32_t provided_data_len);
```

Update DRBG internal state with provided data.

### `drbg_uninstantiate`

```c
noxtls_return_t drbg_uninstantiate(drbg_state_t *state);
```

Clear DRBG state and mark uninstantiated.

