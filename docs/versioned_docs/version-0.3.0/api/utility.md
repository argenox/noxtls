---
sidebar_position: 28
title: Utility
description: "NoxTLS Utility C API reference for embedded TLS, DTLS, and cryptography."
---

# Utility

Base64, file I/O.

:::note 0.3.0
Text and file-name parameters are `uint8_t` instead of `char` (MISRA C:2025). The file helpers need host stdio: when the library is built with `NOXTLS_HAVE_FILE_IO=0`, `noxtls_load_file()`, `noxtls_load_text_file()`, `noxtls_write_file()`, and `noxtls_write_text_file()` are compiled as stubs that return a failure. See [MISRA C:2025](../misra-c.md#host-stdio-is-opt-in).
:::

## API

### `noxtls_base64_encode`

```c
int32_t noxtls_base64_encode(const uint8_t * input, uint32_t len, uint8_t * output);
```

Encodes data in Base64

**Parameters:**

- `input` — is the input data
- `len` — is the length of the input data
- `output` — is a pointer to the buffer where Base64 data will be placed

**Returns:** number of bytes encoded, negative error otherwise

### `noxtls_base64_decode`

```c
int32_t noxtls_base64_decode(const uint8_t * input, uint32_t len, uint8_t * output);
```

Decodes Base64 data

**Parameters:**

- `input` — is the Base64 data
- `len` — is the length of the input data
- `output` — is a pointer to the buffer for the decoded data

**Returns:** number of bytes decoded, negative error otherwise

### `noxtls_base64_decode_char`

```c
uint8_t noxtls_base64_decode_char(uint8_t c);
```

Decodes Base64 character to value

**Parameters:**

- `base64` — Character to decode

**Returns:** value decoded

### `noxtls_load_file`

```c
int noxtls_load_file(const uint8_t * filename, uint8_t ** buffer);
```

Loads a binary file into a buffer

**Parameters:**

- `filename` — is the name of the file to create
- `buffer` — is a pointer to the data to write
- `len` — is the length of the output buffer

**Returns:** on success, number of bytes written, otherwise negative error

### `noxtls_load_text_file`

```c
int noxtls_load_text_file(const uint8_t * filename, uint8_t ** buffer);
```

Loads a binary file into a buffer

**Parameters:**

- `filename` — is the name of the file to create
- `buffer` — is a pointer to the data to write
- `len` — is the length of the output buffer

**Returns:** on success, number of bytes written, otherwise negative error

### `noxtls_write_text_file`

```c
int noxtls_write_text_file(const uint8_t * filename, const uint8_t * buffer, uint32_t len);
```

Creates a new file and writes string data

**Parameters:**

- `filename` — is the name of the file to create
- `buffer` — is a pointer to the data to write
- `len` — is the length of the output buffer

**Returns:** on success, number of bytes written, otherwise negative error

### `noxtls_write_file`

```c
int noxtls_write_file(const uint8_t * filename, const uint8_t * buffer, uint32_t len);
```

Creates a new file and writes binary data

**Parameters:**

- `filename` — is the name of the file to create
- `buffer` — is a pointer to the data to write
- `len` — is the length of the output buffer

**Returns:** on success, number of bytes written, otherwise negative error

