---
sidebar_position: 1
title: "Common"
---

# Common

Memory, debug, and shared utilities.

## API

### `noxtls_debug_printf`

```c
int noxtls_debug_printf(const char *format, ...);
```

Print formatted debug output (similar to printf)  This function provides a platform-independent way to print formatted debug output. Currently, it wraps the standard printf function, but can be customized for different platforms (e.g., embedded systems, different logging mechanisms).

**Parameters:**

- `format` — Format string (same as printf)
- `...` — Variable arguments (same as printf)

**Returns:** Number of characters printed, or negative value on error

### `noxtls_debug_vprintf`

```c
int noxtls_debug_vprintf(const char *format, va_list args);
```

Print formatted debug output with va_list (similar to vprintf)  This function is the va_list version of noxtls_debug_printf, useful for creating wrapper functions.

**Parameters:**

- `format` — Format string (same as printf)
- `args` — Variable argument list

**Returns:** Number of characters printed, or negative value on error

### `noxtls_mem_init`

```c
noxtls_return_t noxtls_mem_init(uint8_t *buffer, size_t buffer_size);
```

Initialize static buffer memory allocator

**Parameters:**

- `buffer` — Pre-allocated buffer to use (can be NULL to use internal allocation)
- `buffer_size` — Size of the buffer in bytes

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success, error code on failure. Note: If buffer is NULL, an internal buffer of size buffer_size will be allocated. If buffer_size is 0, NOXTLS_STATIC_BUFFER_SIZE will be used.

### `noxtls_mem_cleanup`

```c
noxtls_return_t noxtls_mem_cleanup(void);
```

Cleanup static buffer memory allocator

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success

### `noxtls_malloc`

```c
void *noxtls_malloc(size_t size);
```

Allocate memory

**Parameters:**

- `size` — Number of bytes to allocate

**Returns:** Pointer to allocated memory, or NULL on failure

### `noxtls_free`

```c
void noxtls_free(void *ptr);
```

Free allocated memory

**Parameters:**

- `ptr` — Pointer to memory to free (can be NULL)

### `noxtls_calloc`

```c
void *noxtls_calloc(size_t nmemb, size_t size);
```

Allocate and zero-initialize memory

**Parameters:**

- `nmemb` — Number of elements
- `size` — Size of each element

**Returns:** Pointer to allocated memory, or NULL on failure

### `noxtls_realloc`

```c
void *noxtls_realloc(void *ptr, size_t size);
```

Reallocate memory

**Parameters:**

- `ptr` — Pointer to previously allocated memory (can be NULL)
- `size` — New size in bytes

**Returns:** Pointer to reallocated memory, or NULL on failure

### `noxtls_mem_get_stats`

```c
noxtls_return_t noxtls_mem_get_stats(size_t *total_allocated, size_t *total_used, size_t *max_used);
```

Get memory usage statistics

**Parameters:**

- `total_allocated` — Output: Total bytes allocated
- `total_used` — Output: Total bytes currently in use
- `max_used` — Output: Maximum bytes used at peak

**Returns:** [noxtls_return_t](/docs/api/return_codes): [NOXTLS_RETURN_SUCCESS](/docs/api/return_codes) on success

### `noxtls_hex_string_to_bytes`

```c
int noxtls_hex_string_to_bytes(const char * string, uint8_t * out_buf, uint16_t out_length);
```

Converts a hex string to binary bytes.  Parses a null-terminated string of hex digit pairs (e.g. "0A1B2C") and writes the corresponding byte values into out_buf. No spaces or separators; string length must be even.

**Parameters:**

- `string` — Null-terminated hex string (e.g. "0123456789abcdef").
- `out_buf` — Buffer to receive the converted bytes.
- `out_length` — Maximum number of bytes that out_buf can hold.

**Returns:** On success, the number of bytes written. On error: -1 if string or out_buf is NULL, -2 if out_buf is too small.

### `noxtls_process_string_to_bytes`

```c
int noxtls_process_string_to_bytes(const char* string, uint8_t* bytes);
```

Converts a hex string to bytes with no output length limit.  Same format as noxtls_hex_string_to_bytes: pairs of hex digits, no separators. Caller must ensure bytes points to a buffer large enough for strlen(string)/2 bytes. No bounds check is performed on bytes.

**Parameters:**

- `string` — Null-terminated hex string.
- `bytes` — Buffer to receive the converted bytes (must be pre-allocated).

**Returns:** On success, the number of bytes written. -1 if string or bytes is NULL.

### `noxtls_print_data`

```c
void noxtls_print_data(const uint8_t * data, size_t len);
```

Prints binary data as uppercase hex to the debug output.  Each byte is printed as two hex digits (e.g. "0A1B2C...") followed by a newline. Uses noxtls_debug_printf; no output if data is NULL or len is 0.

**Parameters:**

- `data` — Pointer to the byte buffer to print.
- `len` — Number of bytes to print.

**Returns:** None (void).

