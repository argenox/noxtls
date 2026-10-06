---
sidebar_position: 1
title: Common
description: "NoxTLS Common C API reference for embedded TLS, DTLS, and cryptography."
---

# Common

Memory, debug, and shared utilities.

## API

### `noxtls_debug_printf`

```c
int noxtls_debug_printf(const uint8_t *format, ...);
```

Print formatted debug output (similar to printf).

**Since 0.3.0 debug output is off by default.** Unless the library is configured with the CMake option `-DNOXTLS_DEBUG_PRINTF_STDIO=ON`, `noxtls_debug_printf()` is a macro that evaluates to `0`, so library debug output uses neither stdio nor `stdarg` (MISRA C:2025 Rules 17.1 and 21.6). With the option enabled, a stdio/`stdarg` implementation is compiled. The format string is `const uint8_t *`. See [MISRA C:2025](../misra-c.md#host-stdio-is-opt-in).

**Parameters:**

- `format` — Format string (same as printf)
- `...` — Variable arguments (same as printf)

**Returns:** Number of characters printed, or negative value on error

### `noxtls_debug_vprintf`

```c
int noxtls_debug_vprintf(const uint8_t *format, va_list args);
```

Print formatted debug output with va_list (similar to vprintf). Useful for creating wrapper functions. Declared only when the library is built with `NOXTLS_DEBUG_PRINTF_STDIO=ON`.

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

### `noxtls_mem_get_last_error`

```c
noxtls_return_t noxtls_mem_get_last_error(noxtls_mem_error_info_t *info);
void noxtls_mem_clear_last_error(void);
```

Query or clear the most recent allocation failure. The diagnostic reports the
allocation operation and failure reason, requested bytes, source file/function/line,
allocator mode, pool capacity and usage, largest available payload block, and the
minimum additional contiguous payload capacity required. System allocators report
sizes they cannot determine as `NOXTLS_MEM_SIZE_UNKNOWN`.

The saved error is not cleared by a later successful allocation. Call
`noxtls_mem_clear_last_error()` when beginning an operation if only failures from
that operation are relevant. The record is module-wide rather than per-thread.

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
int noxtls_hex_string_to_bytes(const uint8_t * string, uint8_t * out_buf, size_t out_length);
```

Converts a hex string to binary bytes.  Parses a null-terminated string of hex digit pairs (e.g. "0A1B2C") and writes the corresponding byte values into out_buf. No spaces or separators; string length must be even.

**Parameters:**

- `string` — Null-terminated hex string (e.g. "0123456789abcdef").
- `out_buf` — Buffer to receive the converted bytes.
- `out_length` — Maximum number of bytes that out_buf can hold.

**Returns:** On success, the number of bytes written. On error: `-1` if string or out_buf is NULL, `-2` if out_buf is too small, `-3` for odd-length input.

### `noxtls_print_data`

```c
void noxtls_print_data(const uint8_t * data, size_t len);
```

Prints binary data as uppercase hex to the debug output.  Each byte is printed as two hex digits (e.g. "0A1B2C...") followed by a newline. Uses noxtls_debug_printf; no output if data is NULL or len is 0.

**Parameters:**

- `data` — Pointer to the byte buffer to print.
- `len` — Number of bytes to print.

**Returns:** None (void).

## Bounded byte and text helpers (`noxtls_ct.h`)

New in 0.3.0. The library uses these helpers internally instead of `memcpy`/`memset`/`memmove` and the libc string functions (MISRA C:2025 Rule 21.18 and Directive 1.1). You can also call them from application code.

```c
void noxtls_copy_u8(uint8_t *dst, size_t dst_cap, const uint8_t *src, size_t n); /* non-overlapping copy */
void noxtls_move_u8(uint8_t *dst, size_t dst_cap, const uint8_t *src, size_t n); /* overlap-safe (memmove semantics) */
void noxtls_fill_u8(uint8_t *dst, size_t dst_cap, uint8_t fill_byte, size_t n);

size_t noxtls_u8_strlen(const uint8_t *s);
int noxtls_u8_strcmp(const uint8_t *a, const uint8_t *b);
int noxtls_u8_strncmp(const uint8_t *a, const uint8_t *b, size_t n);
```

- The copy, move, and fill helpers write `min(n, dst_cap)` bytes. A destination that is too small is **truncated silently**, so validate lengths before calling when truncation would be an error.
- The `noxtls_u8_str*` functions operate on NUL-terminated `uint8_t` text, the type used by the 0.3.0 text APIs (hostnames, SNI, ALPN, paths, DN strings).
- To erase secrets, use `noxtls_secure_zero(ptr, len)`, which the compiler cannot elide, not `noxtls_fill_u8()`.
