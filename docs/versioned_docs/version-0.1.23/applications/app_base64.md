---
sidebar_position: 2
title: "Base64 utility"
---

# Base64 utility

Base64 encode/decode command-line utility.

Encode strings or hex to Base64, or decode Base64 to hex.
Parameters: one switch (-s, -x, -d, -D) then input as needed.
Options:
  -s    Encode string to Base64
  -x    Encode hex to Base64
  -d    Decode Base64 to hex (lowercase)
  -D    Decode Base64 to hex (uppercase)
  -v    Version
  -h    Help

Command-line tool for Base64 encoding and decoding using the NoxTLS library.

## Building

Built as part of the main project when `BUILD_APPLICATIONS` is ON:

```bash
cmake -B build
cmake --build build
# Executable: build/applications/base64/base64 (or base64.exe on Windows)
```

## Usage

- **Encode string to Base64:** `base64 -s "Hello World"`
- **Encode hex to Base64:** `base64 -x <hex_string>`
- **Decode Base64:** `base64 -d` or `base64 -D` (decode to hex)
- **Help:** `base64 -h`
- **Version:** `base64 -v`

See the source and Doxygen comments for full option details.

## Examples

Encode a string:
  base64 -s "Hello World"
Encode hex to Base64:
  base64 -x 48656c6c6f
Decode Base64:
  base64 -d SGVsbG8=
  base64 -h

