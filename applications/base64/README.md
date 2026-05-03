# Base64 Utility

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
