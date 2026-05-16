## Building

Built as part of the main project when `BUILD_APPLICATIONS` is ON. Target name: `sha` (or similar per CMake).

## Usage

```text
sha <algorithm> [options] [text...]
sha <algorithm> -f <file> [options]
```

- **Global options:** `-h` (help), `-v` (version).

## Digest Command

Compute a hash using one of the supported algorithms.

```text
sha <algorithm> [options] <input>
```

### Algorithms

The enabled algorithms are shown by `sha -h`. Typical builds include MD5,
SHA1, SHA224, SHA256, SHA384, SHA512, SHA512-224, SHA512-256, SHA3,
SHA3-224, SHA3-256, SHA3-384, SHA3-512, RIPEMD160, BLAKE2S-256, and
BLAKE2B-512. MD4 is shown only when the MD4 feature is enabled.

### Options

| Option | Description |
|--------|-------------|
| `-f`   | Read input from a file. |
| `-o`   | Write the hex digest to a file. |
| `-s`   | Start hashing file input at a byte offset. |
| `-h`   | Input is hex-encoded (decode before hashing). |
| `-d`   | Enable debug output. |

### Examples

Hash a string (default is string input):

```bash
sha SHA256 hello world
```

Hash from hex input (use `-h` and pass hex string):

```bash
sha SHA256 -h 68656c6c6f
```

Hash a file:

```bash
sha SHA3-256 -f firmware.bin
```

Show help and version:

```bash
sha -h
sha -v
```
