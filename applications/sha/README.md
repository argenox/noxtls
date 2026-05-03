## Building

Built as part of the main project when `BUILD_APPLICATIONS` is ON. Target name: `sha` (or similar per CMake).

## Usage

```text
sha [command] [options] [arguments]
```

- **Top-level command:** `dgst` — compute a message digest.
- **Global options:** `-h` (help), `-v` (version).

## Command: dgst

Compute a hash using one of the supported algorithms.

```text
sha dgst <algorithm> [options] <input>
```

### Algorithms

MD5, SHA1, SHA224, SHA256, SHA384, SHA512, SHA512_224, SHA512_256.

### Options

| Option | Description |
|--------|-------------|
| `-h`   | Input is hex-encoded (decode before hashing). |
| `-d`   | Enable debug output. |

### Examples

Hash a string (default is string input):

```bash
sha dgst SHA256 hello world
```

Hash from hex input (use `-h` and pass hex string):

```bash
sha dgst SHA256 -h 68656c6c6f
```

Show help and version:

```bash
sha -h
sha -v
```
