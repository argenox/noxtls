# NoxTLS CLI

Multi-command command-line utility for NoxTLS operations.

## Building

Built as part of the main project when `BUILD_APPLICATIONS` is ON. Executable name is typically `noxtls`.

## Usage

```text
noxtls [command] <parameters>
```

### Commands

- **dgst** – Message digest (hash) generation (SHA, MD5, etc.)

### Switches

- `-v` – Version
- `-h` – Help

Example: `noxtls dgst -sha256 file.bin`
