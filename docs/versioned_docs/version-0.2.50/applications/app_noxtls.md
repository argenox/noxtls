---
sidebar_position: 10
title: NoxTLS CLI
description: "NoxTLS NoxTLS CLI sample application: build, usage, and command-line options."
---

# NoxTLS CLI

Unified command-line utility for NoxTLS operations.

The `noxtls` executable combines digest, symmetric encryption/decryption,
public/private key, and X.509 certificate workflows behind one command.

Multi-command command-line utility for NoxTLS operations.

## Building

Built as part of the main project when `BUILD_APPLICATIONS` is ON. Executable name is typically `noxtls`.

## Usage

```text
noxtls [command] <parameters>
```

### Commands

- **dgst** – Message digest generation.
- **enc** – AES encryption.
- **dec** – AES decryption.
- **pkc** / **key** – Public/private key operations.
- **cert** / **x509** – X.509 certificate and private-key file operations.

### Switches

- `-v` – Version
- `-h` – Help

Run a subcommand without parameters or with `--help` to list its supported
algorithms or operations.

## Examples

```bash
noxtls dgst sha256 hello world
noxtls dgst sha3-256 -f firmware.bin
noxtls enc 128 -k 2b7e151628aed2a6abf7158809cf4f3c hello
noxtls dec 128 -k 2b7e151628aed2a6abf7158809cf4f3c -h <ciphertext_hex>
noxtls cert convert -i cert.der -I der -o cert.pem -O pem
noxtls cert convert -i cert.pem -I pem -o cert.der -O der
noxtls pkc genkey rsa -k 2048
noxtls -h
noxtls -v
```
