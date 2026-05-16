---
sidebar_position: 10
title: "NoxTLS CLI"
---

# NoxTLS CLI

Multi-command NoxTLS CLI (e.g. message digest).

Unified CLI with subcommands. Command: dgst — message digest (same as sha app).
Parameters: command then algorithm/options/input. Options: -v version, -h help.

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

## Examples

noxtls dgst SHA256 hello world
noxtls dgst MD5 -h 48656c6c6f
noxtls -h
noxtls -v

