---
sidebar_position: 15
title: "Noxcrypt Utility"
---

# Noxcrypt Utility

Command-style CLI utility under `applications/noxcrypt/`.

## Purpose

- Provides a top-level `noxcrypt` command dispatcher.
- Currently exposes `dgst` (message digest generation).

## Source

- `applications/noxcrypt/main.c`
- `applications/noxcrypt/message_digest.c`

## Usage (current)

```bash
noxcrypt dgst <ALGORITHM> [options] <data>
```

Examples of supported digest names in current source: `MD5`, `SHA1`, `SHA224`, `SHA256`, `SHA384`, `SHA512`, `SHA512_224`, `SHA512_256`.

