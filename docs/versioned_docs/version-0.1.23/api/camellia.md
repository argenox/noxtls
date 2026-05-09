---
sidebar_position: 18
title: "Camellia"
---

# Camellia

**Camellia** is a 128-bit block cipher with 128-, 192-, and 256-bit key sizes (NTT/Mitsubishi, ISO/IEC, NESSIE, CRYPTREC). Use it in a mode of operation for multi-block data; key and IV rules match AES in the same mode.

**Prefer AES** unless Camellia is required by protocol or deployment.

## Modes of operation

| Mode | Description |
|------|-------------|
| [**Camellia - ECB**](/docs/api/camellia_ecb) | Electronic Codebook — single-block or deterministic use only |
| [**Camellia - CBC**](/docs/api/camellia_cbc) | Cipher Block Chaining |
| [**Camellia - CTR**](/docs/api/camellia_ctr) | Counter mode (stream) |
| [**Camellia - CFB**](/docs/api/camellia_cfb) | Cipher Feedback (stream) |
| [**Camellia - OFB**](/docs/api/camellia_ofb) | Output Feedback (stream) |

## Shared API (streaming and types)

For incremental processing, one-shot encrypt/decrypt, shared types (context, key type, mode enum), and self-test, see **[Camellia (shared)](/docs/api/camellia_shared)** — `camellia_init()`, `camellia_update()`, `camellia_final()`, `camellia_encrypt_data()`, `camellia_decrypt_data()`, and common definitions.
