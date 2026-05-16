---
sidebar_position: 1
title: "AES"
---

# AES

**AES** (Advanced Encryption Standard) is a 128-bit block cipher with 128-, 192-, and 256-bit key sizes. NoxTLS supports ECB, CBC, CTR, CFB, OFB, GCM, CCM, and XTS modes.

## Modes of operation

| Mode | Description |
|------|-------------|
| [**AES - ECB**](/docs/api/aes_ecb) | Electronic Codebook — single-block or deterministic use only |
| [**AES - CBC**](/docs/api/aes_cbc) | Cipher Block Chaining |
| [**AES - CTR**](/docs/api/aes_ctr) | Counter mode (stream) |
| [**AES - CFB**](/docs/api/aes_cfb) | Cipher Feedback (stream) |
| [**AES - OFB**](/docs/api/aes_ofb) | Output Feedback (stream) |
| [**AES - GCM**](/docs/api/aes_gcm) | Galois/Counter Mode (authenticated) |
| [**AES - CCM**](/docs/api/aes_ccm) | Counter with CBC-MAC (authenticated) |
| [**AES - XTS**](/docs/api/aes_xts) | XEX-based tweaked codebook (e.g. disk encryption) |

## Shared API (streaming and types)

For incremental processing and shared types (context, key type, mode enum), see **[AES (shared)](/docs/api/aes_shared)** — `noxtls_aes_init()`, `noxtls_aes_update()`, `noxtls_aes_final()` and common definitions.
