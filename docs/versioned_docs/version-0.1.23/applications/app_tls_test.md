---
sidebar_position: 14
title: "TLS test"
---

# TLS test

TLS test client — handshake and encryption/decryption verification.

In-process test: creates TLS server and client, connects via callbacks,
performs handshake and verifies encryption/decryption. No command-line
parameters required; run from project or build directory.

TLS test client for exercising the NoxTLS TLS stack.

## Building

Built as part of the main project when `BUILD_APPLICATIONS` is ON. Target name: `tls_test`.

## Usage

Run the executable with the target host/port. See the source for options and usage.

## Examples

tls_test

