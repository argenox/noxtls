---
sidebar_position: 4
title: Certificate application
description: "NoxTLS Certificate application sample application: build, usage, and command-line options."
---

# Certificate application

Certificate handling utility (GCC/MinGW; may be excluded with MSVC).

Demo application that loads a sample certificate from disk and displays
or processes it. Options: -v version, -h help. Primarily for testing
certificate loading; see cert utility for full CLI operations.

Certificate handling application. Built only with GCC/MinGW (may be excluded with MSVC due to compiler limits).

## Building

From the project root, with a non-MSVC compiler:

```bash
cmake -B build
cmake --build build
```

Target name: `certificate`.

## Examples

certificate
certificate -h
certificate -v

