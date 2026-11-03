---
sidebar_position: 8
title: HTTPS client
description: "NoxTLS HTTPS client sample application: build, usage, and command-line options."
---

# HTTPS client

Simple HTTPS client using the NoxTLS TLS library.

Parameters: URL (e.g. https://example.com/), optional port, optional tls12|tls13|auto,
optional keylog or tlsdump path. Port overrides URL port; tls12/tls13/auto selects TLS version.

Example HTTPS client using the NoxTLS TLS library.

## Building

Built as part of the main project when `BUILD_APPLICATIONS` is ON. Target name: `https_client`.

## Usage

Run the executable with the target URL. See the source for command-line options and usage.

## Examples

https_client https://example.com/
https_client https://example.com/ 443
https_client https://example.com/ 443 tls13
https_client https://example.com/ tls12
https_client https://example.com/ 443 tls13 keylog=/tmp/keylog.txt


## Exit status

The client exits with status 1 when the response is not ended by an authenticated `close_notify` (transport EOF, a record that fails authentication, or a fatal alert), because the printed response may then be truncated or forged.
