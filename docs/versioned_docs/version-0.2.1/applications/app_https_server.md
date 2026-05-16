---
sidebar_position: 9
title: "HTTPS server"
---

# HTTPS server

Simple HTTPS server using the NoxTLS TLS library.

Listens on localhost and serves a simple page over TLS. Parameters: [port] [--cert &lt;cert.pem&gt;] [--key &lt;key.pem&gt;].
Default port 8443, default cert server.crt and key server.key. Options: --help, -h.

Example HTTPS server using the NoxTLS TLS library.

## Building

Built as part of the main project when `BUILD_APPLICATIONS` is ON. Target name: `https_server`.

## Usage

Run the executable; see the source for options (port, certificate, etc.).

## Examples

https_server
https_server 9443
https_server 8443 --cert server.crt --key server.key
https_server --help

