---
sidebar_position: 3
title: "Cert utility"
---

# Cert utility

X.509 certificate parsing and verification utility.

Operations: read, write, info, convert, verify, keyinfo, keywrite, debug, keydebug.
Parameters: operation name then options. Options: -i &lt;file&gt; input, -o &lt;file&gt; output,
-f der|pem format, -d debug, -v version/verbose, -h help.

Certificate parsing and verification utility using NoxTLS cert/X.509 support.

## Building

Built as part of the main project when `BUILD_APPLICATIONS` is ON. Target name: `cert`.

## Usage

Run the executable with certificate file(s) or options. See the source for details.

## Examples

cert read -i cert.der
cert info -i cert.pem
cert convert -i cert.der -o cert.pem -f pem
cert verify -i cert.der
cert keyinfo -i key.pem
cert keywrite -i key.der -o key_out.pem -f pem
cert -h

