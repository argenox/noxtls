# NoxTLS Applications

Command-line utilities and demos built on the NoxTLS library. They are built when `BUILD_APPLICATIONS` is ON (default).

## Building

From the repository root:

```bash
cmake -B build -D BUILD_TESTS=OFF
cmake --build build
```

To build only the library and skip all applications:

```bash
cmake -B build -D BUILD_APPLICATIONS=OFF
cmake --build build
```

## Applications

| Application | Description |
|-------------|-------------|
| [aes](aes/README.md) | AES encryption/decryption (ECB, CBC, CTR, CFB, OFB, XTS, GCM) |
| [base64](base64/README.md) | Base64 encode/decode |
| [cert](cert/README.md) | Certificate parsing and verification |
| [certificate](certificate/README.md) | Certificate handling (GCC/MinGW; may not build with MSVC) |
| [certgen](certgen/README.md) | Key and certificate generation (genrsa, req) |
| [dtls_psk_demo](dtls_psk_demo/README.md) | DTLS 1.2/1.3 PSK handshake demo |
| [dtls_psk_test](dtls_psk_test/README.md) | DTLS PSK test |
| [https_client](https_client/README.md) | HTTPS client example |
| [https_server](https_server/README.md) | HTTPS server example |
| [noxtls](noxtls/README.md) | Multi-command NoxTLS CLI (e.g. message digest) |
| [pkc](pkc/README.md) | Public key crypto (RSA encrypt/decrypt, sign/verify) |
| [prime](prime/README.md) | Prime number utilities |
| [sha](sha/README.md) | Message digest (SHA, MD5, etc.) |
| [tls_test](tls_test/README.md) | TLS test client |

Each subdirectory may contain a `README.md` with build and usage details.

## Documentation

Application source is documented with Doxygen. The generated docs appear under **Applications** in the [NoxTLS documentation](https://docs.noxtls.com).
