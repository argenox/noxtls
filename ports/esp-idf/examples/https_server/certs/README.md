# HTTPS server certificates


> **Warning:**  
> The certificates in this directory are **for development and testing only**.  
> **Do not use these certificates or keys in production environments.**  
> They are not secure for real-world deployment and are provided solely for demo purposes.

# Existing Certificates
Two demo certificates are provided for testing. These are self-signed certificates and will therefore
cause a browser to alert about connection not being secure, but connection will be secure using TLS.

You can place new HTTPS server certificate and key in this directory:

- `server_cert.pem`
- `server_key.pem`

Both certificate and key are PEM format.

These files are embedded into the firmware by `main/CMakeLists.txt`.

Quick self-signed test certificate using NoxTLS `certgen` (RSA-2048):

```sh
# From the NoxTLS repo root (build certgen first if needed):
#   cmake -S . -B build -DBUILD_APPLICATIONS=ON && cmake --build build --target certgen
certgen genrsa -out server -bits 2048
certgen req -new -x509 -key server.key -out server_cert.pem -days 365 -subj /CN=esp32.local
cp server.key server_key.pem
```
