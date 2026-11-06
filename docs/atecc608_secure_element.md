# Using the ATECC608B/C secure element with NoxTLS

NoxTLS can authenticate with a private key that lives in a Microchip ATECC608B or ATECC608C and never leaves the chip,
and it can run the TLS ECDHE key exchange inside the chip. The feature is off by default and the software path is
unchanged unless you turn it on.

| Option (CMake / `noxtls_config.h`) | Default | Meaning |
|---|---|---|
| `NOXTLS_CFG_FEATURE_ATECC608` / `NOXTLS_FEATURE_ATECC608` | OFF | Opaque ECDSA P-256 keys and chip-generated ECDHE keys through the crypto provider interface. Needs ECC, ECDSA and ECDH. |
| `NOXTLS_CFG_FEATURE_ATECC608_ENTROPY` / `NOXTLS_FEATURE_ATECC608_ENTROPY` | OFF | The chip RNG seeds the DRBG (`noxtls_drbg_entropy_accel_port`). Exclusive with the nRF54 entropy port. |
| `NOXTLS_CFG_ATECC608_NOXSENSOR` | OFF | Build the adapter to the NoxSensor driver. Set `NOXTLS_ATECC608_NOXSENSOR_INCLUDE_DIR` to the NoxSensor root. |

NoxTLS itself never includes a NoxSensor header: the provider talks to the chip through a small backend table
(`noxtls_atecc608_backend_t`). `noxtls-lib/vendor/microchip/atecc608/noxtls_atecc608_noxsensor.c` binds that table to the
NoxSensor `noxsensor_atecc608_*` driver (`docs/ATECC608.md` in NoxSensor); any other transport can supply its own table.

## What is delegated

* **Signatures.** `noxtls_atecc608_bind_ecc_key()` reads the slot's public key into an `ecc_key_t` and binds it to the
  provider (`noxtls_ecc_opaque_bind`). Pass that key to the usual setters (`noxtls_tls13_set_server_private_ecdsa`,
  `noxtls_tls13_set_client_cert_ecdsa`, `noxtls_tls12_set_server_private_ecdsa`, `noxtls_tls12_set_client_cert_ecdsa`).
  Every NoxTLS ECDSA signature with that key (TLS 1.3 CertificateVerify, TLS 1.2 ServerKeyExchange and client
  CertificateVerify) is produced by the provider's `ecdsa_sign` callback with the key handle
  `{backend, slot}` (`noxtls_atecc608_key_t`). The provider hashes the message (SHA-256, or SHA-384/512 truncated to the
  leftmost 256 bits) and the chip signs the 32 byte digest. NoxTLS passes `NOXTLS_CRYPTO_HASH_PREHASHED` when it has
  already hashed (the TLS 1.2 client).
* **ECDHE.** `noxtls_atecc608_register_ecdhe()` makes the TLS key exchange generate its `secp256r1` ephemeral key in the
  chip (`ecdh_keygen`) and derive the shared secret there (`ecdh_shared`). Other groups (X25519, P-384, hybrids) stay in
  software. Ephemeral keys go to the key ids you give `noxtls_atecc608_provider_init()`: slots configured with GenKey and
  ECDH (one id per concurrent handshake), or `NOXTLS_ATECC608_KEYID_TEMPKEY`.
* **Entropy.** `noxtls_atecc608_set_entropy_backend()`; the CTR-DRBG stays on top of the chip output.

```c
noxsensor_atecc608_t se;                       /* initialised NoxSensor driver, IO protection key optional */
noxtls_atecc608_backend_t backend;
noxtls_atecc608_provider_t provider;
noxtls_atecc608_key_t device_key;              /* slot 0: the TLS device key */
static ecc_key_t proxy;                        /* must keep its address while bound */
const uint16_t ephemeral[2] = { 2U, 3U };      /* slots with GenKey + ECDH */

noxtls_atecc608_noxsensor_backend(&backend, &se);
noxtls_atecc608_provider_init(&provider, &backend, ephemeral, 2U);
noxtls_atecc608_key_init(&device_key, &backend, 0U);
noxtls_atecc608_bind_ecc_key(&provider, &device_key, &proxy);   /* public key read from the chip */
noxtls_atecc608_register_ecdhe(&provider);                      /* optional */

noxtls_tls13_set_server_private_ecdsa(ctx, &proxy);             /* certificate for that key as usual */
```

The certificate for the chip key is a normal certificate (issue it from the public key the chip reports, or use a
compressed certificate stored in slot 8 as in Microchip's Trust&GO flow).

## Decisions and limits

* **No SHA-256 / HKDF offload.** Every chip command costs a protocol round trip (at least a 64 byte block plus about
  1 ms of wake / poll overhead on I2C, 25 to 75 ms of execution per SHA command at the slowest clock setting) and the
  device is limited by its watchdog (about 1.3 s) between commands. Software SHA-256 on a Cortex-M class MCU takes
  microseconds per block, and CRACEN / STM32 HASH engines are faster still. The chip's KDF command could derive TLS 1.3
  keys, but the TLS key schedule hands keys to NoxTLS record code anyway, so there is nothing to gain.
* **One chip, one command at a time.** The backend must serialise access (a mutex around each call). The NoxSensor helpers
  open one wake session per operation.
* **TempKey ephemerals are volatile.** With `NOXTLS_ATECC608_KEYID_TEMPKEY` the key exists only while the chip stays
  awake; a handshake slower than the watchdog loses it and fails the handshake rather than falling back silently.
  Slot ephemerals survive, but each handshake writes EEPROM (the device endurance is the limit); prefer them when the
  link is slow, and rotate several ids.
* **Binding table.** `NOXTLS_ECC_OPAQUE_MAX` (default 8) bound keys exist at once (device keys plus in-flight ephemerals).
* **Only P-256.** The chip supports NIST P-256 only. RSA, Ed25519 and other curves are unaffected.
* **Static memory configuration.** The binding table is static storage (no allocation); the provider structures are
  caller owned.

## Core changes (guarded by `NOXTLS_FEATURE_ATECC608`, except the provider header)

| File | Change |
|---|---|
| `common/noxtls_crypto_provider.h` | **unguarded**: `NOXTLS_CRYPTO_HASH_PREHASHED`, optional `ecdh_keygen` / `ecdh_shared` operations appended to the ops table (see below) |
| `pkc/ecc/noxtls_ecc_opaque.[ch]` (new) | binding table: key address -> provider + handle |
| `pkc/ecdsa/noxtls_ecdsa.c` | `ecdsa_sign_core()` delegates bound keys to the provider |
| `pkc/ecdh/noxtls_ecdh.c` | `noxtls_ecdh_compute_shared_secret_ex()` delegates bound keys to the provider |
| `pkc/ecc/noxtls_ecc.c` | `noxtls_ecc_key_free()` removes a binding |
| `tls/noxtls_tls_key_exchange.c` | ephemeral key generation asks the ECDHE provider first (P-256 only) |
| `common/noxtls_accel_port.h` | `NOXTLS_PORT_ENTROPY_ACCEL` also true for `NOXTLS_FEATURE_ATECC608_ENTROPY` |

The provider header is deliberately not conditional: a struct whose layout depends on a feature option would make the
same header describe two different tables in two translation units. The new fields are appended, so a provider that uses
designated or zero initialisers (unset fields are NULL, which keeps the software path) compiles and behaves unchanged. A
provider built separately against the old header must be rebuilt, because NoxTLS now reads two more pointers from the
table. No provider other than the ATECC608 one exists in the NoxADK tree.

## Tests

`ut/atecc608` (ctest names `atecc608_*`): provider unit tests against a fake backend (real ECC on the host, so
signatures verify and shared secrets match), DER edge cases, binding table limits, and in-memory TLS 1.2 and TLS 1.3
handshakes where the server key, the client key (mutual TLS) and the ECDHE keys live in the simulated chip, plus chip
failure cases that must fail the handshake cleanly without leaks. The NoxSensor side has its own chip model tests.
