# DTLS 1.3 RFC 9147 conformance plan

This file tracks the implementation status for NoxTLS DTLS 1.3 against RFC 9147. It is intentionally engineering-facing: keep it updated when changing wire format, key schedule, record protection, ACK/retransmit, or interop behavior.

## Implemented in this work

- RFC 9147 Section 5.9: DTLS 1.3 HKDF labels use the `dtls13` prefix through DTLS-aware KDF wrappers.
- RFC 9147 Section 5.3: DTLS ClientHello uses empty `legacy_session_id`, includes zero-length `legacy_cookie`, sends DTLS supported_versions, and validates non-zero legacy_cookie as `illegal_parameter`.
- RFC 9147 Section 4.2 and 4.2.3: unified header send/parse handles S bit, 8- or 16-bit protected record numbers, and leading-byte record number masking.
- RFC 9147 Section 4.2.2: encrypted receive reconstructs full record numbers from truncated values before nonce construction.
- RFC 9147 Section 4.5.1: encrypted replay state is kept per low epoch and updated after successful AEAD deprotection.
- RFC 9147 Section 4.2.1: benign plaintext epoch mismatches are discarded as timeout-like events rather than tearing down the association.
- RFC 9147 Section 4.2.3: DTLS 1.3 short ciphertexts are padded before AEAD when the selected suite has a tag shorter than 16 bytes.
- RFC 9147 Section 5.2 and 5.5: handshake reassembly keeps a bounded future-message queue and checks overlapping fragment byte identity.
- RFC 9147 Section 5.8.3: retransmission sends at most 10 records per pass and skips records covered by parsed ACK ranges.
- RFC 9147 Section 4.3 and 4.4: DTLS 1.3 MTU-derived handshake fragment size accounts for unified header and AEAD record-number-protection overhead.
- RFC 9147 Section 5.8.2 and Section 9: RequestConnectionId and NewConnectionId post-handshake messages have public send APIs, receive-side parsing, outstanding-message ACK tracking, RFC 9147 handshake type constants, bounded spare CID pools, generated spare-CID responses, and explicit peer-CID rotation support.
- RFC 9147 Section 5.8.1: the server flushes and retains the final-flight ACK for a 2 MSL window and resends it when duplicate final-flight records are replayed.
- RFC 9147 Section 5.8.1: retransmission timeout uses an RTT estimator when ACKs cover a flight, keeps exponential/per-mille backoff for loss, and resets to the current base RTO instead of a hard-coded timeout.
- RFC 9147 Section 4.2.2 and Section 4.5.3: DTLS KeyUpdate uses separate full read/write epoch tracking so low-epoch replay windows reset on the correct peer direction across epoch wraparound.

## Still requiring interop hardening

- RequestConnectionId and NewConnectionId now maintain bounded spare CID pools and generate spare-CID responses; asymmetric rotation still needs BoGo/OpenSSL tests.
- Final-flight ACK retention is implemented with a 120 second default window; BoGo/OpenSSL duplicate-final-flight coverage is still needed.
- RTT-based retransmission timer adjustment is implemented; interop should confirm behavior under lossy BoGo/OpenSSL runs.
- Full epoch disambiguation now tracks read/write epochs independently; long KeyUpdate epoch wrap still needs BoGo/OpenSSL stress testing.

## Regression and interop matrix

Run these after changing DTLS 1.3 code paths:

- `cmake --build build -j2`
- `ctest --test-dir build --output-on-failure` when the build directory has registered tests
- `oss-fuzz/fuzz_dtls13_record_size.c` with the oss-fuzz harness
- BoGo DTLS 1.3 server and client shards using `applications/bogo_shim`
- OpenSSL 3 DTLS 1.3 smoke test with short application records, fragmented handshakes, and retransmitted final flights

## Migration note

The DTLS 1.3 key schedule and ClientHello wire image changed. Existing NoxTLS-to-NoxTLS DTLS 1.3 peers built before this work will not interoperate with peers using RFC 9147-conformant `dtls13` labels and the DTLS ClientHello cookie field.
