# DTLS 1.3 recovery regression

Tracks [issue #44](https://github.com/argenox/noxtls/issues/44), found in NoxTLS 0.3.5 at `bf1f580c8290c97e0e1a69f186806a636048aaef`.

The key-share parser allocated 512 descriptors for a ClientHello containing one X25519 share. On the CC1354P10 this requested 4096 bytes and could fail before the handshake started. It now validates the wire vector and allocates the actual entry count.

Encrypted DTLS 1.3 handshake messages were sent without being retained in the retransmission flight. They are now saved in the existing flight buffer and re-encrypted with a fresh record sequence number when retransmitted. Recovery also handles handshake epochs after application keys are installed, ACK tracking, old plaintext flights and out-of-order encrypted messages. Future encrypted messages are discarded without ACK, as permitted by RFC 9147 section 5.2, and recovered through retransmission.

No fixed large buffer is added. The DTLS context gains one callback pointer, which changes its layout. Rebuild the library and all code that allocates or embeds its contexts together. Retained messages use the existing flight buffer and its capacity limits.

## Run the tests

Use an existing UTNox source checkout:

```sh
cmake -S . -B build/dtls13-recovery -G Ninja \
  -DBUILD_APPLICATIONS=OFF -DBUILD_TESTS=OFF \
  -DNOXTLS_BUILD_DTLS13_RECOVERY_TESTS=ON \
  -DNOXTLS_ERROR_UTNOX=/path/to/utnox/utnox
cmake --build build/dtls13-recovery --target tls13_link_ut dtls13_recovery_ut key_share_memory_ut
ctest --test-dir build/dtls13-recovery --output-on-failure
```

The focused option is off by default. With TLS 1.3, DTLS, X25519, AES-GCM and ECC enabled it builds three UTNox executables with eleven cases in total:

- TLS 1.3 context initialization and linkage.
- The largest classical share, a 137-byte P-521 KeyShareEntry, fits the client staging buffers.
- Normal PSK-DHE handshake and bidirectional authenticated application data.
- Loss of the first encrypted server handshake record.
- Loss of the client Finished.
- Loss of the final server ACK.
- All three losses in one handshake.
- Flight-buffer binding, length and capacity boundaries.
- A single X25519 key share with a 1 KB allocator.
- Malformed key-share vectors and empty vectors.
- Allocation failure cleanup and multiple key shares.

The recovery tests use the real handshake, AEAD and retransmission timer. Transport queues and time are simulated. Cryptographic entropy uses the normal library provider. The tests also check that protected handshake retransmissions do not reuse record sequence numbers.

Repeat the configuration in a separate build directory with `-DNOXTLS_CFG_FEATURE_DTLS=OFF`. Build `tls13_link_ut` and `key_share_memory_ut`, then run CTest. The loss tests are skipped and the TLS context check verifies that ordinary TLS users do not acquire an unresolved reference to the optional DTLS flight implementation. This check caught a missing compile guard during review and passed after it was added.

Nonblocking callers must keep servicing DTLS receive and timers after the client becomes locally connected, until its final Finished is acknowledged. Losing that flight does not undo the client's local connected state. The application must allow recovery to finish before relying on application traffic.

## Hardware validation, October 14, 2026

Both CC1354P10 Thread peers were programmed with the same Secure CoAP LED firmware, with CCFG preserved. The path was PC Wi-Fi to CC35x1 leader, SPI to its CC1354 radio, then Sub1GHz Thread to each peer. BLE advertising remained enabled on the peers.

| Check | Board 2 | Board 3 |
| --- | --- | --- |
| Authenticated GET, PUT on, GET, PUT off, GET | 5/5 passed | 5/5 passed |
| Drop first encrypted server handshake record | Passed | Passed |
| Drop client Finished | Passed | Passed |
| Drop final server ACK | Passed | Passed |
| Drop all three in one connection | Passed | Passed |
| CLI responsive and Thread attached after LED requests | Passed | Passed |

Loss was injected by a PC UDP relay before forwarding selected records. These tests establish recovery with real devices and the radio path, without attributing the original packet loss to RF noise. The programmed peer ELF SHA-256 was `0ae06086133c13c944f87ba721742bfab23a2ba807c654ae61256376a3647b1d`.

The application also contains separate fixes for entropy callback ownership when BLE and Thread share NoxTLS, and for driving pending DTLS timers. Those changes belong to the application and Thread integration, outside this library patch. The standalone regressions do not depend on them.

This validation does not cover long-duration operation, BLE connection cycling, other cipher suites or DTLS 1.2 interoperability.

## Outgoing embedded client stack

Enabling node-to-leader button notifications exposed another memory issue in the same
revision. ClientHello used 4096-byte vector staging and a 2048-byte encoded-entry
scratch array even in a classical-only build that emits one X25519 share. Nested radio
transmission from that function overflowed the CC1354 application's existing 16 KiB
Thread task stack. The lower stack guard was overwritten and the overflow handler's
breakpoint stopped the firmware.

Classical-only ClientHello staging now uses the existing 160-byte inline share limit.
The largest supported classical encoding is P-521 at 137 bytes including its header,
covered by a real key-generation/encoding regression. ML-KEM-enabled builds retain
their existing larger capacities. No heap or static context buffer is added.
Arm GCC 14.2 Release stack-usage reports show `noxtls_tls13_send_client_hello` shrinking
from 6608 to 1568 bytes, with the task stack unchanged.

On board 2, a temporary 200 ms inversion of BTN-1 input sensing exercised the real
GPIO polling, debounce, secure client and Sub1GHz path to the CC35x1 leader. The input
configuration was restored after each test; the pin remained an input. Four consecutive
notifications completed without reboot, with authenticated blink acknowledgements,
released sessions, intact stack guards and clear fault registers. This is an injected
logical input check, not validation of the mechanical button. The companion Thread
deadline code also needed to accept a partial peer-flight receive wait after its local
flight had been acknowledged; that integration fix is outside NoxTLS.
