---
sidebar_position: 8
title: Static Memory
description: "NoxTLS documentation: build-time sized memory without a heap (NOXTLS_CONFIG_STATIC_MEMORY)."
---

# Static Memory

`NOXTLS_CONFIG_STATIC_MEMORY=1` builds NoxTLS so that every byte it uses is sized
at build time and nothing reaches `malloc()` or a general-purpose heap. A device
then has deterministic memory: no heap growth, no fragmentation of a shared heap,
and no allocation that can fail in the middle of a connection because some other
part of the firmware used the heap. The default is `0`, which keeps the existing
behavior (system allocator, or the `NOXTLS_USE_STATIC_BUFFERS` pool).

The configuration covers TLS 1.3 and DTLS 1.3 connections with external PSK
(PSK-DHE) and with X.509 certificates, the trust store and certificate parsing.

## How it works

With static memory, `NOXTLS_MALLOC`, `NOXTLS_CALLOC`, `NOXTLS_REALLOC` and
`noxtls_free()` resolve to a **region allocator** in `noxtls_memory.c`. The
translation unit does not include `<stdlib.h>`, and `ut/static_memory` checks
with `nm` that no NoxTLS library references `malloc`, `calloc`, `realloc`,
`free` or their relatives.

A region is a byte array of fixed size:

- An **arena** is a bump allocator with LIFO reclamation. A request is carved at
  the top. A freed block is wiped with `noxtls_secure_zero()`, and freed blocks at
  the top return to the free space. There is no free list and no search; the same
  sequence of operations always produces the same layout.
- A **fixed region** holds slots that the library places explicitly, for example
  the record buffers. `noxtls_free()` of a slot pointer does nothing.

An allocation is served by the region of the active **scope**. Each public TLS 1.3
entry point (`noxtls_tls13_connect`, `_accept`, `_recv`, `_send`,
`_send_key_update`, `_send_early_data`, `_close`, `_context_free`, the
client-certificate setters) runs in the scope of its connection. Outside any
scope, allocations use the **global arena** (trust store, keys and certificates
the application parses). An arena that cannot hold a request returns `NULL`, the
API returns `NOXTLS_RETURN_NOT_ENOUGH_MEMORY`, and
`noxtls_mem_get_last_error()` reports `NOXTLS_MEM_FAILURE_POOL_EXHAUSTED` with
the region name. Nothing falls back to another region or to the C library.

### Per-connection memory

Each TLS 1.3 / DTLS 1.3 context owns one caller-provided block, carved at
initialization:

```
[header][steady part                                      ][handshake part                            ]
        TX record | DTLS record workspace | TX queue      hs state | handshake workspace | DTLS flight
        ACK ranges | datagram stash | post-HS flight      handshake arena
        peer leaf DER (certificate profiles) | steady arena
```

- The **handshake part** holds `tls13_hs_state_t` (secrets, transcript hash,
  randoms, key shares, PSK identity and key), the handshake workspace, the DTLS
  flight buffer and the handshake arena (received records, raw transcript,
  handshake reassembly and message copies, parsed extensions, key share copies,
  PSK binder input, X.509 parsing, public-key arithmetic).
- The **steady part** holds what record protection needs for the life of the
  connection, plus a small steady arena for one received record at a time and
  post-handshake messages.

### Release after the handshake

When the handshake is complete the whole handshake part is wiped with
`noxtls_secure_zero()` and released. The release runs at the end of the outermost
library call, so no stack frame still points into it:

| Endpoint | Released when |
| --- | --- |
| TLS 1.3 client and server | the handshake completes (the server's NewSessionTicket is sent before). |
| DTLS 1.3 client | its final flight is acknowledged, or its retransmissions are exhausted (RFC 9147, Section 5.8). Until then the flight and epoch-2 keys stay. |
| DTLS 1.3 server | it has verified the client Finished. It keeps only the client epoch-2 read secret and record-number key (at most 80 bytes, in the header) so that a retransmitted Finished, sent because the final ACK was lost, is decrypted and acknowledged again. They are wiped after `NOXTLS_STATIC_DTLS13_EPOCH2_RETAIN_MS` (default: the 2 MSL final-ACK window) or when the context is freed. |

Before the wipe, buffers that are still owed to the application or to the next
parse (unread handshake bytes such as a NewSessionTicket that arrived with the
server Finished, pending application data, a partially read record) are copied to
the steady arena. A safety scan then checks that no pointer in the context still
refers to the handshake part (`noxtls_connection_memory_stats_t.dangling_pointers`,
always zero; the tests assert it). Late epoch-2 records after release are dropped
like duplicates.

After the release the application may reuse the handshake part, for example as
scratch for its own protocol, until it frees the context:

```c
uint8_t *spare;
size_t spare_len;
if(noxtls_connection_memory_handshake_region(&ctx, &spare, &spare_len) == NOXTLS_RETURN_SUCCESS) {
    /* spare_len bytes, wiped; valid until noxtls_tls13_context_free(&ctx). */
}
```

Post-handshake operation needs no handshake state: KeyUpdate (both directions),
the DTLS ACK of the last flight, NewSessionTicket reception (client; up to
`NOXTLS_STATIC_POST_HANDSHAKE_MSG_MAX` bytes) and DTLS post-handshake messages
(KeyUpdate and connection-ID messages; their flight uses a
`NOXTLS_STATIC_DTLS_POST_HS_FLIGHT_SIZE` steady slot). Certificate profiles keep
the peer's leaf certificate DER (`NOXTLS_STATIC_RETAIN_PEER_CERT_DER`, default 1)
as heap builds do, so `tls-server-end-point` channel binding keeps working. The
parsed peer certificate (`NOXTLS_TLS_RETAIN_PEER_CERT=1`) is not retained in
static mode.

Freeing the context wipes the whole block (steady and handshake parts).

## API

```c
#include "tls/noxtls_connection_memory.h"

/* Profiles */
NOXTLS_CONN_PROFILE_TLS13_PSK   NOXTLS_CONN_PROFILE_DTLS13_PSK
NOXTLS_CONN_PROFILE_TLS13_CERT  NOXTLS_CONN_PROFILE_DTLS13_CERT

/* Build-time sizes: constant expressions, multiples of 8 bytes.
 * profile is the token TLS13_PSK, DTLS13_PSK, TLS13_CERT or DTLS13_CERT. */
NOXTLS_CONNECTION_MEMORY_SIZE(role, profile)            /* block = peak */
NOXTLS_CONNECTION_MEMORY_STEADY_SIZE(role, profile)     /* kept after the handshake */
NOXTLS_CONNECTION_MEMORY_HANDSHAKE_SIZE(role, profile)  /* released after the handshake */

size_t noxtls_connection_memory_size(tls_role_t role, uint32_t profile);
noxtls_return_t noxtls_connection_memory_footprint(tls_role_t role, uint32_t profile,
                                                   noxtls_connection_footprint_t *footprint);
noxtls_return_t noxtls_tls13_context_init_static(tls13_context_t *ctx, tls_role_t role,
                                                 uint32_t profile, void *memory, size_t memory_len);
noxtls_return_t noxtls_dtls13_context_init_static(tls13_context_t *ctx, tls_role_t role,
                                                  uint32_t profile, void *memory, size_t memory_len);
/* Steady part and handshake part in two blocks (a handshake block shared in turn). */
noxtls_return_t noxtls_tls13_context_init_static_split(tls13_context_t *ctx, tls_role_t role,
                                                       uint32_t profile, void *steady, size_t steady_len,
                                                       void *handshake, size_t handshake_len);
noxtls_return_t noxtls_dtls13_context_init_static_split(tls13_context_t *ctx, tls_role_t role,
                                                        uint32_t profile, void *steady, size_t steady_len,
                                                        void *handshake, size_t handshake_len);
noxtls_return_t noxtls_connection_memory_get_stats(const tls13_context_t *ctx,
                                                   noxtls_connection_memory_stats_t *stats);
noxtls_return_t noxtls_connection_memory_handshake_region(tls13_context_t *ctx,
                                                          uint8_t **region, size_t *len);
```

Example (DTLS 1.3 PSK server):

```c
static uint64_t s_dtls_mem[NOXTLS_CONNECTION_MEMORY_SIZE(TLS_ROLE_SERVER, DTLS13_PSK) / 8U];
static tls13_context_t s_dtls;

rc = noxtls_dtls13_context_init_static(&s_dtls, TLS_ROLE_SERVER, NOXTLS_CONN_PROFILE_DTLS13_PSK,
                                       s_dtls_mem, sizeof(s_dtls_mem));
/* then, as before: I/O and time callbacks, noxtls_dtls_set_mtu(), retransmission,
 * tls13_set_external_psk(), groups and suites. The flight is part of the block:
 * noxtls_dtls_set_flight_buffer() is not needed (a buffer it installs is kept). */
```

The block must be 8-byte aligned and stay valid until `noxtls_tls13_context_free()`.
The sizes of this version are the same for both roles; the role is part of the
macro so a role-specific budget does not change callers.

The plain init functions (`noxtls_tls13_context_init`, `noxtls_dtls13_context_init`
and the `_with_workspaces` variants) take a block from a library pool of
`NOXTLS_STATIC_CONNECTION_POOL_COUNT` blocks (default 0: they return
`NOXTLS_RETURN_NOT_SUPPORTED`). `_with_workspaces` then uses the caller's record
and handshake workspaces instead of the block's.

### Threads

The active scope is one pointer, and NoxTLS calls on different connections must be
serialized: one owner task drives every connection (the usual case, and the only one
the tests cover). Defining `NOXTLS_STATIC_MEMORY_THREAD_LOCAL` as the compiler's
thread-local keyword (`_Thread_local`, `__thread`) gives each thread its own scope, so
allocations follow the calling thread, but it does not make the library thread-safe:
the region registry, the global arena, the PKC DRBG and the other process-wide state
listed in [Several connections](#several-connections) are not locked.

## Several connections

A device or a host process can hold many connections at once: a leader keeps its MQTT
connection (TLS 1.3 client), the NoxLink associations (DTLS 1.3 PSK servers) and its
node associations (DTLS 1.3 PSK clients); a host helper keeps many DTLS 1.3 PSK
clients. `ut/multi_context` runs these combinations in both configurations.

### Each call allocates in its own connection

Every entry point that can allocate for a connection enters that connection's scope:
the TLS 1.3 calls listed above, the DTLS 1.3 connection-ID messages
(`noxtls_dtls13_send_request_connection_id`, `_send_new_connection_id(s)`), and the
record-layer calls an application may make directly (`noxtls_tls_send_record`,
`noxtls_tls_flush`, `noxtls_tls13_send_dtls13_encrypted_record`,
`noxtls_dtls_retransmit_flight`, `noxtls_dtls_answer_repeated_flight`). Scopes nest,
so the owner may drive connection B from inside a callback of connection A (a leader
publishes a NoxLink datagram through its MQTT connection from the NoxLink send
callback): B's allocations stay in B's memory and A's release still happens at the end
of A's outermost call. A context without connection memory (a freed one, TLS 1.2)
allocates from the global arena, never from the connection whose call is running.

The trust store setters (`noxtls_x509_trust_store_set`, `_set_der_nocopy`) always use
the global arena, also from inside a callback. Other objects the application parses
(keys, certificates) come from the active scope: create long-lived objects outside
NoxTLS callbacks.

`noxtls_free()` looks a pointer up in the active connection's four regions first, then
in the global arena, then in the registry, so a free costs the same with 2 or 2,000
connections registered.

### Release per connection

The release after the handshake is per connection: each connection releases its own
handshake part at the end of its own outermost call, whatever the other connections
are doing. A connection in the middle of its handshake keeps its handshake state, arena
and flight untouched while another one releases, carries data or is freed.

### One handshake block for several connections

The handshake part is most of a block (for example 25,208 of 40,904 bytes for a
DTLS 1.3 PSK context with 1,400-byte records on Cortex-M33). Connections whose
handshakes the application serializes can take turns with one handshake block:

```c
static uint64_t s_fleet_steady[NOXTLS_CONNECTION_MEMORY_STEADY_SIZE(TLS_ROLE_SERVER, DTLS13_PSK) / 8U];
static uint64_t s_local_steady[NOXTLS_CONNECTION_MEMORY_STEADY_SIZE(TLS_ROLE_SERVER, DTLS13_PSK) / 8U];
static uint64_t s_handshake[NOXTLS_CONNECTION_MEMORY_HANDSHAKE_SIZE(TLS_ROLE_SERVER, DTLS13_PSK) / 8U];

rc = noxtls_dtls13_context_init_static_split(&s_fleet, TLS_ROLE_SERVER, NOXTLS_CONN_PROFILE_DTLS13_PSK,
                                             s_fleet_steady, sizeof(s_fleet_steady),
                                             s_handshake, sizeof(s_handshake));
/* While s_fleet holds the block, the same call for s_local returns
 * NOXTLS_RETURN_NOT_ENOUGH_MEMORY and changes nothing: drop that ClientHello, the
 * peer retransmits it. Once s_fleet is released (stats.released), s_local can start. */
```

- A context holds the handshake block from its init until its release (or its free).
  The PSK, key shares and transcript live there, so a server context that waits for a
  ClientHello holds the block: create it when the ClientHello arrives.
- An init whose blocks overlap storage that a live connection still uses fails with
  `NOXTLS_RETURN_NOT_ENOUGH_MEMORY` before anything is written.
- The release wipes the block. Freeing a context that already released it does not
  touch it (another connection may use it now); freeing a context in the middle of
  its handshake wipes it.
- `noxtls_connection_memory_handshake_region()` returns the block to the application
  only while no connection holds it.

### Per-connection record budget (DTLS 1.3)

`NOXTLS_TLS_MAX_RECORD_SIZE` sizes every connection's record buffers. A DTLS 1.3 connection
that only needs smaller records (a single-association client on a 512-byte MTU next to
1,400-byte NoxLink associations) can be sized for its own record size:

```c
static uint64_t s_node_mem[NOXTLS_CONNECTION_MEMORY_SIZE_RECORD(TLS_ROLE_CLIENT, DTLS13_PSK, 512U) / 8U];

rc = noxtls_dtls13_context_init_static_record(&ctx, TLS_ROLE_CLIENT, NOXTLS_CONN_PROFILE_DTLS13_PSK, 512U,
                                              s_node_mem, sizeof(s_node_mem));
```

- The TX record buffer, the record workspace, the datagram stash and the flight follow the
  budget; the steady and handshake arenas give up their datagram terms (and the handshake
  arena its largest-message term), so a measured arena keeps its margin. At
  `NOXTLS_TLS_MAX_RECORD_SIZE` every size equals the build-wide one (checked at build time).
- The connection sends records of at most the budget, fragments handshake messages to fit
  them, advertises `record_size_limit` budget + 1 (RFC 8449; a smaller configured limit
  wins) and reads datagrams of at most budget + `DTLS_MAX_RECORD_EXPANSION` bytes. Set the
  MTU (`noxtls_dtls_set_mtu()`) to the budget on both ends.
- `noxtls_dtls13_context_init_static_split_record()`, `NOXTLS_CONN_PROFILE_RECORD(profile,
  record)` for `noxtls_connection_memory_size()` / `_footprint()`, and
  `NOXTLS_CONNECTION_MEMORY_STEADY_SIZE_RECORD()` / `_HANDSHAKE_SIZE_RECORD()` complete the API.
  Budgets: `NOXTLS_CONN_RECORD_MIN` (256) to `NOXTLS_TLS_MAX_RECORD_SIZE`, DTLS 1.3 only.

Leader with NoxLink (1,400-byte records, Cortex-M33, footprint tool): a DTLS 1.3 PSK block is
34,104 bytes (steady 10,584, handshake 23,520); with a 512-byte budget 24,424 (5,256 and
19,168), 9,680 bytes less per connection. The node profile is already built for 512-byte
records, so a 512-byte budget changes nothing there.

### Server workspace in the handshake arena

`NOXTLS_STATIC_HS_WORKSPACE_IN_ARENA=1` (default 0) leaves the 4 KB handshake workspace slot out
of server connections: each message builder takes its buffer from the handshake arena while it
builds the message (the ServerHello builder's buffers are sized to the build:
`NOXTLS_TLS13_SERVER_HELLO_ALLOC` 512 and `NOXTLS_TLS13_SERVER_KEY_SHARE_ALLOC` 256 without
ML-KEM and FFDHE). Clients keep the slot (their ClientHello builder needs 4 KB while the arena
is busy). A derived arena budget includes the builders; `noxtls_static_profile_node_compact.h`
sets the node's arena from measurements:

| Node server (Cortex-M4F, node `prj.conf`) | Handshake part | Block |
| --- | ---: | ---: |
| `noxtls_static_profile_node.h` (hs state 2,416, workspace 4,096, flight 1,152, arena 11,272) | 18,936 | 24,672 |
| `noxtls_static_profile_node_compact.h` (no workspace, the same arena) | 14,840 | 20,576 |

Measured server handshake arena peaks under the node sizing (x86-64, node features; every
static-memory, multi-context, recovery and single-association case): 8,048 bytes with the slot
(8,080 with a HelloRetryRequest for P-256), 8,848 without it (9,016), within the 11,272-byte
arena. A build of the compact profile with FFDHE or ML-KEM keeps the 2,048-byte ServerHello
builder buffers and gets a 15,432-byte arena (the 3,328 extra builder bytes plus the reserve);
`noxtls_connection_memory.c` refuses to build when the builders outgrow the profile's
`NOXTLS_STATIC_COMPACT_BUILDERS_BUDGET`.

### Process-wide state

Audit of the state that all connections of a process share (TLS 1.3 / DTLS 1.3 paths):

| State | Where | With several connections |
| --- | --- | --- |
| Active scope | `noxtls_memory.c` `g_noxtls_active_scope` | One pointer, saved and restored by every entry point (nesting is safe). Not locked: calls are serialized. |
| Region registry, global arena | `noxtls_memory.c` | Sized by `NOXTLS_STATIC_MAX_CONNECTIONS` (4 regions each). Not locked. |
| Library connection pool | `noxtls_connection_memory.c` | `NOXTLS_STATIC_CONNECTION_POOL_COUNT` blocks for the plain init functions; caller blocks do not use it. |
| Handshake randomness | `tls13.c` (ClientHello/ServerHello random, ticket nonces, connection IDs) | A DRBG instantiated on the stack for each use from the entropy source; nothing shared between connections. |
| PKC DRBG | `noxtls_pkc_rng.c` `s_pkc_rng_state` | One CTR_DRBG (SP 800-90A) for key generation of all connections (X25519 shares, signatures); one instance may serve many consumers. Not locked. |
| Entropy source | `noxtls_drbg.c` `g_entropy_cb`, `g_entropy_source` | Set once at start-up. |
| DTLS cookie secret | `dtls_context_t.cookie_secret` | Per connection. |
| Trust store | `noxtls_x509.c` `s_x509_trust_anchors` | One set for the process, used only by certificate verification (PSK handshakes never read it). Per-connection anchors: `noxtls_tls13_set_server_verify_policy()` (client side). Replacing or clearing it affects every connection that verifies certificates afterwards. |
| TLS 1.3 server ticket store | `noxtls_tls13_psk.c` `psk_ticket_store` | Shared by all server contexts of the process: a ticket issued by one server is accepted by another. DTLS 1.3 servers issue none. Set `NOXTLS_TLS13_PSK_TICKET_STORE_MAX=0` (the leader profiles do) when no server resumes sessions. Client tickets are per context. |
| ECC precompute caches | `noxtls_ecc.c` | Opt-in (`NOXTLS_ECC_GLOBAL_PRECOMPUTE_CACHE`); refused at build time with static memory, since a cached table would live in one connection's memory. |
| Diagnostics | `noxtls_tls13_last_accept_fail_step()`, `_last_connect_fail_step()`, `noxtls_mem_get_last_error()`, certificate failure info | Last event of any connection. |

## Configuration

All settings are `#ifndef` defaults: override them with `-D` or in a profile
header named by `NOXTLS_STATIC_MEMORY_PROFILE` (included first by
`noxtls_config.h`). CMake: `-DNOXTLS_CONFIG_STATIC_MEMORY=ON`,
`-DNOXTLS_STATIC_MEMORY_PROFILE=profiles/static_memory/<file>.h`,
`-DNOXTLS_STATIC_CONNECTION_POOL_COUNT=<n>`.

| Setting | Default | Meaning |
| --- | --- | --- |
| `NOXTLS_CONFIG_STATIC_MEMORY` | 0 | Enable static memory. Exclusive with `NOXTLS_USE_STATIC_BUFFERS`. |
| `NOXTLS_STATIC_MAX_CONNECTIONS` | 4 | Connections that hold memory at once (sizes the region registry, 1 + 4 per connection). |
| `NOXTLS_STATIC_CONNECTION_POOL_COUNT` | 0 | Library-owned blocks for the plain init functions. |
| `NOXTLS_STATIC_CONNECTION_POOL_CERT` | 1 | Pool blocks carve certificate (1) or PSK (0) profiles. |
| `NOXTLS_STATIC_TRUST_ANCHORS_MAX` | 4 | Trust anchors; more fail with `NOT_ENOUGH_MEMORY` (store left empty). |
| `NOXTLS_STATIC_CERT_DER_MAX` | 2048 | Largest certificate copy (anchor, peer leaf, own certificate). |
| `NOXTLS_STATIC_CERT_CHAIN_DEPTH_MAX` | 4 | Certificates in a received Certificate message (leaf included). |
| `NOXTLS_STATIC_X509_CERT_STRUCT_BYTES` | 512 | Budget per parsed certificate; checked against `sizeof(x509_certificate_t)`. |
| `NOXTLS_STATIC_GLOBAL_EXTRA` | 4096 | Global arena beyond the trust store (device key and certificate). |
| `NOXTLS_STATIC_GLOBAL_POOL_SIZE` | trust store + extra | Global arena; `noxtls_mem_init()` may replace it with a caller buffer. |
| `NOXTLS_STATIC_PSK_MSG_MAX` | 2048 | Largest PSK-handshake message budgeted. |
| `NOXTLS_STATIC_TRANSCRIPT_BYTES` | 3072 | Raw transcript and binder input until the hash is fixed. |
| `NOXTLS_STATIC_PARSE_BYTES` | 3072 | Extension tables, key share copies (two ClientHellos). |
| `NOXTLS_STATIC_PKC_SCRATCH_BYTES` | 8192 | Public-key arithmetic of certificate profiles. |
| `NOXTLS_STATIC_ARENA_RESERVE_PERCENT` | 25 | Reserve on top of the handshake terms (LIFO holes). |
| `NOXTLS_STATIC_DTLS_FLIGHT_SIZE` | 2 x (record + 64) | DTLS flight (PSK); `..._CERT_FLIGHT_SIZE` adds the chain. |
| `NOXTLS_STATIC_DTLS_ACK_RANGES` | 8 | ACK ranges this endpoint sends. |
| `NOXTLS_STATIC_DTLS_POST_HS_FLIGHT_SIZE` | 256 | Flight slot after release. |
| `NOXTLS_STATIC_DTLS13_EPOCH2_RETAIN_MS` | 120000 | DTLS server: epoch-2 read secret lifetime after release (0: until free). |
| `NOXTLS_STATIC_TLS_TX_QUEUE_SIZE` | 2 x TX record | Non-blocking partial-write queue (TLS). |
| `NOXTLS_STATIC_POST_HANDSHAKE_MSG_MAX` | 512 | Largest post-handshake message (NewSessionTicket). |
| `NOXTLS_STATIC_RETAIN_PEER_CERT_DER` | 1 | Keep the peer leaf DER after release (certificate profiles). |
| `NOXTLS_STATIC_MEMORY_THREAD_LOCAL` | empty | Storage class of the active scope pointer. |

Each arena budget can also be set directly: `NOXTLS_STATIC_HS_ARENA_PSK`,
`_CERT`, `_DTLS_PSK`, `_DTLS_CERT`, `NOXTLS_STATIC_STEADY_ARENA`,
`NOXTLS_STATIC_STEADY_ARENA_DTLS`.

Static mode also requires `NOXTLS_TLS_HANDSHAKE_WORKSPACE_SIZE >= 4096` (the
ClientHello and the ServerHello with its staged key share are built in it), and
`NOXTLS_TLS_MAX_HANDSHAKE_SIZE >= NOXTLS_STATIC_CERT_MSG_MAX`. Both are checked at
build time.

### Build-time sizing

Every size is a constant expression, and the build stops (`NOXTLS_STATIC_ASSERT`,
the C99 negative-array idiom) when a configuration cannot fit: workspace too small
for the hello builders, the handshake limit below the largest Certificate message,
`sizeof(x509_certificate_t)` above its budget, too few region registry entries for
`NOXTLS_STATIC_MAX_CONNECTIONS`, ACK ranges above `DTLS_MAX_ACK_RANGES`, and others.

The handshake arena budget is the sum of what can be live at once:

```
received record + its copy              2 x COST(datagram or protected record)
largest handshake message               2 x COST(max(PSK_MSG_MAX, record)) + bitmap
transcript and binder                   NOXTLS_STATIC_TRANSCRIPT_BYTES
extension tables, key share copies      NOXTLS_STATIC_PARSE_BYTES
DTLS fragment buffer                    when the MTU allows fragments above the TX record
certificate profiles:  Certificate message (2 x COST(CERT_MSG_MAX) + bitmap),
                       leaf DER + parsed leaf + chain of intermediates,
                       NOXTLS_STATIC_PKC_SCRATCH_BYTES
+ NOXTLS_STATIC_ARENA_RESERVE_PERCENT
```

`COST(n)` is `n` rounded to 8 plus the 16-byte block header. The reserve covers
blocks that a LIFO arena cannot reuse while a later block is alive (for example a
DTLS server keeps the first ClientHello's tables under the cookie exchange's
transcript state). The budgets are derived, not proven: `ut/static_memory` and the
28 DTLS 1.3 loss, reorder and repeated-flight cases run every profile within them, and an exhausted
arena fails the handshake with a deterministic `NOXTLS_RETURN_NOT_ENOUGH_MEMORY`.

### Footprint report

- `tools/static_memory_footprint/static_memory_footprint.py` compiles
  `noxtls_static_footprint.c` with any compiler and configuration (host or cross,
  optionally reading a Zephyr `prj.conf`) and prints every profile's block, steady
  and released sizes and their components, using the target's own `sizeof()`
  values.
- `static_footprint_report` (CTest, static configuration) prints the layout
  next to the arena high-water marks measured in real handshakes.
- `heap_footprint_report` (CTest, heap configuration) prints the heap peak and
  steady state of the same handshakes for comparison.

```sh
python tools/static_memory_footprint/static_memory_footprint.py \
    --cc arm-none-eabi-gcc --objdump arm-none-eabi-objdump \
    --cflags "-mcpu=cortex-m4 -mthumb -mfloat-abi=hard -mfpu=fpv4-sp-d16 -Os" \
    --profile profiles/static_memory/noxtls_static_profile_node.h --kconfig prj.conf
```

## Profiles

Ready profile headers are in `profiles/static_memory/`. They set sizes only;
feature switches stay with the build (CMake `NOXTLS_CFG_FEATURE_*`, Kconfig).

Numbers below: block sizes from `static_memory_footprint.py` with Arm GNU 14.2 and
the device's `prj.conf` features (32-bit, as built for the device); measured arena
peaks from `ut/static_memory` on x86-64 with the same sizing (64-bit structures,
so the 32-bit peaks are lower); heap references from `heap_footprint_report` on
x86-64 with the same sizing, and from the device.

### (i) Node: DTLS 1.3 PSK server, one connection

`noxtls_static_profile_node.h`: CC1354 (Cortex-M4F), 512-byte records, 4 KB
handshake workspace, PSK messages up to 1 KB, one connection, no ticket store.

| | Bytes |
| --- | --- |
| Block `NOXTLS_CONNECTION_MEMORY_SIZE(TLS_ROLE_SERVER, DTLS13_PSK)` (peak) | 24,664 |
| Steady part (header 352, TX 608, record workspace 1,088, ACK/stash/post-HS flight 1,400, steady arena 2,288) | 5,736 |
| Released after the handshake (hs 2,408, workspace 4,096, flight 1,152, handshake arena 11,272) | 18,928 |
| Caller `tls13_context_t` | 2,648 |
| Global arena (unused by a PSK server; minimum) | 3,664 |
| Measured handshake arena peak: cookie exchange with MTU 512 / worst of the 28 DTLS 1.3 recovery cases (no MTU, 1.5 KB fragment buffer) | 7,936 / 9,392 |
| Measured steady arena peak | 984 |
| 0.3.15 heap mode on the node (hardware): heap high-water, plus the caller's context, record and handshake workspaces and flight | 6,236 + caller buffers |
| 0.3.15 heap mode, same sizing (x86-64): server heap peak / held during the connection | 12,775 / 11,831 |

With TLS 1.2 compiled out (recommended for the node) the steady part is 5,528.

### (ii) Host native helper: DTLS 1.3 PSK client

`noxtls_static_profile_host_client.h`: the node's record and message limits, so
the helper never sends what the node refuses. x86-64, default features.

| | Bytes |
| --- | --- |
| Block `NOXTLS_CONNECTION_MEMORY_SIZE(TLS_ROLE_CLIENT, DTLS13_PSK)` | 26,096 |
| Steady part | 5,984 |
| Released after the handshake | 20,112 |
| Caller `tls13_context_t` | 3,024 |
| Measured handshake / steady arena peak | 4,200 / 984 |
| 0.3.15 heap mode, same sizing: client heap peak / held during the connection | 11,758 / 10,814 |

### (iii) Leader: TLS 1.3 certificate client and DTLS 1.3 PSK client

`noxtls_static_profile_leader.h`: CC35x1 (Cortex-M33), MQTT over TLS 1.3 to AWS IoT
Core with mutual authentication, plus the DTLS 1.3 PSK client toward the nodes.
512-byte records, 4 KB workspace, four trust anchors, chains of up to four 2 KB
certificates, NewSessionTicket up to 2 KB, RSA-2048 or ECDSA P-256.

| | Bytes |
| --- | --- |
| MQTT block `NOXTLS_CONNECTION_MEMORY_SIZE(TLS_ROLE_CLIENT, TLS13_CERT)` | 66,184 |
| of which steady (peer leaf DER 2,048 included) / released | 10,528 / 55,656 |
| Node-channel block `NOXTLS_CONNECTION_MEMORY_SIZE(TLS_ROLE_CLIENT, DTLS13_PSK)` | 29,688 |
| of which steady / released | 9,480 / 20,208 |
| Global arena (trust store 21,168 + device key/certificate 8,192) | 29,360 |
| Two caller contexts | 5,296 |
| Total peak / steady (both connections after their handshakes) | 130,528 / 54,664 |
| Measured TLS handshake arena peak over RSA-2048 and ECDSA P-256 mutual authentication, client / server (budget 49,152 on Cortex-M33) | 10,128 / 9,624 |
| 0.3.15 heap mode, same sizing: TLS client heap peak / held, ECDSA and RSA mutual authentication | 13,217 / 1,626 and 14,231 / 2,401 |

The TLS budget reserves a four-certificate chain of 2 KB certificates and RSA-2048
signing; with the broker's actual chain (leaf and one intermediate) the measured
peak is a fifth of it. Lower `NOXTLS_STATIC_CERT_CHAIN_DEPTH_MAX`,
`NOXTLS_STATIC_CERT_DER_MAX` and `NOXTLS_STATIC_PKC_SCRATCH_BYTES` to the
deployment's chain to reclaim it.

### (iv) Leader with NoxLink: MQTT, NoxLink servers and node clients

`noxtls_static_profile_leader_noxlink.h` (on top of the leader profile): one TLS 1.3
certificate client (MQTT), three DTLS 1.3 PSK servers (NoxLink `nlk1-fleet`,
`nlk1-local` and a replacement association during a re-handshake) and four DTLS 1.3
PSK clients (node associations), `NOXTLS_STATIC_MAX_CONNECTIONS` 8. NoxLink frames
of up to 1,400 bytes travel in one record, so the records are 1,400 bytes
(`CONFIG_NOXTLS_TLS_MAX_RECORD_SIZE=1400`) and the NoxLink contexts advertise
`record_size_limit` 1,401; the MQTT and node contexts keep 513 with
`noxtls_tls13_set_record_size_limit()`. The record size is one build setting, so every
context's buffers follow it. The DTLS 1.3 PSK arenas, the trust store and the global
arena are set from measured peaks (below). Cortex-M33, the leader's `prj.conf` features:

| | 1,400-byte records | 512-byte records |
| --- | ---: | ---: |
| MQTT block (TLS13_CERT), steady / released | 74,736 (15,856 / 58,880) | 66,184 (10,528 / 55,656) |
| DTLS13_PSK block, steady / handshake | 34,096 (10,584 / 23,512) | 29,688 (9,480 / 20,208) |
| NoxLink fleet + local, separate blocks | 68,192 | 59,376 |
| NoxLink fleet + local, one shared handshake block | 44,680 | 39,168 |
| ... plus the replacement association | 55,264 | 48,648 |
| Four node associations, one shared handshake block | 65,848 | 58,128 |
| Global arena (trust store of 2 anchors 12,912 + identity 5,376) | 18,288 | 18,288 |
| All seven DTLS contexts on one handshake block, MQTT, global arena, eight contexts (8 x 2,664) | 211,936 | 192,352 |

The seven DTLS contexts can share one handshake block only if the leader serializes
all their handshakes; with one block for NoxLink and one for the nodes, add one
handshake block (23,512 or 20,208).

Budgets before the measurements (0.3.15 profile): DTLS13_PSK block 40,904 (steady
15,696, handshake 25,208: steady arena 8,760, handshake arena 15,776), global arena
29,360 (4 anchors, 8,192 extra). For the leader's NoxLink servers (2), node clients (4),
MQTT client and global arena: 349,520 bytes before, 297,600 after (51,920 less).

Measured peaks (x86-64 with this profile, whose structures are larger than on the
Cortex-M33; the highest of every test under the profile, including the 28 DTLS 1.3
recovery cases and the record-discard cases run in DTLS13_PSK blocks with
`NOXTLS_STATIC_CONNECTION_POOL_CERT=0`) and the budgets (x86-64 / Cortex-M33):

| Context | Handshake arena peak / budget | Steady arena peak / budget |
| --- | ---: | ---: |
| MQTT client, RSA-2048 chain of 3 (1,893 + 1,083 + 1,082 bytes), RSA-2048 device certificate, record_size_limit 513 | 25,416 / 56,856, 52,376 | 552 / 12,744, 9,160 |
| MQTT client, RSA-2048 chain of 4 after a rotation (5,127 bytes), full records | 32,888 / 56,856, 52,376 | 1,432 |
| MQTT client, four RSA certificates of 2,040 bytes (the profile's limit) | 54,816 / 56,856, 52,376 | 1,432 |
| MQTT client, ECDSA P-256 chain of 2, P-256 device certificate, full records | 15,848 | 1,432 |
| NoxLink server (split, shared handshake block), 1,399-byte frames | 10,360 / 14,080 | 2,912 / 3,648 |
| Node client, 1,399-byte records, also read in 100-byte pieces | 9,880 / 14,080 | 2,912 / 3,648 |
| DTLS 1.3 PSK, recovery and record-discard cases (no MTU: fragment buffer) | 11,248 / 14,080 | 1,552 / 3,648 |

- DTLS 1.3 PSK handshake arena: 11,248 + 25% = 14,080 (was 15,776).
- DTLS 1.3 steady arena: 2,912 + 25% = 3,648 (was 8,760); the margin also holds a
  256-byte post-handshake message (KeyUpdate, NewConnectionId) on top of a full
  datagram and its record. DTLS 1.3 servers issue no NewSessionTicket.
- Trust store: 2 anchors (was 4). The MQTT client verifies the broker with its own
  anchors (`noxtls_tls13_set_server_verify_policy()`, as `fleet_mqtt.c` does), so the
  process store needs at most a broker's RSA and ECC roots.
- `NOXTLS_STATIC_GLOBAL_EXTRA` 5,376 (was 8,192): the leader's identity (gateway root
  parsed with a copy into the verify policy's chain, P-256 device key) takes 2,992 with
  an 859-byte root, 4,181 with a 2,048-byte root, plus 25%. An RSA-2048 device key
  would need about 7 KB.
- Unchanged: the TLS 1.3 certificate handshake arena (the largest chain the profile
  accepts uses 96% of it on x86-64) and the TLS steady arena (a broker NewSessionTicket
  of up to 2 KB; the loopback broker's tickets are small).

The measured budgets apply with 1,400-byte records; a build with another record size
keeps the derived DTLS budgets. Beyond a budget a connection fails with
`NOXTLS_RETURN_NOT_ENOUGH_MEMORY` and names the region (`mc_leader_budget_limits`).
The test harness installs a global arena of the profile's size plus 16 KB for the
test peers' keys (`lb_main()`); the leader cases check their own use against
`NOXTLS_STATIC_GLOBAL_EXTRA`.

`NOXTLS_STATIC_MAX_CONNECTIONS` 8 counts the leader's own contexts. An in-process
test holds both ends of each association, so with 8 it runs four associations
(the NoxLink servers and one node association; `mc_concurrent_server_client` and
`mc_many_psk_clients` run four), and with `-DNOXTLS_STATIC_MAX_CONNECTIONS=16U`
(region registry only, 32 more entries) the whole set of eight leader connections
at once.

Heap mode reports what the test handshakes used; static mode reserves the
configured worst case once, at build time, and reports the part that is free again
after each handshake. Between sessions a node can keep its block allocated and
reuse the released part.

## Allocation audit

Allocation sites reached by the three paths (0.3.15 code, traced with
`LB_TRACE_ALL=1` on the heap configuration with the leader sizing, 512-byte
records; sizes are the largest seen). Lifetime: **handshake** (static mode: in the
handshake part, released at the end of the handshake), **call** (freed before the
API call returns), **connection** (static mode: a steady slot), **global** (global
arena).

### (a) DTLS 1.3 PSK server and client

| Site | Size | Lifetime | Static mode |
| --- | --- | --- | --- |
| `tls13_context_init_internal` `ctx->hs` (`tls13.c`) | 2,408 (M4) / 3,592 (x86-64) | handshake (DTLS heap mode keeps it to free) | hs slot |
| `tls13_context_init_internal` handshake workspace | `TLS_HANDSHAKE_WORKSPACE_SIZE` | handshake | workspace slot |
| `tls13_dtls_record_workspace` | `TLS13_RECORD_WORKSPACE_SIZE` (1,088) | connection | steady slot |
| `noxtls_tls_record_tx_buffer` (`tls_common.c`) | `TLS_RECORD_TX_BUFFER_SIZE` (605) | connection | steady slot |
| `dtls_flight_reserve` (`dtls_common.c`) | 1,024 grow step | handshake (until ACKed) | flight slot; post-HS flight slot after release |
| `dtls_ack_range_add` (x2), `tls13_dtls_ack_range_add` | 8 x ranges | connection | steady slots |
| `tls13_dtls_handle_ack` last ACK ranges (realloc) | 8 x ranges | connection | steady slots (32 ranges) |
| `dtls_rx_stash_remainder` | rest of a datagram | across calls | steady slot |
| `tls13_dtls_store_hrr_cookie` (client) | cookie | handshake | handshake arena |
| `noxtls_dtls_recv_record` datagram buffer, record copy | 525, 419 | call | arena |
| `noxtls_dtls_reassemble_handshake`, `tls_dtls_deliver_handshake`, `tls13_dtls_append_inner_handshake_fragments`, `tls13_recv_handshake_message`, `tls13_handshake_buffer_append/_get` | up to the message | call / handshake | arena |
| `noxtls_tls13_send_dtls13_encrypted_record` (x2) | record | call | arena |
| fragmentation buffer (`dtls_common.c` send, no MTU set) | 1,487 | call | arena (budgeted) |
| `tls13_append_handshake_message` raw transcript, `tls13_reset_transcript_for_hrr` | 485, 36 | handshake | arena |
| `tls_parse_extensions_for_peer` and the per-extension parsers (server) | 1,024 + small | handshake | arena |
| `tls13_extract_clienthello_extension_type_order` (server) | 128 | handshake | arena |
| `tls13_copy_client_key_shares` (server, x2) | 16 + 32 | handshake | arena |
| `tls13_parse_raw_extension_list` (client, x2) | 256 + 36 | handshake | arena |
| `psk_hash_binder_input` (`tls13_psk.c`) | 0 (streamed into one running hash) | call | none |
| `noxtls_tls_ecdhe_compute_shared_secret_x25519` | 32 | call | arena |
| `noxtls_tls13_send_server_hello` key share entry | 2,048 (in workspace when it is 4 KB) | call | workspace / arena |
| `tls13_dtls_flush_ack` | 22 | call | arena |
| pending application data copy (`tls13_recv`, short reads) | rest of a record | across calls | steady arena |

### (b) TLS 1.3 PSK client

| Site | Size | Lifetime | Static mode |
| --- | --- | --- | --- |
| `ctx->hs`, handshake workspace | as above | handshake (released at CONNECTED) | slots |
| `noxtls_tls_record_tx_buffer` | 605 | connection | steady slot |
| `tls_queue_pending_output` (non-blocking partial write) | queued bytes | across calls | steady slot (`NOXTLS_STATIC_TLS_TX_QUEUE_SIZE`) |
| `tls_nonblocking_recv_record` record payload | up to 529 | call, or pending data across calls | arena |
| `tls13_append_handshake_message` | 386 | handshake | arena |
| `tls13_handshake_buffer_append/_get` | message | call (NST/KeyUpdate after release) | arena / steady arena |
| `tls13_parse_raw_extension_list` (x2) | 256 + 36 | handshake | arena |
| x25519 shared secret (`psk_hash_binder_input` streams, 0) | 32 | call | arena |

### (c) TLS 1.3 certificate client (chain, X.509, trust store)

Everything in (b), plus:

| Site | Size | Lifetime | Static mode |
| --- | --- | --- | --- |
| `noxtls_tls13_recv_certificate` peer leaf DER | leaf (913 RSA, 540 ECDSA) | connection (heap) | arena, copied to the peer-cert slot at release |
| `noxtls_tls13_recv_certificate` parsed leaf | `sizeof(x509_certificate_t)` | handshake | arena |
| `noxtls_x509_certificate_chain_reserve` presented chain (borrowed DER) | `NOXTLS_STATIC_CHAIN_CAPACITY` x struct | call | arena, one allocation, capacity checked |
| `noxtls_x509_certificate_get_public_key` | 160 | call | arena |
| `noxtls_tls13_set_client_cert*` own certificate copy (`tls13_conn_malloc`) | 883 / 481 | handshake | handshake arena (connection scope) |
| ECDSA verify/sign: `ecc_ctable_alloc/_build_window/_normalize`, `ecdsa_verify_core`, `ecdsa_sign_core`, `noxtls_ecc_key_init`, `bn_mod_exp_mont` | 32 to 512 | call | arena (`PKC_SCRATCH`) |
| RSA verify: `noxtls_rsa_key_init_public`, `noxtls_rsa_verify`, `rsa_verify_pss_core`, `bn_mod_exp_mont_public` | 256 to 1,544 | call | arena |
| RSA sign (CRT, blinding): `rsa_private_op`, `rsa_crt_exp`, `rsa_blinding_pair`, `rsa_mul_mod`, `noxtls_bn_mul`, `noxtls_bn_mod_inv`, `bn_div_remainder_limb`, `bn_mod_2n_by_n_limb`, `bn_mod_exp_mont`, `noxtls_rsa_sign_pss` | 128 to 2,048 | call | arena |
| Trust store: `x509_certificate_parse_der_common` DER copy, `noxtls_x509_certificate_chain_reserve` | 873 per anchor, chain array | global | global arena; count, DER size and chain capacity checked |
| Application key and certificate parsing | key dependent | global | global arena (`NOXTLS_STATIC_GLOBAL_EXTRA`) |

### Pools and deterministic errors

| Pool | Exhausted when | Result |
| --- | --- | --- |
| Trust store | more than `NOXTLS_STATIC_TRUST_ANCHORS_MAX` anchors | `NOXTLS_RETURN_NOT_ENOUGH_MEMORY`, store empty (fail closed) |
| Certificate copy | DER above `NOXTLS_STATIC_CERT_DER_MAX` | `NOXTLS_RETURN_NOT_ENOUGH_MEMORY` before any copy |
| Chain | more than `NOXTLS_STATIC_CHAIN_CAPACITY` certificates; a Certificate message with more than `NOXTLS_STATIC_CERT_CHAIN_DEPTH_MAX` | add fails; handshake fails with the same code every time |
| Global arena | request above the free space | `NULL`, last error `POOL_EXHAUSTED`, region "global" |
| Connection arenas | request above the free space | API returns `NOT_ENOUGH_MEMORY`; region named in the last error |
| Library connection pool | all `NOXTLS_STATIC_CONNECTION_POOL_COUNT` blocks in use | `NOXTLS_RETURN_NOT_ENOUGH_MEMORY` |
| Region registry | more than `NOXTLS_STATIC_MAX_CONNECTIONS` connections | init returns `NOXTLS_RETURN_NOT_ENOUGH_MEMORY` |
| Caller block | smaller than the profile | init returns `NOXTLS_RETURN_INVALID_PARAM` |

## Tests

- Heap configuration (default): the whole suite, unchanged, plus
  `heap_footprint_report`.
- Static configuration: `-DNOXTLS_CONFIG_STATIC_MEMORY=ON
  -DNOXTLS_STATIC_CONNECTION_POOL_COUNT=2
  -DNOXTLS_STATIC_MEMORY_PROFILE=profiles/static_memory/noxtls_static_profile_host_test.h
  -DNOXTLS_BUILD_DTLS13_RECOVERY_TESTS=ON -DNOXTLS_BUILD_TLS13_PEER_CERT_TESTS=ON`.
  It runs the TLS 1.3 loopback suite (31 cases: certificate chains, RSA-PSS,
  Ed25519, mutual authentication, resumption, 0-RTT, KeyUpdate, exporters,
  fragmented transport, the allocation-failure sweep), the DTLS 1.3 loopback cases,
  the DTLS 1.3 recovery suite (28 cases: the 23 loss and reorder cases and 5 repeated-flight cases), `tls13_link_ut`, `key_share_memory_ut`,
  `dtls_reassembly_ut`, `tls13_peer_cert_ut`, and `ut/static_memory`:
  - `static_*` handshakes in caller blocks (DTLS 1.3 PSK, TLS 1.3 PSK, ECDSA and
    RSA certificates, RSA and ECDSA mutual authentication): release checked (hs
    NULL, region wiped, no dangling pointer), application data and KeyUpdate in
    both directions after the application overwrote the released part, steady
    arena idle, block wiped on free, and zero `malloc`/`calloc`/`realloc`/`free`
    calls through `-Wl,--wrap` (GNU ld);
  - `static_release_timing`, `static_pool_exhaustion`,
    `static_peer_chain_too_deep` (same error twice);
  - `static_memory_symbols`: `nm` finds no C heap symbol in any NoxTLS library;
  - `static_footprint_report`.
- Both configurations run `ut/multi_context` (`mc_*`, several associations in one
  process, each with its own link and PSK; static builds check every connection's
  memory and, with GNU ld, zero C allocator calls):
  - `mc_concurrent_server_client`: two DTLS 1.3 PSK server associations (NoxLink
    fleet and local), two node-facing DTLS 1.3 associations and a TLS 1.3 stream
    association live at once; data, KeyUpdate and a 1,399-byte record on each;
  - `mc_cross_identity_refused`: a server refuses another association's identity
    while that association keeps working;
  - `mc_interleaved_handshakes`: four handshakes one flight per turn in a changing
    order, with a late start, a lost server flight and a duplicated ClientHello;
  - `mc_release_per_context`: one association releases while another is in the middle
    of its handshake, whose state and arena stay unchanged;
  - `mc_shared_handshake_region` (static): two servers and a replacement take turns
    with one handshake block (refusal while held, free without wipe, errors);
  - `mc_foreign_scope_isolation`: connection B driven from connection A's send
    callback (send, encrypted record, flush, trust store): B allocates in its own
    memory, the trust store in the global arena, A sees only its own send;
  - `mc_many_psk_clients`: eight PSK client associations, closed one by one and
    reopened while the others carry data;
  - `mc_noxlink_frame_records`: a 1,400-byte frame takes two records with
    `record_size_limit` 1,400 and one with 1,401;
  - `mc_leader_mqtt_rsa`, `mc_leader_mqtt_ecdsa`, `mc_leader_mqtt_rsa_rotated` (four
    certificates after an intermediate rotation), `mc_leader_mqtt_rsa_max_chain` (four
    2,040-byte certificates): the leader's MQTT connection
    (TLS 1.3 client, certificate profile) to a broker presenting a cloud broker's
    chain (`ut/multi_context/gen_leader_pki.py`: RSA-2048 leaf with ten SAN names,
    AIA, CRL distribution point, policies and embedded SCTs, its intermediate and
    the root cross-signed by an untrusted legacy root; or a P-256 leaf and
    intermediate), the anchors in the connection's verify policy, wildcard hostname,
    mutual authentication with an RSA-2048 or
    P-256 device certificate issued by the broker's device CA, record_size_limit
    513 honored by the broker, release after the handshake with the peer leaf kept
    for channel binding, and 256 KeyUpdates with data (steady arena idle after every
    exchange, its high-water mark constant);
  - `mc_leader_topology`: the NoxLink fleet and local servers created when their
    peers' ClientHellos arrive, taking turns with one handshake block (a refused
    ClientHello is dropped and retransmitted), next to concurrent node associations
    (a lost node flight, a duplicated ClientHello) and, with 16 connections, the
    MQTT connection; a re-handshake of the fleet peer while the old association
    carries data; the ACK of its Finished lost, the handshake block reused and
    wiped by another re-handshake, and the released server still answering the
    retransmitted Finished (epoch-2 read key kept in its steady part); then
    1,399-byte frames and KeyUpdates on every association (600 on one);
  - `mc_leader_budget_limits` (static): a node client reads three full records in
    100-byte pieces (the steady arena's peak); with its steady arena taken but for 256
    bytes a full record, and with its handshake arena taken but for 4 KB the handshake,
    fail with `NOXTLS_RETURN_NOT_ENOUGH_MEMORY` (twice the same, region named, guard
    words around the block intact, block wiped by the free); the MQTT client's
    handshake fails the same way with its handshake arena taken but for 12 KB.

Profile-dependent cases: with no server ticket store
(`NOXTLS_TLS13_PSK_TICKET_STORE_MAX` 0, the leader profiles) the four resumption and
0-RTT cases are skipped, since the loopback server issues no ticket;
`dtls_reassembly_ut` sizes its reference message to
`NOXTLS_DTLS_REASSEMBLY_MAX_BYTES`; `static_pool_exhaustion` expects
`NOXTLS_RETURN_CERT_PARSE_FAILED` when `NOXTLS_MAX_CERT_SIZE` equals
`NOXTLS_STATIC_CERT_DER_MAX`, because the build-wide certificate bound is checked
first.

## Limitations

- TLS 1.2 and DTLS 1.2 contexts have no connection memory: they allocate from the
  global arena, which has no per-connection sizing. Compile TLS 1.2 out on static
  devices.
- DTLS 1.3 with certificates and records below 2 KB fails in heap builds as well
  (`dtls13_ecdsa_handshake_data` with 512-byte records); `static_dtls13_cert_ecdsa`
  is skipped there.
- A TLS server that reassembles a ClientHello split over several records, early
  data accepted by a server, and NewSessionTickets above
  `NOXTLS_STATIC_POST_HANDSHAKE_MSG_MAX` are bounded by the arenas: beyond them the
  connection fails deterministically.
- The parsed peer certificate (`NOXTLS_TLS_RETAIN_PEER_CERT`) is released with the
  handshake part; its DER is kept.
- The record size (`NOXTLS_TLS_MAX_RECORD_SIZE`) is one build setting for every
  connection: a device with one connection that needs large records sizes the buffers
  of all its connections for them; `record_size_limit` still limits each peer.
- RFC 8449 makes `record_size_limit` optional: a server that does not acknowledge it
  in EncryptedExtensions may send TLS records of 2^14 bytes. A build that sends small
  records but must accept them sets `NOXTLS_TLS_MAX_RECV_RECORD_SIZE` (up to 16384,
  default `NOXTLS_TLS_MAX_RECORD_SIZE`). It sizes only the stream (TLS) receive
  record in the arenas, not the send buffer or DTLS. Once the peer acknowledges the
  limit, the connection refuses larger records again. `noxtls_tls13_last_handshake_diag()`
  reports the record lengths, the acknowledgement and the certificate sizes of the
  last TLS client handshake.
