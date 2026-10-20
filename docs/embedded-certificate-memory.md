# Embedded Certificate Chain Memory

Repository: `argenox/noxtls`, PR #52, version 0.3.10.

Certificate-chain initialization previously allocated eight parsed-certificate
objects even for a single trust anchor. In the CC35x1 profile a parsed certificate
is 8,216 bytes, so each newly initialized chain requested 65,728 bytes. The gateway
also owns a trust chain and the global trust-store snapshot; receiving a server
certificate initializes another presented chain. Those independent reservations
can exhaust an embedded heap before certificate verification completes.

`NOXTLS_X509_CHAIN_INITIAL_CAPACITY` now defaults to one slot. Existing doubling
still grows a chain as certificates are added. An application can select a larger
initial capacity if desired. Certificate parsing, owned DER copies, trust checks,
verification-depth limits and the public structure layout are unchanged.

The bounded-heap regression fails with the previous allocation and passes with
the correction. It covers three independent small chains, growth beyond eight
certificates, independent DER copies after freeing the source, allocation failure
and cleanup without leaked pool bytes. The existing server-name acknowledgment
regression also passes. Hosted Linux/macOS/Windows application checks run both.

The actual CC35x1 reached `recv_certificate` and failed before this correction;
its corrected hardware qualification is still pending. This document does not
claim a completed physical MQTT connection or firmware upgrade.
