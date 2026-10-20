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

The actual CC35x1 reached `recv_certificate` and failed before this correction.
Firmware 0.1.91, built with NoxTLS `acd4a20`, subsequently completed mutual TLS,
received the AWS IoT MQTT CONNACK and accepted a boot-correlated backend control
session. That run used full certificate date checks and a volatile development
credential adapter. It is not an OTA qualification or a live telemetry result.

The optional TLS 1.3 server verification policy now permits an application to
borrow its own trust chain, avoiding a redundant global-store snapshot. It also
offers explicit `NOXTLS_X509_TIME_DEFERRED` for clockless bootstrap. This mode
parses validity bounds but cannot reject expired or not-yet-valid certificates
until UTC is known. It retains path signatures, issuer and purpose checks; TLS
hostname and CertificateVerify processing are unchanged. Deferred mode refuses
CRLs because their freshness needs UTC. Existing default callers still use the
global trust store and system-time checks. Applications that choose deferral
must reverify the complete chain when time becomes available.

The server-time regression drives the actual TLS 1.3 Certificate receive path.
It covers explicit dates, clockless opt-in, tampered signatures, wrong anchors,
wrong EKU, malformed dates, invalid policies and CRL refusal. The application
owns the time-acquisition policy and reconnects to recheck dates after UTC arrives.
