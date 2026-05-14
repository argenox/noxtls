---
sidebar_position: 4
---

# Security

## General

Security for systems is mostly about disciplined operations, not only algorithm choice. A strong design can still fail if secrets leak through logs, outdated dependencies are shipped, or a permissive runtime configuration is used in production. Treat security as a lifecycle activity that starts at development time and continues through deployment, monitoring, and incident handling.

Production deployments should run with secure defaults, least privilege, and strict separation between environments. Development and staging are useful for testing controls, but they must not reuse production credentials or trust anchors. Teams should also define clear ownership for patching, key management, and certificate operations so that urgent remediation can happen quickly.

At a minimum, apply the following baseline controls:

- Use current, supported TLS versions and strong cipher suites in production.
- Keep the library and toolchain updated and apply security advisories.
- Store keys and secrets in secure storage where available, and avoid logging or exposing them.
- Run services with least privilege and isolate cryptographic operations from non-trusted components where practical.
- Require explicit opt-in for weaker or legacy behavior.
- Review third-party dependencies regularly, pin versions where appropriate, and remove unused packages.
- Enable auditing for authentication, key management, and configuration changes to support incident response.
- Document an incident process, including key compromise handling and certificate revocation procedures.

For vulnerability intake and coordinated disclosure workflow, see [Security Reporting](/docs/next/security-reporting).

## Cryptography

Modern cryptography is reliable when it is selected and integrated correctly. The main risk is often misuse, such as weak random generation, missing authentication, or bypassed certificate checks. Choose standard primitives, avoid custom protocol behavior, and make secure verification logic mandatory in production paths.

Core cryptographic expectations:

- Prefer **authenticated encryption** (for example, AES-GCM or ChaCha20-Poly1305) when both confidentiality and integrity are required.
- Use a cryptographically secure DRBG for key and nonce generation.
- Validate certificate chains and host names in TLS clients, and do not disable verification in production.

### TLS 1.2 suite policy (secure by default)

NoxTLS uses a secure-by-default TLS 1.2 cipher-suite posture:

- Legacy TLS 1.2 CBC-mode and RSA key-exchange suites are disabled by default.
- Default TLS 1.2 negotiation favors modern AEAD suites.

Enable legacy TLS 1.2 suites only when interoperability with older peers is required, and scope that exception tightly:

```bash
cmake -S noxtls -B noxtls/build-legacy \
  -DNOXTLS_CFG_TLS12_ENABLE_LEGACY_CIPHER_SUITES=ON
cmake --build noxtls/build-legacy
```

For non-CMake builds, set `NOXTLS_TLS12_ENABLE_LEGACY_CIPHER_SUITES=1` in `noxtls_config.h` (or equivalent compiler defines).

For full build-time configuration options and profile guidance, see the [Configuration Guide](/docs/configuration-guide).

### Post-quantum deployment guidance

When enabling PQC features:

- Treat current PQ TLS IDs as interoperability/prototyping values unless standards-track assignments are locked for your deployment target.
- Prefer hybrid migration paths (`X25519+ML-KEM`) during staged rollout where compatibility is required.
- Keep a compatibility fallback policy (classical groups/signatures) for peers that do not negotiate PQ paths.
- Track cryptographic agility in your certificate and key-management process so algorithm transitions remain operationally safe.

### Side-channel security

Side-channel attacks recover secret information from implementation behavior instead of breaking the underlying math. Common examples include timing leakage, cache effects, memory access patterns, and observable error behavior. These attacks are practical in some environments, especially on shared hardware or multi-tenant systems.

Reduce this risk by using constant-time implementations for secret-dependent operations, avoiding data-dependent branches and table lookups on secret material, and keeping the cryptographic boundary small. In higher assurance environments, isolate sensitive workloads from untrusted code and validate side-channel assumptions on each target platform.

NoxTLS supports build-time side-channel profiles through `NOXTLS_SIDECHANNEL_PROFILE`:

- `performance`: legacy behavior (opt-in for speed-focused builds).
- `balanced`: default profile; uses constant-time secret comparisons in core verification paths.
- `constant_time_strict`: high-assurance profile with stricter hardening expectations.

For production systems exposed to shared or hostile environments, prefer `constant_time_strict` and treat `performance` as an explicit exception.

### Key security

Key management usually determines the real security level of a deployment. Even strong algorithms provide little protection if private keys are copied broadly, rotated infrequently, or retained after compromise. Treat keys as controlled assets with explicit lifecycle and access policy.

Keys should be generated from approved CSPRNG or DRBG sources and sized according to current standards. Private keys should be protected in hardware-backed stores such as HSM, TPM, or secure element devices when available, with tightly restricted export paths. Implement lifecycle controls for creation, activation, rotation, revocation, backup, and secure destruction. Separate long-term identity keys from ephemeral session keys, prefer ephemeral key exchange for forward secrecy, and never hardcode keys in source code, firmware images, or default configuration.

### Memory security

Secrets are vulnerable while they are in memory, even if they are encrypted at rest. Bugs, crash dumps, debug tooling, and accidental telemetry can expose key material or plaintext. For C and systems-level code, memory discipline is a first-class security control.

Minimize the in-memory lifetime of secrets and wipe sensitive buffers immediately after use. Avoid unnecessary copies of key material, and pass references or opaque handles where practical. Disable core dumps and similar diagnostics on systems that process secrets in production. Use static and dynamic analysis to detect buffer misuse and undefined behavior, and ensure logs, crash reports, and telemetry redact secret-containing fields by default.

## Build and deployment

Build and release choices have direct security impact. Compiler warnings, sanitizer coverage, and reproducible release processes help prevent vulnerable artifacts from reaching production. Security hardening should be applied consistently across CI and local release workflows.

Build with warnings enabled and fix or document any suppressions. For additional hardening, consider `-DWARNINGS_AS_ERRORS=ON`, release builds with optimizations, and removal of debug symbols from production binaries when operationally appropriate.

For API details, see the [Crypto API](/docs/api).

## Security reporting and lifecycle

- Use private reporting channels for suspected vulnerabilities.
- Include affected version(s), deployment context, and minimal reproduction data in reports.
- Prepare coordinated fixes across code, tests, and docs/release notes.
- Publish mitigations and affected-range guidance once patches are available.

See:

- [Security Reporting](/docs/next/security-reporting)
- [Release Notes](/docs/release-notes)
