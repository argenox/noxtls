---
sidebar_position: 9
title: Documentation Parity Matrix
---

# Documentation Parity Matrix

This matrix tracks documentation coverage for the `noxtls` surface area and parity targets relative to a full cryptography/TLS docs hub model.

## Coverage Baseline

- Scope: current docs tree (`docs/docs`) only.
- Source of truth for API surface: headers and implementation in `noxtls-lib`.
- Parity model: complete API families + user guides + project/security/process pages, adapted to `noxtls`.

## Module Coverage Matrix

| Area | Implemented in code | Current docs | Gap status |
| --- | --- | --- | --- |
| TLS 1.0/1.1/1.2/1.3 and DTLS | `noxtls-lib/tls/*` | `api/tls*.md`, `api/dtls*.md`, `tls.md`, `dtls13.md` | Good (0.2.4: DTLS 1.3 docs, DTLS API group, and PQC in `tls13_pqc`) |
| X.509 / certificate parse + verify | `noxtls-lib/certs/noxtls_x509.*` | `api/certs.md` | Partial (ML-DSA cert/signature handling not documented) |
| Symmetric encryption | `noxtls-lib/encryption/*` | `api/encryption.md` + algorithm pages | Covered |
| Hash / digest / SHA-3 | `noxtls-lib/mdigest/*` | `api/mdigest.md` + algorithm pages | Covered |
| DRBG | `noxtls-lib/drbg/*` | `api/drbg.md` | Covered |
| Classical PKC (RSA/ECC/DSA/DH/X25519/X448/EdDSA) | `noxtls-lib/pkc/*` | `api/pkc.md` + algorithm pages | Partial (hub page outdated) |
| ML-KEM (FIPS 203) | `noxtls-lib/pkc/mlkem/*` | none | Missing |
| ML-DSA (FIPS 204) | `noxtls-lib/pkc/mldsa/*` | none | Missing |
| TLS 1.3 PQ groups/signatures | `noxtls-lib/tls/noxtls_tls_common.h`, `noxtls_tls13.*` | `api/tls13.md` | Missing dedicated section/page |
| Build/profile/feature checks | `CMakeLists.txt`, `noxtls_check_config.h` | `configuration-guide.md`, `api/build_config.md`, `BUILDING.md` | Partial (ML-KEM/ML-DSA deps/profiles incomplete) |
| Applications | `applications/*` | `docs/applications/*` | Covered (cross-links can improve) |

## High-Priority Gaps

1. Add first-class PQC API docs for ML-KEM and ML-DSA.
2. Add TLS 1.3 PQ integration page (named groups, hybrid groups, signature schemes, setup APIs).
3. Update PKC/TLS13/certs/build configuration docs to include PQC feature gates and dependencies.
4. Add full-hub support pages for project/process/security-reporting navigation.
5. Reconcile release metadata and versioning guidance with current releases and recent changes.

## Parity Completion Criteria

Documentation parity for this pass is considered complete when:

- Every implemented crypto family has at least one discoverable top-level API page.
- PQC is documented in PKC, TLS, certs, and build/config guides with working cross-links.
- Site navigation includes user docs, API docs, project/process pages, and security reporting paths.
- Release notes and changelog reflect recent platform/security/PQC work in consistent format.
- Docs build passes and internal links resolve without warnings promoted to errors.
