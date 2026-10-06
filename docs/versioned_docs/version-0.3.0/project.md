---
sidebar_position: 10
title: Project
description: "NoxTLS documentation: Project."
---

# Project

This page summarizes project-level information for `noxtls`: release model, maintenance workflow, and documentation lifecycle.

## Release model

- Source of truth for releases: [GitHub Releases](https://github.com/argenox/noxtls/releases)
- Current docs are maintained in the default docs tree (`docs/docs`).
- Versioned snapshots are created after release documentation is finalized.

## Documentation lifecycle

1. Update docs for code changes (APIs, guides, release notes).
2. Run docs build and link checks.
3. Update `docs/changelog.json`.
4. Generate release notes content.
5. Create version snapshot for the release.

See [`docs/VERSIONING.md`](https://github.com/argenox/noxtls/blob/master/docs/VERSIONING.md) (maintainer workflow) and [Release Notes](/docs/release-notes).

## Scope areas

- TLS/DTLS protocol stack
- X.509 and certificate tooling
- Symmetric and message-digest primitives
- PKC including classical and post-quantum (ML-KEM / ML-DSA)
- Embedded integration and applications
