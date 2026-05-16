---
sidebar_position: 11
title: Contributing
description: "NoxTLS documentation: Contributing."
---

# Contributing

## Code and documentation contributions

- Open issues/PRs in the [noxtls GitHub repository](https://github.com/argenox/noxtls).
- Keep API docs aligned with exported headers and behavior.
- Include tests for new crypto/TLS paths where practical.

## Documentation standards

- Update relevant guides and API pages in the same change as implementation updates.
- For new feature gates, update:
  - configuration/build docs
  - API module pages
  - release notes/changelog
- Keep cross-links between TLS, PKC, cert, and build-config pages current.

## Documentation versioning

For release snapshots and docs-version workflow, see:

- [`docs/VERSIONING.md`](https://github.com/argenox/noxtls/blob/main/noxtls/docs/VERSIONING.md)
- [`docs/changelog.json`](https://github.com/argenox/noxtls/blob/main/noxtls/docs/changelog.json)

## Review checklist

- Build succeeds for relevant profiles and platforms.
- New feature toggles are documented.
- Security-sensitive behavior changes are called out in release notes.
- API references and examples match current symbols and signatures.
