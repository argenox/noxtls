# Documentation versioning

The docs site supports multiple versions so users can view documentation for the latest release and for older releases.

## For visitors

Use the **version dropdown** in the top-right of the documentation navbar to switch between:

- **Next** — current (unreleased) docs from the default branch
- **X.Y.Z** — snapshot of the docs at that release (e.g. 0.1.6)

## For maintainers: adding a new version

When you release a new version (e.g. `v0.1.6`):

1. **Release notes:** Add an entry for the new version in `docs/changelog.json` (see `releases[]` with `version`, `date`, `changes`, `fixed`, `known_issues`). From the repo root, generate per-version release notes:

   ```bash
   node scripts/generate-release-notes.js .
   ```

   This writes `docs/release-notes.md` (latest version) and `versioned_docs/version-<X.Y.Z>/release-notes.md` for each version, so each doc set shows only that version’s release notes.

2. From the repo root, ensure the docs are up to date (Doxygen + convert script if needed), then:

   ```bash
   cd docs
   npm run docs:version 0.1.6
   ```

3. This creates:
   - `versioned_docs/version-0.1.6/` — copy of current `docs/` content (including the generated release-notes.md for latest)
   - `versioned_sidebars/version-0.1.6-sidebars.json`
   - Updates `versions.json` (new version at the top)

   **Note:** After adding a new version, run `node scripts/generate-release-notes.js .` again so that `versioned_docs/version-0.1.6/release-notes.md` is filled with 0.1.6-specific content from the changelog (the copy from step 2 will have had the previous “latest” content).

4. Commit and push:

   ```bash
   git add versioned_docs versioned_sidebars versions.json docs/release-notes.md docs/changelog.json
   git commit -m "Docs: add version 0.1.6"
   git push
   ```

5. On the next deploy, the dropdown will list **0.1.6** (and any older versions already in `versions.json`).

Use the same version number as the library release (e.g. from `noxtls_version.h` or the release tag).
