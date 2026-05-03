# API page overrides

Markdown files in this folder are **prepended** to the corresponding generated API page when you run `scripts/generate-api-docs-from-source.js`.

- **File name** must match the API page slug, e.g. `md4.md` → content is added to `docs/docs/api/md4.md`.
- **Content** is inserted after the page title and before the "## API" section. Use it for module-level description, security notes, or usage guidance.
- **Not overwritten**: Only the override file is edited by you; the generator merges it into the page and regenerates the function list below.

## Example

To add intro text for the MD4 page:

1. Edit or create `docs/api-page-overrides/md4.md`.
2. Run the doc generator. The generated `docs/docs/api/md4.md` will contain your content followed by the API section.

Supported slugs (message digest, encryption, etc.) are those used in the generator's subgroup config (e.g. `md4`, `md5`, `sha256`, `aes`, `blake2`, `ripemd160`, …). Use the same slug as the generated filename without `.md` if in doubt.
