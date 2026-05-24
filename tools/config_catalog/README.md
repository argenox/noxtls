# NoxTLS configuration catalog

Machine-readable inventory of all settings in `noxtls/noxtls_config.h`, maintained as
`noxtls/noxtls_config_catalog.xml`.

## Files

| File | Role |
|------|------|
| `generate_config_catalog.py` | Parses the header, merges overlays, writes XML |
| `config_catalog_overrides.json` | Manual names, legacy flags, constraints, parent links |
| `noxtls_config_catalog.xml` | Generated catalog (checked into repo root under `noxtls/`) |

## Regenerate

From the repository root:

```bash
python noxtls/tools/config_catalog/generate_config_catalog.py
```

## Validate (CI-friendly)

```bash
python noxtls/tools/config_catalog/generate_config_catalog.py --check
```

Checks:

- Every `NOXTLS_*` setting from the header appears in the XML
- Catalog `version` matches `noxtls_version.h`
- Dependency `ref` attributes point at known setting IDs

## Workflow

1. Edit `noxtls_config.h` (defaults, comments, profile presets).
2. Adjust `config_catalog_overrides.json` when automation cannot infer friendly metadata
   (legacy classification, `atLeastOneEnabled` constraints, parent component links).
3. Run the generator and commit both the script output and any overlay changes.

## XML schema (summary)

```xml
<noxtls-config-catalog version="0.2.25">
  <metadata>...</metadata>
  <profiles><profile id="..." name="...">...</profile></profiles>
  <categories>
    <category id="tls" name="TLS / DTLS">
      <setting id="NOXTLS_FEATURE_TLS" type="boolean" default="enabled" legacy="false">
        <description>...</description>
        <dependencies><allOf><dependency ref="..." value="1"/></allOf></dependencies>
        <constraints>...</constraints>
        <profile-overrides><override profile="..." value="disabled"/></profile-overrides>
        <suboptions>
          <setting id="NOXTLS_FEATURE_TLS13" .../>
        </suboptions>
      </setting>
    </category>
  </categories>
</noxtls-config-catalog>
```
