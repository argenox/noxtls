# NoxTLS ESP-IDF examples

Each subdirectory is a standalone ESP-IDF project (TLS client/server, HTTPS, OTA, benchmarks, etc.).

> **Note:**  
> Currently, **only the `https_server` example is fully functional**.  
> All other examples are **work in progress** and may not build or run correctly yet.


## NoxTLS dependency (local vs registry)

Examples use **two modes** with no duplicate port tree:

| Where you build | How NoxTLS is resolved |
|-----------------|------------------------|
| **In the NoxTLS repo** (`ports/esp-idf/examples/...`) | CMake detects `ports/esp-idf` one level above `examples/` and adds it via `EXTRA_COMPONENT_DIRS`. You build against the current branch. |
| **Copied elsewhere / release zip** | `main/idf_component.yml` declares **`argenox/noxtls`** (`^0.2.55`); Component Manager downloads it into `managed_components/`. |

In-repo sources do **not** commit `main/idf_component.yml` (that would fetch the registry in parallel). The release zip injects the manifest when packaging.

Requires ESP-IDF **5.0+** or **6.x** with the component manager enabled for standalone builds.

## Build (in repo)

```sh
cd ports/esp-idf/examples/<example>
idf.py set-target esp32s3
idf.py build flash monitor
```

## Build (standalone copy or release zip)

```sh
cd <example>
idf.py set-target esp32s3
idf.py build flash monitor
```

## Adding a new example

1. Include `../noxtls_example_project.cmake` in the project `CMakeLists.txt` before `project()`.
2. Use `REQUIRES esp-idf` in `main/CMakeLists.txt` (in-repo component name).
3. For standalone packaging, the release script copies `idf_component.yml.standalone` into `main/` as `idf_component.yml`.
