# Build system

CMake ≥ 3.25 with Ninja, driven by presets. In-source builds are refused.

## Layout

| File | Role |
|---|---|
| `CMakeLists.txt` | project (`mqtt_secure` 0.1.0, C++23, no extensions, `compile_commands.json`), options, `find_package`, module/app/test/bench/fuzz subdirectories |
| `cmake/ProjectOptions.cmake` | `msec::project_options` INTERFACE target: warnings, hardening, sanitizers |
| `cmake/StaticAnalysis.cmake` | clang-tidy command line (`MSEC_CLANG_TIDY_COMMAND`) |
| `cmake/MsecModule.cmake` | `msec_add_module()`, `msec_add_test()` |
| `CMakePresets.json` | configure/build/test presets |
| `modules/*/CMakeLists.txt` | one `msec_add_module` call each |
| `apps/*/CMakeLists.txt` | executables (skip themselves if a back-end is disabled) |
| `tests/`, `benchmarks/`, `fuzz/` `CMakeLists.txt` | GoogleTest, Google Benchmark, libFuzzer targets |

## Options

| Option | Default | Effect |
|---|---|---|
| `MSEC_WARNINGS_AS_ERRORS` | ON | `-Werror` / `/WX` |
| `MSEC_ENABLE_SANITIZERS` | OFF | ASan + UBSan, `-fno-sanitize-recover=all` |
| `MSEC_ENABLE_TSAN` | OFF | ThreadSanitizer (fatal error if combined with the above) |
| `MSEC_ENABLE_CLANG_TIDY` | OFF | run clang-tidy on first-party modules, warnings as errors |
| `MSEC_ENABLE_HARDENING` | ON | stack protector, frame pointers, `_FORTIFY_SOURCE=3` (non-Debug), `_GLIBCXX_ASSERTIONS`, full RELRO, `-z now`, `-z noexecstack` |
| `MSEC_BUILD_TESTS` | ON | `tests/` |
| `MSEC_BUILD_APPS` | ON | `apps/gateway`, `apps/load_gateway` |
| `MSEC_BUILD_BENCHMARKS` | OFF | `benchmarks/` (requires OpenSSL) |
| `MSEC_BUILD_FUZZERS` | OFF | `fuzz/` (requires Clang); adds `-fsanitize=fuzzer-no-link` to every first-party target |
| `MSEC_WITH_OPENSSL` | ON | `find_package(OpenSSL 3.0 REQUIRED)`; builds `openssl/` sources; needed by the apps, security/integration tests, benchmarks |
| `MSEC_WITH_PAHO` | ON | `find_package(PahoMqttCpp REQUIRED)`; builds `paho_client.cpp`; needed by `msec_load_gateway` |

## Presets

All configure into `build/<preset>` with Ninja.

| Preset | Build type | Adds | Use |
|---|---|---|---|
| `dev` | Debug | ASan + UBSan | daily development; `ctest --preset dev` |
| `tsan` | Debug | ThreadSanitizer | data-race checks (GCC 13: run under `setarch $(uname -m) -R`) |
| `release` | RelWithDebInfo | hardening only | |
| `bench` | RelWithDebInfo | benchmarks on, tests off | benchmarks and the load-lab gateway |
| `ci` | RelWithDebInfo (inherits release) | clang-tidy | static analysis gate |
| `fuzz` | RelWithDebInfo, `clang++` | ASan/UBSan, fuzzers on; tests, apps, Paho off | libFuzzer |

```bash
cmake --preset dev && cmake --build --preset dev && ctest --preset dev
cmake --preset bench && cmake --build --preset bench
cmake --preset fuzz && cmake --build --preset fuzz
```

Test presets exist for `dev`, `tsan`, `ci` (with `outputOnFailure`).

## `msec::project_options`

An INTERFACE library carrying every project-wide compile/link policy. Each
first-party target links it **PRIVATE**, so the flags never leak into
third-party code (GoogleTest, OpenSSL, Paho, Google Benchmark).

Warnings (GCC and Clang): `-Wall -Wextra -Wpedantic -Wshadow -Wconversion
-Wsign-conversion -Wold-style-cast -Wcast-align -Wnon-virtual-dtor
-Woverloaded-virtual -Wnull-dereference -Wdouble-promotion -Wformat=2
-Wimplicit-fallthrough -Wunused -Wmissing-declarations`; GCC additionally
`-Wduplicated-cond -Wduplicated-branches -Wlogical-op -Wuseless-cast`. MSVC:
`/W4 /permissive- /utf-8`.

## `msec_add_module`

```cmake
msec_add_module(
    NAME         <name>          # target msec_<name>, alias msec::<name>
    SOURCES      <files…>
    PUBLIC_DEPS  <targets…>      # exposed through this module's headers
    PRIVATE_DEPS <targets…>)     # implementation detail (e.g. OpenSSL::Crypto)
```

Sets the include directory `modules/<name>/include` (build interface),
`cxx_std_23`, PIC, links `msec::project_options` privately, and attaches
clang-tidy when enabled. Every module follows:

```
modules/<name>/include/msec/<name>/*.hpp   public API
modules/<name>/src/*.cpp                   implementation
```

Back-ends are private dependencies, so consumers of `msec::security` never see
OpenSSL headers and consumers of `msec::mqtt` never see Paho headers
(`paho_client.hpp` forward-declares Paho's classes).

`msec_add_test(NAME … SOURCES … DEPS …)` builds an executable linked with
`GTest::gtest_main` and registers it with `gtest_discover_tests` (30 s
discovery timeout).

## Third-party dependencies

| Dependency | How | Version |
|---|---|---|
| OpenSSL | system (`find_package`) | ≥ 3.0 |
| Eclipse Paho MQTT C++ | system (`libpaho-mqttpp-dev`) | 1.2 tested (see token workaround) |
| GoogleTest | system ≥ 1.14 if found, else `FetchContent` v1.15.2, SHA-256 pinned | |
| Google Benchmark | system ≥ 1.8 if found, else `FetchContent` v1.9.1, SHA-256 pinned | |
| clang-tidy | system, CI uses 18 | |
| libFuzzer | Clang + `libclang-rt-18-dev` | |

## Static analysis

`.clang-tidy` enables `bugprone-*`, `cert-*`, `clang-analyzer-*`,
`concurrency-*`, `cppcoreguidelines-*`, `misc-*`, `modernize-*`,
`performance-*`, `readability-*` minus a few noisy checks (trailing return
types, identifier length, magic numbers, include cleaner, non-private members,
redundant member init). All warnings are errors. Header filter:
`modules/.*/include/msec/.*`. Naming rules: classes `CamelCase`, functions and
variables `lower_case`, private members suffix `_`, constants `kCamelCase`,
enum values `CamelCase`. `(void)f()` is accepted as "result intentionally
ignored".

clang-tidy parses the GCC command line with Clang, hence the extra arguments
in `StaticAnalysis.cmake`: `-Wno-unknown-warning-option` (GCC-only warnings)
and `-D__cpp_concepts=202002L -Wno-builtin-macro-redefined` (libstdc++ 13 only
exposes `std::expected` when `__cpp_concepts >= 202002L`, which Clang 18
implements but does not advertise). The `fuzz` preset passes the same define.

## Formatting

`.clang-format`: Google style, 100 columns, 4-space indent, access modifiers
at −4, left-aligned pointers, regrouped includes.

## Continuous integration

`.github/workflows/ci.yml`, on push to `master`/`develop` and on pull
requests, Ubuntu 24.04:

| Job | Steps |
|---|---|
| `build-and-test` | apt deps (cmake, ninja, g++, libssl, paho, gtest, mosquitto, python3-venv) → `dev` build + ctest → venv + Python unit tests → `bench` build + `loadgen.py scenarios --set load.sensors=10 --set load.rate=10 --settle 3 --duration 5` |
| `clang-tidy` | `ci` preset build + ctest with clang-tidy 18 |
| `fuzz` | `fuzz` preset with clang++-18 → `fuzz_envelope` and `fuzz_security_inbound` on `fuzz/corpus/envelope`, `fuzz_topic` on `fuzz/corpus/topic`, 60 s each |

## Build outputs

| Path | Content |
|---|---|
| `build/dev/apps/gateway/msec_gateway_demo` | demo |
| `build/bench/apps/load_gateway/msec_load_gateway` | load-lab gateway (what `run.sh` and `loadgen.py` use) |
| `build/bench/benchmarks/msec_pipeline_benchmarks` | benchmarks |
| `build/fuzz/fuzz/fuzz_*` | fuzzers |
| `build/loadtest/` | matrix/scenario results, controller state |
