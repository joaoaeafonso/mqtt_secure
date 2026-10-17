# Getting started

## 1. Prerequisites

| Tool | Version | Ubuntu 24.04 package |
|---|---|---|
| CMake | ≥ 3.25 | `cmake` |
| Ninja | | `ninja-build` |
| C++ compiler | GCC ≥ 13 or Clang ≥ 17 | `g++` |
| OpenSSL | ≥ 3.0 | `libssl-dev` |
| Eclipse Paho MQTT C/C++ | | `libpaho-mqtt-dev libpaho-mqttpp-dev` (or build with `-DMSEC_WITH_PAHO=OFF`) |
| GoogleTest (optional) | ≥ 1.14 | `libgtest-dev` (otherwise fetched, hash-pinned) |
| Mosquitto (load lab) | 2.0.x | `mosquitto` (provides `mosquitto_passwd`) |
| Python (load lab) | ≥ 3.11 | `python3-venv` |
| Clang + libFuzzer (fuzzing) | 18 | `clang-18 libclang-rt-18-dev` |
| clang-tidy (CI preset) | 18 | `clang-tidy-18` |
| Wireshark / tshark (captures, optional) | ≥ 3.6 | `wireshark tshark` — see [network-analysis.md](network-analysis.md) |

```bash
sudo apt-get install -y cmake ninja-build g++ libssl-dev libpaho-mqtt-dev \
    libpaho-mqttpp-dev libgtest-dev mosquitto python3-venv
```

## 2. Build and test

```bash
cmake --preset dev            # Debug + ASan/UBSan into build/dev
cmake --build --preset dev
ctest --preset dev            # 69 C++ tests
./build/dev/apps/gateway/msec_gateway_demo   # narrated demo; exit 0 = all checks passed
```

Other presets: `tsan`, `release`, `bench`, `ci`, `fuzz` — see
[build-system.md](build-system.md).

## 3. Start the live lab in one command

```bash
./run.sh                       # 100 sensors, dashboard at http://127.0.0.1:8088/
./run.sh --preset hardened     # every defence on
./run.sh --set load.sensors=500 --set transport.mode=tls
```

`run.sh` checks for `cmake`, `ninja`, `python3`, `mosquitto`,
`mosquitto_passwd`; configures the `bench` preset if needed; builds
`msec_load_gateway` and the TLS key-log shim; creates `tools/loadgen/.venv` and installs
`requirements.txt` if needed; then runs `loadgen.py live` with
`lab.example.toml`, 100 sensors and `--open`. Ctrl-C stops broker, gateway,
sensors and attacker.

## 4. Things to try on the dashboard

1. With the defaults (plain transport, ACL on, restricted zone, `encrypt`):
   the attacker is connected but "Eavesdropped" is 0 — the ACL hides the zone.
2. **Load → zone `open/`**: Eavesdropped jumps to the full rate, but payloads
   are ciphertext.
3. **Attacker → Inject forged = 20**: "Gateway rejections" shows
   `Malformed / not an envelope`; "Forged accepted" stays 0.
   **Payload → Protection None**: "Forged accepted" rises.
4. **Attacker → Replay captured = 20** with **Replay protection off** and
   **Freshness on**: replays are accepted — freshness alone is not enough.
5. **Transport → Authentication on**, **Attacker → Impersonate gateway**: the
   attacker is refused; sensors are unaffected (they always send credentials).
6. **Payload → Sign**: watch the gateway CPU chart.
7. **Rotate** keys; **Revoke** a sensor.
8. **Harden**: everything on at once.

Every change is marked on the charts and listed under "Changes". Add
`--capture` to also record everything for Wireshark, decryptable and
annotated with the same changes ([network-analysis.md](network-analysis.md)).

## 5. Run the experiments non-interactively

```bash
venv=tools/loadgen/.venv/bin/python
$venv tools/loadgen/loadgen.py scenarios --set load.sensors=20         # PASS/FAIL table
$venv tools/loadgen/loadgen.py matrix --vary payload.protection=none,auth_only,encrypt,sign
```

Results go to `build/loadtest/`.

## 6. Benchmarks and fuzzing

```bash
cmake --preset bench && cmake --build --preset bench
./build/bench/benchmarks/msec_pipeline_benchmarks --benchmark_counters_tabular=true

cmake --preset fuzz && cmake --build --preset fuzz
./build/fuzz/fuzz/fuzz_security_inbound fuzz/corpus/envelope -max_total_time=60
```

## 7. Using the libraries in your own gateway

```cpp
#include "msec/core/clock.hpp"
#include "msec/mqtt/endpoint.hpp"
#include "msec/mqtt/paho/paho_client.hpp"
#include "msec/security/key_store.hpp"
#include "msec/security/openssl/aes_gcm_cipher.hpp"
#include "msec/security/openssl/random_source.hpp"
#include "msec/security/security_layer.hpp"

using namespace msec;

auto keys = std::make_shared<security::InMemoryKeyStore>();
(void)keys->add(1, SecureBuffer{/* 32-byte key from your provisioning */});

auto security = security::SecurityLayer::create(
    {.sending_key_id = 1},
    {.cipher = std::make_shared<security::openssl::AesGcmCipher>(),
     .key_store = keys,
     .random = std::make_shared<security::openssl::RandomSource>(),
     .clock = std::make_shared<SystemClock>()});
if (!security) { /* handle security.error() */ }

auto pipeline = Pipeline::Builder{}.add(std::move(*security)).build();
mqtt::Endpoint endpoint{std::make_shared<mqtt::paho::PahoClient>(), std::move(*pipeline),
                        std::make_shared<ConsoleLogger>()};

endpoint.on_message([](const Message& m) { /* plaintext, verified */ });
endpoint.on_rejected([](const mqtt::Endpoint::Rejected& r, const Error& e) { /* metrics */ });

mqtt::ConnectionOptions options{.broker_uri = "ssl://broker.local:8883", .client_id = "gateway",
                                .tls = mqtt::TlsOptions{.ca_file = "ca.crt"}};
if (auto ok = endpoint.start(options); !ok) { /* … */ }
(void)endpoint.subscribe("sensors/#", QoS::AtLeastOnce);
(void)endpoint.publish(Message{.topic = *Topic::create("actuators/door/cmd"),
                               .payload = to_bytes("open")});
```

Link against `msec::mqtt msec::security` (plus `msec::data` / `msec::limits`
if used). See [extending.md](extending.md) for adding layers and back-ends.
