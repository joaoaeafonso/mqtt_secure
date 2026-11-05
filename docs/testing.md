# Testing and verification

| Level | Tool | Location | Run |
|---|---|---|---|
| C++ unit + integration | GoogleTest | `tests/` | `ctest --preset dev` |
| Cross-language vectors | GoogleTest + unittest | `tests/vectors/envelope_vectors.txt` | both suites |
| Python unit | unittest | `tools/loadgen/tests/`, `tools/analysis/tests/` | see below |
| Wireshark tooling | unittest + tshark (+ mosquitto) | `tools/loadgen/tests/test_wireshark.py` | see below |
| Fuzzing | libFuzzer + ASan/UBSan | `fuzz/` | `fuzz` preset |
| Static analysis | clang-tidy | `.clang-tidy` | `ci` preset |
| Memory / UB | ASan + UBSan | | `dev` preset |
| Data races | ThreadSanitizer | | `tsan` preset |
| System / attack | load-lab scenarios against Mosquitto | `tools/loadgen/scenarios.py` | `loadgen.py scenarios` |
| Smoke | demo exit status | `apps/gateway` | `msec_gateway_demo` |
| Performance | Google Benchmark | `benchmarks/` | see [benchmarks.md](benchmarks.md) |

## C++ test suites

`tests/test_support.hpp` provides `msec::test::FakeClock` (fixed start,
`advance(ms)`), `test::topic(name)` and `test::message(topic, payload)`.

| Executable | Tests | Covers |
|---|---|---|
| `core_tests` | 9 | `Topic` validation; `SecureBuffer` move; `secure_zero`; pipeline direction order, failure stops and names the layer, null/duplicate rejection; `SwitchableLayer` pass-through and renaming |
| `mqtt_tests` | 8 | topic filter matching (incl. `$SYS`, parent level) and validation; loopback routing; ACL deny-by-default and per-client rules; ACL blocks publishes; `#` subscriber only receives readable topics; publish requires connection |
| `data_tests` | 4 | ring-buffer eviction; find by topic; persistence config; factory validation |
| `limits_tests` | 7 | unlimited by default; burst then refill; independent topic budgets; outbound never limited; runtime rate change; bounded memory under topic flood; factory validation |
| `acceptance_tests` | 17 | the receiver's acceptance rules (report §6): one test per row of the verification order (each breaks two rules and checks which rejection wins), window limits and reordering, mode policy, key → topic with `%u`, Δa/Δs at their (inclusive) limits, per-flow validity, dependency validation, restart rule and `FileEpochStore`. Each test was checked to fail when its rule is removed or moved in `security_layer.cpp` |
| `security_tests` | 46 | envelope; replay guard; AES-GCM; ChaCha20-Poly1305 (RFC 8439 §2.8.2 vector, neither algorithm opens the other's output, one receiver serves both, unconfigured algorithm, duplicate cipher); security layer (confidentiality, tampering, header, topic rebinding, replay, expiry, future, revocation, plaintext injection, rotation, sequence/nonce, auth-only, mode policy, authenticated mode, ablation switches, runtime switching); cross-language vectors; factory; RFC 8032 vector; key → topic policy; signatures; key binding and replay-window interaction |
| `integration_tests` | 2 | full stack sensor → loopback broker → gateway `[persistence, security]`: delivers and stores plaintext; attacker cannot replay (`ReplayDetected`) or inject (`MalformedMessage`) and the rejection observer sees the topic |

`security_tests` and `integration_tests` require `MSEC_WITH_OPENSSL`. The
vectors path is compiled in as `MSEC_ENVELOPE_VECTORS`.

Determinism: time comes from `FakeClock`; for the vector test, randomness from
a `FixedRandom` that repeats a given byte string. Only key generation in some
tests uses the real CSPRNG, which does not affect assertions.

## Cross-language test vectors

`tests/vectors/envelope_vectors.txt` holds seven vectors (`encrypt_short`,
`encrypt_empty`, `auth_only`, `sign`, `sign_binary` — the last with key id
2³²−1 and binary payload — and `encrypt_chacha20`, `auth_only_chacha20`, the
same envelope format with a ChaCha20-Poly1305 key). The C++ test seals each with the fixed key, nonce,
timestamp and sequence 1 and compares **byte for byte**, then opens the
expected envelope; the Python test reproduces every envelope with
`Protector`. Neither implementation can drift without breaking a test. Format:
[protocol spec §6](protocol/envelope-format.md#6-test-vectors-file-format).

## Python tests

```bash
tools/loadgen/.venv/bin/python -m unittest discover -s tools/loadgen/tests -t tools/loadgen
tools/loadgen/.venv/bin/python -m unittest discover -s tools/analysis/tests -t tools/analysis
```

The lab tests include the dependency rules (`payload.protection = none` with a
check on is refused), K11 and the attacker settings' prerequisites; the
analysis tests run `analyze.py` on a synthetic campaign (bootstrap, marginal
cost, S(c), cost(c), use-case filter, Pareto frontier, c*, feasibility and the
PROVISIONAL flag).

31 tests across `test_envelope.py`, `test_lab_config.py`, `test_pki.py` and
`test_wireshark.py` (details in
[loadgen/components.md](loadgen/components.md#tests-toolsloadgentests)). The
first three need no broker (the passwd/CRL test is skipped without
`mosquitto_passwd`). `test_wireshark.py` needs `tshark` (or `TSHARK=/path`);
its TLS tests also need mosquitto and the bench build's
`libmsec_sslkeylog.so`. Missing tools mean skipped tests, not failures. See
[network-analysis.md §10](network-analysis.md#10-verification).

## Fuzzing

Build with the `fuzz` preset (Clang + `libclang-rt-18-dev`):

```bash
cmake --preset fuzz && cmake --build --preset fuzz
./build/fuzz/fuzz/fuzz_envelope         fuzz/corpus/envelope -max_total_time=60
./build/fuzz/fuzz/fuzz_security_inbound fuzz/corpus/envelope -max_total_time=60
./build/fuzz/fuzz/fuzz_topic            fuzz/corpus/topic    -max_total_time=60
```

| Target | Input | Oracle (abort ⇒ bug) |
|---|---|---|
| `fuzz_envelope` | arbitrary bytes → `envelope::parse` | never crashes; every accepted input must re-serialize to exactly the same bytes |
| `fuzz_topic` | bytes split at the first NUL into filter and topic | `Topic::create` round-trips its input; a valid topic name used as a filter matches itself; no crash in validation/matching |
| `fuzz_security_inbound` | arbitrary payload on `open/sensors/sensor-7/temp` into a `SecurityLayer` accepting **all three modes**, key binding on, keys 0 and 7 known, fixed clock | **nothing may be accepted** — forging a GCM tag or Ed25519 signature by chance is not something a fuzzer can do |

Seeds: `fuzz/corpus/envelope/*.bin` are the five test-vector envelopes;
`fuzz/corpus/topic/seed*` are filter/topic pairs (e.g.
`+/sensors/#\0open/sensors/sensor-1/temp`).

## Sanitizers and races

- `dev`: ASan + UBSan with `-fno-sanitize-recover=all` — any finding fails the
  test.
- `tsan`: `cmake --preset tsan && cmake --build --preset tsan && setarch $(uname -m) -R ctest --preset tsan`
  (GCC 13's TSan fails with "unexpected memory mapping" on kernels with high
  mmap randomisation).

## System scenarios

`loadgen.py scenarios` is the end-to-end regression test: real Mosquitto, the
real C++ gateway over Paho, real TLS, Python sensors and attacker. CI runs it
with 10 sensors at 10 msg/s. See [loadgen/scenarios.md](loadgen/scenarios.md).

## Adding tests

- C++: add `TEST`/`TEST_F` to the matching `tests/*_tests.cpp`, or a new file
  registered with `msec_add_test` in `tests/CMakeLists.txt`.
- Inject `FakeClock`, a fixed RNG, and `LoopbackBroker` rather than sleeping or
  using the network.
- If you change the envelope, regenerate the vectors with the Python
  `Protector` (fixed clock/random/sequence 0), update both implementations,
  and bump the version byte if the change is incompatible.
