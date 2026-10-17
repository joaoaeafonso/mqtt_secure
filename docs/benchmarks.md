# Benchmarks

**Source:** `benchmarks/pipeline_benchmarks.cpp` · **Target:**
`msec_pipeline_benchmarks` · **Preset:** `bench`

Measures the **end-to-end CPU cost of each security level** over the
in-process loopback broker, and — in the same row — **what that level buys**
against a set of attacks.

```bash
cmake --preset bench && cmake --build --preset bench
./build/bench/benchmarks/msec_pipeline_benchmarks --benchmark_counters_tabular=true
# stable numbers
./build/bench/benchmarks/msec_pipeline_benchmarks --benchmark_repetitions=10 --benchmark_report_aggregates_only=true
# machine-readable
./build/bench/benchmarks/msec_pipeline_benchmarks --benchmark_out=results.json --benchmark_out_format=json
# a subset
./build/bench/benchmarks/msec_pipeline_benchmarks --benchmark_filter='restricted/6_full'
```

## What one iteration is

```
sensor.publish ─▶ [sensor pipeline] ─▶ LoopbackBroker (ACL?) ─▶ [gateway pipeline] ─▶ app handler
                                                            └─▶ eavesdropper subscribed to '#'
```

The loopback transport is synchronous, so one iteration is one complete
publish → deliver round trip. No network, no TLS, no broker process: the
numbers isolate the **CPU cost of the layers**. TLS, broker authentication and
network latency are measured by the load lab instead.

An eavesdropper (`mallory`) stays subscribed to `#` during the timed loop, so
wildcard fan-out is part of the cost wherever the ACL lets it through. If any
message fails to reach the application, the run is marked as an error.

## Axes

Benchmark name: `<zone>/<profile>/payload:<bytes>`.

### Zones

| Zone | Broker | Topic |
|---|---|---|
| `noacl` | no ACL | `open/sensors/room1/temp` |
| `open` | ACL; `open/#` readable & writable by all | `open/sensors/room1/temp` |
| `restricted` | ACL; only `sensor-1` writes `restricted/sensors/room1/#`, only `gateway` reads | `restricted/sensors/room1/temp` |

### Profiles

Ordered from no protection to full protection; each step adds one guarantee.

| Profile | Gateway pipeline | `SecurityConfig` | Adds |
|---|---|---|---|
| `0_baseline` | none | — | — |
| `1_persistence_only` | `[persistence]` | — | storage cost |
| `2_auth_only` | `[security]` | AuthenticateOnly, no freshness, no replay | integrity + topic binding (GMAC), payload readable |
| `3_aead` | `[security]` | Encrypt, no freshness, no replay | + confidentiality |
| `4_aead_freshness` | `[security]` | + freshness | stale-message rejection |
| `5_aead_replay` | `[security]` | replay only | replay rejection |
| `6_full` | `[security]` | defaults | everything |
| `7_full_persist_plain` | `[persistence, security]` | defaults | stores plaintext |
| `8_full_persist_at_rest` | `[security, persistence]` | defaults | stores envelopes |
| `9_sign` | `[security]` | Sign (Ed25519) | proof of origin; payload readable |
| `10_full_key_binding` | `[security]` + `KeyTopicPolicy` (key 1 → `+/sensors/room1/#`) | defaults | a key may only publish on its owner's topics |

The sensor pipeline is the same minus persistence.

### Payload sizes

16 B, 256 B, 4 KiB, 64 KiB (deterministic pseudo-random content).

## Counters per row

Before timing, each run is **attacked once** (`probe`): the eavesdropper
records three messages, then each attack is published by the attacker client.

| Counter | Meaning |
|---|---|
| `items_per_second`, `bytes_per_second` | throughput |
| `wire_B` | bytes on the wire for one message (measured on a separate pipeline) |
| `overhead_B` | `wire_B − payload` (53 for AEAD modes, 89 for sign) |
| `leak` | fraction of timed messages the `#` subscriber received |
| `confid` | 1 if the captured payload does not contain the plaintext |
| `replay` | 1 if re-publishing a captured message was stopped |
| `tamper` | 1 if a captured message with its last byte flipped was stopped |
| `rebind` | 1 if a captured message re-published on `…/room2/temp` was stopped |
| `inject` | 1 if a freshly made plaintext message was stopped |
| `by_acl` | how many of the 4 attacks the broker stopped before the gateway pipeline was involved (publish denied, or no captured material because the ACL hid the traffic) |

An attack counts as stopped if the broker refused the publish or the gateway's
`rejected_inbound` increased.

## Allocator pinning

With glibc's defaults, freeing the large per-message buffers can trim the heap,
and the next round trip faults the pages back in; whether that happens depends
on heap layout left by earlier runs, which made 64 KiB results swing ~3× with
the `--benchmark_filter` used. `main` therefore sets
`M_TRIM_THRESHOLD = 2³⁰` and `M_MMAP_THRESHOLD = 16 MiB`. Set
`MSEC_BENCH_DEFAULT_MALLOC=1` to measure with the defaults.

## Reference figures

From the README (development machine, 256 B): `9_sign` ≈ **205 µs** per
message end to end (sign + verify) vs ≈ **5.4 µs** for `6_full` (AES-256-GCM).
In the load lab with the `hardened` preset and 20 sensors the gateway spends
≈ 190 µs of CPU per message.

## Relation to the load gateway

`msec_load_gateway --profile <p>` accepts `none`, `auth_only`, `aead`,
`aead_freshness`, `aead_replay`, `full`, matching profiles 0/2/3/4/5/6, so the
same configurations can be measured over a real broker.
