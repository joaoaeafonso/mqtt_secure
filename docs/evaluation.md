# Evaluation procedure (report Part 2)

How the repository carries out the evaluation plan of the report (Section 7):
configurations K0–K11, the attack set 𝒜, the metrics, the criterion for the
best configuration and the experimental procedure. Everything below is code;
this page says which command does which part and where its output goes.

| Report | Here |
|---|---|
| Configurations K0–K11 (configuration table) | `tools/loadgen/lab.py` `LEVELS`; K11 = K8 with `payload.cipher = chacha20-poly1305` |
| Level 1: microbenchmarks, 16 B – 64 KiB, AES hardware on/off | `benchmarks/pipeline_benchmarks.cpp` (profile `11_full_key_binding_chacha20` = K11), run by `tools/analysis/microbench.py` |
| Level 2: load lab, broker + gateway on the Pi, sensors and attacker elsewhere | `loadgen.py campaign` (+ `cluster.sensor_agents` / `attacker_agents`) |
| Cost metrics (metrics table) | columns of every run: `gw_cpu_us_per_msg`, `lat_p50_us`, `lat_p99_us`, `delivered_msg_s`, `gw_rss_peak_kb`, `broker_rss_peak_kb`, `bytes_*`, `connect_ms_p50`, `connect_cpu_ms`; saturation sweep for the maximum sustained throughput |
| Attack set 𝒜 and π_a(c) | `tools/loadgen/attacks.py`, `loadgen.py attacks` / `campaign --attacks` |
| Each attack against its defence, with a negative control | `tools/loadgen/scenarios.py`, `loadgen.py scenarios` |
| S(c), cost(c), feasibility, use cases, Pareto frontier, c* | `tools/analysis/analyze.py` |
| 10 repetitions, random order, bootstrap CIs, marginal cost, difference of differences | `campaign` (order, raw data) + `analyze.py` (statistics) |
| Reproducible artefact | `results/<campaign>/` (manifest, seed, frozen parameters, raw data) → `analyze.py` |

## 1. Before the campaign: fix the parameters

`tools/analysis/params.toml` holds the attack weights ω_a, the cost weights
v_m, R_alvo and L_max, and the bootstrap settings. The report requires them to
be fixed **before** the measurements: `campaign` copies the file into the
campaign directory before the first run and records its SHA-256 in the
manifest, and the analysis uses that frozen copy.

The file in the repository is a **proposal** (`status = "proposal"`):
ω_a = 1 per row of the report's attack table (the two rows measured as two
attacks each, eavesdropping and injection/tampering, weigh 0.5 + 0.5);
v_m = 0.4 CPU per message, 0.4 p99 latency, 0.05 each for maximum throughput,
octets per message, gateway memory and connection establishment (CPU per
connection, `connect_cpu_ms`).
R_alvo and L_max come from the application scenario, checked against a pilot
on the Pi (fixed 2026-11-11: telemetry 10,000 msg/s, commands 1,000 msg/s,
L_max 50 ms). R_alvo can differ per use case
(`[feasibility.r_target_by_use_case]`; a use case without its own value uses
`r_target_msg_s`): commands are a far lower flow than telemetry, and only the
signature level gives the proof of origin they require. `criterion.csv` has a
`feasible_<use case>` column per use case. While the status is not `fixed` or
either limit is missing, every analysis output says **PROVISIONAL** and the
feasibility filter is not applied.

Pilot (gives realistic R_alvo / L_max candidates without committing data):

```bash
tools/loadgen/.venv/bin/python tools/loadgen/loadgen.py campaign \
    --levels K0,K8,K9,K11 --repetitions 3 --duration 15 \
    --saturate 10,20,50,100,125,150,200,300,400,500,600,700,800,1000,1200,1600 \
    --out build/pilot
```

### On the Raspberry Pi 5

- **Toolchain**: the code needs GCC ≥ 13 (`std::format`, `std::ranges::contains`).
  Raspberry Pi OS based on Debian 12 "bookworm" ships GCC 12 and cannot build it;
  use the Debian 13 "trixie" based release or Ubuntu 24.04 for the Pi. The rest
  is in the distribution: `cmake ninja-build g++ libssl-dev libpaho-mqtt-dev
  libpaho-mqttpp-dev mosquitto python3-venv iproute2` (`ss` is used for the
  octets per message). The first configure downloads google-benchmark, so the
  Pi needs network access once.
- Stop the system broker so it does not compete for CPU: `sudo systemctl stop
  mosquitto` (the lab starts its own on port 18830).
- Sync the clocks with NTP, then turn NTP off on every machine for the
  campaign (see Clock below); a governor other than `performance`, a
  missing heatsink or a non-zero `throttled` column all show up in the data.
- The same checkout on the Pi and on every agent machine (same commit, clean
  tree: the manifest records `git describe` and marks a dirty tree).

## 2. Level 1: microbenchmarks

```bash
cmake --preset bench && cmake --build --preset bench
tools/analysis/microbench.py --out results/pi5-<date>/microbench --repetitions 10
```

Runs every profile and payload size (16 B, 256 B, 4 KiB, 64 KiB) in a random
interleaved order, once as is and once with the CPU's AES instructions
disabled for OpenSSL (`OPENSSL_armcap=0` on ARM, the `OPENSSL_ia32cap`
equivalent on x86), keeping google-benchmark's raw JSON. On the Pi, check on
the first day that `OPENSSL_armcap=0` really slows AES-GCM down (plan, risks):
if AES and ChaCha20 cost the same with and without it, the variable is not
taking effect.

`OPENSSL_armcap=0` (the report's setting) switches off **every** ARM extension
OpenSSL uses, NEON included, so it also slows ChaCha20-Poly1305 down. A device
without the crypto extensions still has NEON, so on ARM the script adds a
third run, `aes-armcap1.json` (`OPENSSL_armcap=1`: NEON only); the table shows
it as "não (NEON)". Use that row for the AES-vs-ChaCha20 comparison of QP4 and
say in the report which one is which.

Level 1 has a pipeline profile for K0, K2–K7, K9 and K11. K1, K8 and K10
differ from their neighbours only in transport and limits, which exist only at
level 2.

## 3. Level 2: the campaign

```bash
tools/loadgen/.venv/bin/python tools/loadgen/loadgen.py campaign \
    --repetitions 10 --seed 20261201 --settle 3 --duration 30 --connect-test 5 \
    --attacks --saturate 10,20,50,100,125,150,200,300,400,500,600,700,800,1000,1200,1600 \
    --set broker.host=0.0.0.0 --set cluster.sensor_agents=2 --set cluster.attacker_agents=1 \
    --out results/pi5-<date>
```

- **Order**: per lab, every (level × `--vary` combination × repetition) is
  shuffled with the seed (recorded in the manifest; drawn and recorded if not
  given) and written to `plan.csv` before the first measurement.
- **Extra factors** (`--vary load.payload=16,256,4096`, repeatable): each
  combination is a context of its own in the analysis; the first one in value
  order is the context of the headline tables and figures. A level's limits
  (`max_packet`, rate limit) are derived from the cell's load. The attack
  matrix and the saturation sweep run at the base load only.
- **Each run**: apply the level, wait `--settle` s, measure `--duration` s,
  then time `--connect-test` gateway reconnections. One row in `runs.csv`
  with every metric, the settings, and the Pi's temperature, frequency and
  throttling flags at the end of the run.
- **Attacks** (`--attacks`): every attack of `attacks.py` against every level
  (levels in random order), one row per pair in `attacks.csv` with
  `prevented` = π_a(c) and all the evidence columns. Attacks from a compromised
  device (`stolen_key`) run with the real device offline
  (`attacker.stolen_exclusive`, the default): otherwise both fight for the
  device's MQTT session and the attack is throttled to a trickle. The attacks that need an
  on-path attacker turn on `attacker.wiretap` for the whole campaign: the
  gateway's link then runs through a local relay, which adds a hop to every
  run's latency. To keep the cost measurements clean, run `campaign` without
  `--attacks` and the attack matrix separately (`loadgen.py attacks --out
  results/<campaign>/attacks.csv`).
- **Saturation** (`--saturate R1,R2,…`): per level, raise the per-sensor rate
  until a run loses ≥ 1 % (`saturation.csv`); the analysis takes the largest
  rate with loss < 1 % (and p99 ≤ L_max once fixed) as the maximum sustained
  throughput. After the run that saturates, the lab goes back to the lowest
  rate and waits until the overload's backlog has reached the gateway
  (`Lab.drain`), so it cannot leak into the next cell as rejections or loss.
  The rates are dense between 100 and 800 per sensor because that is where
  the Pi pilot put the limits (K9 between 100 and 150; K0, K8, K11 between
  400 and 800).
- Rows are appended as they are measured; an interrupted campaign keeps what
  it measured. A campaign never writes into a non-empty directory.
- **Agents** must run the same checkout as the controller (the control
  protocol is versioned and an older agent is rejected). Sensors on agents
  report on demand at both window edges, so `loss_pct` is as exact with agents
  as locally (a few milliseconds of the window).

Raw data goes to `results/`, outside `build/`, and can be committed.

### Octets per message

`bytes_payload` (the plaintext), `bytes_envelope` (25 + 12 + 16 = 53, or 89
for signatures) and `bytes_mqtt` (fixed header, topic, MQTT 5 property length)
follow from the formats. `bytes_wire` is what the gateway's TCP socket
received in the window (Linux `tcp_info` via `ss`, no capture or root
needed) divided by the messages received, and `bytes_tls_other` the rest: TLS
records plus MQTT control traffic in the window. For a packet-level view, use
`--capture` (docs/network-analysis.md).

### Known limits of the instrument

- `gw_rss_peak_kb` includes the gateway's own bookkeeping (latency samples of
  the window, and the table of seen messages, which grows over the first
  ≈ 260 000 messages of a lab and then stays flat). Differences between levels
  are meaningful; the first minutes of a lab read a few MiB lower.
- `connect_ms_p50` moves in steps of about 100 ms (waits inside the Paho C
  library), which hide a TLS handshake of a few ms; `connect_cpu_ms` is the
  indicator for H4.
- `republished_ok` is keyed by device and send time. (Until 2026-11-11 it was
  keyed by send time alone and showed 1–2 false positives per window at
  saturation rates: two sensors drawing the same nanosecond.)

### Clock skew (calibration of Δa / Δs)

Every run records `clock_source` (`local` or `agents`), `clock_offset_ms_max`
(the largest |offset| between a sensor agent's clock and the controller's,
estimated NTP-style over the control channel), `clock_uncertainty_ms_max`
(the residual after correction, best RTT / 2), `clock_corrected`, and the
latency tail `lat_p999_us` / `lat_max_us`. Skew can only be measured with
sensors on other machines (`cluster.sensor_agents`); with local sensors the
clock is shared and `calibration.md` says so. The agents fit the drift
between the two clocks over the last minute of pings (`ClockEstimator`), which
handles a constant drift; a clock whose rate changes during the run (NTP still
slewing a large offset) is not handled until the fit catches up. So: sync
with NTP first, then turn NTP off on the Pi and the agent machines for the
whole campaign (two free-running clocks drift at a near-constant rate), and
turn it back on afterwards.

### Receiver restarts

The lab's gateway runs with `--epoch-state <workdir>/gateway-epoch`. A restarted
gateway accepts only key epochs later than the last it recorded, so a restart
must be followed by a key rotation (`payload.key_epoch + 1`).

## 4. Analysis

```bash
tools/analysis/analyze.py results/pi5-<date> results/desktop-<date>
```

Pure Python, standard library only, deterministic (fixed bootstrap seed).
Deleting `build/` and running it again rebuilds every table and figure from
the raw data. Output in `build/analysis/<campaign>/`:

| File | Content |
|---|---|
| `summary.csv`, `summary.tex` | per configuration and metric: median over runs, 95 % percentile-bootstrap CI (resampling runs); the `.tex` holds two tables (`tab:resumo`: CPU, p50, p99; `tab:resumo-b`: memory, octets, connection) |
| `marginal.csv`, `marginal.tex` | m(c_ℓ=1) − m(c_ℓ=0) for the pairs that differ in one layer: K0→K1 transport, K1→K2 GMAC envelope, K2→K3 encryption, K3→K4 validity, K3→K5 window, K6→K7 key–topic, K7→K8 limits, K8→K9 signatures, K10→K7 TLS with envelope, K8→K11 ChaCha20 |
| `interaction.csv` | difference of differences: validity × anti-replay ((K6−K5) − (K4−K3)), TLS × envelope ((K7−K10) − (K1−K0)) |
| `protection.csv` | π_a(c) (majority over attack repetitions) and S(c) = Σω_aπ_a(c)/Σω_a |
| `criterion.csv`, `criterion.tex` | cost(c) = Σ v_m r_m(c) normalised by K0, feasibility, admissibility per use case, Pareto frontier, c* and Δcost/ΔS along the frontier |
| `hypotheses.md` | the numbers H1–H5 (and AES vs ChaCha20) are judged on; the verdict is the authors' |
| `calibration.md`, `calibration.csv` | Δa and Δs proposed from the data (report §6.6): worst latency (`lat_max_us`) and worst clock skew between the sensor agents and the gateway, × `safety_factor`, rounded up to `round_ms` (`[calibration]` in params.toml); one row for clocks without correction (Δs covers the offset) and one for synchronised clocks (only the residual) |
| `microbench.csv`, `microbench.tex` | level 1: CPU time per message by level, size and AES hardware on/off |
| `fig-cpu.tex`, `fig-p99.tex`, `fig-pareto.tex` | pgfplots figures, `\input` them in the report |
| `README.md` | code version, platform, seed, parameters used and whether they were still provisional |

Use cases (report §7.5), as properties a level must have:

| Use case | Required |
|---|---|
| telemetry, not sensitive (T) | integrity, topic binding, anti-replay |
| telemetry, sensitive (TS) | the above + confidentiality towards the broker (encrypt mode only) |
| commands (O) | integrity, validity, anti-replay, key–topic restriction, proof of origin (sign mode only) |

A cost metric that was not measured (e.g. throughput without `--saturate`)
has its weight spread over the others; `criterion.csv` lists which.

## 5. Attack-vs-defence scenarios

`loadgen.py scenarios` (docs/loadgen/scenarios.md) isolates one defence per
experiment on an open baseline and pairs each attack of 𝒜 with a negative
control — the same configuration without that defence, where the attack must
succeed — so a rejection is attributed to the right layer. It is the
regression test of the whole system and the attack table of the Part 2
report; `attacks` is the matrix behind S(c).
