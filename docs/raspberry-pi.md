# Running the evaluation on the Raspberry Pi 5 — step by step

The checklist for the Part 2 measurements. What each command does and what
its output means is in [evaluation.md](evaluation.md); this page is only the
order of operations.

Roles:

| Machine | Runs | Needs |
|---|---|---|
| **Pi 5** (controller) | broker, gateway, campaign, analysis | the C++ build, Mosquitto, the Python venv |
| **Load machine(s)** (laptop/desktop on the same LAN, 1 or 2) | sensor agents, attacker agent | the repository checkout and the Python venv only (no C++ build) |

All machines must be on **the same commit**, with a clean tree. Commit
everything before starting: the manifest records `git describe` and marks a
dirty tree, and agents from another version are rejected.

## 0. Before going to the Pi

- [ ] Changes reviewed and committed; the same commit pushed/pulled everywhere.
- [ ] `tools/analysis/params.toml` has the weights the group agreed on
      (`status = "proposal"` is expected at this point: R_alvo and L_max come
      from the pilot, step 4).
- [ ] Wired Ethernet between the Pi and the load machines if possible (Wi-Fi
      adds latency noise); heatsink or fan on the Pi.

## 1. Prepare the Pi (once)

1. **Operating system.** The code needs GCC ≥ 13. Check first:

   ```bash
   g++ --version        # must say 13 or newer
   python3 --version    # must say 3.11 or newer
   ```

   Raspberry Pi OS based on Debian 12 ("bookworm") ships GCC 12 and will not
   build the project: use the Debian 13 ("trixie") based release, or Ubuntu
   24.04 for the Pi. 64-bit in either case.

2. **Packages.**

   ```bash
   sudo apt update
   sudo apt install -y git cmake ninja-build g++ libssl-dev \
       libpaho-mqtt-dev libpaho-mqttpp-dev libgtest-dev \
       mosquitto python3-venv iproute2
   ```

3. **Stop the system broker** (the lab starts its own, on port 18830):

   ```bash
   sudo systemctl disable --now mosquitto
   ```

4. **Get the code and build it** (the first configure downloads
   google-benchmark, so the Pi needs internet access once):

   ```bash
   git clone <repository URL> mqtt-secure && cd mqtt-secure
   git checkout <the agreed commit>
   cmake --preset dev   && cmake --build --preset dev   && ctest --preset dev    # 93 tests
   cmake --preset bench && cmake --build --preset bench
   python3 -m venv tools/loadgen/.venv
   tools/loadgen/.venv/bin/pip install -r tools/loadgen/requirements.txt
   tools/loadgen/.venv/bin/python -m unittest discover -s tools/loadgen/tests -t tools/loadgen
   ```

   If `ctest` or the Python tests fail on the Pi, stop here and fix that first.

5. **Steady conditions.**

   ```bash
   echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
   vcgencmd get_throttled       # must print throttled=0x0
   vcgencmd measure_temp
   hostname -I                  # the Pi's LAN address: <PI_IP> below
   ```

   Close everything else on the Pi (desktop session, browsers).

   **Clock.** Turn NTP on and let it settle before any run with agents:

   ```bash
   sudo timedatectl set-ntp true
   timedatectl timesync-status      # Offset: within ±1 ms, twice, a few minutes apart
   ```

   While NTP is still pulling a large offset in, it changes the clock's rate,
   and the agents' drift correction lags for a few runs (pilot 2 showed
   latencies off by ≈ 200 µs, some negative). Say in the report that NTP was
   on.

## 2. Prepare each load machine (once)

```bash
git clone <repository URL> mqtt-secure && cd mqtt-secure
git checkout <the agreed commit>
python3 -m venv tools/loadgen/.venv
tools/loadgen/.venv/bin/pip install -r tools/loadgen/requirements.txt
ping <PI_IP>
```

The load machines must reach the Pi on TCP **18830** (MQTT) and **8089**
(agent control). Open them on the Pi's firewall if it has one.

## 3. Smoke test on the Pi alone (5 minutes)

Everything local, to know the Pi itself is fine before adding the network:

```bash
tools/loadgen/.venv/bin/python tools/loadgen/loadgen.py scenarios \
    --set load.sensors=10 --set load.rate=10 --out build/loadtest/pi-smoke
```

Expected: `39/39 passed`. Keep `build/loadtest/pi-smoke.md`: it is validation
evidence for the report.

## 4. How a run with agents starts (used by steps 5–7)

1. On the **Pi**, start the command (pilot, campaign or attacks). With
   `cluster.*_agents` set it prints a line like

   ```
   agents join with:
     loadgen.py agent --controller <PI_IP>:8089 --token … --fingerprint … --role sensors|attacker
   ```

   and waits (up to 10 minutes) for the agents.

2. On the **load machine(s)**, start the agents with that token and
   fingerprint, one terminal each:

   ```bash
   # two sensor agents (two machines, or two terminals on one)
   tools/loadgen/.venv/bin/python tools/loadgen/loadgen.py agent \
       --controller <PI_IP>:8089 --token … --fingerprint … --role sensors
   # one attacker agent
   tools/loadgen/.venv/bin/python tools/loadgen/loadgen.py agent \
       --controller <PI_IP>:8089 --token … --fingerprint … --role attacker
   ```

   Agents stay up and serve one run after another: start them once and leave
   them running for steps 5–7. The token and fingerprint stay the same
   between runs (they live in `build/loadtest/controller/` on the Pi).

The options every command below shares, written `$AGENTS` from here on:

```bash
AGENTS="--set broker.host=0.0.0.0 --set broker.advertise=<PI_IP> \
        --set cluster.sensor_agents=2 --set cluster.attacker_agents=1"
PY=tools/loadgen/.venv/bin/python
```

## 5. Pilot → fix R_alvo and L_max (≈ 30 minutes)

```bash
$PY tools/loadgen/loadgen.py campaign $AGENTS \
    --levels K0,K8,K9,K11 --repetitions 3 --duration 15 \
    --saturate 10,20,50,100,125,150,200,300,400,500,600,700,800,1600 --out build/pilot
tools/analysis/analyze.py build/pilot
```

Look at `build/pilot/saturation.csv` and `build/analysis/pilot/summary.csv`:

- [ ] The rates in `--saturate` reach saturation (a row with `loss_pct ≥ 1`)
      for every level. If the highest rate still has no loss, add higher
      rates to the list in step 6 too.
- [ ] `clock_source` is `agents` and `clock_uncertainty_ms_max` is well below
      the latencies measured (otherwise the network is too noisy: use cable).
- [ ] `throttled` is `0x0` in every row.
- [ ] The confidence intervals in `summary.csv` separate the levels; if they
      overlap everywhere, plan more than 10 repetitions (the report allows it).

Then, **as a group**, choose R_alvo (messages/s the gateway must sustain) and
L_max (p99 latency limit) for the application scenario, write them in
`tools/analysis/params.toml` (`[feasibility]`), set `status = "fixed"`,
**commit**, and pull that commit on every machine (restart the agents). The
pilot data is not a result: it stays in `build/`.

## 6. Level 1: microbenchmarks (≈ 15–20 minutes, Pi only, no agents)

```bash
NAME=pi5-$(date +%Y%m%d)
tools/analysis/microbench.py --out results/$NAME/microbench --repetitions 10
```

Day-one check: in `results/$NAME/microbench/`, the AES profiles (`3_aead`,
`6_full`) must be clearly slower in `aes-armcap0.json` and `aes-armcap1.json`
than in `aes-on.json`. If they are not, `OPENSSL_armcap` is not taking effect:
stop and investigate before trusting any AES-vs-ChaCha20 number.

Run this **before** the campaign of step 7 only if you use the same `$NAME`:
the campaign refuses a non-empty directory. Simplest: run step 7 first, then
this step into the directory it created.

## 7. Level 2: the campaign (≈ 3–4 hours of machine time)

Do not touch the Pi or the load machines while it runs.

```bash
NAME=pi5-$(date +%Y%m%d)

# 7a. cost: 12 levels × 10 repetitions, random order, + saturation   (≈ 2.5 h)
$PY tools/loadgen/loadgen.py campaign $AGENTS \
    --repetitions 10 --seed 20261201 --settle 3 --duration 30 --connect-test 5 \
    --saturate 10,20,50,100,125,150,200,300,400,500,600,700,800,1600 \
    --out results/$NAME

# 7b. attacks: every attack against every level, 3 repetitions       (≈ 1.2 h)
for i in 1 2 3; do
  $PY tools/loadgen/loadgen.py attacks $AGENTS --out results/$NAME/attacks-$i.csv
done
```

Step 7a runs **without** `--attacks` on purpose: the on-path attacks route
the gateway through a relay, which would add latency to the cost runs.

Merge the attack repetitions into the file the analysis reads:

```bash
python3 - "results/$NAME" <<'EOF'
import csv, glob, sys
rows = []
for rep, path in enumerate(sorted(glob.glob(f"{sys.argv[1]}/attacks-*.csv")), 1):
    rows += [{"repetition": rep, **r} for r in csv.DictReader(open(path, newline=""))]
with open(f"{sys.argv[1]}/attacks.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(dict.fromkeys(k for r in rows for k in r)), restval="")
    w.writeheader(); w.writerows(rows)
print(len(rows), "rows")
EOF
```

Then step 6 (microbenchmarks) into `results/$NAME/microbench`, and the
scenarios once more with agents, as the attack table of the report:

```bash
$PY tools/loadgen/loadgen.py scenarios $AGENTS --out results/$NAME/scenarios
```

If a campaign is interrupted, what it measured is kept, but start a **new**
directory for the rerun (raw data is never overwritten) and say so in the
report.

## 8. Check the data before leaving the Pi

```bash
tools/analysis/analyze.py results/$NAME
```

- [ ] `runs.csv` has 120 rows; `manifest.json` says `"dirty": false` and
      `runs_completed: 120`.
- [ ] No `throttled` value other than `0x0`; temperatures plausible.
- [ ] `sensors_up` equals the number of sensors in every cost run; `loss_pct`
      ≈ 0 outside the saturation sweep.
- [ ] `build/analysis/$NAME/README.md` does **not** say PROVISÓRIO.
- [ ] `protection.csv`: K0 prevents nothing; K8, K9 and K11 prevent
      everything. Anything else is a finding to explain, not to hide.
- [ ] `calibration.md` proposes Δa and Δs (it needs the agents: with local
      sensors it says the skew was not measured).

Copy `results/$NAME` off the Pi (`git add results/$NAME`, or `scp -r`).

## 9. The same on the desktop (reference platform)

Repeat steps 6–8 with the desktop as controller and `NAME=desktop-<date>`:
same commit, same `params.toml`, same seed, agents on another machine.

## 10. Analysis for the report

```bash
tools/analysis/analyze.py results/pi5-<date> results/desktop-<date>
```

Tables and figures land in `build/analysis/<campaign>/`; copy them into the
Part 2 report with `make dados` in `report/parte2/` (see its README).

## If something goes wrong

| Symptom | Cause / fix |
|---|---|
| `only 0 of 2 sensors agents joined in time` | agents not started, wrong token/fingerprint, or port 8089 blocked |
| agent says `controller rejected this agent: protocol version …` | the agent's checkout is older or newer than the Pi's: same commit everywhere |
| `…:18830 is already in use` | the system Mosquitto is still running (step 1.3), or a previous lab did not exit: `pgrep -a mosquitto` |
| sensors never come up with TLS levels | `broker.advertise` is not the address the agents use; it must be in the broker certificate |
| `… is not empty: campaigns never overwrite raw data` | choose a new `--out` directory |
| latencies negative or huge with agents | clocks: let the agents run a minute before starting, and do not step the clock (NTP) during a run |
| `gateway did not start` | the bench build is missing: `cmake --build --preset bench` |
