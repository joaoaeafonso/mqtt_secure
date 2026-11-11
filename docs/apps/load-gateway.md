# `msec_load_gateway` — the gateway under test

**Source:** `apps/load_gateway/main.cpp` · **Target:** `msec_load_gateway` ·
**Links:** `msec::mqtt`, `msec::security`, `msec::data`, `msec::limits` ·
**Requires:** `MSEC_WITH_OPENSSL` and `MSEC_WITH_PAHO` · **Built by:** the
`bench` preset (`build/bench/apps/load_gateway/msec_load_gateway`)

A gateway for a **real broker** (Mosquitto), fed by the Python load lab. Every
security feature is a setting given on the command line and changeable while
traffic flows. It is normally driven by `tools/loadgen/gateway.py`, but can be
run by hand.

## 1. Architecture

```
sensors ─▶ mosquitto ─▶ PahoClient ─▶ [rate-limit] ▶ [persistence-at-rest⁎] ▶ [security⁎] ▶ [persistence-plain⁎] ─▶ Stats
Stats   ◀─ (gateway) ── commands ─▶ [persistence-plain⁎] ▶ [security⁎] ▶ [persistence-at-rest⁎] ▶ … ─▶ mosquitto ─▶ actuators
```

Pipeline (application side → transport side), built **once**:

| # | Layer | Wrapped | Controlled by |
|---|---|---|---|
| 0 | `persistence-plain` (`PersistenceLayer`) | `SwitchableLayer`, off | `persistence == plain` |
| 1 | `security` (`SecurityLayer`) | `SwitchableLayer`, off | `protection != none` (+ mode and switches) |
| 2 | `persistence-at-rest` (`PersistenceLayer`) | `SwitchableLayer`, off | `persistence == at-rest` |
| 3 | `rate-limit` (`RateLimitLayer`) | no (rate 0 = off) | `rate_limit` |

Both persistence layers share one `InMemoryMessageRepository(10 000)`. The
security layer gets AES-256-GCM, `RandomSource`, `SystemClock`,
`Ed25519Signer`, the three key stores and the key → topic policy; its
`max_tracked_senders` is raised to at least the number of keys loaded.

Main classes in the file:

| Class | Role |
|---|---|
| `Settings` | all options with defaults |
| `KeyRing` | AEAD / sign-private / sign-public stores, `KeyTopicPolicy`, owner map; load, add, revoke |
| `Stats` | thread-safe counters and latency samples fed by the Paho callback thread |
| `RejectionLogger` | prints rejections only with `--verbose` (errors always) |
| `CommandQueue` | background stdin reader; EOF ⇒ `quit` |
| `Gateway` | owns endpoint and layers; `apply_pipeline()`, `connect()`, `send_commands()` |

## 2. Command line

`msec_load_gateway [--option value]...` (`--help`; `--verbose` takes no value).
Dashes in names become underscores; the same names are used by the stdin `set`
command.

### Transport (applied on connect / `reconnect`)

| Option | Default | Meaning |
|---|---|---|
| `--host H` | `127.0.0.1` | broker host |
| `--port N` | `18830` | plain listener |
| `--tls-port N` | `18831` | TLS listener |
| `--mtls-port N` | `18832` | mutual-TLS listener |
| `--transport T` | `plain` | `plain` · `tls` · `mtls` ⇒ URI `tcp://` or `ssl://host:<port for T>` |
| `--ca FILE` | | CA certificate (tls, mtls) |
| `--cert FILE --key FILE` | | client certificate and key (mtls) |
| `--client-id ID` | `gateway` | |
| `--username NAME` | `gateway` | sent if non-empty |
| `--password PW` | | sent if non-empty (as `SecureBuffer`) |
| `--credentials FILE` | | read the password for the current `--username` from `"user password"` lines — put `--username` first if you change it |
| `--subscribe FILTER` | `open/sensors/#`, `restricted/sensors/#` | repeatable; `set subscribe` replaces the list |
| `--qos N` | `0` | subscription and downlink QoS |
| `--protocol V` | `3.1.1` | `3.1.1` · `5` |

The lab passes the same port for all three listeners because its broker only
ever has the active transport's listener.

### Pipeline (applied immediately)

| Option | Default | Meaning |
|---|---|---|
| `--protection P` | `encrypt` | `none` (security layer switched off) · `auth_only` · `encrypt` · `sign` |
| `--accept LIST` | | inbound modes, comma-separated (e.g. `encrypt,auth_only`); default (or `-`): the `--protection` mode only |
| `--freshness on\|off` | on | |
| `--replay on\|off` | on | |
| `--key-binding on\|off` | on | key may only publish on its owner's topics |
| `--key-pattern F` | `+/sensors/%u/#` | repeatable; `%u` owner, `%k` key id |
| `--rate-limit N` | 0 | inbound msg/s per topic, 0 = off |
| `--sending-key ID` | 0 | key the gateway seals downlink with (changes on rotation) |
| `--persistence P` | `none` | `none` · `plain` · `at-rest` |
| `--profile P` | | preset: `none`, `auth_only`, `aead`, `aead_freshness`, `aead_replay`, `full` (names match the benchmark profiles) |
| `--keys FILE` | | key file; required unless `--protection none` and no `--control` |

Switch values accept `on/true/1` and `off/false/0`. Integers must be
non-negative.

**Dependencies are validated**: `freshness`, `replay` and `key_binding` check
the envelope, so they cannot be on with `--protection none`. Such a
combination is refused at startup (exit) and by `set`/`apply` (the settings
stay as they were), instead of being silently ignored. To change several
settings that only make sense together, use `apply` (§4).

### Receiver rules (startup only)

| Option | Default | Meaning |
|---|---|---|
| `--max-age MS` | 60000 | temporal validity Δa (global) |
| `--max-skew MS` | 5000 | tolerated clock skew Δs (global) |
| `--freshness-rule F=AGE[/SKEW]` | | per-flow validity for topics matching filter F (ms); repeatable, first match wins, e.g. `+/actuators/#=5000/1000` |
| `--epoch-state FILE` | | record the newest key epoch accepted; after a restart accept only later epochs (§5) |
| `--epoch-stride N` | 1000000 | key id = epoch × N + device |

### Downlink (applied immediately)

| Option | Default | Meaning |
|---|---|---|
| `--downlink N` | 0 | commands/s to `<zone>/actuators/<owner>/cmd`, 0 = off |
| `--zone Z` | `restricted` | `open` · `restricted` |

### Process

| Option | Default | Meaning |
|---|---|---|
| `--report MS` | 1000 | stats interval; 0 disables |
| `--stats json\|text` | text | JSON lines on stdout, or a text line on stderr |
| `--control stdin` | | accept commands on stdin |
| `--duration S` | 0 | stop after S seconds (0 = until SIGINT/SIGTERM/`quit`) |
| `--json FILE` | | write the exit summary to a file instead of stdout |
| `--verbose` | | log every rejected message |

## 3. Key file

One key per line, `#` comments and blank lines ignored:

```
<key id> <kind> <64 hex chars> [owner]
```

| kind | Store | Use |
|---|---|---|
| `aead` | AEAD store, AES-256-GCM | encrypt / auth_only, both directions |
| `aead-chacha20` | AEAD store, ChaCha20-Poly1305 | the same, with the other algorithm (the envelope is unchanged) |
| `sign-private` | signing store | sending `sign` (the gateway has only its own) |
| `sign-public` | verify store | receiving `sign` |

A legacy two-field line `<id> <hex>` is an `aead` key. Key ids follow the lab
convention `epoch × 1 000 000 + device`, device 0 = the gateway. **Owners**
name devices: they feed `%u` in the key → topic policy and define the downlink
targets (`devices()` = every owner except `gateway`).

## 4. Stdin control protocol (`--control stdin`)

| Command | Effect |
|---|---|
| `set <key> <value>` | any runtime option above without `--` (underscores); pipeline keys apply immediately, transport keys on the next `reconnect`; startup-only keys are refused |
| `apply <k>=<v> [<k>=<v> …]` | several settings validated together and applied at once (e.g. `apply protection=none freshness=off replay=off key_binding=off`); the lab uses it for every payload change |
| `key add <id> <kind> <hex> [owner]` | install a key (rotation) |
| `key revoke <id>` | remove the id from every store, the policy owner/rules, the replay window and the owner map (revocation) |
| `reconnect` | close and reconnect with current transport settings, resubscribe |
| `sync` | print `{"type":"sync"}` on stdout: every command sent before it is in effect (used before senders switch to new keys) |
| `reset` | start a new measurement window (counters, latencies, first/last timestamps) |
| `connect-test N` | time N reconnections (TCP + TLS + CONNECT + resubscribe; 1–100, default 5) and print `{"type":"connect","samples_ms":[…],"failed":…,"cpu_ms":…}` |
| `summary` | print the current window's summary JSON on stdout |
| `quit` | stop |

Errors are reported on stderr (`load_gateway: set rate_limit: …`) and do not
stop the process. When stdin reaches EOF (the controller died) the gateway quits.

## 5. Runtime behaviour

- **Startup**: parse options, load keys, build pipeline, apply settings, try to
  connect. Standalone it dies if the first connect fails; with `--control` it
  keeps retrying. Prints `READY {settings}` on stderr.
- **Main loop** every 20 ms: stop on duration/signal; drain commands; send due
  downlink commands; if disconnected, reconnect at most once a second (the
  broker drops the gateway when TLS, credentials or ACL change); every
  `--report` ms emit a stats line.
- **Downlink**: when `--downlink N > 0` and connected, send commands on
  schedule, round-robin over devices, through the **outbound pipeline** (so
  they are protected like uplink). Plaintext = u64 BE send time (ns) ‖ u64 BE
  command id (starts at the startup time in ns) ‖ `"CMD:<owner>"`. After a
  pause it never bursts more than one second's worth.
- **Restarts** (`--epoch-state`): the security layer records the newest key
  epoch it has accepted in that file (atomically, once per rotation). Started
  again with the same file, it logs `restarted: accepting key epochs N and
  later only` and rejects everything sealed with older keys
  (`ReplayDetected`) until the senders rotate. The lab passes
  `<workdir>/gateway-epoch`.
- **Exit**: disconnect and print the summary.

### Measurement semantics (`Stats`)

| Quantity | Definition |
|---|---|
| send time | first 8 plaintext bytes, u64 BE ns since the Unix epoch, written by the sensor (corrected by its clock offset on agents) |
| latency | gateway `system_clock::now()` − send time, measured **after** the pipeline (decryption included) |
| forged accepted | delivered payload with `"FORGED!!"` at offset 8 (the attacker's marker) |
| replay accepted | delivered payload whose (send time ⊕ hash(topic)) was seen before (FIFO of 2¹⁸ fingerprints) |
| republished accepted | delivered payload whose send time was seen before **on another topic** (a copy moved to a new topic) |
| duplicates rejected | rejected messages that carried the MQTT DUP flag |
| `msg_per_s` | (delivered − 1) / (last − first activity) — N messages span N−1 gaps |
| CPU | `getrusage(RUSAGE_SELF)` user + system |

## 6. Output schemas

**Ready line** (stderr): `READY {"transport":"plain","protocol":"3.1.1",…}`

**Settings object** (embedded in every line):

```json
"transport":"mtls","protocol":"5","username":"gateway","protection":"sign",
"freshness":true,"replay":true,"key_binding":true,"rate_limit":41,
"persistence":"none","downlink":20
```

**Counters object** (embedded):

```json
"forged_accepted":0,"replays_accepted":0,"republished_accepted":0,"retained_received":0,
"duplicates_rejected":0,"commands_sent":200,"commands_failed":0
```

**Stats line** (`--stats json`, stdout, every `--report` ms):

```json
{"type":"stats","connected":true, <settings>, "rx_per_s":1000.0,
 "delivered":12345,"rejected":17,"rejected_by":{"AuthenticationFailed":17},
 <counters>, "devices":50,"lat_p50_us":412.3,"lat_p99_us":1210.8,"cpu_pct":23.4}
```

`delivered`/`rejected`/counters are cumulative since the last `reset`;
`rx_per_s`, latencies and `cpu_pct` cover the last interval.

**Summary** (on `summary` and on exit):

```json
{"type":"summary", <settings>, "received":…, "delivered":…, "rejected":…,
 "rejected_by":{…}, <counters>, "active_s":10.002, "msg_per_s":999.7,
 "latency_us":{"p50":…,"p90":…,"p99":…,"p999":…,"max":…},
 "cpu_s":2.345, "cpu_pct":23.4, "cpu_us_per_msg":234.10}
```

`rejected_by` keys are `ErrorCode` names; only non-zero codes appear.

## 7. Running by hand

```bash
# plain, no payload protection, 10 s, text stats on stderr
./build/bench/apps/load_gateway/msec_load_gateway --protection none --duration 10

# mtls + signatures, controlled from the terminal
./build/bench/apps/load_gateway/msec_load_gateway \
    --transport mtls --ca pki/ca.crt --cert pki/clients/gateway.crt --key pki/clients/gateway.key \
    --credentials credentials.txt --keys keys.txt --protection sign --control stdin
set rate_limit 30
set persistence at-rest
summary
quit
```
