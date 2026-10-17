# Load lab — dashboard, HTTP API and metrics

## Dashboard

`loadgen.py live` serves a single page (`tools/loadgen/dashboard.html`, no
external dependencies) from a stdlib `ThreadingHTTPServer`
(`tools/loadgen/dashboard.py`), by default on `http://127.0.0.1:8088/`.

> **The dashboard has no authentication.** Anyone who can reach it controls the
> lab. It binds to `127.0.0.1` by default; reach it from elsewhere through an SSH
> tunnel rather than `--http-host 0.0.0.0`.

Layout:

- **Header pills** — Broker (transport, TLS version, MQTT version, auth, ACL),
  Gateway (connected?), Sensors (up/total, revoked, last error), Attacker
  (off / its status detail). Colour = good / warning / critical.
- **Control cards** (left):
  Profile (**Harden** button) · Transport · Payload (protection, freshness,
  replay, key binding, rate limit, **Rotate** button showing the epoch) ·
  Downlink (commands/s) · Incident response (**Revoke** a sensor number; list
  of revoked) · Storage · Load (rate, payload, zone; sensors/processes/QoS shown
  as fixed) · Attacker (enabled, impersonate, inject rate, replay rate) ·
  Agents (only with cluster agents: role, host, status, clock offset ±
  uncertainty) · Changes (event log).
- **Charts** (right), last 3 minutes, one point per second, dashed vertical
  markers at every configuration change (hover shows values and the change):

| Chart | Series |
|---|---|
| Throughput (msg/s) | Sent (sensors), Delivered (accepted by the gateway) |
| End-to-end latency (µs) | p50, p99 — sensor send → after the gateway pipeline |
| CPU (%) | Gateway, Broker (100 % = one core) |
| Gateway rejections (msg/s) | by reason: AuthenticationFailed, ReplayDetected, MalformedMessage, MessageExpired, PermissionDenied, ProtectionNotAccepted, RateLimited |
| What the attacker achieves (msg/s) | Eavesdropped (received via `#`), Forged accepted, Replays accepted |
| Downlink commands (msg/s) | Sent, Accepted, Rejected (by the actuators) |

The page polls `/api/state?since=<last t>` every second, keeps ~210 points,
re-renders on resize and on colour-scheme change (light/dark themes via CSS
custom properties). Every control posts the single changed key to
`/api/config`; errors are shown inline.

## HTTP API

| Method | Path | Request | Response |
|---|---|---|---|
| `GET` | `/` | — | the page |
| `GET` | `/api/state?since=T` | — | `200 {config, startup_only, history, events, agents}` |
| `POST` | `/api/config` | partial config JSON | `200 {changed, config}` · `400 {error, config}` |
| `POST` | `/api/preset` | `{"name": "hardened"}` | `200 {changed, config}` · `400 {error, config}` |
| any other | | | `404 {"error": "not found"}` |

Responses carry `Cache-Control: no-store`. HTTP access logging is suppressed
(the terminal shows lab events instead).

```bash
curl -s localhost:8088/api/config -d '{"payload": {"replay": false}}'
curl -s localhost:8088/api/config -d '{"transport": {"mode": "mtls", "auth": true}}'
curl -s localhost:8088/api/config -d '{"payload": {"key_epoch": 1}}'          # rotate
curl -s localhost:8088/api/config -d '{"response": {"revoked": "3,7"}}'       # revoke
curl -s localhost:8088/api/preset -d '{"name": "hardened"}'
curl -s 'localhost:8088/api/state?since=0' | jq '.history[-1]'
```

`changed` lists human-readable descriptions such as
`"transport.mode: plain → mtls"`. An invalid request changes nothing.

### `/api/state` fields

| Field | Content |
|---|---|
| `config` | the full current configuration |
| `startup_only` | `["broker.host", …, "load.sensors", …]` |
| `history` | metric points with `t > since` (max 900 kept) |
| `events` | `[{t, text}]` (max 200) — "lab started", every change, "keys of epoch N revoked" |
| `agents` | `[{id, role, host, connected, busy, clock, report}]` |

### History point (one per second)

All rates are per second over the last sampling interval; counter resets
(gateway `reset`, broker restart) are handled.

| Field | Source | Meaning |
|---|---|---|
| `t` | | Unix time |
| `sent`, `skipped` | fleet | messages published / skipped (backlog or sensor down) |
| `kicked` | fleet | sensor connections lost while up |
| `sensors_up`, `sensors_total`, `sensor_error` | fleet | |
| `gw_connected` | gateway | |
| `delivered`, `rejected`, `rejected_by{code}` | gateway | |
| `forged_ok`, `replays_ok` | gateway | attacks the gateway accepted |
| `dup_rejected` | gateway | QoS redeliveries rejected |
| `cmd_sent` | gateway | downlink commands |
| `cmd_ok`, `cmd_rejected`, `cmd_rejected_by`, `cmd_forged_ok`, `cmd_replay_ok` | fleet (actuators) | |
| `lat_p50`, `lat_p99` | gateway | µs, last interval |
| `gw_cpu`, `broker_cpu` | gateway / `/proc` | % of one core (broker 0 across a restart) |
| `eavesdropped`, `injected`, `replayed` | attacker | |
| `attacker` | attacker | `{connected, detail, identity, enabled, captured}` |

## Measurement columns

`Lab.measure(settle, duration)` produces one row per matrix cell or scenario:

| Column | Definition |
|---|---|
| `sent_msg_s` | sensor messages sent in the window / window length |
| `delivered_msg_s` | gateway summary `msg_per_s` |
| `loss_pct` | 100 × (sent − received by gateway) / sent, clamped 0–100 |
| `rejected`, `rejected_by` | gateway rejections in the window, total and `Code=n …` |
| `rate_limited` | `rejected_by.RateLimited` |
| `leak_pct` | 100 × attacker-received / sent |
| `forged_ok`, `replays_ok` | forgeries / replays the gateway accepted |
| `cmd_sent`, `cmd_ok`, `cmd_rejected` | downlink sent by gateway; verified / rejected by actuators |
| `kicked` | sensor connections lost |
| `lat_p50_us`, `lat_p99_us` | window latency percentiles |
| `gw_cpu_pct`, `gw_cpu_us_per_msg` | gateway CPU, and CPU µs per received message |
| `broker_cpu_pct` | empty if the broker restarted within the window |
| `sensors_up`, `attacker_connected`, `attacker` | state at the end |

Shares are accurate to roughly ±0.5 s / duration because sensors report twice
a second.
