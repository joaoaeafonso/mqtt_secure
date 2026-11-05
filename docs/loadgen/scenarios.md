# Load lab — attack-vs-defence scenarios

`loadgen.py scenarios` runs named experiments on one lab. Each pits **one
attack against one set of defences**, states the outcome the design predicts,
measures a window, and reports **PASS/FAIL**. The table doubles as a
regression test for the whole system (CI runs it against a real Mosquitto) and
as the results table of a report.

```bash
tools/loadgen/.venv/bin/python tools/loadgen/loadgen.py scenarios --list
tools/loadgen/.venv/bin/python tools/loadgen/loadgen.py scenarios --set load.sensors=20
tools/loadgen/.venv/bin/python tools/loadgen/loadgen.py scenarios --only replay-window,inject-sign
```

Output: `build/loadtest/scenarios-<time>.md` (Markdown table: scenario,
attack, defence, expected, result, evidence) and `.csv` (all measured columns,
prefixed `m_`). Exit status is non-zero if any scenario fails.

## Baseline

Every scenario starts from `BASELINE` plus its own patch, so scenarios are
independent of each other (except the last two, which are irreversible and
therefore run last):

| Section | Baseline |
|---|---|
| transport | `plain`, TLS 1.2, MQTT 3.1.1, no auth, **no ACL**, no client-id binding, no `$SYS`, no limits |
| payload | `encrypt` with AES-256-GCM keys, `accept` = encrypt only, freshness, replay, key binding, no rate limit (each scenario turns off what it examines) |
| storage | `none` |
| downlink | rate 0 |
| load | default rate (20) and payload (64), **zone `open`** |
| attacker | enabled, not impersonating, every attack rate 0, no compromised device, relay passive |

With no ACL and the open zone, the broker lets everything through, so **each
scenario's defence is the only thing between the attack and the gateway**.

Each cell: `Lab.apply(baseline + patch)`, `Lab.measure(settle, duration)`
(defaults 3 s / 6 s), then the predicate. A scenario may first apply and settle
a `prepare` patch (the defence in place before the attack starts), and may end
the attack (`recover`) to time the recovery (`recovery_s`). After any scenario
with a compromised device (`attacker.stolen_key`) every key is rotated, because
messages accepted with the stolen key in a control push the victim's replay
window ahead and would make the next scenarios reject its genuine traffic.

**Negative controls.** The attacks of the report's attack table come in pairs:
`<name>` (the defence that should stop it) and `<name>-control` (the same
configuration without that defence, where the attack must succeed). A
rejection is attributed to a layer only when its control fails as predicted.
Scenarios that need an on-path attacker (`eavesdrop-network-*`,
`eavesdrop-broker-encrypt`, `active-broker-*`) make `scenarios` start the lab
with `attacker.wiretap = true`: the gateway's link runs through a relay that
counts readable readings and, with `attacker.tamper`, plays a malicious broker
(only on plaintext MQTT; under TLS it sees ciphertext).

## Scenarios

| # | Name | Attack | Defence (patch) | Prediction | PASS if | Evidence |
|---|---|---|---|---|---|---|
| 1 | `eavesdrop-open` | subscribe to `#` | none | the attacker receives the sensors' traffic | `leak_pct > 50` | `leak_pct` |
| 2 | `eavesdrop-acl` | subscribe to `#` | `acl=on`, zone `restricted` | nothing reaches the attacker | `leak_pct == 0` and `delivered_msg_s > 0` | `leak_pct`, `delivered_msg_s` |
| 3 | `impersonate-no-auth` | claim username `gateway` | ACL without authentication | a claimed name passes the ACL: the attacker reads the restricted zone | `leak_pct > 50` | `leak_pct`, `attacker` |
| 4 | `impersonate-auth` | claim username `gateway` | ACL + passwords | the broker refuses the attacker | attacker not connected and `leak_pct == 0` | `attacker_connected`, `attacker` |
| 5 | `inject-unprotected` | forged readings at 20 msg/s | `protection=none` | the gateway accepts the forgeries | `forged_ok > 0` | `forged_ok` |
| 6 | `inject-auth-only` | forged readings | `auth_only` (GMAC) | every forgery is rejected | `forged_ok == 0` and `rejected > 0` | `forged_ok`, `rejected_by` |
| 7 | `inject-sign` | forged readings | `sign` (Ed25519) | every forgery rejected; real traffic still flows | `forged_ok == 0`, `rejected > 0`, `delivered_msg_s > 0` | `forged_ok`, `rejected_by`, `gw_cpu_us_per_msg` |
| 8 | `replay-no-checks` | replay at 20 msg/s | encryption only (`freshness=off`, `replay=off`) | authentic old messages are accepted again | `replays_ok > 0` | `replays_ok` |
| 9 | `replay-freshness-only` | replay | encryption + 60 s freshness | **replays younger than 60 s still get through** | `replays_ok > 0` | `replays_ok` |
| 10 | `replay-window` | replay | encryption + replay window | every replay is rejected | `replays_ok == 0` and `ReplayDetected` in `rejected_by` | `replays_ok`, `rejected_by` |
| 11 | `flood-rate-limit` | flood sensor-1's topic at 150 msg/s | gateway rate limit 30 msg/s per topic | the excess is dropped before any crypto | `rate_limited > 0` | `rate_limited`, `gw_cpu_pct` |
| 12 | `downlink-commands` | — | commands protected end to end, 20/s | every actuator verifies and accepts | `cmd_ok > 0` and `cmd_rejected == 0` | `cmd_sent`, `cmd_ok`, `cmd_rejected` |
| 13 | `modern-transport` | — | TLS 1.3 + MQTT 5 | everything keeps working | `delivered_msg_s > 0` and `loss_pct < 5` | `delivered_msg_s`, `loss_pct` |
| 14 | `hardened` | eavesdrop + impersonate + inject 20/s + replay 20/s | the `hardened` preset + downlink 20/s | the attacker gets nothing; all legitimate traffic, both ways, flows | attacker not connected, `leak_pct == 0`, `forged_ok == 0`, `replays_ok == 0`, `delivered_msg_s > 0`, `loss_pct < 5`, `rejected == 0`, all sensors up, `cmd_ok > 0`, `cmd_rejected == 0` | `attacker`, `leak_pct`, `forged_ok`, `replays_ok`, `delivered_msg_s`, `loss_pct`, `cmd_ok`, `gw_cpu_us_per_msg` |
| 15 | `key-rotation` | keys captured earlier | rotate every payload key (`key_epoch + 1`) | traffic continues without rejections across the switch | `rejected == 0` and `loss_pct < 5` | `rejected`, `loss_pct` |
| 16 | `revocation` | a device is compromised | `auth=on`, revoke sensor-1 | sensor-1 is locked out; the others continue | `sensors_up == sensors_total − 1` and `delivered_msg_s > 0` | `sensors_up`, `delivered_msg_s` |

### Attacks of the report's attack table (WP3)

| Name | Attack | Defence | PASS if |
|---|---|---|---|
| `eavesdrop-network-control` | capture the gateway's link | none (plain TCP, no envelope) | `wire_readable_pct > 50` |
| `eavesdrop-network-tls` | capture the gateway's link | TLS | no MQTT parsed on the wire, ciphertext seen, **but `leak_readable_pct > 50`**: TLS protects the hop, not the content from the broker |
| `eavesdrop-broker-encrypt` | `#` subscriber + link capture | envelope, encrypt, no TLS | everything received, nothing readable (topic/size/timing still visible) |
| `inject-chacha20` | forged readings | envelope with ChaCha20-Poly1305 keys | forgeries rejected, genuine traffic flows after the algorithm switch (a key rotation) |
| `republish-topic-control` / `republish-topic` | copy captured messages to `…/humidity` of the same device | none / topic in the AAD | `republished_ok > 0` / `republished_ok == 0`, `AuthenticationFailed`, no `PermissionDenied` (the key may publish there) |
| `stolen-key-other-topic-control` / `stolen-key-other-topic` | sensor-1's key on sensor-2's topic | key binding off / on (no ACL) | `forged_ok > 0` / `forged_ok == 0` with `PermissionDenied` |
| `stolen-key-acl` | same, with sensor-1's password | broker ACL, key binding off | the broker refuses it: `forged_ok == 0` |
| `old-unseen-message-control` / `old-unseen-message` | 2-minute-old messages with new sequence numbers | window only / temporal validity | `forged_ok > 0` / `forged_ok == 0` with `MessageExpired` |
| `downgrade-relabel` | encrypt → auth_only in captured envelopes | mode in the AAD (both modes accepted) | `AuthenticationFailed`, no replay accepted |
| `downgrade-policy-control` / `downgrade-policy` | valid auth_only messages with a stolen key | receiver accepts both / encrypt only | `forged_ok > 0` / `ProtectionNotAccepted` |
| `receiver-forgery-control` / `receiver-forgery` | actuator sensor-1 forges commands to sensor-2 | AES group key / signatures | `cmd_forged_ok > 0` / none accepted, genuine commands are |
| `slow-connections-control` / `slow-connections` | 300 half-open connections (SlowITe) + a connection probe | no limit / `max_connections` = sensors + 16, in place before the attack | the broker holds all 300 / at most 16 held and every sensor stays up; the probe shows newcomers refused, `recovery_s` after the attack |
| `active-broker-alter-control` / `active-broker-alter` | malicious broker alters every 2nd message | none / envelope | delivered unnoticed / ≥ 90 % of them `AuthenticationFailed` |
| `active-broker-redirect` | … moves them to another topic | topic in the AAD | ≥ 90 % `AuthenticationFailed` |
| `active-broker-delay` | … delays them 2 s | temporal validity (60 s) | **not prevented**: no rejection, p99 ≥ 1.5 s |
| `active-broker-drop` | … drops them | envelope | **not prevented**: no rejection, ≈ 50 % loss |

The last two state the limits of the design: a delay shorter than Δa and
suppression are invisible to the receiver. A scenario that needs the relay but
runs on a lab without it is reported as `SKIPPED`.

Observed while developing them: if the broker restarts during a SlowITe attack
(e.g. because the connection limit is applied then), the attacker can take
every free slot before the sensors reconnect, and none of them gets back in.

## What they teach

- **1 vs 2** — the ACL is what hides traffic from other broker clients.
- **3 vs 4** — without authentication, a client id/username is only a claim;
  the ACL then grants an impersonator exactly what the real client has.
- **5–7** — any payload authentication stops forgeries; signatures additionally
  prove origin at ~40× the CPU cost (visible in `gw_cpu_us_per_msg`).
- **8–10** — `replay-freshness-only` is the instructive one: a freshness window
  alone lets every replay younger than 60 s through; only the sequence-number
  window stops them.
- **11** — the rate limit protects the gateway's CPU, but because the attacker
  floods sensor-1's topic, sensor-1's legitimate messages share the budget
  (limitation L3 in the SDD).
- **14** — with every defence on, the attacker cannot even connect, and the
  system still carries all legitimate traffic in both directions.
- **15–16** — operational responses: rotation is seamless (3 s overlap), and
  revocation locks out exactly one device.

## Adding a scenario

Append a `Scenario(name, attack, defence, expect, check, patch, shows)` to
`SCENARIOS` in `tools/loadgen/scenarios.py`. `patch` is a partial config or a
function of the current config; `check` receives the measured row (see
[measurement columns](dashboard-and-api.md#measurement-columns), plus
`sensors_total`). Keep irreversible scenarios at the end.
