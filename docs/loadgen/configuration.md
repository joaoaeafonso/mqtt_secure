# Load lab — configuration reference

The configuration is a nested dict with nine sections. It can come from a TOML
file (`--config`, see `tools/loadgen/lab.example.toml`), `--preset`, `--set
section.key=value`, the dashboard, or `POST /api/config` with a partial JSON
object. Every key is optional; missing keys take the defaults below
(`lab.py: DEFAULTS`). Keys marked **startup** cannot change while the lab runs
(`STARTUP_ONLY`); everything else can.

## Settings

### `[broker]` — all startup

| Key | Default | Type | Meaning |
|---|---|---|---|
| `host` | `"127.0.0.1"` | str | bind address; `"0.0.0.0"` when agents run elsewhere |
| `port` | `18830` | int | a private Mosquitto; the system one is untouched |
| `advertise` | `""` | str | address clients use; default `host`, or this machine's LAN address when `host` is `0.0.0.0`/`::`. Added to the broker certificate's SAN so TLS hostname checks pass |

### `[transport]` — defence layer 1 (broker and connections)

| Key | Default | Values | Meaning |
|---|---|---|---|
| `mode` | `"plain"` | `plain` · `tls` · `mtls` | the broker has only this listener; `mtls` requires client certificates and uses the CN as username |
| `tls_version` | `"1.2"` | `1.2` · `1.3` | tls and mtls |
| `protocol` | `"3.1.1"` | `3.1.1` · `5` | MQTT version of every client |
| `auth` | `false` | bool | username/password required (`allow_anonymous false` + `password_file`) |
| `acl` | `true` | bool | `open/` for everyone, `restricted/` per client; **off = no ACL at all** (`$SYS` included) |
| `clientid_binding` | `false` | bool | `use_username_as_clientid`: nobody can take over another client's session by reusing its client id |
| `sys_topics` | `false` | bool | publish `$SYS/#` statistics every 10 s (readable by all without ACL) |
| `max_packet` | `0` | int ≥ 0 | bytes; larger packets disconnect the sender; 0 = no limit |
| `max_connections` | `0` | int ≥ 0 | broker-wide; 0 = no limit |

### `[payload]` — defence layer 2 (end to end)

| Key | Default | Values | Meaning |
|---|---|---|---|
| `protection` | `"encrypt"` | `none` · `auth_only` · `encrypt` · `sign` | sensors, actuators and gateway |
| `freshness` | `true` | bool | reject messages older than 60 s (or > 5 s in the future) |
| `replay` | `true` | bool | sequence-number replay window |
| `key_binding` | `true` | bool | a key may only publish on `+/sensors/<owner>/#` |
| `rate_limit` | `0` | int ≥ 0 | gateway inbound msg/s per topic; 0 = off |
| `key_epoch` | `0` | int ≥ 0 | **raise while running** to rotate every payload key; may only increase; must be 0 at startup |

### `[storage]`

| Key | Default | Values | Meaning |
|---|---|---|---|
| `persistence` | `"none"` | `none` · `plain` · `at-rest` | gateway: store decrypted messages, or envelopes |

### `[downlink]`

| Key | Default | Meaning |
|---|---|---|
| `rate` | `0` | gateway → actuator commands/s (round robin; every sensor is an actuator) |

### `[response]`

| Key | Default | Meaning |
|---|---|---|
| `revoked` | `""` | comma-separated sensor numbers, e.g. `"3,7"`; **may only grow while running**, must be empty at startup. Withdraws payload keys, password and certificate (CRL). Normalised to sorted, deduplicated form |

### `[load]`

| Key | Default | Type | Meaning |
|---|---|---|---|
| `sensors` | `50` | int ≥ 1, **startup** | number of sensors |
| `processes` | `2` | int, **startup** | Python worker processes (local fleet) |
| `qos` | `0` | 0 · 1 · 2, **startup** | sensor publish/subscribe and gateway QoS |
| `rate` | `20.0` | float ≥ 0 | msg/s per sensor |
| `payload` | `64` | int ≥ 8 | plaintext bytes (first 8 = send time) |
| `zone` | `"restricted"` | `open` · `restricted` | topic zone for sensors, attacker and downlink |

### `[attacker]`

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | connected and subscribed to `#`; has only the CA certificate |
| `impersonate` | `false` | claim username `gateway` (no password, no certificate) |
| `inject_rate` | `0.0` | forged plaintext msg/s into `<zone>/sensors/sensor-1/temp` |
| `replay_rate` | `0.0` | captured messages re-published per second |

### `[cluster]` — all startup

| Key | Default | Meaning |
|---|---|---|
| `sensor_agents` | `0` | 0 = sensors run here; N = wait for N agents, split sensors evenly |
| `attacker_agents` | `0` | 0 = one attacker here; N = one attacker per agent |
| `listen` | `"0.0.0.0"` | control port bind address |
| `port` | `8089` | control port |
| `join_timeout` | `600.0` | seconds to wait for agents |

## Validation (`lab.validate`, `lab.merged`)

- Unknown sections or keys ⇒ error.
- Choice values are compared **as text**, so TOML/JSON may give `5` or `"5"`,
  `1.3` or `"1.3"`; the canonical value is stored.
- `int`: non-negative integer, not bool. `float`: non-negative number, not
  bool (stored as float). `str`: anything, converted with `str()`. `bool`: must
  be a real boolean.
- Cross-field rules:
  - `response.revoked` entries are integers ≥ 1 and ≤ `load.sensors`;
  - `transport.max_packet`, if non-zero, ≥ `load.payload + 512`
    (`PACKET_OVERHEAD`: envelope ≤ 25 + 12 + 64, topic, MQTT headers);
  - `load.payload` ≥ 8; `load.sensors` ≥ 1;
  - `cluster.sensor_agents` ≤ `load.sensors`;
  - agents require `broker.host` not to be a loopback address.
- In `Lab.apply` additionally: startup-only keys cannot change;
  `payload.key_epoch` cannot decrease; `response.revoked` cannot shrink. At
  `Lab.start`: `key_epoch` must be 0 and `revoked` empty.

An invalid patch changes nothing (validation happens before any action).

## How each setting is applied

| Setting | Broker | Gateway | Sensors / actuators | Attacker |
|---|---|---|---|---|
| `transport.mode` | **restart** (only that listener) | `set transport` + `reconnect` | reconnect with new transport | reconnect |
| `transport.tls_version` | **restart** | `reconnect` (after restart) | reconnect themselves (connection lost) | reconnects (paho loop) |
| `transport.protocol` | — | `set protocol` + `reconnect` | reconnect | reconnect |
| `transport.auth` | **reload** (`SIGHUP`): clients without valid credentials are dropped | always presents credentials | always present credentials | dropped (has no password) |
| `transport.acl` | **reload**, effective on the next message | — | — | — |
| `transport.clientid_binding` | **restart** | `reconnect` | reconnect | reconnect |
| `transport.sys_topics` | **reload** | — | — | — |
| `transport.max_packet`, `max_connections` | **restart** | `reconnect` | reconnect | reconnect |
| `payload.protection` | — | `set protection` (pipeline switch) | `update(protection)` (sender mode + actuator accept set) | — |
| `payload.freshness`, `replay` | — | `set` | actuator `Verifier` | — |
| `payload.key_binding`, `rate_limit` | — | `set` | — | — |
| `payload.key_epoch` | — | `key add` (new), `set sending_key`, `key revoke` (old, after 3 s) | `add_keys`, `epoch` (rekey), `drop_keys` (after 3 s) | — |
| `storage.persistence` | — | `set persistence` | — | — |
| `downlink.rate` | — | `set downlink` | (verify commands) | — |
| `response.revoked` | rewrite `passwd` without them (**reload**; **restart** with mtls so the CRL takes effect and live sessions end) + rewrite CRL | `key revoke` for every key id they own | revoked sensors get no new keys on rotation | — |
| `load.rate`, `load.payload` | — | — | `update` | — |
| `load.zone` | — | `set zone` (downlink topics) | `update` (re-subscribe commands) | `update` |
| `attacker.*` | — | — | — | `update` (reconnect on `enabled`, `impersonate`, transport) |

Which Mosquitto (2.0.18) options apply on `SIGHUP` and which need a restart was
**measured, not assumed**: `sys_interval`, the password file and the ACL are
re-read; `use_username_as_clientid`, `max_packet_size` and listener options are
not. Listener options must follow the `listener` line, or Mosquitto silently
opens an extra default listener on 1883.

Legitimate clients always present their credentials (password, and with mtls
their certificate), so toggling authentication never interrupts them; only the
attacker is affected.

## Presets

`--preset hardened`, the dashboard's **Harden** button, or `POST /api/preset
{"name":"hardened"}`:

| Layer | Settings |
|---|---|
| Broker | `mode=mtls`, `tls_version=1.3`, `protocol=5`, `auth`, `acl`, `clientid_binding`, `sys_topics=false`, `max_packet = load.payload + 512`, `max_connections = load.sensors + 16` |
| Payload | `protection=sign`, `freshness`, `replay`, `key_binding`, `rate_limit = max(10, int(2 × load.rate) + 1)` |
| Topics | `load.zone=restricted` |

The limits are derived from the load so legitimate traffic always fits.
Explicit `--set` values still win.

## Matrix behaviour with startup-only keys

`matrix` splits `--vary` axes into startup-only ones (outer loop: a **fresh
lab** per combination) and live ones (inner loop: `Lab.apply` per cell). All
combinations are validated before anything starts. Agents stay connected for
the whole matrix and are re-provisioned per lab.

## Example file

`tools/loadgen/lab.example.toml` lists every key with its default and a
comment. A minimal custom file:

```toml
[transport]
mode = "tls"
tls_version = "1.3"
auth = true

[payload]
protection = "sign"

[load]
sensors = 200
rate = 10
```
