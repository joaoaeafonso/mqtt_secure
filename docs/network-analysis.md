# Network analysis with Wireshark

This guide shows how to record what the system does on the wire and turn it
into evidence for a report: which defence hides what, what an attacker
actually sends, and how much each protection costs in bytes.

Tooling in this repository:

| Piece | Location | Purpose |
|---|---|---|
| Dissector | `tools/wireshark/msec.lua` | decodes the lab port as MQTT or TLS+MQTT, every envelope field, flags replays, forgeries and unprotected payloads |
| Key-log shim | `tools/wireshark/sslkeylog.cpp` → `build/bench/tools/wireshark/libmsec_sslkeylog.so` | makes Mosquitto and the C++ gateway log their TLS secrets (`LD_PRELOAD`) |
| Python key logging | `tools/loadgen/keylog.py` | sensors, attacker and the agent control channel log their TLS secrets |
| Lab capture | `tools/loadgen/capture.py`, `loadgen.py … --capture` | records a run, embeds TLS secrets and an annotation per configuration change |
| Sample capture | `tools/loadgen/pcapgen.py sample out.pcap` | typical traffic built from the test vectors, no lab needed |
| Tests | `tools/loadgen/tests/test_wireshark.py` | dissector, real TLS 1.2/1.3 decryption, capture post-processing |

## 1. What is visible where

```
          ┌──────────── TLS (if on) ────────────┐
 sensor ──┤ MQTT: CONNECT, topic, flags, …      ├──▶ mosquitto ──▶ gateway
          │   PUBLISH payload = msec envelope   │
          │     header (mode, key id, seq, ts)  │   ← readable even without keys
          │     body: ciphertext / payload+tag  │   ← readable only for auth_only / sign
          └─────────────────────────────────────┘
```

| Configuration | On the wire without secrets | After decrypting TLS |
|---|---|---|
| plain + `none` | everything: topics, client ids, usernames, **passwords**, payloads | — |
| plain + `encrypt` | MQTT metadata; envelope header; ciphertext | — |
| plain + `auth_only` / `sign` | MQTT metadata; envelope; **readable payload** + tag/signature | — |
| `tls` / `mtls` + anything | TLS records only (and, with TLS 1.2, the certificates) | as the plain rows |

The dissector decodes structure. It **does not verify** tags or signatures; it
holds no keys. Verification is the gateway's job, and its decisions show up
in the lab's metrics. Replays and forgeries are recognised from what is on the
wire (repeated key id + sequence, the lab attacker's markers).

## 2. Setup (once)

```bash
sudo apt install wireshark tshark            # answer "Yes": non-root users may capture
sudo usermod -aG wireshark $USER             # then log out and in again
# already installed and answered "No"?  sudo dpkg-reconfigure wireshark-common

mkdir -p ~/.local/lib/wireshark/plugins
ln -sf "$PWD/tools/wireshark/msec.lua" ~/.local/lib/wireshark/plugins/msec.lua

cmake --preset bench && cmake --build --preset bench    # also builds the key-log shim
```

Check in Wireshark: *Help → About Wireshark → Plugins* lists `msec.lua`
(*Folders* shows the personal plugin folder if yours differs). Without
installing, load it per run: `wireshark -X lua_script:tools/wireshark/msec.lua`.

The dissector's preferences are in *Edit → Preferences → Protocols → MSEC*:
the broker port (default 18830) and "Lab conventions".

## 3. Try it without the lab

```bash
tools/loadgen/.venv/bin/python tools/loadgen/pcapgen.py sample /tmp/msec-sample.pcap
wireshark /tmp/msec-sample.pcap
```

The capture contains: a gateway and an eavesdropper subscribing; one sensor
publishing an `encrypt`, an `auth_only` and a `sign` envelope; the broker
delivering each to both subscribers; the eavesdropper replaying the
encrypted one, injecting a forged reading and a malformed envelope. Try
`msec.replay_of`, `msec.mode == 3`, `msec.lab.forged`, and *Analyze → Expert
Information*.

## 4. Recording a lab run

Add `--capture` to `live`, `matrix` or `scenarios` (and `run.sh`):

```bash
./run.sh --set load.sensors=3 --set load.rate=1 --capture
tools/loadgen/.venv/bin/python tools/loadgen/loadgen.py scenarios --set load.sensors=5 --capture
tools/loadgen/.venv/bin/python tools/loadgen/loadgen.py matrix --vary transport.mode=plain,tls,mtls \
    --vary payload.protection=none,encrypt,sign --capture
```

| Option | Meaning |
|---|---|
| `--capture` | record to `build/loadtest/<live\|matrix\|scenarios>-<time>.pcapng` (next to the results) |
| `--capture FILE.pcapng` | record to this file |
| `--capture-iface IFACE` | default `lo`; `any` when agents (other machines) are configured |
| `--keylog FILE` | where TLS secrets go (default `<capture>.keys`); usable without `--capture`, e.g. when you run Wireshark yourself |

What happens:

1. `SSLKEYLOGFILE` is set **before** anything starts, so every TLS endpoint
   inherits it: Mosquitto and `msec_load_gateway` through the preloaded shim,
   the Python sensors, attacker and agent control channel through
   `keylog.enable()`.
2. `dumpcap` records `tcp port 18830` (plus the control port 8089 with
   agents).
3. Every lab event — each configuration change, each scenario, each matrix
   cell — is time-stamped.
4. On stop, `editcap`:
   - **embeds the TLS secrets** in the pcapng (a Decryption Secrets Block), so
     the file opens decrypted on any machine, with no key file;
   - adds a **packet comment** (`lab: transport.mode: plain → tls`, `lab:
     scenario replay-window: …`) at the first frame after each event.

Outputs: `<name>.pcapng`, `<name>.keys` (0600), `<name>.events.tsv` (Unix time,
event).

In Wireshark, filter `frame.comment` to list the annotations and jump
between phases. *Statistics → Capture File Properties* lists them too.

**Keep the load small for screenshots** (3–5 sensors, 1 msg/s). At 100 sensors
× 20 msg/s a capture grows by several MB per second, which is fine for
statistics but unreadable packet by packet.

## 5. How TLS decryption works here

Wireshark needs the session secrets of each TLS connection, from **either**
end. In the lab:

| Endpoint | Logs via | Covers |
|---|---|---|
| Mosquitto | `LD_PRELOAD=libmsec_sslkeylog.so` | **every** MQTT/TLS connection, local or from agents |
| `msec_load_gateway` (Paho C / OpenSSL) | same shim | gateway ↔ broker |
| Python sensors, attacker | `ssl.SSLContext.keylog_filename` | their own connections |
| controller and agents (8089) | `keylog_filename` | the provisioning channel |

The shim wraps OpenSSL's `SSL_new` and installs a key-log callback on each
new connection's context; lines are appended with one `write()` each, so the
processes never interleave. (Mosquitto 2.0 and Paho C have no key-log option,
and OpenSSL 3.0 ignores `SSLKEYLOGFILE`.)

TLS 1.2 sessions log `CLIENT_RANDOM` lines; TLS 1.3 sessions log
`*_HANDSHAKE_TRAFFIC_SECRET` / `*_TRAFFIC_SECRET_0` lines. With TLS 1.3 the
certificates are encrypted, so mTLS client certificates are visible only after
decryption. With TLS 1.2 they are visible to anyone. That's a nice
comparison for the report.

Without `--capture`, point Wireshark at the key file yourself: *Preferences →
Protocols → TLS → (Pre)-Master-Secret log filename*, or
`tshark -o tls.keylog_file:FILE`.

> The key file and a pcapng with embedded secrets decrypt everything recorded.
> They contain test credentials only (MQTT passwords travel inside TLS). Don't
> publish them outside the report, and never enable key logging in a
> deployment.

### TLS version: what the lab really negotiates

Measuring with the shim showed that Mosquitto's `tls_version` is only a
**minimum**: with `transport.tls_version = "1.2"` every client still
negotiated TLS 1.3. Paho C's `sslVersion` is a minimum as well. The lab broker
therefore also caps the **maximum** through an OpenSSL configuration
(`OPENSSL_CONF` with `MaxProtocol = TLSv1.2`, `tools/loadgen/broker.py`). Since
that fix, `"1.2"` means TLS 1.2 on the wire for every client. Test:
`test_tls12_is_really_tls12`. Results recorded before the fix compared
TLS 1.3 with TLS 1.3.

## 6. Dissector reference

The lab switches plain/TLS on one port, so the dissector decides **per TCP
stream** from the first bytes. A TLS record starts with content type
0x14–0x17 and version 3; no valid MQTT packet does. TLS application data on
the port is decoded as MQTT.

| Field | Meaning |
|---|---|
| `msec` | an envelope (or an unprotected device payload) |
| `msec.magic`, `msec.version` | `MS`, 2 |
| `msec.mode` | 1 encrypt · 2 auth_only · 3 sign |
| `msec.key_id` | key id |
| `msec.lab.epoch`, `msec.lab.device`, `msec.lab.owner` | key id = epoch × 10⁶ + device (lab convention) |
| `msec.seq` | sequence number |
| `msec.timestamp_ms`, `msec.time` | sender timestamp, raw and as a date |
| `msec.nonce_len`, `msec.nonce` | 12 B nonce (AEAD modes) |
| `msec.ciphertext` | encrypt mode |
| `msec.payload` | readable payload (auth_only, sign) |
| `msec.tag`, `msec.signature` | 16 B GCM tag, 64 B Ed25519 signature |
| `msec.overhead` | envelope bytes on top of the payload (53 / 89) |
| `msec.topic` | the topic bound into the AAD |
| `msec.replay_of` | this PUBLISH to the broker repeats key id + sequence of that earlier frame |
| `msec.published_in` | for a broker → subscriber copy: the frame where it was published |
| `msec.lab.sent` | sender's send time (first 8 plaintext bytes) |
| `msec.lab.command_id`, `msec.lab.command` | downlink command id and text |
| `msec.lab.forged` | attacker marker `FORGED!!` (uplink) / `FORGED-C` (downlink) |

Expert information (*Analyze → Expert Information*):

| Expert | Severity | When |
|---|---|---|
| `msec.replay` | warning | a second PUBLISH **to the broker** with the same key id, sequence and mode |
| `msec.unprotected` | warning | a payload on a `/sensors/` or `/actuators/` topic that is not an envelope |
| `msec.forged` | warning | the lab attacker's marker in a readable payload |
| `msec.malformed` | error | starts with `MS` but violates the format (truncated, bad version/mode, seq 0, bad nonce length, no body, body shorter than the tag) |
| `msec.mode.info` | chat | the protection mode of each envelope |

The Info column gets `[msec <mode> key=<id> seq=<n>]`, `[REPLAY of #<frame>]`,
`[unprotected]` or `[msec malformed]`.

## 7. Filter cookbook

| Goal | Display filter |
|---|---|
| all lab traffic | `tcp.port == 18830` |
| publishes | `mqtt.msgtype == 3` |
| envelopes / by mode | `msec.mode` · `msec.mode == 1` · `msec.mode == 3` |
| one device | `msec.lab.owner == "sensor-3"` |
| uplink vs downlink | `mqtt.topic contains "/sensors/"` · `mqtt.topic contains "/actuators/"` |
| replays | `msec.replay_of` |
| forgeries / unprotected | `msec.lab.forged` · `_ws.expert.message contains "Unprotected"` |
| the attacker | `mqtt.clientid contains "mallory"` |
| what the eavesdropper receives | `tcp.dstport != 18830 && mqtt.msgtype == 3` (then *Follow → TCP stream* on mallory's connection) |
| refused connections | `mqtt.conack.val != 0` |
| MQTT 5 reason codes | `mqtt.connack.reason_code` · `mqtt.suback.reason_code` · `mqtt.disconnect.reason_code` |
| passwords in clear (plain transport) | `mqtt.passwd` |
| TLS handshakes / versions | `tls.handshake.type == 1` · `tls.handshake.version` · `tls.record.version` |
| certificates (TLS 1.2 mTLS) | `tls.handshake.type == 11` |
| TLS alerts (no / revoked certificate) | `tls.alert_message` |
| `$SYS` leaks | `mqtt.topic contains "$SYS"` |
| lab annotations | `frame.comment` |
| agent control channel | `tcp.port == 8089` |

## 8. Experiments for the report

Run `live` with a small load and `--capture`, apply each step on the
dashboard (each lands as a comment in the capture), and take the screenshot
listed.

| # | Steps | Screenshot / figure | Point |
|---|---|---|---|
| 1 | plain, `protection=none`, zone open | a PUBLISH with readable payload; CONNECT with `mqtt.passwd` (auth on) | baseline: everything readable, including credentials |
| 2 | `protection=encrypt` | envelope tree: header readable, ciphertext + tag | payload confidentiality without TLS; what metadata remains |
| 3 | `auth_only`, then `sign` | `msec.payload` readable + 16 B tag / 64 B signature; `msec.overhead` 53 vs 89 | integrity without confidentiality; cost in bytes |
| 4 | attacker replay 5/s | `msec.replay_of` frames next to the originals | replay is byte-identical; only the replay window can stop it (cf. `replay-freshness-only`) |
| 5 | attacker inject 5/s, protection none vs encrypt | `[unprotected]` + forgery marker | injection is trivial at the broker; the gateway's envelope check stops it |
| 6 | `transport.mode=tls` | only TLS records; then with the embedded secrets, the same envelope inside | defence in depth: TLS hides the wire, the envelope survives the broker |
| 7 | `mtls`, `tls_version` 1.2 vs 1.3 | client certificate in clear (1.2) vs encrypted (1.3) | metadata privacy of TLS 1.3 |
| 8 | `auth` on + attacker impersonate | CONNACK *not authorized*; with mtls: TLS alert / failed handshake | impersonation stopped at the broker |
| 9 | ACL on, restricted zone | mallory's stream: SUBSCRIBE `#`, no PUBLISH delivered | authorisation hides traffic from other clients |
| 10 | revoke a sensor (mtls) | its handshake ends in an alert after the CRL restart | incident response is visible on the wire |
| 11 | `downlink.rate` | `/actuators/…/cmd` envelopes with `msec.lab.command` | both directions are protected |
| 12 | Harden | attacker never completes a handshake; every frame is TLS 1.3 | the hardened preset on the wire |

Figures:

- *Statistics → I/O Graphs*: bytes/s over the run with the comment markers.
  Plain → TLS → mTLS and none → encrypt → sign appear as steps.
- *Statistics → Protocol Hierarchy*: share of TLS vs MQTT.
- *Statistics → Conversations → TCP*: one row per client; the attacker's
  byte counts per configuration.
- `tshark` one-liners for tables:

```bash
f=build/loadtest/scenarios-*.pcapng
tshark -r $f -X lua_script:tools/wireshark/msec.lua -q -z expert                     # attack summary
tshark -r $f -X lua_script:tools/wireshark/msec.lua -Y msec.replay_of | wc -l        # replays seen
tshark -r $f -X lua_script:tools/wireshark/msec.lua -q \
       -z io,stat,0,"COUNT(msec.mode)msec.mode==1","COUNT(msec.mode)msec.mode==3"   # envelopes per mode
tshark -r $f -T fields -e frame.number -e frame.comment -Y frame.comment              # timeline
```

(With the dissector installed as a plugin, drop `-X lua_script:…`.)

## 9. Multiple machines

With agents, the controller captures on `any` and sees every MQTT connection
(the broker logs secrets for all of them) plus the agent control channel.
Decrypting port 8089 shows the provisioning messages (CSRs, certificates,
passwords and keys for that agent's sensors). That makes it a good figure for
the trust-bootstrap section, and a reason to treat that capture as secret.

## 10. Verification

`tools/loadgen/tests/test_wireshark.py` (needs tshark; set `TSHARK=…` for a
non-system one; the TLS tests also need mosquitto and the bench build):

| Test | Checks |
|---|---|
| `test_every_mode_is_decoded_with_its_overhead` | modes 1/2/3 decoded, overhead 53/53/89, key id, sequence, owner |
| `test_replay_is_flagged_and_linked_to_the_original` | exactly one replay, linked to the right frame |
| `test_broker_deliveries_are_not_replays` | broker → subscriber copies are linked, not flagged |
| `test_forgery_unprotected_and_malformed` | forgery marker, unprotected payload, truncated envelope |
| `test_tls12_is_really_tls12`, `test_tls13` | a real TLS session to `broker.Broker`, decrypted with secrets **only the broker** logged via the shim; negotiated version is the configured one; nothing readable without the secrets |
| `test_capture_finish_embeds_secrets_and_event_comments` | pcapng timestamps, embedded secrets decrypt without a key file, comments on the right frame |
