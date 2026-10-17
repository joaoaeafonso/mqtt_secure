# `msec_gateway_demo` — the architecture in one process

**Source:** `apps/gateway/main.cpp` · **Target:** `msec_gateway_demo` ·
**Links:** `msec::mqtt`, `msec::security`, `msec::data` · **Requires:**
`MSEC_WITH_OPENSSL` (skipped otherwise; Paho not needed)

```bash
cmake --preset dev && cmake --build --preset dev
./build/dev/apps/gateway/msec_gateway_demo; echo "exit $?"
```

It is the reference **composition root**: the only place that names concrete
classes. Swapping the loopback broker for Paho, or the in-memory repository for
SQLite, is a change here only.

## What it wires

| Object | Concrete type |
|---|---|
| logger | `ConsoleLogger(Info)` |
| clock | `SystemClock` |
| cipher | `openssl::AesGcmCipher` |
| RNG | `openssl::RandomSource` |
| keys | `InMemoryKeyStore` with one random 32-byte key, id 1 |
| repository | `InMemoryMessageRepository(1000)` |
| broker | `LoopbackBroker` with the two-zone ACL |

ACL:

| Rule | Meaning |
|---|---|
| `allow_all("open/#", ReadWrite)` | anyone may publish and read `open/` |
| `allow("sensor-1", "restricted/sensors/room1/#", Write)` | only sensor-1 publishes its room |
| `allow("gateway", "restricted/sensors/#", Read)` | only the gateway reads the restricted zone |

Pipelines:

```
sensor   (client id "sensor-1"):  [security] ─▶ MQTT
gateway  (client id "gateway"):   app ◀─ [persistence] ◀─ [security] ◀─ MQTT   (plaintext stored)
attacker (client id "mallory"):   raw LoopbackClient subscribed to "#"
```

## Script

1. **Legitimate traffic** — the sensor publishes `21.4`, `21.5`, `21.7` to
   `restricted/sensors/room1/temp` and `online`, `battery 87%` to
   `open/sensors/room1/status`, all encrypted.
2. **Eavesdropping** — mallory's `#` subscription receives only the two `open/`
   messages (the ACL hides `restricted/`), and those are ciphertext.
3. **Attacks**:

| Attack | Message | Stopped by | Code |
|---|---|---|---|
| replay | captured[0] re-published | gateway `ReplayGuard` | `ReplayDetected` |
| tamper | captured[1] with last byte flipped | gateway AES-GCM | `AuthenticationFailed` |
| rebind into restricted | captured[0] with topic changed to restricted | broker ACL (publish denied) | `PermissionDenied` |
| inject restricted | plaintext `99.9` to restricted | broker ACL | `PermissionDenied` |
| inject open | plaintext `offline` to open | gateway envelope parse | `MalformedMessage` |

4. **Verdict** — logs gateway delivered/rejected/stored counts and broker
   denials; exits `0` iff captured = 2, delivered = 5, rejected = 3, denied by
   ACL = 2, otherwise `1`. This makes the demo a smoke test of the whole stack.

Actual output (timestamps removed):

```
INFO  [gateway] received restricted/sensors/room1/temp = 21.4
INFO  [gateway] received restricted/sensors/room1/temp = 21.5
INFO  [gateway] received restricted/sensors/room1/temp = 21.7
INFO  [gateway] received open/sensors/room1/status = online
INFO  [gateway] received open/sensors/room1/status = battery 87%
INFO  [demo] attacker captured 2 messages (all open), ciphertext of 59 bytes
WARN  [endpoint] inbound on 'open/sensors/room1/status' rejected (ReplayDetected): [security] duplicate sequence number
WARN  [endpoint] inbound on 'open/sensors/room1/status' rejected (AuthenticationFailed): [security] message authentication failed
INFO  [demo] rebind into restricted: denied by broker (client 'mallory' may not publish to 'restricted/sensors/room1/temp')
INFO  [demo] inject restricted: denied by broker (client 'mallory' may not publish to 'restricted/sensors/room1/temp')
WARN  [endpoint] inbound on 'open/sensors/room1/status' rejected (MalformedMessage): [security] envelope truncated
INFO  [demo] gateway delivered=5 rejected=3 stored=5; broker denied=2
```

(59 bytes = 6-byte `"online"` + 53 bytes envelope overhead. The injected
`"offline"` is 7 bytes, shorter than the 25-byte header, hence "envelope
truncated". Rejection messages carry the `[security]` prefix added by the
pipeline.)

## Error handling style

Startup uses `require(result, "what")`, which prints
`fatal: <what>: <message> (<Code>)` and exits — appropriate for a
single-threaded composition root, never inside library code.
