# Load lab — dashboard test findings (2026-11-11)

Every security level and every dashboard attack was exercised through the live
dashboard. This page records what worked, the bugs found (major and minor), and
a proposal for a second ladder of levels that shows the defence layers stacking
up, which the K0–K11 ladder cannot do. No code was changed during the session.
Everything below was observed on the running lab, except the parts marked as a
proposal.

## Status (2026-11-11, after the session)

| Item | Status |
|---|---|
| B1 wall-clock intervals | fixed: the lab keeps one clock that never goes back (`Lab.now()`), `measure()` uses monotonic time |
| B2 rotation rejects genuine messages | fixed: senders switch only after the gateway confirms the new keys (`sync`) |
| B3 delivered rate misread | fixed: gateway rates use the gateway's own report interval; a repeated report is not sampled |
| B4 stopping Eavesdrop | fixed: it clears every attack; **Stop everything** does the same |
| B5 Flood verdict | fixed: format, mode and timestamp rejections are "before any crypto" |
| B6 verdict right after a change | fixed: only points measured after the change are averaged |
| B7 K11 label | fixed |
| B8, B10 | open (cosmetic) |
| B9 rejections while the mode switches | left as is: they fall inside the settle time, and accepting the old mode for a grace period would weaken the downgrade policy |
| B11 | grammar and favicon fixed; the rest open |
| Defence ladder | implemented as D0–D10 (a key–topic step, D5, was added, so the numbers after D4 moved by one); see [dashboard-and-api.md](dashboard-and-api.md#defence-ladder-d0d10-demonstrations-only) |
| Insider attacks | three dashboard rows: old message, stolen key on another topic, forged commands. The real device is offline while compromised (`attacker.stolen_exclusive`), so the session takeover noted below no longer happens |

Verified by driving the lab through the dashboard's own verdict code (not in
a browser): every step D0–D10 against the outsider attacks, the three insider
rows at D2–D5, D9 and K9, and the B4 sequence. The page itself (layout, the
new buttons) still needs a look in a browser.

## How it was tested

| Item | Value |
|---|---|
| Lab | `docker compose up` (`compose.yaml`): broker, gateway and dashboard in `lab`; 100 sensors on 2 sensor agents; 1 attacker agent |
| Load | 100 sensors × 20 msg/s = 2 000 msg/s, 64-byte payload, QoS 0 |
| Host | Windows with WSL2 (Linux 6.6) and Docker |
| Driver | Playwright clicking the real buttons at `http://127.0.0.1:8088/`; values read from the page and from `/api/state` |
| Method | per level: click it, wait for it to settle, then start each attack on its own for ~11 s, read the verdict at ~6 s and ~11 s, stop it |

Every attack button also switches the attacker on (`attacker.enabled`), so
Eavesdrop runs alongside every other attack.

## Results

### Every level against every attack

| Level | Eavesdrop | Impersonate | Inject | Replay | Flood |
|---|---|---|---|---|---|
| K0 | succeeds — reads in clear | succeeds | succeeds — 20 forged msg/s accepted | succeeds — 20 replays/s accepted | succeeds — accepted as readings |
| K1–K9, K11 | blocked — mTLS | blocked — mTLS | blocked — mTLS | blocked — mTLS | blocked — mTLS |
| K10 | blocked — only ciphertext | succeeds — no authentication | blocked — envelope check | blocked — replay window | "partly blocked" — wrong verdict (B5) |

Once settled, every verdict matched the design except K10's Flood. Legitimate
traffic stayed at about 100 % delivered at every level, apart from the
transients listed under B9. The cost tile showed the expected overheads: 53 B
per message for GMAC, AES-GCM and ChaCha20, 89 B for Ed25519, and about three
times the gateway CPU per message at K9. The level K10 → K11 → K0 changes rotated
every key (epoch 0 → 1 → 2) without a single rejection.

### One defence at a time (Advanced settings, plain TCP)

mTLS stops the attacker before it reaches anything else, so K1–K9 cannot show
what their payload layers do. These configurations, each built from K0 under
Advanced settings, can:

| Defence switched on | Eavesdrop | Impersonate | Inject | Replay | Flood |
|---|---|---|---|---|---|
| ACL | blocked — `#` gets nothing | succeeds — **inherits the gateway's rights**, after which Eavesdrop succeeds | blocked — ACL drops it | blocked — ACL drops it | blocked — ACL drops it |
| password auth | blocked — refused ("Not authorized") | blocked | | | |
| server-only TLS | succeeds — reads in clear | succeeds | | | |
| `auth_only` | succeeds — readable | | blocked — envelope check | succeeds | "partly blocked" (B5) |
| `auth_only` + timestamp check | | | | **succeeds** — copies younger than 60 s accepted | |
| `auth_only` + replay window | | | | blocked — replay window | |
| … + rate limit 41 msg/s | | | | | blocked — 137 msg/s dropped before crypto |
| `sign` | succeeds — readable | | blocked — envelope check | | |

Empty cells were not run in that configuration. Invalid combinations
(protection `none` with the replay window on, `max_packet` below 576) were
refused with an inline error, and the control went back to its previous value.

Also checked: the **Rotate** button, Inject and Flood replacing each other,
stopping and restarting attacks, the charts, the event log and the agents card.

## Bugs

**Major** means wrong numbers, wrong verdicts or wrong control state that a
viewer or the report could rely on. **Minor** means cosmetic, wording, or a
transient of a second or two.

| # | Severity | Where | Problem |
|---|---|---|---|
| B1 | Major | `lab.py` sampler and `Lab.measure` | intervals timed with the wall clock: ×10⁶ rate spikes, inflated `measure()` results |
| B2 | Major | `Lab._rotate` | the Rotate button made the gateway reject genuine messages (`AuthenticationFailed`) |
| B3 | Major | `lab.py` sampler | delivered rate misread: false drops to 0 and a ~1 % over-count |
| B4 | Major | dashboard attack buttons | stopping Eavesdrop leaves the other attacks set; starting any attack restarts them all |
| B5 | Major | dashboard Flood verdict | "partly blocked … only after crypto" for a flood rejected before any crypto |
| B6 | Major | dashboard verdict timing | a wrong verdict for about a second after every change |
| B7 | Minor | *Is it secure?* tile | K11 (ChaCha20) labelled "encrypted (AES-GCM)" |
| B8 | Minor | banner | "Broker restarting" never appears |
| B9 | Minor | gateway policy | genuine messages rejected for 1–2 s when the protection mode changes |
| B10 | Minor | charts | y-axis labels clipped at large values; change labels cut mid-word |
| B11 | Minor | wording and forms | grammar, an error that stays on screen, a negative input ignored silently, no favicon |

### Major

#### B1. Intervals timed with the wall clock

- **Seen:** about every 32 s, one history point has a timestamp ~0.9 s
  *earlier* than the point before it. Every rate in that point is about 10⁶
  times too large (sent ≈ 2.0 × 10⁹ msg/s). A freshly loaded dashboard draws
  these as spikes on the Throughput and CPU charts, with the y-axis labels
  clipped to "00000k" (B10). On this host the WSL2 wall clock steps back about
  2 s every 30 s (measured against `time.monotonic()`).
- **Cause:** the sampler takes the interval from `time.time()` and clamps a
  negative interval to 1 µs (`tools/loadgen/lab.py:636`, `:651`).
  `Lab.measure()` also divides by a wall-clock interval (`lab.py:730–735`). As a
  result, `sent_msg_s` and `broker_cpu_pct` from `scenarios` and `matrix` are
  inflated whenever a step falls inside the window: a 2 s step in a 6 s window
  makes them 1.5 times too large. During live polling the bad points are
  silently skipped instead, because their `t` is lower than the dashboard's
  `since=` cursor.
- **Fix:** time intervals with `time.monotonic()` and keep `time.time()` only
  for the `t` labels. Drop a non-positive interval rather than clamping it.

#### B2. Key rotation rejects genuine messages

- **Seen:** pressing **Rotate** at K6 (epoch 2 → 3) made the gateway reject 17
  genuine messages as `AuthenticationFailed` in the next second. The attacker
  could not connect at K6, so they were real sensor messages. The two
  rotations caused by changing the cipher had no rejections, so the problem is
  intermittent. Scenario 15 (`key-rotation`) expects `rejected == 0`.
- **Likely cause:** `Lab._rotate` writes the new keys to the gateway's stdin
  (`gateway.add_key`) and immediately tells the sensors to switch
  (`fleet.rotate`), without waiting for the gateway to confirm it has installed
  them (`tools/loadgen/lab.py:593–596`). With remote agents, a sensor can send
  under a new key id before the gateway knows it, and an unknown key fails as
  `AuthenticationFailed` by design.
- **Fix:** wait for the gateway to acknowledge the new keys, for example by
  waiting for its reply to a later stdin command, before calling `fleet.rotate`.

#### B3. Delivered rate misread

- **Seen:** about every 100 s, one history point has `delivered = 0` while the
  gateway is connected. Its `gw_cpu` and `lat_p99` are identical to the point
  before, and the next point is normal, not doubled. Over 15 minutes the median
  delivered rate was 2 018 msg/s against 2 001 sent, which is why the traffic
  tile can read "Delivered 2.0k of 1.9k msg/s sent". A zero point inside the 5 s
  window drops the tile to "81 % delivered" (yellow) although nothing was lost.
  Integrated over the whole run, 99.5 % of messages were delivered.
- **Cause:** the gateway publishes its counters about every 1.01 s. The
  sampler reads them every 1.00 s and divides the change by its own interval
  (`tools/loadgen/lab.py:672`). Each report therefore covers slightly more than
  a sampler second, which causes the over-count. Once in a while the sampler
  sees the same report twice, which causes the zero.
- **Fix:** take the gateway's rates from the report itself, since its
  `rx_per_s` covers the gateway's own interval (see
  [load-gateway.md](../apps/load-gateway.md)). Alternatively, skip a point when
  the stats line has not changed.

#### B4. Stopping Eavesdrop doesn't stop the other attacks

- **Seen:** with Flood and Impersonate running, **Stop** on Eavesdrop showed
  every attack as "not running" and disconnected the attacker. Pressing
  **Start** on Replay alone then brought Impersonate and Flood back as well,
  and the tile jumped to "4 of 4 attacks succeed".
- **Cause:** Eavesdrop's Stop only sets `attacker.enabled = false`
  (`tools/loadgen/dashboard.html:536`), so `impersonate` and `inject_rate` keep
  their values. Every Start then sets `enabled = true` again.
- **Fix:** make Eavesdrop's Stop also clear `impersonate`, `inject_rate` and
  `replay_rate`. The row already says that stopping it disconnects the
  attacker.

#### B5. Wrong Flood verdict

- **Seen:** at K10, and with `auth_only`, Flood shows "partly blocked — rejected
  by the envelope check (not a protected message), but only after crypto —
  gateway CPU 13.9 %", and the *Is it secure?* tile turns yellow. In fact all
  164 msg/s were rejected, legitimate traffic was 100 % delivered, and gateway
  CPU only went from 12.8 % to 13.9 %.
- **Cause:** the verdict treats `MalformedMessage` as a rejection that happens
  after crypto (`tools/loadgen/dashboard.html:595–597`). The gateway checks, in
  order:
  1. envelope parse (`MalformedMessage`)
  2. mode policy
  3. freshness
  4. AEAD or signature (`AuthenticationFailed`)
  5. key–topic restriction (`PermissionDenied`)
  6. replay window

  (`modules/security/src/security_layer.cpp:234–295` and
  `modules/security/src/envelope.cpp:64–91`). The attacker's flood is
  plaintext, so with any protection on it is always rejected at step 1, before
  any crypto. The "after crypto" text can never be the right description for
  it.
- **Fix:** report `MalformedMessage`, `ProtectionNotAccepted` and
  `MessageExpired` as "blocked before any crypto". Keep "partly blocked — after
  crypto" for `AuthenticationFailed` and `PermissionDenied`, which only a
  well-formed flood (from a compromised device, for example) would produce.

#### B6. A wrong verdict right after every change

- **Seen:** switching K0 → K10 with Inject running, the row read "succeeds —
  the gateway accepts 1.59 forged msg/s — payload protection is off" for about
  a second, although protection was already on. It then turned to "blocked".
  The same happens the other way round. The first rate shown after a change is
  also too low: Eavesdrop showed "1.4k" and then climbed to "2.0k".
- **Cause:** verdicts wait 4 s after a change (`SETTLE_S`) but average the last
  5 s (`RECENT_S`), so the first verdict still includes a second from before
  the change (`tools/loadgen/dashboard.html:350–351`, `:421`, `:425`). In a
  demo, that first verdict is the one the audience reads.
- **Fix:** average only the points after the last change
  (`p.t > lastChange()`), or make `SETTLE_S` at least `RECENT_S + 1`.

### Minor

#### B7. K11 shown as AES-GCM

At K11 (`cipher = chacha20-poly1305`) the *Is it secure?* tile reads "Payload
encrypted (AES-GCM)". The label depends only on `protection`
(`tools/loadgen/dashboard.html:673–674`). It should use `payload.cipher` for the
`encrypt` case.

#### B8. "Broker restarting" banner never appears

Two broker restarts were forced (TLS 1.3 → 1.2 → 1.3) and the page was sampled
every 200 ms for 12 s. Delivery fell to 84 % and 76 %, but `sensors_up` stayed
at 100/100 in every sample, so the banner never showed. The same happened in
the four level changes that restart the broker. The banner requires
`sensors_up < total` (`tools/loadgen/dashboard.html:694–700`), and the sensors
apparently keep counting messages as sent into the dead connection without
marking themselves down. Showing the banner for ~10 s after any change that
restarts the broker, or reacting to the drop in delivered/sent, would fix it.

#### B9. Genuine messages rejected during switches

- K2 → K3 (`auth_only` → `encrypt`): about 3 msg/s of `ProtectionNotAccepted`
  for 1 s.
- K8 → K9 (`encrypt` → `sign`): about 34 msg/s for 2 s.
- At K11, about one genuine message per second was `RateLimited` for one
  sample, 9 s after a key rotation, with no attack running.

The gateway accepts only the new mode from the moment it switches, while
messages already in flight still use the old one. The per-topic limit
(2 × rate + 1) leaves little room for a burst after a pause. Accepting both the
old and the new mode for a grace period, like the 3 s overlap of key rotation,
would remove the first two.

#### B10. Chart labels

- y-axis tick labels wider than the 44 px left margin are clipped, as seen with
  B1's spikes (`tools/loadgen/dashboard.html:784`).
- Change labels that don't match `section.key: a → b` are cut at 18 characters
  without an ellipsis, for example "keys of epoch 2 re" (`dashboard.html:740`).

#### B11. Wording and form details

- "authentication-only mode keep the payload readable" should read "keeps"
  (`tools/loadgen/dashboard.html:547`).
- "payload.replay need the envelope" should read "needs" when only one key is
  listed (`tools/loadgen/lab.py:293`).
- An error stays on screen until the next successful change
  (`dashboard.html:448`).
- A negative number in a field is ignored without any message
  (`dashboard.html:473`).
- `/favicon.ico` returns 404, which logs a console error on every load.

## Inject and Flood can't run together — by design

Both rows drive the same setting, `attacker.inject_rate`. Inject sets it to
20 msg/s and Flood to 150 msg/s, and which row counts as running depends on the
value: below 150 it is Inject, 150 or more it is Flood
(`tools/loadgen/dashboard.html:558`, `:588`). The Flood row says "(replaces the
injection)" and [dashboard-and-api.md](dashboard-and-api.md) documents this.

That is reasonable: a flood is the same forged readings sent faster, and the
Flood verdict already says whether they are accepted. Running both would just
be 170 msg/s on the same topic. One quirk: the "Inject forged" field under
Advanced settings shows any value below 150 as Inject, although that row says
20/s.

## Proposal: a defence ladder for demos

### Why K0–K11 don't work as a demo

K0–K11 are the report's evaluation configurations (Section 7,
`report/seccoes/07-plano-avaliacao.tex`). Each adds one mechanism so that its
marginal **cost** can be measured. That is the right order for the cost study,
but it shows very little on the attack table:

1. **K1 turns on the whole broker layer at once**: mTLS, passwords, ACL and
   client-id binding. The dashboard's attacker has neither a certificate nor a
   password, so from K1 on it fails the TLS handshake and every attack reads
   "blocked — mutual TLS". No attack ever reaches the payload layers that K2–K9
   add.
2. **Three layers defend only against insiders.** The timestamp check (K4), the
   key–topic restriction (K7) and signatures (K9) stop attacks by a compromised
   device: an old message never seen before, a stolen key used on another
   device's topic, an actuator forging commands. None of the five dashboard
   attacks is of that kind, so even over plain TCP they cannot show these
   levels doing anything.
3. **K10 is the only level after K1 where the attacker can connect**, and it
   comes last, out of order.

In a demo, the audience sees one change from red to green at K1, and then
nothing changes for nine levels.

### Principles

- **Inside out.** Turn on the end-to-end (payload) layers first, over plain TCP,
  while the attacker is still on the broker. Turn on the broker layers (the
  perimeter) last: once the perimeter is up the attacker cannot connect, and
  nothing behind it can be shown any more.
- **One mechanism per step**, each flipping at most one attack from *succeeds*
  to *blocked*.
- **Keep the steps that change nothing.** The timestamp check on its own, and
  an ACL without authentication, look as if they should help and don't. Those
  are the lessons.
- **End with a breach.** Take the perimeter away again and show that the inner
  layers still hold. That is what defence in depth means.

### The ladder

Every step uses `load.zone = restricted` and keeps everything from the step
before it.

| Step | Adds | Blocked from this step | Still succeeds | What it teaches |
|---|---|---|---|---|
| D0 | nothing (= K0) | — | all five | an open broker gives everything away |
| D1 | `payload.protection = auth_only` | Inject, Flood (envelope check) | Eavesdrop, Impersonate, Replay | integrity is not confidentiality: forgeries stop, contents are still readable |
| D2 | `payload.protection = encrypt` | Eavesdrop (ciphertext only) | Impersonate, Replay | confidentiality end to end, even from the broker; but an authentic copy is still authentic |
| D3 | `payload.freshness` | **nothing** | Impersonate, Replay | a 60 s window alone lets copies through |
| D4 | `payload.replay` | Replay | Impersonate | sequence numbers stop copies |
| D5 | `payload.rate_limit = max(10, 2 × rate + 1)` | Flood, now dropped before parsing | Impersonate | excess traffic is dropped before any work is done |
| D6 | `transport.acl` | **nothing new**; the reasons move from the gateway to "broker ACL" | Impersonate (inherits the gateway's rights) | an ACL without authentication trusts whatever name a client claims |
| D7 | `transport.auth` | Impersonate — the attacker is now off the broker | — | the perimeter stops everything at the door |
| D8 | `transport.mode = mtls`, `clientid_binding` | nothing new on the table | — | each hop is encrypted and identity is bound to a certificate; the price shows in the cost tile |
| D9 | breach: D8 with the broker layer off (`plain`, no auth, no ACL, no binding) | everything except Impersonate stays blocked | Impersonate | defence in depth: the inner layers hold when the perimeter falls |

Every change in this table was observed during this session, mostly with one
defence on at a time, so run the whole sequence once before a demo. D1 and D9
will show Flood as "partly blocked" until B5 is fixed. B4 and B6 change what the
audience sees right after each click, so those three are worth fixing first.

### Next step: insider attacks for K4, K7 and K9

The attacker can already act as a compromised device. With
`attacker.stolen_key = n` it gets sensor-n's payload keys, password and
certificate, so it gets past mTLS and authentication. These are the attacks that
show the payload layers mattering **with** the perimeter on. They exist in
`tools/loadgen/attacker.py` and `loadgen.py scenarios` runs them, but the
dashboard has no rows or verdicts for them:

| Insider attack | Settings | Stopped by | Scenario |
|---|---|---|---|
| an old message never seen before | `stolen_key`, `stolen_rate`, `stolen_age_s = 120` | timestamp check (`MessageExpired`) | `old-unseen-message` |
| a stolen key used on another device's topic | `stolen_target = other` | key–topic restriction (`PermissionDenied`); with the ACL on, the broker stops it first | `stolen-key-other-topic`, `stolen-key-acl` |
| a downgrade to authentication only | `stolen_mode = auth_only` | protection-mode policy (`ProtectionNotAccepted`) | `downgrade-policy` |
| an actuator forging commands to another actuator | `forge_commands_rate`, with `downlink.rate > 0` | signatures: only the gateway's private key can sign | `receiver-forgery` |

Adding these as dashboard rows, and as steps after D8, would give the remaining
levels a visible effect. A flood of *valid* envelopes from a compromised device
(a high `stolen_rate`) would also show what the rate limit is really for,
because each of those messages costs a full AEAD or signature check. The
plaintext flood used today is already rejected cheaply by the envelope check.

Two cautions, from the scenarios and the attacker code:
- Messages accepted under a stolen key push the victim's replay window ahead,
  so rotate the keys afterwards.
- The compromised device logs in with the victim's username. With client-id
  binding on, it therefore takes over the real sensor's session.

### Implementation notes

- Keep `LEVELS` (K0–K11) unchanged. The report and
  `tools/loadgen/tests/test_lab_config.py` (`test_ids_match_the_report`) depend
  on them.
- Add the D steps as a second list next to `LEVELS` in `tools/loadgen/lab.py`.
  Register them in `PRESETS` so that `POST /api/preset {"name": "D4"}` works,
  return them from `/api/state`, and draw them as a second row of buttons on
  the dashboard.
- Make each step a full patch, like `Level.patch`, rather than a change
  relative to the previous step, so that clicking D4 from anywhere gives the
  same configuration.
- A "Start all attacks" button would let the breach (D9) be shown in one click.

## Not tested

- Incident response (**Revoke**): it is permanent until the lab restarts.
- Downlink commands, storage, MQTT 3.1.1, `$SYS` topics, and an agent
  disconnecting mid-run.
- The narrow-screen layout.
