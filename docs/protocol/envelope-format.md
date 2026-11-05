# Envelope wire format, version 2

The envelope is the byte string that replaces an MQTT payload when payload
protection is on. It is produced and consumed by
`msec::security::SecurityLayer` (C++, `modules/security/src/envelope.cpp`,
`security_layer.cpp`) and by `Protector` / `Verifier` (Python,
`tools/loadgen/msec_envelope.py`). Both implementations are pinned to each
other by the shared test vectors in `tests/vectors/envelope_vectors.txt`.

## 1. Layout

All integers are **big-endian**.

```
 0       2   3   4           8                  16                 24  25        25+N
 ┌───────┬───┬───┬───────────┬──────────────────┬──────────────────┬───┬─────────┬─────────────────┐
 │ "MS"  │ver│mod│  key id   │     sequence     │   timestamp ms   │ N │  nonce  │      body       │
 └───────┴───┴───┴───────────┴──────────────────┴──────────────────┴───┴─────────┴─────────────────┘
 │◀────────────────────────── authenticated as associated data (+ MQTT topic) ──────────────────▶│
```

| Offset | Size | Field | Values |
|---|---|---|---|
| 0 | 2 | magic | `0x4D 0x53` (`"MS"`) |
| 2 | 1 | version | `2` |
| 3 | 1 | protection mode | `1` encrypt · `2` auth_only · `3` sign |
| 4 | 4 | key id | unsigned 32-bit; identifies the key and, by convention, the sender |
| 8 | 8 | sequence number | unsigned 64-bit, ≥ 1, strictly increasing per sender |
| 16 | 8 | timestamp | signed 64-bit, milliseconds since the Unix epoch, sender's clock |
| 24 | 1 | nonce length *N* | 12 for the AEAD modes (AES-256-GCM or ChaCha20-Poly1305), 0 for sign; at most 32 |
| 25 | *N* | nonce | random per message (AEAD modes) |
| 25+*N* | rest | body | see below; must be non-empty |

### Body per mode

| Mode | Body | Computation |
|---|---|---|
| 1 encrypt | ciphertext ‖ tag (16) | `AEAD.seal(key, nonce, plaintext = payload, aad = AAD)` |
| 2 auth_only | payload ‖ tag (16) | `AEAD.seal(key, nonce, plaintext = ∅, aad = AAD ‖ payload)` — GMAC with AES, Poly1305 with ChaCha20 |
| 3 sign | payload ‖ signature (64) | `Ed25519.sign(private key, AAD ‖ payload)`; N = 0 |

**AEAD** is AES-256-GCM or ChaCha20-Poly1305 (RFC 8439 §2.8). Which one is an
attribute of the key, not a field of the envelope: the key id selects the key
and the key its algorithm, which sender and receiver agree on when the key is
provisioned (key-file kind `aead` = AES-256-GCM, `aead-chacha20` =
ChaCha20-Poly1305). Both use 12-byte nonces and 16-byte tags, so the format,
the AAD and the overhead are identical; switching algorithm is a key
rotation.

### Associated data (AAD)

```
AAD = envelope[0 : 25+N]  ‖  u16_be(len(topic))  ‖  topic (UTF-8 bytes as published)
```

i.e. the full header including the nonce, followed by the MQTT topic. Binding
the topic means a valid envelope **cannot be re-published on another topic**;
binding the header means **no header field — the mode included — can be
changed** without failing verification.

### Size overhead

| Mode | Overhead (bytes) |
|---|---|
| encrypt | 25 + 12 + 16 = **53** |
| auth_only | 25 + 12 + 16 = **53** |
| sign | 25 + 0 + 64 = **89** |

The load lab's `PACKET_OVERHEAD = 512` (room for envelope + topic + MQTT
headers) is derived from this.

## 2. Parsing rules

A receiver MUST reject with `MalformedMessage` if any of:

1. length < 25;
2. magic ≠ `MS`;
3. version ≠ 2;
4. mode ∉ {1, 2, 3};
5. sequence = 0 (reserved);
6. nonce length > 32;
7. length ≤ 25 + N (no body);
8. (layer) nonce length ≠ the length required by the mode and cipher.

`parse` is total and non-allocating beyond copying the nonce and body; for
every accepted input `serialize(parse(x)) == x` (asserted by
`fuzz/fuzz_envelope.cpp`).

## 3. Receiver processing order

| # | Step | Error |
|---|---|---|
| 1 | parse | `MalformedMessage` |
| 2 | mode in the receiver's accepted set | `ProtectionNotAccepted` |
| 3 | nonce length matches | `MalformedMessage` |
| 4 | freshness, if enabled: `now − 60 s ≤ timestamp ≤ now + 5 s` | `MessageExpired` |
| 5 | key id known (AEAD store, or public-key store for sign) | `AuthenticationFailed` |
| 6 | verify / decrypt with AAD over the **received** topic | `AuthenticationFailed` |
| 7 | key → topic binding, if configured | `PermissionDenied` |
| 8 | replay window (64 entries, RFC 4303), if enabled | `ReplayDetected` |

Rationale for the order is in
[`../modules/security.md`](../modules/security.md#inbound-on_inbound). The
Python `Verifier` performs the same checks in the same order (it expresses key
binding as an `allowed_senders` set of key ids).

## 4. Sender rules

- Sequence numbers start at 1 (C++ `SecurityLayer`) or at the current time in
  microseconds (Python `Protector`, so a restarted sender keeps moving forward
  through the receiver's window) and increase by one per message.
- A fresh random nonce is drawn for every AEAD message.
- The timestamp is the sender's wall clock in ms.
- One key id MUST be used by exactly one sender (else replay windows break).
- Key ids MUST NOT be reused after revocation.

## 5. Worked example

From `tests/vectors/envelope_vectors.txt`, vector `encrypt_short`:

| Parameter | Value |
|---|---|
| AES key | `000102…1f` |
| nonce | `000102030405060708090a0b` |
| timestamp | 1 700 000 000 123 ms (`0x0000018BCFE5687B`) |
| key id | 7 |
| sequence | 1 |
| topic | `restricted/sensors/sensor-7/temp` (32 bytes) |
| payload | `"21.5C"` = `32 31 2e 35 43` |

Envelope (58 bytes):

```
4d 53                                magic "MS"
02                                   version 2
01                                   mode 1 = encrypt
00 00 00 07                          key id 7
00 00 00 00 00 00 00 01              sequence 1
00 00 01 8b cf e5 68 7b              timestamp 1700000000123
0c                                   nonce length 12
00 01 02 03 04 05 06 07 08 09 0a 0b  nonce
75 33 f8 2e 86                       ciphertext of "21.5C"
48 c1 c0 ed 08 73 db 68 80 f9 a8 27 78 e2 41 ee   GCM tag
```

AAD = the first 37 bytes above ‖ `00 20` ‖ `"restricted/sensors/sensor-7/temp"`.

The same payload in **auth_only** keeps `32 31 2e 35 43` visible, followed by a
16-byte tag; in **sign** the nonce length is `00`, the payload is visible and a
64-byte Ed25519 signature follows (RFC 8032 test key 1 is used as the signing
key in the vectors).

## 6. Test vectors file format

```
# comment
aead_key   <64 hex>            parameters: "<name> <value>"
sign_key   <64 hex>
nonce      <24 hex>
timestamp_ms <int>
<name> <mode>[:chacha20] <key_id> <topic> <payload_hex | -> <envelope_hex>     vectors (6 fields)
```

Every vector uses sequence 1 and the fixed parameters. `-` is an empty
payload. A `:chacha20` suffix on the mode means the aead key is used with
ChaCha20-Poly1305 instead of AES-256-GCM. The C++ test (`EnvelopeVectors.CxxMatchesPythonByteForByte`) seals
each vector with a `FixedRandom` and `FakeClock` and compares bytes, then opens
the expected envelope; the Python test (`test_python_reproduces_every_vector`)
seals with injected clock/random/sequence. The fuzz corpus
`fuzz/corpus/envelope/*.bin` contains the same five envelopes as binary seeds.

## 7. Versioning

The version byte allows incompatible changes. Version 2 introduced the mode
byte (and with it auth_only and sign). ChaCha20-Poly1305 did not need a new
version (the algorithm belongs to the key). Receiver restarts are handled
without a format change either: key ids encode an epoch, and a restarted
receiver accepts only epochs later than the last it recorded (see
`IEpochStore` in docs/modules/security.md).
