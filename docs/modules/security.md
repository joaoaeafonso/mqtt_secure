# Module `msec::security`

**Target:** `msec_security` (alias `msec::security`) · **Public deps:**
`msec::core` · **Private deps:** `OpenSSL::Crypto` (only with
`MSEC_WITH_OPENSSL=ON`)

End-to-end payload protection, independent of (and in addition to) TLS. The
central class is `SecurityLayer`, an `ILayer` that wraps every outbound payload
in an authenticated **envelope** and unwraps/verifies inbound ones. Everything
it needs (cipher, signer, keys, RNG, clock, policy) is injected through
interfaces; OpenSSL implementations live under `openssl/`.

| Header | Contents |
|---|---|
| `types.hpp` | `KeyId`, `AeadAlgorithm`, `PayloadProtection`, `to_string`, `protection_from_wire`, `ProtectionSet` |
| `envelope.hpp` | `EnvelopeHeader`, `Envelope`, `envelope::{serialize, parse, associated_data}` |
| `security_layer.hpp` | `SecurityConfig`, `SecurityDependencies`, `SecurityLayer` |
| `replay_guard.hpp` | `ReplayGuard` |
| `key_store.hpp` | `IKeyStore`, `InMemoryKeyStore` (each AEAD key carries its `AeadAlgorithm`) |
| `epoch_store.hpp` | `IEpochStore`, `FileEpochStore` (receiver restarts) |
| `key_policy.hpp` | `IKeyAuthorization`, `KeyTopicPolicy` |
| `aead_cipher.hpp` | `IAeadCipher` |
| `signature_scheme.hpp` | `ISignatureScheme` |
| `random_source.hpp` | `IRandomSource` |
| `openssl/aes_gcm_cipher.hpp` | `openssl::AesGcmCipher` |
| `openssl/chacha20_poly1305_cipher.hpp` | `openssl::ChaCha20Poly1305Cipher` |
| `openssl/ed25519_signer.hpp` | `openssl::Ed25519Signer` |
| `openssl/random_source.hpp` | `openssl::RandomSource` |

---

## Types (`types.hpp`)

```cpp
using KeyId = std::uint32_t;   // one key ⇔ one sender (by convention)

enum class PayloadProtection : std::uint8_t {
    Encrypt = 1,           // AEAD: confidentiality + integrity (default)
    AuthenticateOnly = 2,  // GMAC: integrity, payload readable
    Sign = 3,              // Ed25519: integrity + proof of origin, payload readable
};
constexpr std::string_view to_string(PayloadProtection);   // "encrypt" | "auth_only" | "sign"
constexpr std::optional<PayloadProtection> protection_from_wire(std::uint8_t);

class ProtectionSet {   // constexpr bitset, bit = 1 << mode
    ProtectionSet(std::initializer_list<PayloadProtection>);
    bool contains(PayloadProtection) const; bool empty() const;
    std::uint8_t bits() const; static ProtectionSet from_bits(std::uint8_t);
};
```

| Mode | Confidentiality | Integrity | Origin provable to 3rd parties | Who can forge |
|---|---|---|---|---|
| `Encrypt` | ✔ | ✔ | ✘ | any holder of the AES key (sender **and** gateway) |
| `AuthenticateOnly` | ✘ | ✔ | ✘ | any holder of the AES key |
| `Sign` | ✘ | ✔ | ✔ | only the private-key holder |

## Envelope (`envelope.hpp`)

Wire format v2 — full specification in
[`../protocol/envelope-format.md`](../protocol/envelope-format.md).

```cpp
struct EnvelopeHeader { std::uint8_t version{2}; PayloadProtection protection{Encrypt};
                        KeyId key_id{0}; std::uint64_t sequence{0}; std::int64_t timestamp_ms{0}; };
struct Envelope { EnvelopeHeader header; Bytes nonce; Bytes ciphertext; /* = body */ };

namespace envelope {
inline constexpr std::uint8_t kVersion = 2;
inline constexpr std::size_t  kFixedHeaderSize = 25;
inline constexpr std::size_t  kMaxNonceSize = 32;
Result<Bytes>    serialize(const Envelope&);                 // InvalidArgument if nonce > 32
Result<Envelope> parse(ByteView);                            // MalformedMessage on any defect
Result<Bytes>    associated_data(const EnvelopeHeader&, ByteView nonce, std::string_view topic);
}
```

`parse` rejects (all `MalformedMessage`): shorter than 25 bytes; magic ≠ `MS`;
version ≠ 2; unknown mode; sequence 0; nonce length > 32; no body bytes.

## `SecurityConfig` and `SecurityDependencies`

```cpp
struct FreshnessRule {                              // temporal validity for one flow
    std::string filter;                             // MQTT topic filter
    std::chrono::milliseconds max_message_age, max_clock_skew;
};

struct SecurityConfig {
    KeyId sending_key_id{0};
    std::chrono::milliseconds max_message_age{60s}; // Δa (global default)
    std::chrono::milliseconds max_clock_skew{5s};   // Δs (global default)
    std::vector<FreshnessRule> freshness_rules{};   // per flow; first match wins
    std::size_t max_tracked_senders{1024};
    std::uint32_t key_epoch_stride{0};              // key id = epoch * stride + device
    PayloadProtection protection{Encrypt};          // how outbound is protected
    std::optional<ProtectionSet> accept{};          // inbound policy; nullopt = {protection}
    bool enforce_freshness{true};                   // ablation switches (benchmarks/lab)
    bool enforce_replay_protection{true};
    bool enforce_key_binding{true};                 // requires deps.authorization
};

struct SecurityDependencies {
    std::shared_ptr<const IAeadCipher> cipher;      // required
    std::shared_ptr<const IKeyStore>   key_store;   // required: AEAD keys
    std::shared_ptr<IRandomSource>     random;      // required
    std::shared_ptr<const IClock>      clock;       // required
    std::shared_ptr<const ISignatureScheme> signer{};       // Sign only
    std::shared_ptr<const IKeyStore>   signing_keys{};      // private keys, to send Sign
    std::shared_ptr<const IKeyStore>   verify_keys{};       // public keys, to accept Sign
    std::shared_ptr<const IKeyAuthorization> authorization{};  // optional key → topic policy
    std::vector<std::shared_ptr<const IAeadCipher>> more_ciphers{};  // other AEAD algorithms
    std::shared_ptr<IEpochStore> epoch_store{};             // optional: restart rule
};
```

`SecurityLayer::create(config, deps)` returns `InvalidArgument` if a required
dependency is missing, if a cipher's nonce size is 0 or > 32, if two ciphers
serve the same algorithm, if `max_message_age ≤ 0` / `max_clock_skew < 0`
(globally or in a `FreshnessRule`, whose filter must also be valid), if the
accept set is empty, and — **dependencies between mechanisms are refused, not
silently skipped** — if `enforce_key_binding` is on without an
`authorization` policy, or an `epoch_store` is given without
`key_epoch_stride`; `InvalidState` if the sending mode or an accepted mode
needs signer/keys that are absent; `StorageFailure` if the epoch store cannot
be read.

### AEAD algorithm per key (AES-256-GCM or ChaCha20-Poly1305)

The algorithm is an **attribute of the key**, not a field of the envelope:
`InMemoryKeyStore::add(id, key, AeadAlgorithm)` (default `Aes256Gcm`) and
`IKeyStore::algorithm(id)`. Both algorithms use 32-byte keys, 12-byte nonces
and 16-byte tags (RFC 8439 §2.8), so the envelope is byte-for-byte the same
format; the key id in the authenticated header selects the key, and the key
selects the cipher among `cipher` and `more_ciphers`. One receiver therefore
serves both kinds of keys at once, and a fleet switches algorithm by rotating
to a new key epoch. An envelope opened with the other algorithm (the same key
bytes registered as AES on one side and ChaCha20 on the other) fails with
`AuthenticationFailed`; a key whose algorithm has no configured cipher is
refused (`InvalidState` outbound, `AuthenticationFailed` inbound).

### Receiver restarts: a new key epoch (`IEpochStore`)

The replay windows live in memory. With an `epoch_store` (and
`key_epoch_stride`), the receiver records **durably** the newest key epoch
(`key id / stride`) it has accepted — one write per rotation, before the
first message of the new epoch is accepted, never per message — and, when
created again after a restart, accepts only keys of a **later** epoch
(`minimum_epoch()`). Anything sealed before the restart, replayed into the
now-empty windows, is rejected (`ReplayDetected`); senders resume once they
rotate. `FileEpochStore` keeps the number in a file replaced atomically
(write, fsync, rename, fsync the directory); an unreadable or corrupt file
fails closed (`StorageFailure`), and so does a failed write (the message is
rejected).

A typical receiver that only verifies signatures holds **no private keys**:

```cpp
auto gateway = SecurityLayer::create(
    {.accept = ProtectionSet{PayloadProtection::Sign}},
    {.cipher = cipher, .key_store = aead_keys, .random = rng, .clock = clock,
     .signer = ed25519, .verify_keys = device_public_keys, .authorization = policy});
```

## `SecurityLayer`

```
Outbound: plaintext ─▶ seal (AEAD or signature) ─▶ Envelope
Inbound:  Envelope ─▶ parse ─▶ mode policy ─▶ freshness ─▶ verify/decrypt
                    ─▶ key → topic binding ─▶ epoch floor + replay check ─▶ plaintext
```

The inbound order is the report's Table 11; `tests/acceptance_tests.cpp` has
one test per row (each sends a message that breaks two rules and checks which
rejection wins) and fails if a rule is removed or moved.

### Outbound (`on_outbound`)

1. Read the current mode; choose `signing_keys` (Sign) or `key_store`.
2. Find the sending key (`NotFound` propagates) and, for AEAD modes, the cipher
   of its algorithm; check its size against the algorithm (`CryptoFailure`).
3. `sequence = next_sequence_++` (atomic, starts at 1; wrap to 0 ⇒
   `InvalidState` "sequence space exhausted; rotate key").
4. Nonce: 12 random bytes (AEAD modes) or none (Sign).
5. Header `{v2, mode, key id, sequence, now_ms}`; AAD = header ‖ nonce ‖
   u16(topic length) ‖ topic.
6. Body:
   - Encrypt: `AEAD.seal(key, nonce, payload, AAD)` → ciphertext ‖ tag
   - AuthenticateOnly: payload ‖ `AEAD.seal(key, nonce, ∅, AAD ‖ payload)`
   - Sign: payload ‖ `Ed25519.sign(key, AAD ‖ payload)`
7. Serialise; **wipe the original plaintext**; replace the payload.

### Inbound (`on_inbound`)

| Step | Check | Error | Why here |
|---|---|---|---|
| 1 | `envelope::parse` | `MalformedMessage` | anything not an envelope (e.g. injected plaintext) |
| 2 | mode ∈ accept set | `ProtectionNotAccepted` | prevents downgrade; the mode is in the AAD so lying about it can only fail |
| 3 | nonce length fits a configured algorithm (empty for Sign) | `MalformedMessage` | |
| 4 | freshness (if on): `now−Δa ≤ ts ≤ now+Δs`, with Δa/Δs of the first matching `FreshnessRule`, else the global ones; both limits inclusive | `MessageExpired` | cheap, before crypto; bounds computed from `now` to avoid overflow on attacker input |
| 5 | key lookup (`verify_keys` for Sign else `key_store`, then the key's cipher) | `AuthenticationFailed` "message authentication failed" | revoked keys land here; same error and message as step 6 |
| 6 | verify / decrypt with AAD built from the **received** topic | `AuthenticationFailed` (uniform) | no oracle on *why* it failed |
| 7 | key binding (if on; needs `authorization`) | `PermissionDenied` | after auth: unauthenticated input cannot probe policy |
| 8 | epoch floor (if replay on and an epoch store is set): epoch ≥ `minimum_epoch()`; records a new epoch durably | `ReplayDetected` / `StorageFailure` | after a restart, nothing from before it |
| 9 | replay window (if on) | `ReplayDetected` / `CapacityExceeded` | after auth: forged sequence numbers cannot move the window; after binding: a rejected message does not consume its number |

Plaintext is wiped on rejections after decryption (steps 7–9).

### Runtime switches

All are thread-safe (relaxed atomics) and take effect from the next message.

| Method | Effect |
|---|---|
| `set_protection(mode)` | sending mode **and** accept set := `{mode}`; fails if deps missing |
| `set_accepted(set)` | accept set only (e.g. a mixed fleet `{Encrypt, AuthenticateOnly}`) |
| `set_enforce_freshness(bool)` | |
| `set_enforce_replay_protection(bool)` | the window keeps its state, so turning it back on does **not** reopen old sequence numbers |
| `set_enforce_key_binding(bool)` | returns `Status`: turning it on without an `authorization` policy fails (`InvalidState`) and changes nothing |
| `set_sending_key(id)` | key rotation |
| `forget_key(id)` | free a revoked key's replay window — **never reuse that id** |
| `config()` | the static config overlaid with the current switch values |

## `ReplayGuard`

Sliding window per key id, same scheme as IPsec ESP (RFC 4303 §3.4.3):
accepts each sequence number at most once, tolerates reordering within the
last 64 numbers, rejects anything older.

```cpp
static constexpr std::uint64_t kWindowSize = 64;
explicit ReplayGuard(std::size_t max_tracked_keys = 1024) noexcept;
Status check_and_record(KeyId, std::uint64_t sequence);
void   forget(KeyId);
```

State per key: `highest` and a 64-bit `bitmap` (bit *i* ⇔ `highest − i` seen).

| Case | Result |
|---|---|
| sequence 0 | `InvalidArgument` |
| new key, table full | `CapacityExceeded` ("too many tracked senders") |
| new key | accept; window = `{seq, 0b1}` |
| `seq > highest` | accept; shift bitmap (reset if shift ≥ 64), set bit 0 |
| `highest − seq ≥ 64` | `ReplayDetected` "outside replay window" |
| bit already set | `ReplayDetected` "duplicate sequence number" |
| otherwise | accept, set bit |

**Must only be called after authentication.**

## Key stores (`key_store.hpp`)

```cpp
class IKeyStore { virtual Result<std::shared_ptr<const SecureBuffer>> find(KeyId) const = 0; };

class InMemoryKeyStore final : public IKeyStore {
    Status add(KeyId, SecureBuffer key);   // InvalidArgument if empty; InvalidState if id exists
    Status revoke(KeyId);                  // NotFound if absent
    Result<std::shared_ptr<const SecureBuffer>> find(KeyId) const override;  // NotFound
};
```

- Keys are never silently overwritten — rotation is explicit (add new id,
  later revoke old id).
- `find` hands out shared ownership so revocation is safe while an operation is
  in flight.
- Volatile; replace with a file/HSM/TPM-backed store for deployment.
- `SecurityLayer` uses up to three stores: AEAD keys, Ed25519 private keys
  (sending), Ed25519 public keys (receiving).

## Key → topic authorisation (`key_policy.hpp`)

Authentication proves *which key* made a message; without binding, any valid
key holder (e.g. a compromised device) could publish authentic-looking data on
**every other device's topic**.

```cpp
class IKeyAuthorization { virtual bool may_publish(KeyId, std::string_view topic) const = 0; };

class KeyTopicPolicy final : public IKeyAuthorization {
    Status allow_pattern(std::string filter);         // every key; %k = key id, %u = owner
    Status allow(KeyId, std::string filter);          // one key, no substitution
    Status set_owner(KeyId, std::string owner);       // owner must be one plain level
    void   remove(KeyId);                             // drop owner + per-key rules
    bool   may_publish(KeyId, std::string_view topic) const override;
};
```

```cpp
policy.set_owner(7, "sensor-7");
policy.allow_pattern("+/sensors/%u/#");
// key 7 may publish under open/sensors/sensor-7/… and restricted/sensors/sensor-7/… only
```

- Deny by default. Explicit per-key rules are checked first, then patterns.
- A pattern using `%u` never matches a key without an owner (an empty level is
  never substituted).
- `set_owner` rejects empty owners and any of `/ + # $` or NUL, so substitution
  cannot widen a match.
- `allow_pattern` validates the filter with placeholders replaced by a single
  level.
- Thread-safe via `shared_mutex`; owners and rules can change while messages
  flow (rotation adds owners, revocation removes them).

## Crypto interfaces and OpenSSL back-end

```cpp
class IAeadCipher {
    std::string_view algorithm(); AeadAlgorithm id(); std::size_t key_size(), nonce_size(), tag_size();
    Result<Bytes> seal(const SecureBuffer& key, ByteView nonce, ByteView plaintext, ByteView aad) const; // ct‖tag
    Result<Bytes> open(const SecureBuffer& key, ByteView nonce, ByteView ct_and_tag, ByteView aad) const; // AuthenticationFailed on tamper
};
class ISignatureScheme {
    std::string_view algorithm(); std::size_t private_key_size(), public_key_size(), signature_size();
    Result<Bytes> sign(const SecureBuffer& private_key, ByteView message) const;
    Status        verify(ByteView public_key, ByteView message, ByteView signature) const; // AuthenticationFailed
    Result<Bytes> public_key(const SecureBuffer& private_key) const;
};
class IRandomSource { Status fill(MutableByteView out); };
```

| Class | Algorithm | Sizes | Notes |
|---|---|---|---|
| `openssl::AesGcmCipher` | AES-256-GCM (EVP) | key 32, nonce 12, tag 16 | validates sizes and `INT_MAX` limits; on any decrypt/tag failure the output is `secure_zero`ed — unauthenticated plaintext is never released |
| `openssl::ChaCha20Poly1305Cipher` | ChaCha20-Poly1305 (EVP, RFC 8439) | key 32, nonce 12, tag 16 | same code path as AES-GCM (`src/openssl/evp_aead.cpp`); checked against RFC 8439 §2.8.2 |
| `openssl::Ed25519Signer` | Ed25519 (RFC 8032) | private 32 (seed), public 32, signature 64 | raw keys; deterministic signatures; wrong sizes on verify ⇒ `AuthenticationFailed` |
| `openssl::RandomSource` | `RAND_bytes` | — | empty request OK; > `INT_MAX` ⇒ `InvalidArgument` |

OpenSSL errors map to `CryptoFailure`. Adding another back-end (e.g.
XChaCha20-Poly1305, libsodium, an HSM) means implementing the interface (with
a new `AeadAlgorithm` value) and injecting it in `more_ciphers`;
`SecurityLayer` accepts any cipher with a nonce of 1–32 bytes.

## Tests

`tests/acceptance_tests.cpp` covers the receiver's acceptance rules: one
test per row of the verification order, the window limits (w = 64) and
reordering, the mode policy, the key → topic restriction with `%u`, Δa/Δs at
their limits (inclusive), per-flow validity, dependency validation and the
restart rule (`FileEpochStore` included). Each was checked by removing or
moving its rule in the code and watching the test fail.

`tests/security_tests.cpp` covers ChaCha20-Poly1305 (RFC 8439 vector, neither
algorithm opening the other's output, one receiver serving both, unconfigured
algorithm, duplicate cipher) and: envelope round trip, malformed
input, signature envelopes without nonce; replay guard (fresh/duplicate,
reordering, too old, forgetting frees a slot, bounded); AES-GCM round trip,
tamper, empty plaintext; the layer (hides plaintext, tampered ciphertext,
tampered header, topic rebinding, replay, expiry, future timestamps, revoked
key, unprotected payload, key rotation, sequence/nonce uniqueness, auth-only,
receiver mode policy, authenticated mode field, each ablation switch, runtime
switching); cross-language vectors; factory validation; RFC 8032 vector 1;
`KeyTopicPolicy`; signed layer, signing-key requirements, key binding and its
interaction with the replay window. Fuzzers: `fuzz_envelope`,
`fuzz_security_inbound`.
