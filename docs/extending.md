# Extending mqtt-secure

The architecture is built around ports (interfaces) and one composition root
per application. Most extensions are "implement an interface, wire it in
`main.cpp`".

| Extension | Implement | Module | Wire in |
|---|---|---|---|
| New pipeline stage | `msec::ILayer` | new module `modules/<name>` | `Pipeline::Builder::add` |
| Another MQTT library | `mqtt::IMqttClient` | `mqtt` (private dep) | `Endpoint` constructor |
| Persistent storage | `data::IMessageRepository` | `data` | `PersistenceLayer::create` |
| HSM / file key store | `security::IKeyStore` | `security` | `SecurityDependencies` |
| Another AEAD (e.g. XChaCha20-Poly1305) | `security::IAeadCipher` (nonce 1–32 bytes) | `security` | `SecurityDependencies::cipher` |
| Another signature scheme | `security::ISignatureScheme` | `security` | `SecurityDependencies::signer` |
| Another key → topic policy | `security::IKeyAuthorization` | `security` | `SecurityDependencies::authorization` |
| Another RNG | `security::IRandomSource` | `security` | `SecurityDependencies::random` |
| Time source | `msec::IClock` | `core` or app | every factory taking a clock |
| Log sink | `msec::ILogger` (thread-safe, `noexcept`) | `core` or app | `Endpoint` |

## Adding a layer

1. Header `modules/<name>/include/msec/<name>/<name>_layer.hpp`:

   ```cpp
   #pragma once
   #include <memory>
   #include "msec/core/layer.hpp"

   namespace msec::<name> {

   class AuditLayer final : public ILayer {
       struct PassKey {};
   public:
       [[nodiscard]] static Result<std::unique_ptr<AuditLayer>> create(/* deps */);
       explicit AuditLayer(PassKey /*key*/ /*, deps */) noexcept;

       [[nodiscard]] std::string_view name() const noexcept override { return "audit"; }
       [[nodiscard]] Result<Message> on_outbound(Message message) override;
       [[nodiscard]] Result<Message> on_inbound(Message message) override;
   };

   }  // namespace msec::<name>
   ```

   - Validate dependencies in `create`; the `PassKey` keeps the constructor
     usable by `make_unique` but not by callers.
   - Be thread-safe: both directions can run concurrently.
   - Never throw; never log secrets or payloads.
   - Bound any state that attacker input can create.

2. `modules/<name>/CMakeLists.txt`:

   ```cmake
   msec_add_module(NAME <name> SOURCES src/<name>_layer.cpp PUBLIC_DEPS msec::core)
   ```

   Depend **only on `msec::core`** (put third-party libraries in
   `PRIVATE_DEPS`). Never depend on a sibling module; if you need shared logic,
   it belongs in `core` (as topic filters do).

3. `add_subdirectory(modules/<name>)` in the root `CMakeLists.txt`.

4. Add it to the pipeline in the relevant `main.cpp`, at the right position:

   | If the layer must see… | place it |
   |---|---|
   | plaintext | above (before) `security` |
   | envelopes / wire bytes | below (after) `security` |
   | every inbound message before any cost | last (transport side) |

   To make it switchable at run time, wrap it:
   `SwitchableLayer::create(std::move(layer), /*enabled=*/false, "audit")`.

5. Tests in `tests/<name>_tests.cpp`, registered with `msec_add_test`.

Candidate layers: schema validation, audit log, compression. Compression must
sit **above** security (ciphertext does not compress), and
compress-then-encrypt can leak information (CRIME/BREACH) — consider whether
you want it at all.

## Adding an MQTT adapter

Implement `IMqttClient`. Requirements derived from `Endpoint` and
`PahoClient`:

- Map library errors to `ConnectionFailed`, disconnected use to
  `NotConnected`, refused subscriptions to `PermissionDenied`.
- Deliver incoming messages via the handler (any thread is fine); drop messages
  whose topic fails `Topic::create`; propagate QoS, retain and DUP flags.
- Make `set_message_handler({})` effective immediately (the `Endpoint`
  destructor relies on it to detach).
- Keep library headers out of the public header (forward-declare), and link the
  library `PRIVATE`.
- Treat `ConnectionOptions::password` as a secret.

## Adding a crypto back-end

Implement the interface under `modules/security/src/<backend>/`, guard it with
an option like `MSEC_WITH_OPENSSL`, and add the library as a private dependency
of `msec_security`. Rules:

- Return `AuthenticationFailed` for tag/signature mismatches and **never return
  unauthenticated plaintext** (wipe the output buffer).
- `nonce_size()` must be 1–32 bytes (envelope limit); AEAD tag and signature
  sizes are read from the interface, so the envelope adapts.
- Add known-answer tests (e.g. RFC vectors), and extend
  `tests/vectors/envelope_vectors.txt` if the wire output changes.

## Extending the load lab

- **New setting**: add it to `DEFAULTS` and `SPEC` in `lab.py` (and to
  `STARTUP_ONLY` if it cannot change live), apply it in `Lab.apply`, document
  it in `lab.example.toml`, add a control in `dashboard.html`. If the gateway
  needs it, add an option in `apps/load_gateway/main.cpp` (`apply()` is the
  single place option names are defined; add transport keys to
  `is_transport_key`).
- **New broker option**: add it to `broker.py` (`DEFAULT_SETTINGS`, `_write`,
  and `RESTART_KEYS` or `RELOAD_KEYS` — measure which, Mosquitto does not
  re-read everything on `SIGHUP`) and to `BROKER_KEYS` in `lab.py`.
- **New metric**: emit it from the gateway stats JSON or a fleet/attacker
  report, compute it in `Lab._point` and/or `Lab.measure`, chart it in
  `dashboard.html` (`CHARTS`).
- **New scenario**: see [loadgen/scenarios.md](loadgen/scenarios.md#adding-a-scenario).
- **Envelope change**: update `msec_envelope.py` and the C++ side together; the
  shared vectors will tell you if they disagree.
