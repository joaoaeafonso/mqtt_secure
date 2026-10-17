# Glossary

| Term | Meaning |
|---|---|
| **AAD** | Additional Authenticated Data: bytes authenticated but not encrypted by an AEAD. Here: envelope header ‖ nonce ‖ u16 topic length ‖ topic. |
| **ACL** | Access Control List. The broker's per-client topic read/write rules (`AccessControlList` for the loopback broker, Mosquitto `acl_file` in the lab). |
| **AEAD** | Authenticated Encryption with Associated Data (AES-256-GCM here). |
| **Actuator** | A device that receives commands (downlink). In the lab every sensor is also an actuator. |
| **Agent** | `loadgen.py agent`: a process on another machine running sensors or an attacker for a lab controller. |
| **auth_only** | `PayloadProtection::AuthenticateOnly`: GMAC over header, topic and payload; payload stays readable. |
| **Composition root** | The single place that instantiates concrete classes and wires them (`apps/*/main.cpp`). |
| **Controller** | The lab machine running broker, gateway, dashboard and the agent control server. |
| **CRL** | Certificate Revocation List; used by Mosquitto (`crlfile`) under mtls to refuse revoked client certificates. |
| **CSR** | Certificate Signing Request; agents send one per sensor so private TLS keys never leave the agent. |
| **Downlink** | Gateway → actuator commands on `<zone>/actuators/<device>/cmd`. |
| **Endpoint** | `mqtt::Endpoint`: binds an `IMqttClient` to a `Pipeline`. |
| **Envelope** | The protected payload format (v2): header, nonce, body. See [protocol](protocol/envelope-format.md). |
| **Epoch** | Key generation counter; key id = epoch × 1 000 000 + device. Raising `payload.key_epoch` rotates all keys. |
| **Freshness** | Check that a message's timestamp is within `[now − 60 s, now + 5 s]`. |
| **Gateway** | The trusted back-end receiving sensor data and sending commands (`msec_load_gateway`, or your application). |
| **GMAC** | GCM used for authentication only (empty plaintext). |
| **Group key** | A key shared by several parties; the downlink AES key is one (every actuator holds it). |
| **Hardened preset** | Lab profile with every defence on (`lab.hardened`). |
| **Inbound / outbound** | Transport → application / application → transport. |
| **Key binding** | Restricting which topics a key may publish on (`KeyTopicPolicy`, e.g. `+/sensors/%u/#`). |
| **Key id** | 32-bit identifier in the envelope header selecting the key; one key id ⇔ one sender. |
| **Layer** | An `ILayer`: a pipeline stage that can transform, observe or reject messages. |
| **Load lab** | `tools/loadgen`: the Python harness around Mosquitto and `msec_load_gateway`. |
| **Loopback broker** | `mqtt::LoopbackBroker`: in-process synchronous broker for tests, demo and benchmarks. |
| **Mallory** | The attacker's identity in demo, benchmarks and lab. |
| **Matrix** | `loadgen.py matrix`: measure every combination of `--vary` values. |
| **mTLS** | Mutual TLS: clients present certificates; in the lab the certificate CN becomes the MQTT username. |
| **Nonce** | Number used once; 96-bit random per AEAD message. |
| **Owner** | The device name a key belongs to (`sensor-7`), used for `%u` in key binding and as a downlink target. |
| **Pipeline** | Ordered, immutable chain of layers (`msec::Pipeline`). |
| **Preset (CMake)** | Named configure/build/test configuration in `CMakePresets.json`. |
| **Protection mode** | `encrypt`, `auth_only` or `sign` (wire values 1, 2, 3); `none` in the lab means the security layer is switched off. |
| **Rate limit** | Per-topic inbound token bucket at the gateway (`RateLimitLayer`). |
| **Replay window** | 64-entry sliding window of sequence numbers per key (`ReplayGuard`, RFC 4303). |
| **Restricted / open zone** | Topic prefixes `restricted/` (per-client ACL) and `open/` (everyone). |
| **Revocation** | Permanently withdrawing a device's keys, password and certificate. |
| **Rotation** | Replacing every payload key with a new epoch while traffic flows (3 s overlap). |
| **Scenario** | A named attack-vs-defence experiment with a predicted outcome (`scenarios.py`). |
| **SecureBuffer** | Non-copyable, zero-on-destroy buffer for secrets. |
| **Sequence number** | 64-bit per-sender counter in the envelope header used by the replay window. |
| **sign** | `PayloadProtection::Sign`: Ed25519 signature; proof of origin; payload readable. |
| **Switchable layer** | `SwitchableLayer`: wraps a layer with an atomic on/off switch (pass-through when off). |
| **Topic binding** | Including the MQTT topic in the AAD so a message cannot be moved to another topic. |
| **Uplink** | Sensor → gateway readings on `<zone>/sensors/<device>/temp`. |
| **View (key view)** | The subset of keys a role holds: `gateway_view`, `device_view`. |
