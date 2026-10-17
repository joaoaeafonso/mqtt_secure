# Module `msec::mqtt`

**Target:** `msec_mqtt` (alias `msec::mqtt`) · **Public deps:** `msec::core` ·
**Private deps:** `PahoMqttCpp::paho-mqttpp3` (only with `MSEC_WITH_PAHO=ON`)

The transport side: a port (`IMqttClient`) to any MQTT library, the `Endpoint`
that binds a client to a layer pipeline, an in-process broker for tests and
demos, a Mosquitto-style ACL for that broker, and the Eclipse Paho adapter for
real brokers. **This module knows nothing about payload security.**

| Header | Contents |
|---|---|
| `mqtt_client.hpp` | `MessageHandler`, `IMqttClient` |
| `connection_options.hpp` | `TlsOptions`, `ProtocolVersion`, `ConnectionOptions` |
| `endpoint.hpp` | `EndpointStats`, `Endpoint` |
| `loopback_broker.hpp` | `LoopbackBroker`, `LoopbackClient` |
| `access_control.hpp` | `Access`, `AccessControlList` |
| `topic_filter.hpp` | re-exports `msec::topic_matches`, `msec::validate_topic_filter` |
| `paho/paho_client.hpp` | `paho::PahoClient` (built only with Paho) |

---

## `IMqttClient` — the transport port

```cpp
using MessageHandler = std::function<void(Message)>;

class IMqttClient {
public:
    virtual Status connect(const ConnectionOptions&) = 0;
    virtual Status disconnect() = 0;
    virtual bool   is_connected() const noexcept = 0;
    virtual Status publish(const Message&) = 0;
    virtual Status subscribe(std::string_view filter, QoS) = 0;
    virtual Status unsubscribe(std::string_view filter) = 0;
    virtual void   set_message_handler(MessageHandler) = 0;  // may be called from a library thread
};
```

No other module depends on a concrete MQTT library. Implementations:
`LoopbackClient`, `paho::PahoClient`. A libmosquitto adapter would be a third.

## `ConnectionOptions`

```cpp
struct TlsOptions {
    std::filesystem::path ca_file, client_cert_file, client_key_file;  // cert+key for mTLS
    bool verify_peer{true};   // must stay true outside tests
};
enum class ProtocolVersion : std::uint8_t { V311 = 4, V5 = 5 };
struct ConnectionOptions {
    std::string broker_uri;                 // "tcp://host:1883", "ssl://host:8883"
    std::string client_id;
    std::optional<TlsOptions>   tls;
    std::optional<std::string>  username;
    std::optional<SecureBuffer> password;   // secret: zeroed on destruction
    std::chrono::seconds keep_alive{30};
    bool clean_session{true};               // MQTT 5: clean start
    ProtocolVersion protocol{ProtocolVersion::V311};
};
```

This struct is "defence layer 1" (transport); payload protection (layer 2) is
independent of it.

## `Endpoint`

Composition point of one `IMqttClient` and one `Pipeline`:

```
publish():  Message ─▶ pipeline.process_outbound ─▶ client.publish
incoming:   client  ─▶ pipeline.process_inbound  ─▶ application handler
```

```cpp
Endpoint(std::shared_ptr<IMqttClient>, Pipeline, std::shared_ptr<ILogger> /*nullable*/);

Status start(const ConnectionOptions&);   // installs handler, connects
Status stop();                            // removes handler, disconnects
Status publish(Message);
Status subscribe(std::string_view filter, QoS);
void   on_message(ApplicationHandler);    // void(const Message&)
void   on_rejected(RejectionHandler);     // void(const Rejected&, const Error&)
EndpointStats stats() const noexcept;     // {published, delivered, rejected_inbound, rejected_outbound}

struct Rejected { std::string topic; bool retained; bool duplicate; };
```

Behaviour:

| Event | Effect |
|---|---|
| outbound layer error | `rejected_outbound++`, log `Error` "outbound rejected: …", error returned to caller; nothing is sent |
| client publish error | error returned; `published` unchanged |
| outbound OK | `published++` |
| inbound layer error | `rejected_inbound++`, log `Warn` "inbound on '<topic>' rejected (<Code>): …", rejection handler called; message **never** reaches the application |
| inbound OK | application handler called, then `delivered++` |

- The rejection observer gets topic/retain/duplicate only; the payload was
  consumed by the pipeline.
- Handlers are copied under `handler_mutex_` and invoked outside it, so they may
  call back into the endpoint (e.g. publish a reply).
- Destructor: detaches the client's message handler *first* (no callback can
  observe a half-destroyed endpoint), then disconnects if still connected.
- A `nullptr` logger is replaced by a `NullLogger`.
- `start()` returns `InvalidState` when constructed without a client. Note:
  `stop()`, `publish()` and `subscribe()` do not repeat that null check.

## `LoopbackBroker` / `LoopbackClient`

In-process broker for tests, the demo and benchmarks: **synchronous, lossless,
no network**. One `publish` call delivers to every subscriber before returning,
which makes one benchmark iteration exactly one full round trip.

```cpp
auto broker = LoopbackBroker::create(/* std::optional<AccessControlList> */ acl);
auto client = LoopbackClient::create(broker);
client->connect({.client_id = "gateway"});
client->set_message_handler([](Message m) { /* … */ });
client->subscribe("restricted/sensors/#", QoS::AtLeastOnce);
```

Routing (`LoopbackBroker::route(message, publisher_id)`):

1. With an ACL, the publisher needs **Write** on the topic, else
   `PermissionDenied` ("client 'X' may not publish to 'T'").
2. Under the broker mutex, collect every *distinct*, still-alive subscriber
   whose filter matches the topic and — with an ACL — that may **Read** it.
   Read is checked per message, so subscribing to `#` is allowed but yields only
   readable topics.
3. Deliver **after releasing the lock** so handlers can publish re-entrantly.

Client specifics:

| Method | Notes |
|---|---|
| `connect` | stores the client id (atomic `shared_ptr<const string>`); `ConnectionFailed` without a broker |
| `disconnect` | marks disconnected and removes all its subscriptions |
| `publish` / `subscribe` | `NotConnected` when disconnected; `subscribe` validates the filter |
| `unsubscribe` | removes subscriptions with that exact filter |
| `deliver` (broker → client) | invokes the handler only while connected |
| destructor | removes itself from the broker |

QoS, retained messages and sessions are not modelled.

## `AccessControlList`

Broker-side topic authorisation modelled on Mosquitto's `acl_file`, used by
`LoopbackBroker`. (The real broker in the load lab uses a real Mosquitto ACL,
see [`../loadgen/components.md`](../loadgen/components.md#brokerpy).)

```cpp
enum class Access : std::uint8_t { Read = 1, Write = 2, ReadWrite = 3 };

Status allow(std::string client_id, std::string filter, Access);  // one client
Status allow_all(std::string filter, Access);                      // every client ("pattern")
bool   can_publish(std::string_view client_id, std::string_view topic) const;  // needs Write
bool   can_read(std::string_view client_id, std::string_view topic) const;     // needs Read
```

- **Deny by default.** Any matching rule with the needed bit grants access.
- Filters are validated (`InvalidArgument` otherwise); `allow` requires a
  non-empty client id.
- Rules are keyed by **client id, which is only a claim** unless the broker
  authenticates clients (passwords, TLS client certificates).

The demo/benchmark ACL ("two zones"):

```cpp
acl.allow_all("open/#", Access::ReadWrite);                            // anyone
acl.allow("sensor-1", "restricted/sensors/room1/#", Access::Write);   // only sensor-1 writes
acl.allow("gateway",  "restricted/sensors/#",       Access::Read);    // only gateway reads
```

## `paho::PahoClient`

`IMqttClient` over Eclipse Paho MQTT C++ (`mqtt::async_client`) for TCP or TLS
to a real broker.

```cpp
explicit PahoClient(std::chrono::milliseconds timeout = std::chrono::seconds{10});
```

| Aspect | Behaviour |
|---|---|
| Blocking | each call waits for the broker's acknowledgement up to `timeout`; timeout ⇒ `ConnectionFailed` "… timed out" |
| Re-connect | `connect()` may be called at any time to switch broker URI, transport, credentials or protocol; the existing client is closed first |
| Serialisation | lifecycle and operations hold `client_mutex_` |
| Protocol | `ProtocolVersion` mapped to Paho's MQTT version; `clean_start` for v5, `clean_session` for v3.1.1 |
| Credentials | username; password passed as binary from the `SecureBuffer` |
| TLS | `enable_server_cert_auth(verify_peer)`, `verify(verify_peer)`, trust store = `ca_file`, key store = `client_cert_file`, private key = `client_key_file`. With `verify_peer` the broker certificate must chain to `ca_file` and match the host in `broker_uri`. |
| Subscribe refusal | a SUBACK reason code ≥ 0x80 (e.g. ACL refusal) ⇒ `PermissionDenied` |
| Incoming | delivered on Paho's callback thread; messages whose topic is not a valid topic name are dropped; QoS, retain and DUP flags are propagated into `Message` |
| Exceptions | `mqtt::exception` ⇒ `ConnectionFailed` with Paho's text |

**Token-lifetime workaround (Paho C++ 1.2).** Paho wakes a token's waiter
before its callback thread has finished with the token, so dropping the token
right after `wait_for()` was a use-after-free race. `wait()` parks the token in
`last_token_` *before* waiting (also covers the throwing path); the next Paho
call takes Paho's global mutex and thus returns only after the previous
callback left; `close_locked()` releases it only after destroying the client
(`MQTTAsync_destroy` also waits for callbacks).

## Tests

`tests/mqtt_tests.cpp`: `TopicFilter.Matching`, `TopicFilter.Validation`,
`Loopback.RoutesToMatchingSubscribersOnly`,
`AccessControl.DeniesByDefaultAndMatchesPerClient`,
`AccessControl.RejectsInvalidRules`, `Loopback.AclBlocksUnauthorizedPublish`,
`Loopback.WildcardSubscriberOnlyReceivesReadableTopics`,
`Loopback.PublishRequiresConnection`. `Endpoint` is covered end-to-end by
`tests/integration_tests.cpp`. `PahoClient` is exercised against a real
Mosquitto by the load-lab scenarios (CI).
