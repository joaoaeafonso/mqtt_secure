# Module `msec::core`

**Target:** `msec_core` (alias `msec::core`) · **Depends on:** nothing ·
**Headers:** `modules/core/include/msec/core/` · **Sources:** `modules/core/src/`

`core` holds the vocabulary every other module shares: the message type, the
error model, the layer/pipeline abstraction, secret buffers, and the injected
clock and logger. It has no third-party dependencies.

| Header | Contents |
|---|---|
| `bytes.hpp` | `Bytes`, `ByteView`, `MutableByteView`, `to_bytes`, `bytes_to_string` |
| `error.hpp` | `ErrorCode`, `to_string(ErrorCode)`, `Error`, `Result<T>`, `Status`, `make_error` |
| `message.hpp` | `QoS`, `Topic`, `Message` |
| `layer.hpp` | `ILayer` |
| `pipeline.hpp` | `Pipeline`, `Pipeline::Builder` |
| `switchable_layer.hpp` | `SwitchableLayer` |
| `secure_buffer.hpp` | `secure_zero`, `SecureBuffer` |
| `clock.hpp` | `IClock`, `SystemClock` |
| `logger.hpp` | `LogLevel`, `ILogger`, `NullLogger`, `ConsoleLogger` |
| `topic_filter.hpp` | `validate_topic_filter`, `topic_matches` |

---

## Bytes (`bytes.hpp`)

```cpp
using Bytes           = std::vector<std::byte>;
using ByteView        = std::span<const std::byte>;
using MutableByteView = std::span<std::byte>;

Bytes       to_bytes(std::string_view text);   // copy text into bytes
std::string bytes_to_string(ByteView data);    // copy bytes into a std::string
```

`std::byte` is used everywhere for binary data so it cannot be confused with
text or arithmetic types.

## Errors (`error.hpp`)

```cpp
enum class ErrorCode : std::uint8_t {
    InvalidArgument, InvalidState, NotFound, CapacityExceeded, ConnectionFailed,
    NotConnected, CryptoFailure, AuthenticationFailed, PermissionDenied,
    ReplayDetected, MessageExpired, MalformedMessage, ProtectionNotAccepted,
    RateLimited, StorageFailure, Internal };

struct Error { ErrorCode code{ErrorCode::Internal}; std::string message; };
template <typename T> using Result = std::expected<T, Error>;
using Status = Result<void>;

std::unexpected<Error> make_error(ErrorCode, std::string message);
constexpr std::string_view to_string(ErrorCode) noexcept;
```

Rules:

- Every failure maps to exactly one `ErrorCode`. Where each code originates is
  listed in [SDD Appendix A](../SDD.md#appendix-a--error-code-catalogue).
- Errors are values: no exception crosses a module boundary.
- Every function returning `Result`/`Status` is `[[nodiscard]]`. To ignore a
  result deliberately, write `(void)f();`.
- The load gateway relies on `ErrorCode::Internal` being the **last**
  enumerator (it sizes its per-code counters with it). Append new codes before
  `Internal` or update `kErrorCodes` in `apps/load_gateway/main.cpp`.

Idioms used in the codebase:

```cpp
if (auto ok = layer->can_send(mode); !ok) {
    return std::unexpected{std::move(ok.error())};   // propagate
}
return make_error(ErrorCode::InvalidArgument, "topic must not be empty");
```

## Messages (`message.hpp`)

```cpp
enum class QoS : std::uint8_t { AtMostOnce = 0, AtLeastOnce = 1, ExactlyOnce = 2 };

class Topic final {
public:
    static constexpr std::size_t kMaxLength = 65'535;
    static Result<Topic> create(std::string_view name);
    const std::string& str() const noexcept;
    auto operator<=>(const Topic&) const = default;
};

struct Message {
    Topic topic;
    Bytes payload{};
    QoS   qos{QoS::AtLeastOnce};
    bool  retain{false};     // inbound: from the broker's retained store
    bool  duplicate{false};  // inbound: DUP flag (QoS 1/2 redelivery)
};
```

`Topic` is a *topic name* (what one publishes to). `Topic::create` rejects:

| Input | Error |
|---|---|
| empty | `InvalidArgument` "topic must not be empty" |
| > 65 535 bytes | `InvalidArgument` |
| contains `'\0'` | `InvalidArgument` |
| contains `+` or `#` | `InvalidArgument` (wildcards belong in filters) |

Because the constructor is private, **an invalid `Topic` cannot exist**, so no
layer re-validates topics. UTF-8 validity is not yet enforced (TODO in
`message.cpp`).

## Layers (`layer.hpp`)

```cpp
class ILayer {
public:
    virtual std::string_view name() const noexcept = 0;
    virtual Result<Message>  on_outbound(Message message) = 0;  // app → transport
    virtual Result<Message>  on_inbound(Message message)  = 0;  // transport → app
};
```

Contract for implementers:

1. **Thread-safe**: `on_inbound` and `on_outbound` may run concurrently, from
   different threads (e.g. Paho's callback thread and the application thread).
2. **Never throw**; report failure via `Result`.
3. **Deterministic** given injected dependencies (clock, RNG, …).
4. A layer may **transform** (security), **observe** (persistence), or
   **reject** (rate limit) a message. Rejection stops the pipeline.
5. `name()` must be unique within a pipeline (wrap in a `SwitchableLayer` with a
   different name if the same layer type appears twice).

`ILayer` is non-copyable and non-movable to prevent slicing; layers are owned
via `std::unique_ptr`.

## Pipeline (`pipeline.hpp`)

```cpp
auto pipeline = Pipeline::Builder{}
                    .add(std::move(persistence))   // application side
                    .add(std::move(security))
                    .add(std::move(rate_limit))    // transport side
                    .build();                      // Result<Pipeline>
```

| Member | Behaviour |
|---|---|
| `Builder::add(unique_ptr<ILayer>)` | appends below the previous layers (closer to the transport). A null layer is remembered and makes `build()` fail. |
| `Builder::build()` | `InvalidArgument` on a null layer or duplicate name; otherwise moves the layers into an immutable `Pipeline`. |
| `process_outbound(Message)` | layers in insertion order |
| `process_inbound(Message)` | layers in reverse order |
| `layer_names()` | names in insertion order |

On failure the error message is prefixed with the failing layer's name, e.g.
`"[security] message authentication failed"`. `Pipeline` is move-only.

### Ordering semantics

```
application ──outbound──▶ L0 ▶ L1 ▶ … ▶ Ln ──▶ MQTT
application ◀──inbound─── L0 ◀ L1 ◀ … ◀ Ln ◀── MQTT
```

Place a layer according to what it must see:

| Layer | Place | Why |
|---|---|---|
| Persistence (plaintext) | above security | sees decrypted data |
| Persistence (at rest) | below security | sees envelopes |
| Rate limit | last (transport side) | drops floods before crypto |
| Compression (hypothetical) | above security | ciphertext does not compress; beware CRIME/BREACH |

## SwitchableLayer (`switchable_layer.hpp`)

```cpp
static Result<std::unique_ptr<SwitchableLayer>>
    create(std::unique_ptr<ILayer> inner, bool enabled = true, std::string name = {});

void          set_enabled(bool) noexcept;   // atomic, any thread
bool          enabled() const noexcept;
ILayer&       inner() noexcept;
```

While disabled, both directions pass messages through untouched. `name`
overrides the inner layer's name (default: inner's name), which allows e.g.
`persistence-plain` and `persistence-at-rest` in one pipeline. `create` fails
with `InvalidArgument` on a null inner layer.

Pipelines are immutable, so **any feature that must be toggled while traffic
flows is added up front and wrapped**. The flag is a single relaxed atomic; a
message already inside the layer finishes with the setting it started with.

## Secrets (`secure_buffer.hpp`)

```cpp
void secure_zero(MutableByteView data) noexcept;

class SecureBuffer final {
public:
    SecureBuffer() = default;
    explicit SecureBuffer(std::size_t size);   // zero-filled
    explicit SecureBuffer(ByteView data);      // copy
    ~SecureBuffer();                           // zeroes
    SecureBuffer(SecureBuffer&&) noexcept;     // source left empty
    SecureBuffer& operator=(SecureBuffer&&) noexcept;  // zeroes own data first
    ByteView        view() const noexcept;
    MutableByteView mutable_view() noexcept;
    std::size_t     size() const noexcept;
    bool            empty() const noexcept;
};
```

- Non-copyable: secrets are never silently duplicated.
- Fixed size: no reallocation can leave stale copies on the heap.
- `secure_zero` writes through a `volatile` pointer and issues an
  `atomic_signal_fence`, so the compiler cannot treat the stores as dead.

Used for AES keys, Ed25519 keys and MQTT passwords
(`ConnectionOptions::password`). `SecurityLayer` additionally calls
`secure_zero` on plaintext after sealing and on rejection paths.

## Clock (`clock.hpp`)

```cpp
class IClock { virtual std::chrono::system_clock::time_point now() const noexcept = 0; };
class SystemClock final : public IClock { /* system_clock::now() */ };
```

Injected wherever time matters (freshness, rate limit, persistence timestamps).
Tests use `msec::test::FakeClock` (`tests/test_support.hpp`), which starts at a
fixed point and moves only on `advance()`.

## Logger (`logger.hpp`)

```cpp
enum class LogLevel : std::uint8_t { Trace, Debug, Info, Warn, Error };
class ILogger { virtual void log(LogLevel, std::string_view component,
                                 std::string_view message) noexcept = 0; };
class NullLogger;      // discards
class ConsoleLogger;   // explicit ConsoleLogger(LogLevel min_level = Info)
```

`ConsoleLogger` output: `HH:MM:SS.mmm LEVEL [component] message`; `Warn` and
`Error` go to stderr, others to stdout; writes are serialised with a mutex and
flushed; any exception (formatting, I/O) is swallowed — a logger must never
take the system down.

Policy: **never log secrets or plaintext payloads.**

## Topic filters (`topic_filter.hpp`)

```cpp
Status validate_topic_filter(std::string_view filter);
bool   topic_matches(std::string_view filter, std::string_view topic);  // filter assumed valid
```

`validate_topic_filter` rejects (all `InvalidArgument`): empty or > 65 535
bytes, NUL, `+` not occupying a whole level (`a/b+`), `#` not being the whole
last level (`a/#/c`, `a#`).

`topic_matches` implements MQTT 3.1.1 §4.7:

| Filter | Topic | Match |
|---|---|---|
| `a/b/c` | `a/b/c` | ✔ |
| `a/+/c` | `a/b/c` | ✔ |
| `a/#` | `a/b/c` | ✔ |
| `a/#` | `a` | ✔ (`#` includes the parent level) |
| `#` | `a/b` | ✔ |
| `a/+` | `a/b/c` | ✘ |
| `a/b` | `a/b/c` | ✘ |
| `#` or `+/…` | `$SYS/broker` | ✘ (§4.7.2: leading wildcard never matches `$` topics) |
| `$SYS/#` | `$SYS/broker` | ✔ |

These live in `core` (not `mqtt`) so `security::KeyTopicPolicy` can use them;
`msec/mqtt/topic_filter.hpp` re-exports them into `msec::mqtt`.

## Tests

`tests/core_tests.cpp`: `Topic.AcceptsValidNames`, `Topic.RejectsInvalidNames`,
`SecureBuffer.MoveTransfersOwnership`, `SecureZero.ZeroesMemory`,
`Pipeline.OutboundTopDownInboundBottomUp`,
`Pipeline.FailureStopsProcessingAndNamesLayer`,
`Pipeline.RejectsNullAndDuplicateLayers`,
`SwitchableLayer.PassesThroughWhileDisabled`,
`SwitchableLayer.RenamesSoTheSameLayerCanAppearTwice`. Topic filters are tested
in `mqtt_tests.cpp` and fuzzed by `fuzz/fuzz_topic.cpp`.
