# Module `msec::data`

**Target:** `msec_data` (alias `msec::data`) · **Public deps:** `msec::core`

Message persistence as a pipeline layer, behind a storage port.

| Header | Contents |
|---|---|
| `message_repository.hpp` | `Direction`, `StoredMessage`, `IMessageRepository` |
| `in_memory_repository.hpp` | `InMemoryMessageRepository` |
| `persistence_layer.hpp` | `PersistenceConfig`, `PersistenceLayer` |

---

## Storage port

```cpp
enum class Direction : std::uint8_t { Inbound, Outbound };

struct StoredMessage {
    std::uint64_t id{0};
    Direction direction{Direction::Inbound};
    std::chrono::system_clock::time_point stored_at{};
    Message message;
};

class IMessageRepository {   // implementations must be thread-safe
    virtual Result<std::uint64_t> store(const Message&, Direction, time_point at) = 0;
    virtual Result<std::vector<StoredMessage>> find_by_topic(const Topic&, std::size_t limit) const = 0;  // newest first
    virtual Result<std::vector<StoredMessage>> latest(std::size_t limit) const = 0;                        // newest first
    virtual std::size_t size() const = 0;
};
```

## `InMemoryMessageRepository`

```cpp
explicit InMemoryMessageRepository(std::size_t capacity) noexcept;
```

- Bounded ring buffer (`std::deque`): when full, the **oldest** entry is
  evicted, so memory is capped no matter how fast messages arrive.
- Ids start at 1 and increase monotonically (they are not reused after
  eviction).
- `store` fails with `CapacityExceeded` if `capacity == 0`.
- All operations take one mutex.

Future implementations (SQLite, a time-series DB) plug in behind the same
interface; only the composition root changes.

## `PersistenceLayer`

```cpp
struct PersistenceConfig {
    bool store_inbound{true};
    bool store_outbound{false};
    bool fail_on_storage_error{false};   // true: audit-critical, reject on storage failure
};

static Result<std::unique_ptr<PersistenceLayer>> create(
    std::shared_ptr<IMessageRepository>, std::shared_ptr<const IClock>, PersistenceConfig = {});
```

A **pass-through** layer (name `"persistence"`) that records messages with the
injected clock's timestamp. It never modifies messages. `create` returns
`InvalidArgument` if the repository or clock is missing.

Storage errors are ignored (the message still flows) unless
`fail_on_storage_error` is set, in which case the storage error is returned and
the message is rejected.

### Position decides what is stored

```
[persistence, security]   app ◀─ persistence ◀─ security ◀─ MQTT   → plaintext (after decryption)
[security, persistence]   app ◀─ security ◀─ persistence ◀─ MQTT   → envelopes (encrypted at rest)
```

Since both positions have the same layer name, a pipeline that offers both
wraps them in `SwitchableLayer`s named `persistence-plain` and
`persistence-at-rest` (this is what `msec_load_gateway` does).

Note that with `[security, persistence]` on inbound, persistence runs **before**
security, so it also stores messages that security will later reject (forged,
replayed). With `[persistence, security]` only accepted messages are stored.

## Tests

`tests/data_tests.cpp`: `InMemoryRepository.EvictsOldestWhenFull`,
`InMemoryRepository.FindByTopic`, `PersistenceLayer.StoresAccordingToConfig`,
`PersistenceLayer.RejectsMissingDependencies`. The integration test checks that
`[persistence, security]` stores exactly the accepted plaintext.
