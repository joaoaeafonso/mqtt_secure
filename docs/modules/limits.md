# Module `msec::limits`

**Target:** `msec_limits` (alias `msec::limits`) · **Public deps:** `msec::core`

## `RateLimitLayer`

An **inbound** token bucket per topic that drops floods before they reach
expensive layers. Outbound messages always pass.

```cpp
struct RateLimitConfig {
    double messages_per_second{0};        // per topic; 0 = unlimited
    double burst{0};                      // bucket size; 0 = one second's worth
    std::size_t max_tracked_topics{4096};
};

static Result<std::unique_ptr<RateLimitLayer>> create(RateLimitConfig, std::shared_ptr<const IClock>);
void   set_rate(double messages_per_second) noexcept;   // thread-safe; 0 disables
double rate() const noexcept;
// name() == "rate-limit"
```

`create` fails (`InvalidArgument`) without a clock, with a negative or NaN rate
or burst, or with `max_tracked_topics == 0`.

### Placement

Put it **last** (transport side) so that on inbound it runs first and rejected
messages cost no cryptography:

```
application ◀ … ◀ [security] ◀ [rate limit] ◀ MQTT
```

### Algorithm

```
rate  = rate_ (atomic); if rate ≤ 0 → pass
burst = max(config.burst > 0 ? config.burst : rate, 1)
now   = clock.now()
lock
  bucket = buckets[topic]
  if absent:
      if buckets full: evict every bucket that would already be full again (idle)
      if room now:     insert {tokens = burst, last = now}
      else:            use the shared overflow bucket
  elapsed = max(now − bucket.last, 0)          // backwards clock steps mint nothing
  tokens  = min(burst, tokens + elapsed · rate)
  last    = max(last, now)
  if tokens < 1 → RateLimited "more than R msg/s on '<topic>'"
  tokens −= 1
```

Properties:

- **Bounded memory**: at most `max_tracked_topics` buckets. An attacker
  inventing topics cannot mint budget: once full, untracked topics share one
  overflow bucket.
- **Idle eviction**: a bucket that would be full again carries no information
  and can be forgotten.
- **Runtime change**: `set_rate` clamps negative/non-finite values to 0; existing
  buckets keep their tokens.

### Known limitation (by design, visible in the lab)

The topic is chosen by the publisher, so **an attacker flooding a victim's topic
also exhausts the victim's budget**. Per-client limits belong in the broker,
which knows who actually sent a message (Mosquitto 2.0 has none). See the
`flood-rate-limit` scenario.

## Tests

`tests/limits_tests.cpp`: `UnlimitedByDefault`, `AllowsBurstThenRefillsAtRate`,
`TopicsHaveIndependentBudgets`, `OutboundIsNeverLimited`, `RateCanChangeAtRuntime`,
`MemoryStaysBoundedUnderTopicFlood`, `RateLimitFactory.RejectsInvalidConfig`.
