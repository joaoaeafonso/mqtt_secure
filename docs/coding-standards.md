# Engineering practices and coding conventions

These are the conventions the existing code follows; new code should read the
same.

## Error handling

- **Errors are values.** Fallible functions return `Result<T>` or `Status`
  (`std::expected<…, Error>`); every one is `[[nodiscard]]`.
- **No exceptions cross module boundaries.** Exceptions from third-party code
  (Paho) are caught in the adapter and converted. Logging never throws.
- Ignore a result only explicitly: `(void)f();`.
- Propagate with `return std::unexpected{std::move(x.error())};`; create with
  `make_error(ErrorCode::…, "message")`.
- Messages describe *what* failed in lower case; the pipeline adds the layer
  name prefix.
- Security-relevant failures stay **uniform** where distinguishing them would
  create an oracle (`AuthenticationFailed` for every verification failure).
- `std::exit` / `die` is acceptable only in composition roots at startup.

## Making invalid states unrepresentable

- Validated value types with private constructors (`Topic::create`).
- Factories (`static Result<std::unique_ptr<T>> create(...)`) that check
  dependencies, combined with a private `PassKey` tag in the public constructor
  so `std::make_unique` works but nobody can skip validation.
- Interfaces are non-copyable and non-movable (no slicing); concrete classes
  are `final`.
- Immutable structures where possible (`Pipeline`, the loopback broker's ACL).

## Resources and secrets

- RAII for everything (`unique_ptr` with OpenSSL deleters, scoped locks).
- Secrets live in `SecureBuffer` (non-copyable, fixed size, zeroed on
  destruction and move-assignment).
- Wipe plaintext after sealing and on rejection paths (`secure_zero`).
- Never log keys, passwords or payloads.

## Dependencies and testability

- Every external effect is injected: clock, RNG, transport, storage, logger,
  crypto. No globals, no singletons.
- Modules depend only on `core`; only composition roots know concrete classes.
- Third-party libraries are private dependencies; public headers do not include
  them.

## Robustness against hostile input

- Bound every container that attacker input can grow (replay windows, rate
  buckets, repositories, "seen" sets).
- Do cheap, stateless checks before expensive ones; mutate state only after
  authentication.
- Compute bounds from trusted values (e.g. freshness limits from `now`, not from
  the message timestamp) to avoid overflow.
- Parsers are total: any byte string yields a value or an error, and is fuzzed.

## Concurrency

- Layers are thread-safe. Prefer immutability, then atomics (relaxed when the
  flag publishes no data), then a mutex; use `shared_mutex` for read-mostly
  state.
- Copy callbacks out under a lock and invoke them outside it (allows
  re-entrancy and avoids deadlocks).
- Detach callbacks before destroying the objects they reference.

## Style

- `.clang-format`: Google-based, 100 columns, 4-space indent.
- Naming (enforced by clang-tidy): `CamelCase` types and enum values,
  `lower_case` functions and variables, trailing `_` for private members,
  `kCamelCase` constants.
- Namespaces: `msec`, `msec::mqtt`, `msec::mqtt::paho`, `msec::security`,
  `msec::security::openssl`, `msec::security::envelope`, `msec::data`,
  `msec::limits`, `msec::test`.
- Headers: `#pragma once`; standard headers, then project headers
  (`"msec/<module>/…"`).
- Comments explain *why* (design decisions, ordering constraints, library
  quirks), not *what*. `///` for API docs on declarations.
- Use `NOLINT(<check>): reason` sparingly and always with a reason.

## Compiler and tooling gates

- Warnings as errors with a broad warning set (see
  [build-system.md](build-system.md#msecproject_options)).
- Hardened builds: `_FORTIFY_SOURCE=3`, stack protector, full RELRO, non-exec
  stack, bounds-checked standard containers (`_GLIBCXX_ASSERTIONS`).
- Verified under ASan + UBSan, ThreadSanitizer, clang-tidy (CERT and C++ Core
  Guidelines), and libFuzzer.

## Python (load lab)

- Python ≥ 3.11, `from __future__ import annotations`, type hints, dataclasses.
- Stdlib only except `paho-mqtt` and `cryptography`.
- Private files created 0600 (`pki.write_private`), temp dirs 0700.
- Constant-time comparison for secrets (`hmac.compare_digest`).
- Validation before action: an invalid configuration patch changes nothing.
- Worker processes use the `spawn` start method.
- `# noqa: <code> - reason` for intentional lint exceptions.
