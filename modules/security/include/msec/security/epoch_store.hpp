#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>

#include "msec/core/error.hpp"

namespace msec::security {

/// Durable record of the newest key epoch a receiver has accepted.
///
/// The replay window lives in memory, so a restarted receiver would accept
/// every message it had already seen. Instead of persisting the window on
/// every message, the receiver records the newest epoch it has accepted (a
/// write per key rotation, not per message) and, after a restart, accepts
/// only keys of a LATER epoch: old messages cannot be replayed into an empty
/// window, and senders resume once they rotate to a new epoch.
class IEpochStore {
public:
    IEpochStore() = default;
    virtual ~IEpochStore() = default;
    IEpochStore(const IEpochStore&) = delete;
    IEpochStore& operator=(const IEpochStore&) = delete;
    IEpochStore(IEpochStore&&) = delete;
    IEpochStore& operator=(IEpochStore&&) = delete;

    /// nullopt if nothing was ever recorded (first start).
    [[nodiscard]] virtual Result<std::optional<std::uint32_t>> load() const = 0;
    /// Must be durable when it returns successfully.
    [[nodiscard]] virtual Status save(std::uint32_t epoch) = 0;
};

/// One decimal number in a file, replaced atomically (write a temporary file,
/// fsync it, rename it over the old one, fsync the directory), so a crash
/// leaves either the old or the new value, never a torn one.
class FileEpochStore final : public IEpochStore {
public:
    explicit FileEpochStore(std::filesystem::path path) : path_{std::move(path)} {}

    [[nodiscard]] Result<std::optional<std::uint32_t>> load() const override;
    [[nodiscard]] Status save(std::uint32_t epoch) override;

private:
    std::filesystem::path path_;
};

}  // namespace msec::security
