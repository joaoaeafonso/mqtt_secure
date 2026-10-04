#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "msec/core/error.hpp"
#include "msec/core/message.hpp"

namespace msec::data {

enum class Direction : std::uint8_t { Inbound, Outbound };

struct StoredMessage {
    std::uint64_t id{0};
    Direction direction{Direction::Inbound};
    std::chrono::system_clock::time_point stored_at{};
    Message message;
};

/// Storage port. Implementations: in-memory (now), SQLite / time-series DB (later).
/// Implementations must be thread-safe.
class IMessageRepository {
public:
    IMessageRepository() = default;
    virtual ~IMessageRepository() = default;
    IMessageRepository(const IMessageRepository&) = delete;
    IMessageRepository& operator=(const IMessageRepository&) = delete;
    IMessageRepository(IMessageRepository&&) = delete;
    IMessageRepository& operator=(IMessageRepository&&) = delete;

    [[nodiscard]] virtual Result<std::uint64_t> store(
        const Message& message, Direction direction,
        std::chrono::system_clock::time_point at) = 0;

    /// Newest first, at most `limit` entries.
    [[nodiscard]] virtual Result<std::vector<StoredMessage>> find_by_topic(
        const Topic& topic, std::size_t limit) const = 0;

    /// Newest first, at most `limit` entries.
    [[nodiscard]] virtual Result<std::vector<StoredMessage>> latest(std::size_t limit) const = 0;

    [[nodiscard]] virtual std::size_t size() const = 0;
};

}  // namespace msec::data
