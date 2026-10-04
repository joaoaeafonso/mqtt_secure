#pragma once

#include <deque>
#include <mutex>

#include "msec/data/message_repository.hpp"

namespace msec::data {

/// Bounded ring buffer: when full, the oldest entry is evicted. Memory use is
/// therefore capped no matter how fast messages arrive.
class InMemoryMessageRepository final : public IMessageRepository {
public:
    explicit InMemoryMessageRepository(std::size_t capacity) noexcept : capacity_{capacity} {}

    [[nodiscard]] Result<std::uint64_t> store(const Message& message, Direction direction,
                                              std::chrono::system_clock::time_point at) override;
    [[nodiscard]] Result<std::vector<StoredMessage>> find_by_topic(
        const Topic& topic, std::size_t limit) const override;
    [[nodiscard]] Result<std::vector<StoredMessage>> latest(std::size_t limit) const override;
    [[nodiscard]] std::size_t size() const override;

private:
    std::size_t capacity_;
    mutable std::mutex mutex_;
    std::deque<StoredMessage> entries_;
    std::uint64_t next_id_{1};
};

}  // namespace msec::data
