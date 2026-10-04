#include "msec/data/in_memory_repository.hpp"

#include <ranges>

namespace msec::data {

Result<std::uint64_t> InMemoryMessageRepository::store(const Message& message,
                                                       Direction direction,
                                                       std::chrono::system_clock::time_point at) {
    if (capacity_ == 0) {
        return make_error(ErrorCode::CapacityExceeded, "repository has zero capacity");
    }
    const std::scoped_lock lock{mutex_};
    if (entries_.size() >= capacity_) {
        entries_.pop_front();
    }
    const std::uint64_t id = next_id_++;
    entries_.push_back(
        StoredMessage{.id = id, .direction = direction, .stored_at = at, .message = message});
    return id;
}

Result<std::vector<StoredMessage>> InMemoryMessageRepository::find_by_topic(
    const Topic& topic, std::size_t limit) const {
    const std::scoped_lock lock{mutex_};
    std::vector<StoredMessage> out;
    for (const auto& entry : std::views::reverse(entries_)) {
        if (out.size() >= limit) {
            break;
        }
        if (entry.message.topic == topic) {
            out.push_back(entry);
        }
    }
    return out;
}

Result<std::vector<StoredMessage>> InMemoryMessageRepository::latest(std::size_t limit) const {
    const std::scoped_lock lock{mutex_};
    std::vector<StoredMessage> out;
    for (const auto& entry : std::views::reverse(entries_) | std::views::take(limit)) {
        out.push_back(entry);
    }
    return out;
}

std::size_t InMemoryMessageRepository::size() const {
    const std::scoped_lock lock{mutex_};
    return entries_.size();
}

}  // namespace msec::data
