#include "msec/security/replay_guard.hpp"

namespace msec::security {

Status ReplayGuard::check_and_record(KeyId key_id, std::uint64_t sequence) {
    if (sequence == 0) {
        return make_error(ErrorCode::InvalidArgument, "sequence number 0 is reserved");
    }
    const std::scoped_lock lock{mutex_};

    const auto it = windows_.find(key_id);
    if (it == windows_.end()) {
        // Bounded state: an attacker cycling key ids must not exhaust memory.
        if (windows_.size() >= max_tracked_keys_) {
            return make_error(ErrorCode::CapacityExceeded, "too many tracked senders");
        }
        windows_.emplace(key_id, Window{.highest = sequence, .bitmap = 1U});
        return {};
    }

    Window& window = it->second;
    if (sequence > window.highest) {
        const std::uint64_t shift = sequence - window.highest;
        window.bitmap = shift >= kWindowSize ? std::uint64_t{1} : ((window.bitmap << shift) | 1U);
        window.highest = sequence;
        return {};
    }

    const std::uint64_t offset = window.highest - sequence;
    if (offset >= kWindowSize) {
        return make_error(ErrorCode::ReplayDetected, "sequence number outside replay window");
    }
    const std::uint64_t bit = std::uint64_t{1} << offset;
    if ((window.bitmap & bit) != 0U) {
        return make_error(ErrorCode::ReplayDetected, "duplicate sequence number");
    }
    window.bitmap |= bit;
    return {};
}

void ReplayGuard::forget(KeyId key_id) {
    const std::scoped_lock lock{mutex_};
    windows_.erase(key_id);
}

}  // namespace msec::security
