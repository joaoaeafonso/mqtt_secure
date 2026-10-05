#pragma once

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <unordered_map>

#include "msec/core/error.hpp"
#include "msec/security/types.hpp"

namespace msec::security {

/// Anti-replay sliding window (same scheme as IPsec, RFC 4303 §3.4.3).
/// Accepts each sequence number at most once, tolerates reordering within
/// the last kWindowSize numbers, and rejects anything older.
///
/// Must only be updated AFTER a message has been authenticated, otherwise an
/// attacker could advance the window with forged sequence numbers.
class ReplayGuard final {
public:
    static constexpr std::uint64_t kWindowSize = 64;

    explicit ReplayGuard(std::size_t max_tracked_keys = 1024) noexcept
        : max_tracked_keys_{max_tracked_keys} {}

    [[nodiscard]] Status check_and_record(KeyId key_id, std::uint64_t sequence);
    /// Drops a key's window (after revocation or rotation), freeing its slot.
    void forget(KeyId key_id);

private:
    struct Window {
        std::uint64_t highest{0};
        std::uint64_t bitmap{0};  // bit i set => (highest - i) already seen
    };

    std::size_t max_tracked_keys_;
    std::mutex mutex_;
    std::unordered_map<KeyId, Window> windows_;
};

}  // namespace msec::security
