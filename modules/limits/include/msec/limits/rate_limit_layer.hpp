#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

#include "msec/core/clock.hpp"
#include "msec/core/layer.hpp"

namespace msec::limits {

struct RateLimitConfig {
    double messages_per_second{0};  ///< per topic; 0 = unlimited
    double burst{0};                ///< bucket size; 0 = one second's worth
    std::size_t max_tracked_topics{4096};
};

/// Inbound token bucket per topic: drops floods before they reach expensive
/// layers. Place it on the transport side of the pipeline (last), so on
/// inbound it runs before security and rejected messages cost no crypto.
///
///     application ◀ … ◀ [security] ◀ [rate limit] ◀ MQTT
///
/// Limitation, by design visible in the lab: the topic is chosen by the
/// publisher, so an attacker flooding a victim's topic also exhausts the
/// victim's budget. Per-client limits belong in the broker, which knows who
/// actually sent a message.
///
/// Memory is bounded: at most max_tracked_topics buckets; beyond that idle
/// buckets are dropped, and if none is idle, untracked topics share one bucket.
class RateLimitLayer final : public ILayer {
    struct PassKey {};

public:
    [[nodiscard]] static Result<std::unique_ptr<RateLimitLayer>> create(
        RateLimitConfig config, std::shared_ptr<const IClock> clock);

    RateLimitLayer(PassKey /*key*/, RateLimitConfig config, std::shared_ptr<const IClock> clock);

    [[nodiscard]] std::string_view name() const noexcept override { return "rate-limit"; }
    [[nodiscard]] Result<Message> on_outbound(Message message) override { return message; }
    [[nodiscard]] Result<Message> on_inbound(Message message) override;

    /// Thread-safe; 0 disables limiting. Existing buckets keep their tokens.
    void set_rate(double messages_per_second) noexcept;
    [[nodiscard]] double rate() const noexcept;

private:
    struct Bucket {
        double tokens{0};
        std::chrono::system_clock::time_point last{};
    };

    [[nodiscard]] bool take(Bucket& bucket, std::chrono::system_clock::time_point now,
                            double rate, double burst) const noexcept;
    void evict_idle(std::chrono::system_clock::time_point now, double rate, double burst);

    RateLimitConfig config_;
    std::shared_ptr<const IClock> clock_;
    std::atomic<double> rate_;
    std::mutex mutex_;
    std::unordered_map<std::string, Bucket> buckets_;
    Bucket overflow_{};
};

}  // namespace msec::limits
