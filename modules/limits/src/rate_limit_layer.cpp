#include "msec/limits/rate_limit_layer.hpp"

#include <algorithm>
#include <cmath>
#include <format>
#include <utility>

namespace msec::limits {

Result<std::unique_ptr<RateLimitLayer>> RateLimitLayer::create(
    RateLimitConfig config, std::shared_ptr<const IClock> clock) {
    if (!clock) {
        return make_error(ErrorCode::InvalidArgument, "rate limit layer: missing clock");
    }
    if (!(config.messages_per_second >= 0) || !(config.burst >= 0) ||
        config.max_tracked_topics == 0) {
        return make_error(ErrorCode::InvalidArgument, "invalid rate limit configuration");
    }
    return std::make_unique<RateLimitLayer>(PassKey{}, config, std::move(clock));
}

RateLimitLayer::RateLimitLayer(PassKey /*key*/, RateLimitConfig config,
                               std::shared_ptr<const IClock> clock)
    : config_{config}, clock_{std::move(clock)}, rate_{config.messages_per_second} {}

void RateLimitLayer::set_rate(double messages_per_second) noexcept {
    rate_.store(std::isfinite(messages_per_second) ? std::max(messages_per_second, 0.0) : 0.0,
                std::memory_order_relaxed);
}

double RateLimitLayer::rate() const noexcept { return rate_.load(std::memory_order_relaxed); }

bool RateLimitLayer::take(Bucket& bucket, std::chrono::system_clock::time_point now, double rate,
                          double burst) noexcept {
    // Clamp: a clock stepping backwards must not mint or destroy tokens.
    const double elapsed =
        std::max(std::chrono::duration<double>(now - bucket.last).count(), 0.0);
    bucket.tokens = std::min(burst, bucket.tokens + elapsed * rate);
    bucket.last = std::max(bucket.last, now);
    if (bucket.tokens < 1.0) {
        return false;
    }
    bucket.tokens -= 1.0;
    return true;
}

void RateLimitLayer::evict_idle(std::chrono::system_clock::time_point now, double rate,
                                double burst) {
    // A bucket that would be full again carries no information: forget it.
    std::erase_if(buckets_, [&](const auto& entry) {
        const auto& b = entry.second;
        const double elapsed = std::max(std::chrono::duration<double>(now - b.last).count(), 0.0);
        return b.tokens + elapsed * rate >= burst;
    });
}

Result<Message> RateLimitLayer::on_inbound(Message message) {
    const double rate = rate_.load(std::memory_order_relaxed);
    if (rate <= 0) {
        return message;
    }
    const double burst = std::max(config_.burst > 0 ? config_.burst : rate, 1.0);
    const auto now = clock_->now();

    const std::scoped_lock lock{mutex_};
    auto it = buckets_.find(message.topic.str());
    if (it == buckets_.end()) {
        if (buckets_.size() >= config_.max_tracked_topics) {
            evict_idle(now, rate, burst);
        }
        if (buckets_.size() < config_.max_tracked_topics) {
            it = buckets_.emplace(message.topic.str(), Bucket{.tokens = burst, .last = now}).first;
        }
    }
    Bucket& bucket = it != buckets_.end() ? it->second : overflow_;
    if (!take(bucket, now, rate, burst)) {
        return make_error(ErrorCode::RateLimited,
                          std::format("more than {:g} msg/s on '{}'", rate, message.topic.str()));
    }
    return message;
}

}  // namespace msec::limits
