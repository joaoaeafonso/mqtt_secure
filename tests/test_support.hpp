#pragma once

#include <gtest/gtest.h>

#include <chrono>
#include <string_view>

#include "msec/core/clock.hpp"
#include "msec/core/message.hpp"

namespace msec::test {

/// Manually controlled clock for deterministic time-based tests.
class FakeClock final : public IClock {
public:
    explicit FakeClock(std::chrono::system_clock::time_point start =
                           std::chrono::system_clock::time_point{std::chrono::hours{480'000}})
        : now_{start} {}
    [[nodiscard]] std::chrono::system_clock::time_point now() const noexcept override {
        return now_;
    }
    void advance(std::chrono::milliseconds delta) { now_ += delta; }

private:
    std::chrono::system_clock::time_point now_;
};

inline Topic topic(std::string_view name) {
    auto t = Topic::create(name);
    EXPECT_TRUE(t.has_value()) << name;
    return *t;
}

inline Message message(std::string_view topic_name, std::string_view payload) {
    return Message{.topic = topic(topic_name), .payload = to_bytes(payload)};
}

}  // namespace msec::test
