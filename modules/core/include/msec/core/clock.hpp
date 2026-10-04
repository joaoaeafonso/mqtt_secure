#pragma once

#include <chrono>

namespace msec {

/// Time is injected so that time-dependent logic (freshness checks,
/// timestamps) is deterministic under test.
class IClock {
public:
    IClock() = default;
    virtual ~IClock() = default;
    IClock(const IClock&) = delete;
    IClock& operator=(const IClock&) = delete;
    IClock(IClock&&) = delete;
    IClock& operator=(IClock&&) = delete;

    [[nodiscard]] virtual std::chrono::system_clock::time_point now() const noexcept = 0;
};

class SystemClock final : public IClock {
public:
    [[nodiscard]] std::chrono::system_clock::time_point now() const noexcept override {
        return std::chrono::system_clock::now();
    }
};

}  // namespace msec
