#pragma once

#include <cstdint>
#include <mutex>
#include <string_view>

namespace msec {

enum class LogLevel : std::uint8_t { Trace, Debug, Info, Warn, Error };

/// Logging sink. Implementations must be thread-safe and must never throw.
/// Never log secrets or plaintext payloads.
class ILogger {
public:
    ILogger() = default;
    virtual ~ILogger() = default;
    ILogger(const ILogger&) = delete;
    ILogger& operator=(const ILogger&) = delete;
    ILogger(ILogger&&) = delete;
    ILogger& operator=(ILogger&&) = delete;

    virtual void log(LogLevel level, std::string_view component,
                     std::string_view message) noexcept = 0;
};

class NullLogger final : public ILogger {
public:
    void log(LogLevel /*level*/, std::string_view /*component*/,
             std::string_view /*message*/) noexcept override {}
};

class ConsoleLogger final : public ILogger {
public:
    explicit ConsoleLogger(LogLevel min_level = LogLevel::Info) noexcept : min_level_{min_level} {}
    void log(LogLevel level, std::string_view component,
             std::string_view message) noexcept override;

private:
    LogLevel min_level_;
    std::mutex mutex_;
};

}  // namespace msec
