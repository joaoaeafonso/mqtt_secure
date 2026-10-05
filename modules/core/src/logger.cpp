#include "msec/core/logger.hpp"

#include <chrono>
#include <cstdio>
#include <format>
#include <string>

namespace msec {
namespace {

constexpr std::string_view level_name(LogLevel level) noexcept {
    switch (level) {
        case LogLevel::Trace: return "TRACE";
        case LogLevel::Debug: return "DEBUG";
        case LogLevel::Info:  return "INFO ";
        case LogLevel::Warn:  return "WARN ";
        case LogLevel::Error: return "ERROR";
    }
    return "?????";
}

}  // namespace

void ConsoleLogger::log(LogLevel level, std::string_view component,
                        std::string_view message) noexcept {
    if (level < min_level_) {
        return;
    }
    try {
        const auto now = std::chrono::floor<std::chrono::milliseconds>(
            std::chrono::system_clock::now());
        const std::string line =
            std::format("{:%T} {} [{}] {}\n", now, level_name(level), component, message);
        const std::scoped_lock lock{mutex_};
        std::FILE* stream = level >= LogLevel::Warn ? stderr : stdout;
        (void)std::fwrite(line.data(), 1, line.size(), stream);
        (void)std::fflush(stream);
    } catch (...) {  // NOLINT(bugprone-empty-catch)
        // A logger must never take the system down; drop the line.
    }
}

}  // namespace msec
