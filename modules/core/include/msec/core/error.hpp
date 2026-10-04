#pragma once

#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <utility>

namespace msec {

/// Every failure in the system maps to exactly one of these codes.
/// Errors are values (std::expected), never exceptions, across module boundaries.
enum class ErrorCode : std::uint8_t {
    InvalidArgument,
    InvalidState,
    NotFound,
    CapacityExceeded,
    ConnectionFailed,
    NotConnected,
    CryptoFailure,
    AuthenticationFailed,
    PermissionDenied,
    ReplayDetected,
    MessageExpired,
    MalformedMessage,
    StorageFailure,
    Internal,
};

[[nodiscard]] constexpr std::string_view to_string(ErrorCode code) noexcept {
    switch (code) {
        case ErrorCode::InvalidArgument:      return "InvalidArgument";
        case ErrorCode::InvalidState:         return "InvalidState";
        case ErrorCode::NotFound:             return "NotFound";
        case ErrorCode::CapacityExceeded:     return "CapacityExceeded";
        case ErrorCode::ConnectionFailed:     return "ConnectionFailed";
        case ErrorCode::NotConnected:         return "NotConnected";
        case ErrorCode::CryptoFailure:        return "CryptoFailure";
        case ErrorCode::AuthenticationFailed: return "AuthenticationFailed";
        case ErrorCode::PermissionDenied:     return "PermissionDenied";
        case ErrorCode::ReplayDetected:       return "ReplayDetected";
        case ErrorCode::MessageExpired:       return "MessageExpired";
        case ErrorCode::MalformedMessage:     return "MalformedMessage";
        case ErrorCode::StorageFailure:       return "StorageFailure";
        case ErrorCode::Internal:             return "Internal";
    }
    return "Unknown";
}

struct Error {
    ErrorCode code{ErrorCode::Internal};
    std::string message;
};

template <typename T>
using Result = std::expected<T, Error>;

/// Result of an operation that produces no value.
using Status = Result<void>;

[[nodiscard]] inline std::unexpected<Error> make_error(ErrorCode code, std::string message) {
    return std::unexpected<Error>{Error{code, std::move(message)}};
}

}  // namespace msec
