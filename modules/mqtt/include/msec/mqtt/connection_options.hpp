#pragma once

#include <chrono>
#include <filesystem>
#include <optional>
#include <string>

#include "msec/core/secure_buffer.hpp"

namespace msec::mqtt {

/// Transport-level security (defence layer 1). Payload-level protection is
/// handled independently by the security module (defence layer 2).
struct TlsOptions {
    std::filesystem::path ca_file{};
    std::filesystem::path client_cert_file{};  // for mutual TLS
    std::filesystem::path client_key_file{};
    bool verify_peer{true};  // must stay true outside of tests
};

struct ConnectionOptions {
    std::string broker_uri{};  // e.g. "ssl://broker.local:8883"
    std::string client_id{};
    std::optional<TlsOptions> tls{};
    std::optional<std::string> username{};
    std::optional<SecureBuffer> password{};
    std::chrono::seconds keep_alive{30};
    bool clean_session{true};
};

}  // namespace msec::mqtt
