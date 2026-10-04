#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "msec/core/error.hpp"

namespace msec::mqtt {

enum class Access : std::uint8_t {
    Read = 1,       ///< receive messages published on matching topics
    Write = 2,      ///< publish to matching topics
    ReadWrite = 3,
};

/// Broker-side topic authorization, modelled on Mosquitto's `acl_file`.
///
/// Deny by default: a client may publish to a topic only if a Write rule
/// matches it, and receives a message only if a Read rule matches the
/// message's topic. Read access is checked per message at delivery time, so
/// subscribing to a broad filter such as `#` is allowed but only yields the
/// topics the client may read.
///
/// Rules are keyed by client id. Without broker authentication (TLS client
/// certificates, passwords) a client id is only a claim; the ACL is meant to
/// be combined with it, as in a real deployment.
class AccessControlList final {
public:
    /// Rule for one client.
    [[nodiscard]] Status allow(std::string client_id, std::string filter, Access access);
    /// Rule for every client (Mosquitto's `pattern` without substitutions).
    [[nodiscard]] Status allow_all(std::string filter, Access access);

    [[nodiscard]] bool can_publish(std::string_view client_id, std::string_view topic) const;
    [[nodiscard]] bool can_read(std::string_view client_id, std::string_view topic) const;

private:
    struct Rule {
        bool any_client;
        std::string client_id;
        std::string filter;
        Access access;
    };

    [[nodiscard]] Status add(Rule rule);
    [[nodiscard]] bool permits(std::string_view client_id, std::string_view topic,
                               Access needed) const;

    std::vector<Rule> rules_;
};

}  // namespace msec::mqtt
