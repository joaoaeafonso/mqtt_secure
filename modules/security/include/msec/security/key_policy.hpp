#pragma once

#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "msec/core/error.hpp"
#include "msec/security/types.hpp"

namespace msec::security {

/// Which topics a key may publish on. Authentication alone proves that a
/// message was made with key K; without this check, the holder of any valid
/// key (e.g. a compromised device) could publish authentic-looking data on
/// every other device's topic.
class IKeyAuthorization {
public:
    IKeyAuthorization() = default;
    virtual ~IKeyAuthorization() = default;
    IKeyAuthorization(const IKeyAuthorization&) = delete;
    IKeyAuthorization& operator=(const IKeyAuthorization&) = delete;
    IKeyAuthorization(IKeyAuthorization&&) = delete;
    IKeyAuthorization& operator=(IKeyAuthorization&&) = delete;

    [[nodiscard]] virtual bool may_publish(KeyId key_id, std::string_view topic) const = 0;
};

/// Deny-by-default key → topic-filter rules, in the spirit of Mosquitto's ACL
/// patterns:
///
///     policy.set_owner(7, "sensor-7");
///     policy.allow_pattern("+/sensors/%u/#");   // %u: owner, %k: key id
///
/// lets key 7 publish under open/sensors/sensor-7/ and restricted/sensors/sensor-7/
/// only. Thread-safe; owners and rules can change while messages flow (key
/// rotation adds owners, revocation removes them).
class KeyTopicPolicy final : public IKeyAuthorization {
public:
    /// A rule for every key; "%k" and "%u" are substituted per key.
    [[nodiscard]] Status allow_pattern(std::string filter);
    /// A rule for one key (no substitution).
    [[nodiscard]] Status allow(KeyId key_id, std::string filter);
    /// Names the device a key belongs to (used by "%u"). Must be one topic level.
    [[nodiscard]] Status set_owner(KeyId key_id, std::string owner);
    /// Forgets the key's owner and per-key rules.
    void remove(KeyId key_id);

    [[nodiscard]] bool may_publish(KeyId key_id, std::string_view topic) const override;

private:
    mutable std::shared_mutex mutex_;
    std::vector<std::string> patterns_;
    std::unordered_map<KeyId, std::vector<std::string>> rules_;
    std::unordered_map<KeyId, std::string> owners_;
};

}  // namespace msec::security
