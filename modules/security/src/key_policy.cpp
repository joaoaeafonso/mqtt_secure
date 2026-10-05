#include "msec/security/key_policy.hpp"

#include <format>
#include <mutex>
#include <utility>

#include "msec/core/topic_filter.hpp"

namespace msec::security {
namespace {

std::string substitute(std::string_view pattern, std::string_view key, std::string_view owner) {
    std::string out;
    out.reserve(pattern.size() + owner.size());
    for (std::size_t i = 0; i < pattern.size(); ++i) {
        if (pattern[i] == '%' && i + 1 < pattern.size() &&
            (pattern[i + 1] == 'k' || pattern[i + 1] == 'u')) {
            out += pattern[i + 1] == 'k' ? key : owner;
            ++i;
        } else {
            out += pattern[i];
        }
    }
    return out;
}

bool uses_owner(std::string_view pattern) { return pattern.find("%u") != std::string_view::npos; }

}  // namespace

Status KeyTopicPolicy::allow_pattern(std::string filter) {
    // Validate with placeholders standing in for a single level.
    if (auto ok = validate_topic_filter(substitute(filter, "0", "x")); !ok) {
        return ok;
    }
    const std::unique_lock lock{mutex_};
    patterns_.push_back(std::move(filter));
    return {};
}

Status KeyTopicPolicy::allow(KeyId key_id, std::string filter) {
    if (auto ok = validate_topic_filter(filter); !ok) {
        return ok;
    }
    const std::unique_lock lock{mutex_};
    rules_[key_id].push_back(std::move(filter));
    return {};
}

Status KeyTopicPolicy::set_owner(KeyId key_id, std::string owner) {
    if (owner.empty() || owner.find_first_of("/+#$") != std::string::npos ||
        owner.find('\0') != std::string::npos) {
        return make_error(ErrorCode::InvalidArgument,
                          std::format("owner '{}' must be one plain topic level", owner));
    }
    const std::unique_lock lock{mutex_};
    owners_[key_id] = std::move(owner);
    return {};
}

void KeyTopicPolicy::remove(KeyId key_id) {
    const std::unique_lock lock{mutex_};
    owners_.erase(key_id);
    rules_.erase(key_id);
}

bool KeyTopicPolicy::may_publish(KeyId key_id, std::string_view topic) const {
    const std::shared_lock lock{mutex_};
    if (const auto it = rules_.find(key_id); it != rules_.end()) {
        for (const auto& filter : it->second) {
            if (topic_matches(filter, topic)) {
                return true;
            }
        }
    }
    const auto owner = owners_.find(key_id);
    const std::string key = std::to_string(key_id);
    for (const auto& pattern : patterns_) {
        if (uses_owner(pattern) && owner == owners_.end()) {
            continue;  // no owner, no match: never substitute an empty level
        }
        const auto filter =
            substitute(pattern, key, owner == owners_.end() ? std::string_view{} : owner->second);
        if (topic_matches(filter, topic)) {
            return true;
        }
    }
    return false;
}

}  // namespace msec::security
