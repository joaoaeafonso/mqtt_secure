#include "msec/mqtt/access_control.hpp"

#include <algorithm>
#include <utility>

#include "msec/mqtt/topic_filter.hpp"

namespace msec::mqtt {

Status AccessControlList::allow(std::string client_id, std::string filter, Access access) {
    if (client_id.empty()) {
        return make_error(ErrorCode::InvalidArgument, "ACL rule needs a client id");
    }
    return add({.any_client = false,
                .client_id = std::move(client_id),
                .filter = std::move(filter),
                .access = access});
}

Status AccessControlList::allow_all(std::string filter, Access access) {
    return add({.any_client = true, .client_id = {}, .filter = std::move(filter), .access = access});
}

Status AccessControlList::add(Rule rule) {
    if (auto valid = validate_topic_filter(rule.filter); !valid) {
        return valid;
    }
    rules_.push_back(std::move(rule));
    return {};
}

bool AccessControlList::can_publish(std::string_view client_id, std::string_view topic) const {
    return permits(client_id, topic, Access::Write);
}

bool AccessControlList::can_read(std::string_view client_id, std::string_view topic) const {
    return permits(client_id, topic, Access::Read);
}

bool AccessControlList::permits(std::string_view client_id, std::string_view topic,
                                Access needed) const {
    const auto bit = static_cast<std::uint8_t>(needed);
    return std::ranges::any_of(rules_, [&](const Rule& rule) {
        return (static_cast<std::uint8_t>(rule.access) & bit) != 0 &&
               (rule.any_client || rule.client_id == client_id) &&
               topic_matches(rule.filter, topic);
    });
}

}  // namespace msec::mqtt
