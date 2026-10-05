#pragma once

#include <string_view>

#include "msec/core/error.hpp"

namespace msec {

/// Validates a subscription filter ('+' and '#' must occupy a whole level,
/// '#' only as the last level).
[[nodiscard]] Status validate_topic_filter(std::string_view filter);

/// MQTT 3.1.1 §4.7 matching. Topics starting with '$' are not matched by a
/// leading wildcard. The filter is assumed valid.
[[nodiscard]] bool topic_matches(std::string_view filter, std::string_view topic);

}  // namespace msec
