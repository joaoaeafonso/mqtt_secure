#include "msec/mqtt/topic_filter.hpp"

#include <vector>

#include "msec/core/message.hpp"

namespace msec::mqtt {
namespace {

std::vector<std::string_view> split_levels(std::string_view text) {
    std::vector<std::string_view> levels;
    std::size_t start = 0;
    while (true) {
        const auto pos = text.find('/', start);
        if (pos == std::string_view::npos) {
            levels.push_back(text.substr(start));
            return levels;
        }
        levels.push_back(text.substr(start, pos - start));
        start = pos + 1;
    }
}

}  // namespace

Status validate_topic_filter(std::string_view filter) {
    if (filter.empty() || filter.size() > Topic::kMaxLength) {
        return make_error(ErrorCode::InvalidArgument, "topic filter has invalid length");
    }
    if (filter.find('\0') != std::string_view::npos) {
        return make_error(ErrorCode::InvalidArgument, "topic filter contains NUL character");
    }
    const auto levels = split_levels(filter);
    for (std::size_t i = 0; i < levels.size(); ++i) {
        const auto level = levels[i];
        const bool has_plus = level.find('+') != std::string_view::npos;
        const bool has_hash = level.find('#') != std::string_view::npos;
        if (has_plus && level != "+") {
            return make_error(ErrorCode::InvalidArgument, "'+' must occupy a whole level");
        }
        if (has_hash && (level != "#" || i + 1 != levels.size())) {
            return make_error(ErrorCode::InvalidArgument,
                              "'#' must occupy the whole last level");
        }
    }
    return {};
}

bool topic_matches(std::string_view filter, std::string_view topic) {
    if (!topic.empty() && topic.front() == '$' && !filter.empty() &&
        (filter.front() == '+' || filter.front() == '#')) {
        return false;
    }
    const auto f = split_levels(filter);
    const auto t = split_levels(topic);
    for (std::size_t i = 0; i < f.size(); ++i) {
        if (f[i] == "#") {
            return true;  // also matches the parent level ("a/#" matches "a")
        }
        if (i >= t.size()) {
            return false;
        }
        if (f[i] != "+" && f[i] != t[i]) {
            return false;
        }
    }
    return f.size() == t.size();
}

}  // namespace msec::mqtt
