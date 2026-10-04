#include "msec/core/message.hpp"

#include <string>

namespace msec {

Result<Topic> Topic::create(std::string_view name) {
    if (name.empty()) {
        return make_error(ErrorCode::InvalidArgument, "topic must not be empty");
    }
    if (name.size() > kMaxLength) {
        return make_error(ErrorCode::InvalidArgument, "topic exceeds 65535 bytes");
    }
    for (const char c : name) {
        if (c == '\0') {
            return make_error(ErrorCode::InvalidArgument, "topic contains NUL character");
        }
        if (c == '+' || c == '#') {
            return make_error(ErrorCode::InvalidArgument,
                              "topic name must not contain wildcards ('+' or '#')");
        }
    }
    // TODO(validation): enforce well-formed UTF-8 as required by MQTT 3.1.1 §1.5.3.
    return Topic{std::string{name}};
}

}  // namespace msec
