// Topic names and filters: validation and matching on arbitrary text. The
// input is split at the first NUL into a filter and a topic.
#include <cstdint>
#include <cstdlib>
#include <string_view>

#include "msec/core/message.hpp"
#include "msec/core/topic_filter.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::string_view input{reinterpret_cast<const char*>(data), size};  // NOLINT
    const auto split = input.find('\0');
    const auto filter = input.substr(0, split);
    const auto topic = split == std::string_view::npos ? input : input.substr(split + 1);

    const auto name = msec::Topic::create(topic);
    if (name && name->str() != topic) {
        std::abort();
    }
    if (name && msec::validate_topic_filter(filter)) {
        (void)msec::topic_matches(filter, name->str());
        // A topic name has no wildcards, so as a filter it must match itself.
        if (!msec::topic_matches(name->str(), name->str())) {
            std::abort();
        }
    }
    return 0;
}
