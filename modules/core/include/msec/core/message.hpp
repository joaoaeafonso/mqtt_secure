#pragma once

#include <compare>
#include <cstdint>
#include <string>
#include <string_view>

#include "msec/core/bytes.hpp"
#include "msec/core/error.hpp"

namespace msec {

enum class QoS : std::uint8_t {
    AtMostOnce = 0,
    AtLeastOnce = 1,
    ExactlyOnce = 2,
};

/// A validated MQTT topic *name* (what you publish to; never contains wildcards).
/// Invalid topics cannot exist: the only way to obtain a Topic is Topic::create().
class Topic final {
public:
    static constexpr std::size_t kMaxLength = 65'535;  // MQTT spec, 2-byte length prefix

    [[nodiscard]] static Result<Topic> create(std::string_view name);

    [[nodiscard]] const std::string& str() const noexcept { return value_; }

    auto operator<=>(const Topic&) const = default;

private:
    explicit Topic(std::string value) : value_{std::move(value)} {}
    std::string value_;
};

/// The unit of data that flows through the layer pipeline.
struct Message {
    Topic topic;
    Bytes payload{};
    QoS qos{QoS::AtLeastOnce};
    bool retain{false};
};

}  // namespace msec
