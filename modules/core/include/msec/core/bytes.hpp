#pragma once

#include <cstddef>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace msec {

using Bytes = std::vector<std::byte>;
using ByteView = std::span<const std::byte>;
using MutableByteView = std::span<std::byte>;

[[nodiscard]] inline Bytes to_bytes(std::string_view text) {
    const auto view = std::as_bytes(std::span{text.data(), text.size()});
    return {view.begin(), view.end()};
}

[[nodiscard]] inline std::string bytes_to_string(ByteView data) {
    std::string out(data.size(), '\0');
    for (std::size_t i = 0; i < data.size(); ++i) {
        out[i] = static_cast<char>(data[i]);
    }
    return out;
}

}  // namespace msec
