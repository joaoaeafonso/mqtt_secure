#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

#include "msec/core/bytes.hpp"
#include "msec/core/error.hpp"
#include "msec/security/types.hpp"

namespace msec::security {

/// Wire format of a protected payload (all integers big-endian):
///
///   offset size  field
///   0      2     magic "MS"
///   2      1     version (1)
///   3      4     key id
///   7      8     sequence number      (monotonic per key, starts at 1)
///   15     8     timestamp, ms since Unix epoch (signed)
///   23     1     nonce length N
///   24     N     nonce
///   24+N   …     ciphertext || tag
///
/// Everything before the ciphertext, plus the MQTT topic, is authenticated as
/// associated data, so header fields cannot be altered and a valid message
/// cannot be re-published onto a different topic.
struct EnvelopeHeader {
    std::uint8_t version{1};
    KeyId key_id{0};
    std::uint64_t sequence{0};
    std::int64_t timestamp_ms{0};
};

struct Envelope {
    EnvelopeHeader header{};
    Bytes nonce{};
    Bytes ciphertext{};
};

namespace envelope {

inline constexpr std::uint8_t kVersion = 1;
inline constexpr std::size_t kFixedHeaderSize = 24;
inline constexpr std::size_t kMaxNonceSize = 32;

[[nodiscard]] Result<Bytes> serialize(const Envelope& envelope);
[[nodiscard]] Result<Envelope> parse(ByteView data);

/// header || nonce || u16(topic length) || topic
[[nodiscard]] Result<Bytes> associated_data(const EnvelopeHeader& header, ByteView nonce,
                                            std::string_view topic);

}  // namespace envelope
}  // namespace msec::security
