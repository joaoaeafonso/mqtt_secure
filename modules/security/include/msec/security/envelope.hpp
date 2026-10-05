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
///   2      1     version (2)
///   3      1     protection mode      (1 encrypt, 2 auth_only, 3 sign)
///   4      4     key id
///   8      8     sequence number      (monotonic per key, starts at 1)
///   16     8     timestamp, ms since Unix epoch (signed)
///   24     1     nonce length N       (0 for sign: signatures need no nonce)
///   25     N     nonce
///   25+N   …     body:  encrypt    ciphertext || tag
///                       auth_only  payload    || tag
///                       sign       payload    || signature
///
/// Everything before the body, plus the MQTT topic, is authenticated as
/// associated data, so header fields (the mode included) cannot be altered and
/// a valid message cannot be re-published onto a different topic.
struct EnvelopeHeader {
    std::uint8_t version{2};
    PayloadProtection protection{PayloadProtection::Encrypt};
    KeyId key_id{0};
    std::uint64_t sequence{0};
    std::int64_t timestamp_ms{0};
};

struct Envelope {
    EnvelopeHeader header{};
    Bytes nonce{};
    Bytes ciphertext{};  ///< the body (see above)
};

namespace envelope {

inline constexpr std::uint8_t kVersion = 2;
inline constexpr std::size_t kFixedHeaderSize = 25;
inline constexpr std::size_t kMaxNonceSize = 32;

[[nodiscard]] Result<Bytes> serialize(const Envelope& envelope);
[[nodiscard]] Result<Envelope> parse(ByteView data);

/// header || nonce || u16(topic length) || topic
[[nodiscard]] Result<Bytes> associated_data(const EnvelopeHeader& header, ByteView nonce,
                                            std::string_view topic);

}  // namespace envelope
}  // namespace msec::security
