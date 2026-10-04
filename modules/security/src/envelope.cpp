#include "msec/security/envelope.hpp"

#include <array>
#include <bit>

#include "msec/core/message.hpp"

namespace msec::security::envelope {
namespace {

constexpr std::array kMagic{std::byte{'M'}, std::byte{'S'}};
constexpr std::size_t kVersionOffset = 2;
constexpr std::size_t kKeyIdOffset = 3;
constexpr std::size_t kSequenceOffset = 7;
constexpr std::size_t kTimestampOffset = 15;
constexpr std::size_t kNonceLenOffset = 23;

void write_be(Bytes& out, std::uint64_t value, std::size_t width) {
    for (std::size_t i = width; i-- > 0;) {
        out.push_back(static_cast<std::byte>((value >> (i * 8U)) & 0xFFU));
    }
}

std::uint64_t read_be(ByteView data, std::size_t offset, std::size_t width) {
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < width; ++i) {
        value = (value << 8U) | std::to_integer<std::uint64_t>(data[offset + i]);
    }
    return value;
}

Status write_prefix(Bytes& out, const EnvelopeHeader& header, ByteView nonce) {
    if (nonce.empty() || nonce.size() > kMaxNonceSize) {
        return make_error(ErrorCode::InvalidArgument, "invalid nonce size");
    }
    out.insert(out.end(), kMagic.begin(), kMagic.end());
    write_be(out, header.version, 1);
    write_be(out, header.key_id, 4);
    write_be(out, header.sequence, 8);
    write_be(out, std::bit_cast<std::uint64_t>(header.timestamp_ms), 8);
    write_be(out, nonce.size(), 1);
    out.insert(out.end(), nonce.begin(), nonce.end());
    return {};
}

}  // namespace

Result<Bytes> serialize(const Envelope& envelope) {
    Bytes out;
    out.reserve(kFixedHeaderSize + envelope.nonce.size() + envelope.ciphertext.size());
    if (auto ok = write_prefix(out, envelope.header, envelope.nonce); !ok) {
        return std::unexpected{std::move(ok.error())};
    }
    out.insert(out.end(), envelope.ciphertext.begin(), envelope.ciphertext.end());
    return out;
}

Result<Envelope> parse(ByteView data) {
    if (data.size() < kFixedHeaderSize) {
        return make_error(ErrorCode::MalformedMessage, "envelope truncated");
    }
    if (data[0] != kMagic[0] || data[1] != kMagic[1]) {
        return make_error(ErrorCode::MalformedMessage, "bad envelope magic");
    }
    Envelope env;
    env.header.version = std::to_integer<std::uint8_t>(data[kVersionOffset]);
    if (env.header.version != kVersion) {
        return make_error(ErrorCode::MalformedMessage, "unsupported envelope version");
    }
    env.header.key_id = static_cast<KeyId>(read_be(data, kKeyIdOffset, 4));
    env.header.sequence = read_be(data, kSequenceOffset, 8);
    env.header.timestamp_ms = std::bit_cast<std::int64_t>(read_be(data, kTimestampOffset, 8));
    if (env.header.sequence == 0) {
        return make_error(ErrorCode::MalformedMessage, "sequence number 0 is reserved");
    }

    const auto nonce_len = std::to_integer<std::size_t>(data[kNonceLenOffset]);
    if (nonce_len == 0 || nonce_len > kMaxNonceSize) {
        return make_error(ErrorCode::MalformedMessage, "invalid nonce length");
    }
    if (data.size() <= kFixedHeaderSize + nonce_len) {
        return make_error(ErrorCode::MalformedMessage, "envelope has no ciphertext");
    }
    const auto nonce = data.subspan(kFixedHeaderSize, nonce_len);
    const auto ciphertext = data.subspan(kFixedHeaderSize + nonce_len);
    env.nonce.assign(nonce.begin(), nonce.end());
    env.ciphertext.assign(ciphertext.begin(), ciphertext.end());
    return env;
}

Result<Bytes> associated_data(const EnvelopeHeader& header, ByteView nonce,
                              std::string_view topic) {
    if (topic.size() > Topic::kMaxLength) {
        return make_error(ErrorCode::InvalidArgument, "topic too long");
    }
    Bytes aad;
    aad.reserve(kFixedHeaderSize + nonce.size() + 2 + topic.size());
    if (auto ok = write_prefix(aad, header, nonce); !ok) {
        return std::unexpected{std::move(ok.error())};
    }
    write_be(aad, topic.size(), 2);
    const auto topic_bytes = std::as_bytes(std::span{topic.data(), topic.size()});
    aad.insert(aad.end(), topic_bytes.begin(), topic_bytes.end());
    return aad;
}

}  // namespace msec::security::envelope
