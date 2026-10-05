#pragma once

#include <cstdint>
#include <initializer_list>
#include <optional>
#include <string_view>

namespace msec::security {

/// Identifies a key (and, by convention, the single sender that owns it).
using KeyId = std::uint32_t;

/// How a payload is protected. The value is carried in the envelope header and
/// authenticated, so a receiver knows which check to run and can refuse modes
/// its policy does not accept (e.g. a downgrade from Encrypt to AuthenticateOnly).
enum class PayloadProtection : std::uint8_t {
    Encrypt = 1,           ///< AEAD: confidentiality + integrity (default)
    AuthenticateOnly = 2,  ///< AEAD with empty plaintext (GMAC): integrity, payload stays readable
    Sign = 3,              ///< digital signature: integrity + proof of origin, payload readable
};

[[nodiscard]] constexpr std::string_view to_string(PayloadProtection p) noexcept {
    switch (p) {
        case PayloadProtection::Encrypt:          return "encrypt";
        case PayloadProtection::AuthenticateOnly: return "auth_only";
        case PayloadProtection::Sign:             return "sign";
    }
    return "unknown";
}

[[nodiscard]] constexpr std::optional<PayloadProtection> protection_from_wire(
    std::uint8_t value) noexcept {
    switch (value) {
        case 1: return PayloadProtection::Encrypt;
        case 2: return PayloadProtection::AuthenticateOnly;
        case 3: return PayloadProtection::Sign;
        default: return std::nullopt;
    }
}

/// A set of protection modes (the receiver's acceptance policy).
class ProtectionSet final {
public:
    constexpr ProtectionSet() noexcept = default;
    constexpr ProtectionSet(std::initializer_list<PayloadProtection> modes) noexcept {
        for (const auto m : modes) {
            bits_ = static_cast<std::uint8_t>(bits_ | bit(m));
        }
    }

    [[nodiscard]] constexpr bool contains(PayloadProtection m) const noexcept {
        return (bits_ & bit(m)) != 0;
    }
    [[nodiscard]] constexpr bool empty() const noexcept { return bits_ == 0; }
    [[nodiscard]] constexpr std::uint8_t bits() const noexcept { return bits_; }
    [[nodiscard]] static constexpr ProtectionSet from_bits(std::uint8_t bits) noexcept {
        ProtectionSet s;
        s.bits_ = bits;
        return s;
    }
    constexpr bool operator==(const ProtectionSet&) const noexcept = default;

private:
    static constexpr std::uint8_t bit(PayloadProtection m) noexcept {
        return static_cast<std::uint8_t>(1U << static_cast<unsigned>(m));
    }
    std::uint8_t bits_{0};
};

}  // namespace msec::security
