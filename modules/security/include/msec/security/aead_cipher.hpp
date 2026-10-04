#pragma once

#include <cstddef>
#include <string_view>

#include "msec/core/bytes.hpp"
#include "msec/core/error.hpp"
#include "msec/core/secure_buffer.hpp"

namespace msec::security {

/// Authenticated Encryption with Associated Data (AES-GCM, ChaCha20-Poly1305, …).
/// Provides confidentiality of the plaintext and integrity/authenticity of
/// both the plaintext and the associated data.
class IAeadCipher {
public:
    IAeadCipher() = default;
    virtual ~IAeadCipher() = default;
    IAeadCipher(const IAeadCipher&) = delete;
    IAeadCipher& operator=(const IAeadCipher&) = delete;
    IAeadCipher(IAeadCipher&&) = delete;
    IAeadCipher& operator=(IAeadCipher&&) = delete;

    [[nodiscard]] virtual std::string_view algorithm() const noexcept = 0;
    [[nodiscard]] virtual std::size_t key_size() const noexcept = 0;
    [[nodiscard]] virtual std::size_t nonce_size() const noexcept = 0;
    [[nodiscard]] virtual std::size_t tag_size() const noexcept = 0;

    /// Returns ciphertext || tag.
    [[nodiscard]] virtual Result<Bytes> seal(const SecureBuffer& key, ByteView nonce,
                                             ByteView plaintext, ByteView aad) const = 0;

    /// Returns plaintext, or AuthenticationFailed if anything was tampered with.
    [[nodiscard]] virtual Result<Bytes> open(const SecureBuffer& key, ByteView nonce,
                                             ByteView ciphertext_and_tag,
                                             ByteView aad) const = 0;
};

}  // namespace msec::security
