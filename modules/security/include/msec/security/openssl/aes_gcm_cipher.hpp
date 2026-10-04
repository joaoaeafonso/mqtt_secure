#pragma once

#include "msec/security/aead_cipher.hpp"

namespace msec::security::openssl {

/// AES-256-GCM via OpenSSL 3 EVP. 32-byte key, 12-byte nonce, 16-byte tag.
class AesGcmCipher final : public IAeadCipher {
public:
    [[nodiscard]] std::string_view algorithm() const noexcept override { return "AES-256-GCM"; }
    [[nodiscard]] std::size_t key_size() const noexcept override { return 32; }
    [[nodiscard]] std::size_t nonce_size() const noexcept override { return 12; }
    [[nodiscard]] std::size_t tag_size() const noexcept override { return 16; }

    [[nodiscard]] Result<Bytes> seal(const SecureBuffer& key, ByteView nonce, ByteView plaintext,
                                     ByteView aad) const override;
    [[nodiscard]] Result<Bytes> open(const SecureBuffer& key, ByteView nonce,
                                     ByteView ciphertext_and_tag, ByteView aad) const override;
};

}  // namespace msec::security::openssl
