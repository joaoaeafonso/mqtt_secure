#pragma once

#include "msec/security/aead_cipher.hpp"

namespace msec::security::openssl {

/// ChaCha20-Poly1305 (RFC 8439 §2.8) via OpenSSL 3 EVP. 32-byte key, 12-byte
/// nonce, 16-byte tag: the same sizes as AES-256-GCM, so the envelope format
/// does not change. Constant time in software, so it is the faster choice on
/// processors without AES instructions.
class ChaCha20Poly1305Cipher final : public IAeadCipher {
public:
    [[nodiscard]] std::string_view algorithm() const noexcept override {
        return "ChaCha20-Poly1305";
    }
    [[nodiscard]] AeadAlgorithm id() const noexcept override {
        return AeadAlgorithm::ChaCha20Poly1305;
    }
    [[nodiscard]] std::size_t key_size() const noexcept override { return 32; }
    [[nodiscard]] std::size_t nonce_size() const noexcept override { return 12; }
    [[nodiscard]] std::size_t tag_size() const noexcept override { return 16; }

    [[nodiscard]] Result<Bytes> seal(const SecureBuffer& key, ByteView nonce, ByteView plaintext,
                                     ByteView aad) const override;
    [[nodiscard]] Result<Bytes> open(const SecureBuffer& key, ByteView nonce,
                                     ByteView ciphertext_and_tag, ByteView aad) const override;
};

}  // namespace msec::security::openssl
