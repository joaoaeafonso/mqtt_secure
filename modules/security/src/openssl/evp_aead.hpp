#pragma once

// Private helper: one-shot AEAD seal/open over any OpenSSL EVP AEAD cipher with
// a 12-byte nonce and a 16-byte tag (AES-256-GCM, ChaCha20-Poly1305).

#include <openssl/evp.h>

#include <string_view>

#include "msec/core/bytes.hpp"
#include "msec/core/error.hpp"
#include "msec/core/secure_buffer.hpp"

namespace msec::security::openssl::detail {

struct EvpAead {
    const EVP_CIPHER* (*cipher)();  ///< e.g. EVP_aes_256_gcm
    std::string_view name;          ///< for error messages
};

inline constexpr std::size_t kAeadKeySize = 32;
inline constexpr std::size_t kAeadNonceSize = 12;
inline constexpr std::size_t kAeadTagSize = 16;

[[nodiscard]] Result<Bytes> evp_seal(const EvpAead& aead, const SecureBuffer& key, ByteView nonce,
                                     ByteView plaintext, ByteView aad);
[[nodiscard]] Result<Bytes> evp_open(const EvpAead& aead, const SecureBuffer& key, ByteView nonce,
                                     ByteView ciphertext_and_tag, ByteView aad);

}  // namespace msec::security::openssl::detail
