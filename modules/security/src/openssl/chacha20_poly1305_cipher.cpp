#include "msec/security/openssl/chacha20_poly1305_cipher.hpp"

#include "evp_aead.hpp"

namespace msec::security::openssl {
namespace {

constexpr detail::EvpAead kChaCha{.cipher = &EVP_chacha20_poly1305, .name = "ChaCha20-Poly1305"};

}  // namespace

Result<Bytes> ChaCha20Poly1305Cipher::seal(const SecureBuffer& key, ByteView nonce,
                                           ByteView plaintext, ByteView aad) const {
    return detail::evp_seal(kChaCha, key, nonce, plaintext, aad);
}

Result<Bytes> ChaCha20Poly1305Cipher::open(const SecureBuffer& key, ByteView nonce,
                                           ByteView ciphertext_and_tag, ByteView aad) const {
    return detail::evp_open(kChaCha, key, nonce, ciphertext_and_tag, aad);
}

}  // namespace msec::security::openssl
