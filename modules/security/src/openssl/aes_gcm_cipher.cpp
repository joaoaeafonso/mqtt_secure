#include "msec/security/openssl/aes_gcm_cipher.hpp"

#include "evp_aead.hpp"

namespace msec::security::openssl {
namespace {

constexpr detail::EvpAead kAesGcm{.cipher = &EVP_aes_256_gcm, .name = "AES-256-GCM"};

}  // namespace

Result<Bytes> AesGcmCipher::seal(const SecureBuffer& key, ByteView nonce, ByteView plaintext,
                                 ByteView aad) const {
    return detail::evp_seal(kAesGcm, key, nonce, plaintext, aad);
}

Result<Bytes> AesGcmCipher::open(const SecureBuffer& key, ByteView nonce,
                                 ByteView ciphertext_and_tag, ByteView aad) const {
    return detail::evp_open(kAesGcm, key, nonce, ciphertext_and_tag, aad);
}

}  // namespace msec::security::openssl
