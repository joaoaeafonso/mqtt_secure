#include "msec/security/openssl/aes_gcm_cipher.hpp"

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <climits>
#include <memory>

namespace msec::security::openssl {
namespace {

constexpr std::size_t kKeySize = 32;
constexpr std::size_t kNonceSize = 12;
constexpr std::size_t kTagSize = 16;

using CipherCtx = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

CipherCtx make_ctx() { return CipherCtx{EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free}; }

// OpenSSL speaks unsigned char; std::byte is layout-compatible.
const unsigned char* as_uchar(ByteView view) noexcept {
    return reinterpret_cast<const unsigned char*>(view.data());  // NOLINT
}
unsigned char* as_uchar(MutableByteView view) noexcept {
    return reinterpret_cast<unsigned char*>(view.data());  // NOLINT
}

bool fits_int(std::size_t n) noexcept { return n <= static_cast<std::size_t>(INT_MAX); }

Status validate(const SecureBuffer& key, ByteView nonce, ByteView data, ByteView aad) {
    if (key.size() != kKeySize) {
        return make_error(ErrorCode::InvalidArgument, "AES-256-GCM requires a 32-byte key");
    }
    if (nonce.size() != kNonceSize) {
        return make_error(ErrorCode::InvalidArgument, "AES-256-GCM requires a 12-byte nonce");
    }
    if (!fits_int(data.size()) || !fits_int(aad.size())) {
        return make_error(ErrorCode::InvalidArgument, "input too large");
    }
    return {};
}

}  // namespace

Result<Bytes> AesGcmCipher::seal(const SecureBuffer& key, ByteView nonce, ByteView plaintext,
                                 ByteView aad) const {
    if (auto ok = validate(key, nonce, plaintext, aad); !ok) {
        return std::unexpected{std::move(ok.error())};
    }
    const auto ctx = make_ctx();
    if (!ctx) {
        return make_error(ErrorCode::CryptoFailure, "EVP_CIPHER_CTX_new failed");
    }

    int len = 0;
    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(kNonceSize),
                            nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, as_uchar(key.view()), as_uchar(nonce)) !=
            1) {
        return make_error(ErrorCode::CryptoFailure, "encrypt init failed");
    }
    if (!aad.empty() && EVP_EncryptUpdate(ctx.get(), nullptr, &len, as_uchar(aad),
                                          static_cast<int>(aad.size())) != 1) {
        return make_error(ErrorCode::CryptoFailure, "AAD processing failed");
    }

    Bytes out(plaintext.size() + kTagSize);
    const MutableByteView body = std::span{out}.first(plaintext.size());
    const MutableByteView tag = std::span{out}.last(kTagSize);
    if (!plaintext.empty() &&
        EVP_EncryptUpdate(ctx.get(), as_uchar(body), &len, as_uchar(plaintext),
                          static_cast<int>(plaintext.size())) != 1) {
        return make_error(ErrorCode::CryptoFailure, "encryption failed");
    }
    // GCM is a stream mode: Final emits no extra bytes; pass the tag area as scratch.
    if (EVP_EncryptFinal_ex(ctx.get(), as_uchar(tag), &len) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(kTagSize),
                            tag.data()) != 1) {
        return make_error(ErrorCode::CryptoFailure, "finalising encryption failed");
    }
    return out;
}

Result<Bytes> AesGcmCipher::open(const SecureBuffer& key, ByteView nonce,
                                 ByteView ciphertext_and_tag, ByteView aad) const {
    if (auto ok = validate(key, nonce, ciphertext_and_tag, aad); !ok) {
        return std::unexpected{std::move(ok.error())};
    }
    if (ciphertext_and_tag.size() < kTagSize) {
        return make_error(ErrorCode::AuthenticationFailed, "ciphertext shorter than tag");
    }
    const ByteView ciphertext = ciphertext_and_tag.first(ciphertext_and_tag.size() - kTagSize);
    std::array<std::byte, kTagSize> tag{};
    std::ranges::copy(ciphertext_and_tag.last(kTagSize), tag.begin());

    const auto ctx = make_ctx();
    if (!ctx) {
        return make_error(ErrorCode::CryptoFailure, "EVP_CIPHER_CTX_new failed");
    }
    int len = 0;
    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(kNonceSize),
                            nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, as_uchar(key.view()), as_uchar(nonce)) !=
            1) {
        return make_error(ErrorCode::CryptoFailure, "decrypt init failed");
    }
    if (!aad.empty() && EVP_DecryptUpdate(ctx.get(), nullptr, &len, as_uchar(aad),
                                          static_cast<int>(aad.size())) != 1) {
        return make_error(ErrorCode::CryptoFailure, "AAD processing failed");
    }

    Bytes out(ciphertext.size());
    if (!ciphertext.empty() &&
        EVP_DecryptUpdate(ctx.get(), as_uchar(MutableByteView{out}), &len, as_uchar(ciphertext),
                          static_cast<int>(ciphertext.size())) != 1) {
        secure_zero(out);
        return make_error(ErrorCode::CryptoFailure, "decryption failed");
    }
    std::array<std::byte, 1> scratch{};  // GCM final writes nothing
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(kTagSize),
                            tag.data()) != 1 ||
        EVP_DecryptFinal_ex(ctx.get(), as_uchar(MutableByteView{scratch}), &len) != 1) {
        secure_zero(out);  // never release unauthenticated plaintext
        return make_error(ErrorCode::AuthenticationFailed, "authentication tag mismatch");
    }
    return out;
}

}  // namespace msec::security::openssl
