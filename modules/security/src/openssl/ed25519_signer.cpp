#include "msec/security/openssl/ed25519_signer.hpp"

#include <openssl/evp.h>

#include <memory>

namespace msec::security::openssl {
namespace {

constexpr std::size_t kKeySize = 32;
constexpr std::size_t kSignatureSize = 64;

using PKey = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using MdCtx = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

// OpenSSL speaks unsigned char; std::byte is layout-compatible.
const unsigned char* as_uchar(ByteView view) noexcept {
    return reinterpret_cast<const unsigned char*>(view.data());  // NOLINT
}
unsigned char* as_uchar(MutableByteView view) noexcept {
    return reinterpret_cast<unsigned char*>(view.data());  // NOLINT
}

PKey private_pkey(const SecureBuffer& key) {
    return PKey{EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, as_uchar(key.view()),
                                             key.size()),
                &EVP_PKEY_free};
}

}  // namespace

Result<Bytes> Ed25519Signer::sign(const SecureBuffer& private_key, ByteView message) const {
    if (private_key.size() != kKeySize) {
        return make_error(ErrorCode::InvalidArgument, "Ed25519 requires a 32-byte private key");
    }
    const auto pkey = private_pkey(private_key);
    const MdCtx ctx{EVP_MD_CTX_new(), &EVP_MD_CTX_free};
    if (!pkey || !ctx ||
        EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, pkey.get()) != 1) {
        return make_error(ErrorCode::CryptoFailure, "Ed25519 sign init failed");
    }
    Bytes signature(kSignatureSize);
    std::size_t length = signature.size();
    if (EVP_DigestSign(ctx.get(), as_uchar(MutableByteView{signature}), &length,
                       as_uchar(message), message.size()) != 1 ||
        length != kSignatureSize) {
        return make_error(ErrorCode::CryptoFailure, "Ed25519 signing failed");
    }
    return signature;
}

Status Ed25519Signer::verify(ByteView public_key, ByteView message, ByteView signature) const {
    if (public_key.size() != kKeySize || signature.size() != kSignatureSize) {
        return make_error(ErrorCode::AuthenticationFailed, "bad Ed25519 key or signature size");
    }
    const PKey pkey{EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, as_uchar(public_key),
                                                public_key.size()),
                    &EVP_PKEY_free};
    const MdCtx ctx{EVP_MD_CTX_new(), &EVP_MD_CTX_free};
    if (!pkey || !ctx ||
        EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, pkey.get()) != 1) {
        return make_error(ErrorCode::CryptoFailure, "Ed25519 verify init failed");
    }
    if (EVP_DigestVerify(ctx.get(), as_uchar(signature), signature.size(), as_uchar(message),
                         message.size()) != 1) {
        return make_error(ErrorCode::AuthenticationFailed, "signature mismatch");
    }
    return {};
}

Result<Bytes> Ed25519Signer::public_key(const SecureBuffer& private_key) const {
    if (private_key.size() != kKeySize) {
        return make_error(ErrorCode::InvalidArgument, "Ed25519 requires a 32-byte private key");
    }
    const auto pkey = private_pkey(private_key);
    Bytes out(kKeySize);
    std::size_t length = out.size();
    if (!pkey ||
        EVP_PKEY_get_raw_public_key(pkey.get(), as_uchar(MutableByteView{out}), &length) != 1 ||
        length != kKeySize) {
        return make_error(ErrorCode::CryptoFailure, "deriving the Ed25519 public key failed");
    }
    return out;
}

}  // namespace msec::security::openssl
