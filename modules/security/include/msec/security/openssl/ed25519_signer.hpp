#pragma once

#include "msec/security/signature_scheme.hpp"

namespace msec::security::openssl {

/// Ed25519 (RFC 8032) via OpenSSL 3. Keys are raw: 32-byte private seed,
/// 32-byte public key; signatures are 64 bytes and deterministic.
class Ed25519Signer final : public ISignatureScheme {
public:
    [[nodiscard]] std::string_view algorithm() const noexcept override { return "Ed25519"; }
    [[nodiscard]] std::size_t private_key_size() const noexcept override { return 32; }
    [[nodiscard]] std::size_t public_key_size() const noexcept override { return 32; }
    [[nodiscard]] std::size_t signature_size() const noexcept override { return 64; }

    [[nodiscard]] Result<Bytes> sign(const SecureBuffer& private_key,
                                     ByteView message) const override;
    [[nodiscard]] Status verify(ByteView public_key, ByteView message,
                                ByteView signature) const override;
    [[nodiscard]] Result<Bytes> public_key(const SecureBuffer& private_key) const override;
};

}  // namespace msec::security::openssl
