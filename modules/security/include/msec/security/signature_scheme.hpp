#pragma once

#include <cstddef>
#include <string_view>

#include "msec/core/bytes.hpp"
#include "msec/core/error.hpp"
#include "msec/core/secure_buffer.hpp"

namespace msec::security {

/// Digital signatures (Ed25519, ECDSA, …). Unlike an AEAD tag, a signature can
/// only be produced with the sender's private key but checked by anyone with
/// the public key, so the receiver can verify a message without being able
/// to forge one: proof of origin (non-repudiation) instead of a shared secret.
class ISignatureScheme {
public:
    ISignatureScheme() = default;
    virtual ~ISignatureScheme() = default;
    ISignatureScheme(const ISignatureScheme&) = delete;
    ISignatureScheme& operator=(const ISignatureScheme&) = delete;
    ISignatureScheme(ISignatureScheme&&) = delete;
    ISignatureScheme& operator=(ISignatureScheme&&) = delete;

    [[nodiscard]] virtual std::string_view algorithm() const noexcept = 0;
    [[nodiscard]] virtual std::size_t private_key_size() const noexcept = 0;
    [[nodiscard]] virtual std::size_t public_key_size() const noexcept = 0;
    [[nodiscard]] virtual std::size_t signature_size() const noexcept = 0;

    [[nodiscard]] virtual Result<Bytes> sign(const SecureBuffer& private_key,
                                             ByteView message) const = 0;

    /// AuthenticationFailed if the signature does not match.
    [[nodiscard]] virtual Status verify(ByteView public_key, ByteView message,
                                        ByteView signature) const = 0;

    /// The public key belonging to a private key.
    [[nodiscard]] virtual Result<Bytes> public_key(const SecureBuffer& private_key) const = 0;
};

}  // namespace msec::security
