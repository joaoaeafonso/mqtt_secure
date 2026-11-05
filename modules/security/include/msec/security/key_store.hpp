#pragma once

#include <memory>
#include <mutex>
#include <unordered_map>

#include "msec/core/error.hpp"
#include "msec/core/secure_buffer.hpp"
#include "msec/security/types.hpp"

namespace msec::security {

class IKeyStore {
public:
    IKeyStore() = default;
    virtual ~IKeyStore() = default;
    IKeyStore(const IKeyStore&) = delete;
    IKeyStore& operator=(const IKeyStore&) = delete;
    IKeyStore(IKeyStore&&) = delete;
    IKeyStore& operator=(IKeyStore&&) = delete;

    /// Shared ownership lets a key be revoked from the store while an
    /// in-flight operation still holds it safely.
    [[nodiscard]] virtual Result<std::shared_ptr<const SecureBuffer>> find(KeyId id) const = 0;

    /// The AEAD algorithm the key is used with (ignored for signing keys).
    /// The envelope carries only the key id, so the sender and the receiver
    /// agree on the algorithm by agreeing on the key.
    [[nodiscard]] virtual Result<AeadAlgorithm> algorithm(KeyId id) const = 0;
};

/// Volatile key store. Replace with a file/HSM/TPM-backed store for deployment.
class InMemoryKeyStore final : public IKeyStore {
public:
    [[nodiscard]] Status add(KeyId id, SecureBuffer key,
                             AeadAlgorithm algorithm = AeadAlgorithm::Aes256Gcm);
    [[nodiscard]] Status revoke(KeyId id);
    [[nodiscard]] Result<std::shared_ptr<const SecureBuffer>> find(KeyId id) const override;
    [[nodiscard]] Result<AeadAlgorithm> algorithm(KeyId id) const override;

private:
    struct Entry {
        std::shared_ptr<const SecureBuffer> key;
        AeadAlgorithm algorithm;
    };
    mutable std::mutex mutex_;
    std::unordered_map<KeyId, Entry> keys_;
};

}  // namespace msec::security
