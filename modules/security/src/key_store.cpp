#include "msec/security/key_store.hpp"

#include <format>
#include <utility>

namespace msec::security {

Status InMemoryKeyStore::add(KeyId id, SecureBuffer key) {
    if (key.empty()) {
        return make_error(ErrorCode::InvalidArgument, "key must not be empty");
    }
    const std::scoped_lock lock{mutex_};
    // Never silently overwrite key material; rotation must be explicit (revoke + add).
    if (keys_.contains(id)) {
        return make_error(ErrorCode::InvalidState, std::format("key {} already exists", id));
    }
    keys_.emplace(id, std::make_shared<const SecureBuffer>(std::move(key)));
    return {};
}

Status InMemoryKeyStore::revoke(KeyId id) {
    const std::scoped_lock lock{mutex_};
    if (keys_.erase(id) == 0) {
        return make_error(ErrorCode::NotFound, std::format("key {} not found", id));
    }
    return {};
}

Result<std::shared_ptr<const SecureBuffer>> InMemoryKeyStore::find(KeyId id) const {
    const std::scoped_lock lock{mutex_};
    const auto it = keys_.find(id);
    if (it == keys_.end()) {
        return make_error(ErrorCode::NotFound, std::format("key {} not found", id));
    }
    return it->second;
}

}  // namespace msec::security
