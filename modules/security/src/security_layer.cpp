#include "msec/security/security_layer.hpp"

#include <format>
#include <utility>

#include "msec/security/envelope.hpp"

namespace msec::security {

Result<std::unique_ptr<SecurityLayer>> SecurityLayer::create(SecurityConfig config,
                                                             SecurityDependencies deps) {
    if (!deps.cipher || !deps.key_store || !deps.random || !deps.clock) {
        return make_error(ErrorCode::InvalidArgument, "security layer: missing dependency");
    }
    const auto nonce_size = deps.cipher->nonce_size();
    if (nonce_size == 0 || nonce_size > envelope::kMaxNonceSize) {
        return make_error(ErrorCode::InvalidArgument, "cipher nonce size not supported");
    }
    if (config.max_message_age.count() <= 0 || config.max_clock_skew.count() < 0) {
        return make_error(ErrorCode::InvalidArgument, "invalid freshness configuration");
    }
    return std::make_unique<SecurityLayer>(PassKey{}, config, std::move(deps));
}

SecurityLayer::SecurityLayer(PassKey /*key*/, SecurityConfig config, SecurityDependencies deps)
    : config_{config},
      protection_{config.protection},
      enforce_freshness_{config.enforce_freshness},
      enforce_replay_protection_{config.enforce_replay_protection},
      deps_{std::move(deps)},
      replay_guard_{config.max_tracked_senders} {}

void SecurityLayer::set_protection(PayloadProtection protection) noexcept {
    protection_.store(protection, std::memory_order_relaxed);
}

void SecurityLayer::set_enforce_freshness(bool on) noexcept {
    enforce_freshness_.store(on, std::memory_order_relaxed);
}

void SecurityLayer::set_enforce_replay_protection(bool on) noexcept {
    enforce_replay_protection_.store(on, std::memory_order_relaxed);
}

SecurityConfig SecurityLayer::config() const noexcept {
    SecurityConfig current = config_;
    current.protection = protection_.load(std::memory_order_relaxed);
    current.enforce_freshness = enforce_freshness_.load(std::memory_order_relaxed);
    current.enforce_replay_protection = enforce_replay_protection_.load(std::memory_order_relaxed);
    return current;
}

Result<Message> SecurityLayer::on_outbound(Message message) {
    auto key = deps_.key_store->find(config_.sending_key_id);
    if (!key) {
        return std::unexpected{std::move(key.error())};
    }
    const SecureBuffer& key_material = **key;
    if (key_material.size() != deps_.cipher->key_size()) {
        return make_error(ErrorCode::CryptoFailure, "key size does not match cipher");
    }

    const std::uint64_t sequence = next_sequence_.fetch_add(1, std::memory_order_relaxed);
    if (sequence == 0) {
        return make_error(ErrorCode::InvalidState, "sequence space exhausted; rotate key");
    }

    Bytes nonce(deps_.cipher->nonce_size());
    if (auto ok = deps_.random->fill(nonce); !ok) {
        return std::unexpected{std::move(ok.error())};
    }

    const EnvelopeHeader header{.version = envelope::kVersion,
                                .key_id = config_.sending_key_id,
                                .sequence = sequence,
                                .timestamp_ms = now_ms()};

    auto aad = envelope::associated_data(header, nonce, message.topic.str());
    if (!aad) {
        return std::unexpected{std::move(aad.error())};
    }
    auto ciphertext = protect(protection_.load(std::memory_order_relaxed), key_material, nonce,
                              message.payload, std::move(*aad));
    if (!ciphertext) {
        return std::unexpected{std::move(ciphertext.error())};
    }

    auto wire = envelope::serialize(
        Envelope{.header = header, .nonce = std::move(nonce), .ciphertext = std::move(*ciphertext)});
    if (!wire) {
        return std::unexpected{std::move(wire.error())};
    }
    secure_zero(message.payload);
    message.payload = std::move(*wire);
    return message;
}

Result<Message> SecurityLayer::on_inbound(Message message) {
    auto env = envelope::parse(message.payload);
    if (!env) {
        return std::unexpected{std::move(env.error())};
    }
    if (env->nonce.size() != deps_.cipher->nonce_size()) {
        return make_error(ErrorCode::MalformedMessage, "nonce size does not match cipher");
    }

    // Cheap checks first: reject stale/future messages before doing crypto.
    if (enforce_freshness_.load(std::memory_order_relaxed)) {
        if (auto fresh = check_freshness(env->header.timestamp_ms); !fresh) {
            return std::unexpected{std::move(fresh.error())};
        }
    }

    auto key = deps_.key_store->find(env->header.key_id);
    if (!key) {
        return make_error(ErrorCode::AuthenticationFailed, "unknown key id");
    }
    auto aad = envelope::associated_data(env->header, env->nonce, message.topic.str());
    if (!aad) {
        return std::unexpected{std::move(aad.error())};
    }
    auto plaintext = unprotect(protection_.load(std::memory_order_relaxed), **key, env->nonce,
                               env->ciphertext, std::move(*aad));
    if (!plaintext) {
        // Do not distinguish *why* decryption failed: avoids an oracle.
        return make_error(ErrorCode::AuthenticationFailed, "message authentication failed");
    }

    // Only authenticated messages may advance the replay window.
    if (enforce_replay_protection_.load(std::memory_order_relaxed)) {
        if (auto unique =
                replay_guard_.check_and_record(env->header.key_id, env->header.sequence);
            !unique) {
            secure_zero(*plaintext);
            return std::unexpected{std::move(unique.error())};
        }
    }

    message.payload = std::move(*plaintext);
    return message;
}

// Encrypt:          ciphertext || tag  = AEAD(payload, aad)
// AuthenticateOnly: payload    || tag, where tag = AEAD(empty, aad || payload)
Result<Bytes> SecurityLayer::protect(PayloadProtection mode, const SecureBuffer& key,
                                     ByteView nonce, ByteView payload, Bytes aad) const {
    if (mode == PayloadProtection::Encrypt) {
        return deps_.cipher->seal(key, nonce, payload, aad);
    }
    aad.insert(aad.end(), payload.begin(), payload.end());
    auto tag = deps_.cipher->seal(key, nonce, {}, aad);
    if (!tag) {
        return tag;
    }
    Bytes out;
    out.reserve(payload.size() + tag->size());
    out.insert(out.end(), payload.begin(), payload.end());
    out.insert(out.end(), tag->begin(), tag->end());
    return out;
}

Result<Bytes> SecurityLayer::unprotect(PayloadProtection mode, const SecureBuffer& key,
                                       ByteView nonce, ByteView protected_payload,
                                       Bytes aad) const {
    if (mode == PayloadProtection::Encrypt) {
        return deps_.cipher->open(key, nonce, protected_payload, aad);
    }
    const auto tag_size = deps_.cipher->tag_size();
    if (protected_payload.size() < tag_size) {
        return make_error(ErrorCode::AuthenticationFailed, "payload shorter than tag");
    }
    const ByteView payload = protected_payload.first(protected_payload.size() - tag_size);
    aad.insert(aad.end(), payload.begin(), payload.end());
    if (auto ok = deps_.cipher->open(key, nonce, protected_payload.last(tag_size), aad); !ok) {
        return std::unexpected{std::move(ok.error())};
    }
    return Bytes(payload.begin(), payload.end());
}

Status SecurityLayer::check_freshness(std::int64_t timestamp_ms) const {
    // Bounds are computed from `now` (never from the untrusted timestamp) to
    // rule out signed overflow on attacker-controlled input.
    const std::int64_t now = now_ms();
    if (timestamp_ms < now - config_.max_message_age.count()) {
        return make_error(ErrorCode::MessageExpired, "message too old");
    }
    if (timestamp_ms > now + config_.max_clock_skew.count()) {
        return make_error(ErrorCode::MessageExpired, "message timestamp is in the future");
    }
    return {};
}

std::int64_t SecurityLayer::now_ms() const noexcept {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               deps_.clock->now().time_since_epoch())
        .count();
}

}  // namespace msec::security
