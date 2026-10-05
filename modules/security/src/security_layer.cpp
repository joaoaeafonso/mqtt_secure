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
    if (!config.accept) {
        config.accept = ProtectionSet{config.protection};
    }
    auto layer = std::make_unique<SecurityLayer>(PassKey{}, config, std::move(deps));
    if (auto ok = layer->can_send(config.protection); !ok) {
        return std::unexpected{std::move(ok.error())};
    }
    if (auto ok = layer->can_accept(*config.accept); !ok) {
        return std::unexpected{std::move(ok.error())};
    }
    return layer;
}

SecurityLayer::SecurityLayer(PassKey /*key*/, SecurityConfig config, SecurityDependencies deps)
    : config_{config},
      protection_{config.protection},
      accept_{config.accept.value_or(ProtectionSet{config.protection}).bits()},
      enforce_freshness_{config.enforce_freshness},
      enforce_replay_protection_{config.enforce_replay_protection},
      enforce_key_binding_{config.enforce_key_binding},
      sending_key_id_{config.sending_key_id},
      deps_{std::move(deps)},
      replay_guard_{config.max_tracked_senders} {}

Status SecurityLayer::can_send(PayloadProtection mode) const {
    if (mode == PayloadProtection::Sign && (!deps_.signer || !deps_.signing_keys)) {
        return make_error(ErrorCode::InvalidState,
                          "sign mode needs a signature scheme and signing keys");
    }
    return {};
}

Status SecurityLayer::can_accept(ProtectionSet modes) const {
    if (modes.empty()) {
        return make_error(ErrorCode::InvalidArgument, "accept at least one protection mode");
    }
    if (modes.contains(PayloadProtection::Sign) && (!deps_.signer || !deps_.verify_keys)) {
        return make_error(ErrorCode::InvalidState,
                          "accepting signatures needs a signature scheme and public keys");
    }
    return {};
}

Status SecurityLayer::set_protection(PayloadProtection protection) {
    if (auto ok = can_send(protection); !ok) {
        return ok;
    }
    if (auto ok = can_accept(ProtectionSet{protection}); !ok) {
        return ok;
    }
    protection_.store(protection, std::memory_order_relaxed);
    accept_.store(ProtectionSet{protection}.bits(), std::memory_order_relaxed);
    return {};
}

Status SecurityLayer::set_accepted(ProtectionSet accepted) {
    if (auto ok = can_accept(accepted); !ok) {
        return ok;
    }
    accept_.store(accepted.bits(), std::memory_order_relaxed);
    return {};
}

void SecurityLayer::set_enforce_freshness(bool on) noexcept {
    enforce_freshness_.store(on, std::memory_order_relaxed);
}

void SecurityLayer::set_enforce_replay_protection(bool on) noexcept {
    enforce_replay_protection_.store(on, std::memory_order_relaxed);
}

void SecurityLayer::set_enforce_key_binding(bool on) noexcept {
    enforce_key_binding_.store(on, std::memory_order_relaxed);
}

void SecurityLayer::set_sending_key(KeyId key_id) noexcept {
    sending_key_id_.store(key_id, std::memory_order_relaxed);
}

void SecurityLayer::forget_key(KeyId key_id) { replay_guard_.forget(key_id); }

SecurityConfig SecurityLayer::config() const noexcept {
    SecurityConfig current = config_;
    current.sending_key_id = sending_key_id_.load(std::memory_order_relaxed);
    current.protection = protection_.load(std::memory_order_relaxed);
    current.accept = ProtectionSet::from_bits(accept_.load(std::memory_order_relaxed));
    current.enforce_freshness = enforce_freshness_.load(std::memory_order_relaxed);
    current.enforce_replay_protection = enforce_replay_protection_.load(std::memory_order_relaxed);
    current.enforce_key_binding = enforce_key_binding_.load(std::memory_order_relaxed);
    return current;
}

Result<Message> SecurityLayer::on_outbound(Message message) {
    const PayloadProtection mode = protection_.load(std::memory_order_relaxed);
    const bool sign = mode == PayloadProtection::Sign;
    const auto& store = sign ? deps_.signing_keys : deps_.key_store;
    if (!store) {
        return make_error(ErrorCode::InvalidState, "no signing keys configured");
    }
    const KeyId sending_key = sending_key_id_.load(std::memory_order_relaxed);
    auto key = store->find(sending_key);
    if (!key) {
        return std::unexpected{std::move(key.error())};
    }
    const SecureBuffer& key_material = **key;
    const std::size_t expected_size =
        sign ? deps_.signer->private_key_size() : deps_.cipher->key_size();
    if (key_material.size() != expected_size) {
        return make_error(ErrorCode::CryptoFailure, "key size does not match algorithm");
    }

    const std::uint64_t sequence = next_sequence_.fetch_add(1, std::memory_order_relaxed);
    if (sequence == 0) {
        return make_error(ErrorCode::InvalidState, "sequence space exhausted; rotate key");
    }

    Bytes nonce(sign ? 0 : deps_.cipher->nonce_size());
    if (!nonce.empty()) {
        if (auto ok = deps_.random->fill(nonce); !ok) {
            return std::unexpected{std::move(ok.error())};
        }
    }

    const EnvelopeHeader header{.version = envelope::kVersion,
                                .protection = mode,
                                .key_id = sending_key,
                                .sequence = sequence,
                                .timestamp_ms = now_ms()};

    auto aad = envelope::associated_data(header, nonce, message.topic.str());
    if (!aad) {
        return std::unexpected{std::move(aad.error())};
    }
    auto body = protect(mode, key_material, nonce, message.payload, std::move(*aad));
    if (!body) {
        return std::unexpected{std::move(body.error())};
    }

    auto wire = envelope::serialize(
        Envelope{.header = header, .nonce = std::move(nonce), .ciphertext = std::move(*body)});
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
    const PayloadProtection mode = env->header.protection;
    // The mode field is not authenticated yet, but it is part of the AAD: a
    // forged mode can only make verification fail, never weaken it.
    if (!ProtectionSet::from_bits(accept_.load(std::memory_order_relaxed)).contains(mode)) {
        return make_error(ErrorCode::ProtectionNotAccepted,
                          std::format("protection mode '{}' not accepted", to_string(mode)));
    }
    const bool sign = mode == PayloadProtection::Sign;
    if (env->nonce.size() != (sign ? 0 : deps_.cipher->nonce_size())) {
        return make_error(ErrorCode::MalformedMessage, "nonce size does not match algorithm");
    }

    // Cheap checks first: reject stale/future messages before doing crypto.
    if (enforce_freshness_.load(std::memory_order_relaxed)) {
        if (auto fresh = check_freshness(env->header.timestamp_ms); !fresh) {
            return std::unexpected{std::move(fresh.error())};
        }
    }

    const auto& store = sign ? deps_.verify_keys : deps_.key_store;
    auto key = store ? store->find(env->header.key_id)
                     : Result<std::shared_ptr<const SecureBuffer>>{
                           make_error(ErrorCode::NotFound, "no key store")};
    if (!key) {
        return make_error(ErrorCode::AuthenticationFailed, "unknown key id");
    }
    auto aad = envelope::associated_data(env->header, env->nonce, message.topic.str());
    if (!aad) {
        return std::unexpected{std::move(aad.error())};
    }
    auto plaintext = unprotect(mode, **key, env->nonce, env->ciphertext, std::move(*aad));
    if (!plaintext) {
        // Do not distinguish *why* verification failed: avoids an oracle.
        return make_error(ErrorCode::AuthenticationFailed, "message authentication failed");
    }

    // Authentic, but is this key allowed to speak on this topic? Checked only
    // after authentication, so unauthenticated input cannot probe the policy.
    if (deps_.authorization && enforce_key_binding_.load(std::memory_order_relaxed) &&
        !deps_.authorization->may_publish(env->header.key_id, message.topic.str())) {
        secure_zero(*plaintext);
        return make_error(ErrorCode::PermissionDenied,
                          std::format("key {} may not publish on '{}'", env->header.key_id,
                                      message.topic.str()));
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
// Sign:             payload    || sig, where sig = Sign(private key, aad || payload)
Result<Bytes> SecurityLayer::protect(PayloadProtection mode, const SecureBuffer& key,
                                     ByteView nonce, ByteView payload, Bytes aad) const {
    if (mode == PayloadProtection::Encrypt) {
        return deps_.cipher->seal(key, nonce, payload, aad);
    }
    aad.insert(aad.end(), payload.begin(), payload.end());
    auto tag = mode == PayloadProtection::Sign ? deps_.signer->sign(key, aad)
                                               : deps_.cipher->seal(key, nonce, {}, aad);
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
                                       ByteView nonce, ByteView body, Bytes aad) const {
    if (mode == PayloadProtection::Encrypt) {
        return deps_.cipher->open(key, nonce, body, aad);
    }
    const bool sign = mode == PayloadProtection::Sign;
    const auto tag_size = sign ? deps_.signer->signature_size() : deps_.cipher->tag_size();
    if (body.size() < tag_size) {
        return make_error(ErrorCode::AuthenticationFailed, "payload shorter than tag");
    }
    const ByteView payload = body.first(body.size() - tag_size);
    const ByteView tag = body.last(tag_size);
    aad.insert(aad.end(), payload.begin(), payload.end());
    const Status ok = sign ? deps_.signer->verify(key.view(), aad, tag)
                           : deps_.cipher->open(key, nonce, tag, aad).transform([](auto&&) {});
    if (!ok) {
        return std::unexpected{ok.error()};
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
