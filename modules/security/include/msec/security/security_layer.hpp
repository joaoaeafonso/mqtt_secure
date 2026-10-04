#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string_view>

#include "msec/core/clock.hpp"
#include "msec/core/layer.hpp"
#include "msec/security/aead_cipher.hpp"
#include "msec/security/key_store.hpp"
#include "msec/security/random_source.hpp"
#include "msec/security/replay_guard.hpp"

namespace msec::security {

enum class PayloadProtection : std::uint8_t {
    Encrypt,           ///< AEAD: confidentiality + integrity (default)
    AuthenticateOnly,  ///< AEAD with empty plaintext (GMAC): integrity, payload stays readable
};

struct SecurityConfig {
    KeyId sending_key_id{0};
    std::chrono::milliseconds max_message_age{std::chrono::seconds{60}};
    std::chrono::milliseconds max_clock_skew{std::chrono::seconds{5}};
    std::size_t max_tracked_senders{1024};

    /// Must match on both ends; a mismatch makes every message fail authentication.
    PayloadProtection protection{PayloadProtection::Encrypt};

    /// Ablation switches, intended for benchmarking the cost of each check.
    /// Turning either off weakens the guarantees (stale or replayed messages
    /// are accepted); keep both on in production.
    /// protection, enforce_freshness and enforce_replay_protection can also be
    /// changed at runtime through the SecurityLayer setters.
    bool enforce_freshness{true};
    bool enforce_replay_protection{true};
};

struct SecurityDependencies {
    std::shared_ptr<const IAeadCipher> cipher;
    std::shared_ptr<const IKeyStore> key_store;
    std::shared_ptr<IRandomSource> random;
    std::shared_ptr<const IClock> clock;
};

/// End-to-end payload protection, independent of (and in addition to) TLS.
///
/// Outbound: plaintext ─▶ AEAD(seal) ─▶ Envelope
/// Inbound:  Envelope ─▶ parse ─▶ freshness ─▶ AEAD(open) ─▶ replay check ─▶ plaintext
///
/// Guarantees: confidentiality, integrity, sender authenticity (per key),
/// topic binding, freshness and replay protection. SecurityConfig can relax
/// confidentiality, freshness and replay protection individually.
class SecurityLayer final : public ILayer {
    struct PassKey {};

public:
    [[nodiscard]] static Result<std::unique_ptr<SecurityLayer>> create(
        SecurityConfig config, SecurityDependencies deps);

    SecurityLayer(PassKey /*key*/, SecurityConfig config, SecurityDependencies deps);

    [[nodiscard]] std::string_view name() const noexcept override { return "security"; }
    [[nodiscard]] Result<Message> on_outbound(Message message) override;
    [[nodiscard]] Result<Message> on_inbound(Message message) override;

    /// Runtime switches: thread-safe, effective from the next message. The
    /// replay window keeps its state across changes, so turning replay
    /// protection back on does not re-open old sequence numbers.
    void set_protection(PayloadProtection protection) noexcept;
    void set_enforce_freshness(bool on) noexcept;
    void set_enforce_replay_protection(bool on) noexcept;
    /// The configuration currently in effect, runtime switches included.
    [[nodiscard]] SecurityConfig config() const noexcept;

private:
    [[nodiscard]] Result<Bytes> protect(PayloadProtection mode, const SecureBuffer& key,
                                        ByteView nonce, ByteView payload, Bytes aad) const;
    [[nodiscard]] Result<Bytes> unprotect(PayloadProtection mode, const SecureBuffer& key,
                                          ByteView nonce, ByteView protected_payload,
                                          Bytes aad) const;
    [[nodiscard]] Status check_freshness(std::int64_t timestamp_ms) const;
    [[nodiscard]] std::int64_t now_ms() const noexcept;

    SecurityConfig config_;  // static part; the switches below override it
    std::atomic<PayloadProtection> protection_;
    std::atomic<bool> enforce_freshness_;
    std::atomic<bool> enforce_replay_protection_;
    SecurityDependencies deps_;
    ReplayGuard replay_guard_;
    std::atomic<std::uint64_t> next_sequence_{1};
};

}  // namespace msec::security
