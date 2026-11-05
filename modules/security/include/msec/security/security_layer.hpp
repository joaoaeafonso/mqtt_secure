#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "msec/core/clock.hpp"
#include "msec/core/layer.hpp"
#include "msec/security/aead_cipher.hpp"
#include "msec/security/epoch_store.hpp"
#include "msec/security/key_policy.hpp"
#include "msec/security/key_store.hpp"
#include "msec/security/random_source.hpp"
#include "msec/security/replay_guard.hpp"
#include "msec/security/signature_scheme.hpp"
#include "msec/security/types.hpp"

namespace msec::security {

/// Temporal validity for one flow: messages on topics matching `filter` use
/// these limits instead of the global ones (e.g. a command to an actuator may
/// need a shorter validity than a telemetry reading).
struct FreshnessRule {
    std::string filter;  ///< MQTT topic filter ('+' and '#' allowed)
    std::chrono::milliseconds max_message_age;
    std::chrono::milliseconds max_clock_skew;
};

struct SecurityConfig {
    KeyId sending_key_id{0};
    /// Global temporal validity (Δa, Δs); `freshness_rules` override it per flow.
    std::chrono::milliseconds max_message_age{std::chrono::seconds{60}};
    std::chrono::milliseconds max_clock_skew{std::chrono::seconds{5}};
    /// Checked in order; the first rule whose filter matches the topic wins.
    std::vector<FreshnessRule> freshness_rules{};
    std::size_t max_tracked_senders{1024};
    /// Key ids encode an epoch: epoch = key id / key_epoch_stride (0: no
    /// epochs). Needed by SecurityDependencies::epoch_store.
    std::uint32_t key_epoch_stride{0};

    /// How outbound messages are protected. The mode travels (authenticated)
    /// in the envelope header.
    PayloadProtection protection{PayloadProtection::Encrypt};
    /// Which modes inbound messages may use; nullopt means exactly `protection`.
    /// Anything else is rejected with ProtectionNotAccepted, which stops an
    /// attacker holding a key from downgrading e.g. Encrypt to AuthenticateOnly.
    std::optional<ProtectionSet> accept{};

    /// Ablation switches, intended for benchmarking the cost of each check.
    /// Turning either off weakens the guarantees (stale or replayed messages
    /// are accepted); keep both on in production.
    bool enforce_freshness{true};
    bool enforce_replay_protection{true};
    /// Reject messages whose key may not publish on their topic. Requires
    /// SecurityDependencies::authorization: a check that is on but has no
    /// policy to check against is refused, never silently skipped.
    bool enforce_key_binding{true};
};

struct SecurityDependencies {
    /// AEAD algorithms. A key's algorithm (IKeyStore::algorithm) selects the
    /// cipher among `cipher` and `more_ciphers`, so one receiver can serve
    /// AES-256-GCM and ChaCha20-Poly1305 keys at the same time.
    std::shared_ptr<const IAeadCipher> cipher;
    std::shared_ptr<const IKeyStore> key_store;  ///< AEAD keys (Encrypt, AuthenticateOnly)
    std::shared_ptr<IRandomSource> random;
    std::shared_ptr<const IClock> clock;

    /// Needed only for PayloadProtection::Sign.
    std::shared_ptr<const ISignatureScheme> signer{};
    std::shared_ptr<const IKeyStore> signing_keys{};  ///< private keys, to send
    std::shared_ptr<const IKeyStore> verify_keys{};   ///< public keys, to receive

    /// Optional key → topic authorization (see KeyTopicPolicy).
    std::shared_ptr<const IKeyAuthorization> authorization{};

    std::vector<std::shared_ptr<const IAeadCipher>> more_ciphers{};

    /// Optional: survive receiver restarts without replays (see IEpochStore).
    /// Needs SecurityConfig::key_epoch_stride.
    std::shared_ptr<IEpochStore> epoch_store{};
};

/// End-to-end payload protection, independent of (and in addition to) TLS.
///
/// Outbound: plaintext ─▶ seal (AEAD or signature) ─▶ Envelope
/// Inbound:  Envelope ─▶ parse ─▶ mode policy ─▶ freshness ─▶ verify/decrypt
///                   ─▶ key → topic binding ─▶ epoch floor + replay check ─▶ plaintext
///
/// Guarantees: confidentiality (Encrypt), integrity, sender authenticity (per
/// key; with Sign also towards third parties), topic binding, freshness and
/// replay protection. SecurityConfig can relax most of them individually.
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
    ///
    /// set_protection changes the sending mode and accepts only that mode
    /// from then on; set_accepted widens or narrows the acceptance policy.
    /// Both fail if a mode needs dependencies that are missing (Sign).
    [[nodiscard]] Status set_protection(PayloadProtection protection);
    [[nodiscard]] Status set_accepted(ProtectionSet accepted);
    void set_enforce_freshness(bool on) noexcept;
    void set_enforce_replay_protection(bool on) noexcept;
    /// Fails (and changes nothing) when turning it on without an authorization policy.
    [[nodiscard]] Status set_enforce_key_binding(bool on);
    /// Key rotation: sign/seal outbound messages with another key from now on.
    void set_sending_key(KeyId key_id) noexcept;
    /// Call after revoking a key: frees its replay window. A key id must not
    /// be reused afterwards, or old messages would replay into a fresh window.
    void forget_key(KeyId key_id);
    /// The configuration currently in effect, runtime switches included.
    [[nodiscard]] SecurityConfig config() const;
    /// Oldest key epoch accepted (0 without an epoch store): after a restart,
    /// one more than the newest epoch accepted before it.
    [[nodiscard]] std::uint32_t minimum_epoch() const noexcept { return minimum_epoch_; }

private:
    [[nodiscard]] Status can_send(PayloadProtection mode) const;
    [[nodiscard]] Status can_accept(ProtectionSet modes) const;
    [[nodiscard]] Result<const IAeadCipher*> cipher_for(KeyId key_id) const;
    [[nodiscard]] bool nonce_size_supported(std::size_t size) const noexcept;
    [[nodiscard]] Result<Bytes> protect(PayloadProtection mode, const IAeadCipher* cipher,
                                        const SecureBuffer& key, ByteView nonce, ByteView payload,
                                        Bytes aad) const;
    [[nodiscard]] Result<Bytes> unprotect(PayloadProtection mode, const IAeadCipher* cipher,
                                          const SecureBuffer& key, ByteView nonce, ByteView body,
                                          Bytes aad) const;
    [[nodiscard]] Status check_freshness(std::int64_t timestamp_ms, std::string_view topic) const;
    [[nodiscard]] Status check_epoch(KeyId key_id);
    [[nodiscard]] std::int64_t now_ms() const noexcept;

    SecurityConfig config_;  // static part; the switches below override it
    std::atomic<PayloadProtection> protection_;
    std::atomic<std::uint8_t> accept_;
    std::atomic<bool> enforce_freshness_;
    std::atomic<bool> enforce_replay_protection_;
    std::atomic<bool> enforce_key_binding_;
    std::atomic<KeyId> sending_key_id_;
    SecurityDependencies deps_;
    ReplayGuard replay_guard_;
    std::atomic<std::uint64_t> next_sequence_{1};
    std::uint32_t minimum_epoch_{0};
    std::mutex epoch_mutex_;
    std::optional<std::uint32_t> newest_epoch_;  ///< newest epoch recorded in the store
};

}  // namespace msec::security
