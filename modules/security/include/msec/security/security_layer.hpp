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

struct SecurityConfig {
    KeyId sending_key_id{0};
    std::chrono::milliseconds max_message_age{std::chrono::seconds{60}};
    std::chrono::milliseconds max_clock_skew{std::chrono::seconds{5}};
    std::size_t max_tracked_senders{1024};
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
/// topic binding, freshness and replay protection.
class SecurityLayer final : public ILayer {
    struct PassKey {};

public:
    [[nodiscard]] static Result<std::unique_ptr<SecurityLayer>> create(
        SecurityConfig config, SecurityDependencies deps);

    SecurityLayer(PassKey /*key*/, SecurityConfig config, SecurityDependencies deps);

    [[nodiscard]] std::string_view name() const noexcept override { return "security"; }
    [[nodiscard]] Result<Message> on_outbound(Message message) override;
    [[nodiscard]] Result<Message> on_inbound(Message message) override;

private:
    [[nodiscard]] Status check_freshness(std::int64_t timestamp_ms) const;
    [[nodiscard]] std::int64_t now_ms() const noexcept;

    SecurityConfig config_;
    SecurityDependencies deps_;
    ReplayGuard replay_guard_;
    std::atomic<std::uint64_t> next_sequence_{1};
};

}  // namespace msec::security
