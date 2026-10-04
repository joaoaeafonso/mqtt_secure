#pragma once

#include <memory>

#include "msec/core/clock.hpp"
#include "msec/core/layer.hpp"
#include "msec/data/message_repository.hpp"

namespace msec::data {

struct PersistenceConfig {
    bool store_inbound{true};
    bool store_outbound{false};
    /// If false, a storage failure is logged by the caller but the message
    /// still flows; if true, the message is rejected (audit-critical systems).
    bool fail_on_storage_error{false};
};

/// Pass-through layer that records messages.
///
/// Its position in the pipeline decides WHAT is stored:
///   [persistence, security]  → plaintext stored (after decryption)
///   [security, persistence]  → ciphertext envelopes stored (encrypted at rest)
class PersistenceLayer final : public ILayer {
    struct PassKey {};

public:
    [[nodiscard]] static Result<std::unique_ptr<PersistenceLayer>> create(
        std::shared_ptr<IMessageRepository> repository, std::shared_ptr<const IClock> clock,
        PersistenceConfig config = {});

    PersistenceLayer(PassKey /*key*/, std::shared_ptr<IMessageRepository> repository,
                     std::shared_ptr<const IClock> clock, PersistenceConfig config) noexcept;

    [[nodiscard]] std::string_view name() const noexcept override { return "persistence"; }
    [[nodiscard]] Result<Message> on_outbound(Message message) override;
    [[nodiscard]] Result<Message> on_inbound(Message message) override;

private:
    [[nodiscard]] Result<Message> record(Message message, Direction direction);

    std::shared_ptr<IMessageRepository> repository_;
    std::shared_ptr<const IClock> clock_;
    PersistenceConfig config_;
};

}  // namespace msec::data
