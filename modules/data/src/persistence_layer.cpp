#include "msec/data/persistence_layer.hpp"

#include <utility>

namespace msec::data {

Result<std::unique_ptr<PersistenceLayer>> PersistenceLayer::create(
    std::shared_ptr<IMessageRepository> repository, std::shared_ptr<const IClock> clock,
    PersistenceConfig config) {
    if (!repository || !clock) {
        return make_error(ErrorCode::InvalidArgument, "persistence layer: missing dependency");
    }
    return std::make_unique<PersistenceLayer>(PassKey{}, std::move(repository), std::move(clock),
                                              config);
}

PersistenceLayer::PersistenceLayer(PassKey /*key*/, std::shared_ptr<IMessageRepository> repository,
                                   std::shared_ptr<const IClock> clock,
                                   PersistenceConfig config) noexcept
    : repository_{std::move(repository)}, clock_{std::move(clock)}, config_{config} {}

Result<Message> PersistenceLayer::on_outbound(Message message) {
    if (!config_.store_outbound) {
        return message;
    }
    return record(std::move(message), Direction::Outbound);
}

Result<Message> PersistenceLayer::on_inbound(Message message) {
    if (!config_.store_inbound) {
        return message;
    }
    return record(std::move(message), Direction::Inbound);
}

Result<Message> PersistenceLayer::record(Message message, Direction direction) {
    if (auto stored = repository_->store(message, direction, clock_->now());
        !stored && config_.fail_on_storage_error) {
        return std::unexpected{std::move(stored.error())};
    }
    return message;
}

}  // namespace msec::data
