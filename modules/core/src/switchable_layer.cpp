#include "msec/core/switchable_layer.hpp"

#include <utility>

namespace msec {

Result<std::unique_ptr<SwitchableLayer>> SwitchableLayer::create(std::unique_ptr<ILayer> inner,
                                                                 bool enabled, std::string name) {
    if (!inner) {
        return make_error(ErrorCode::InvalidArgument, "switchable layer: inner layer is null");
    }
    if (name.empty()) {
        name = std::string{inner->name()};
    }
    return std::make_unique<SwitchableLayer>(PassKey{}, std::move(inner), enabled,
                                             std::move(name));
}

SwitchableLayer::SwitchableLayer(PassKey /*key*/, std::unique_ptr<ILayer> inner, bool enabled,
                                 std::string name) noexcept
    : inner_{std::move(inner)}, enabled_{enabled}, name_{std::move(name)} {}

Result<Message> SwitchableLayer::on_outbound(Message message) {
    if (!enabled()) {
        return message;
    }
    return inner_->on_outbound(std::move(message));
}

Result<Message> SwitchableLayer::on_inbound(Message message) {
    if (!enabled()) {
        return message;
    }
    return inner_->on_inbound(std::move(message));
}

}  // namespace msec
