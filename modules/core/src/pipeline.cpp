#include "msec/core/pipeline.hpp"

#include <format>
#include <ranges>
#include <set>
#include <string>
#include <utility>

namespace msec {
namespace {

Error annotate(std::string_view layer_name, Error error) {
    error.message = std::format("[{}] {}", layer_name, error.message);
    return error;
}

}  // namespace

Pipeline::Builder& Pipeline::Builder::add(std::unique_ptr<ILayer> layer) {
    if (!layer) {
        rejected_null_ = true;
        return *this;
    }
    layers_.push_back(std::move(layer));
    return *this;
}

Result<Pipeline> Pipeline::Builder::build() {
    if (rejected_null_) {
        return make_error(ErrorCode::InvalidArgument, "a null layer was added to the pipeline");
    }
    std::set<std::string_view> names;
    for (const auto& layer : layers_) {
        if (!names.insert(layer->name()).second) {
            return make_error(ErrorCode::InvalidArgument,
                              std::format("duplicate layer name '{}'", layer->name()));
        }
    }
    return Pipeline{std::exchange(layers_, {})};
}

Pipeline::Pipeline(std::vector<std::unique_ptr<ILayer>> layers) noexcept
    : layers_{std::move(layers)} {}

Result<Message> Pipeline::process_outbound(Message message) {
    for (const auto& layer : layers_) {
        auto result = layer->on_outbound(std::move(message));
        if (!result) {
            return std::unexpected{annotate(layer->name(), std::move(result.error()))};
        }
        message = std::move(*result);
    }
    return message;
}

Result<Message> Pipeline::process_inbound(Message message) {
    for (const auto& layer : std::views::reverse(layers_)) {
        auto result = layer->on_inbound(std::move(message));
        if (!result) {
            return std::unexpected{annotate(layer->name(), std::move(result.error()))};
        }
        message = std::move(*result);
    }
    return message;
}

std::vector<std::string_view> Pipeline::layer_names() const {
    std::vector<std::string_view> names;
    names.reserve(layers_.size());
    for (const auto& layer : layers_) {
        names.push_back(layer->name());
    }
    return names;
}

}  // namespace msec
