#pragma once

#include <memory>
#include <string_view>
#include <vector>

#include "msec/core/error.hpp"
#include "msec/core/layer.hpp"
#include "msec/core/message.hpp"

namespace msec {

/// Ordered, immutable chain of layers (see ILayer for direction semantics).
/// Built once through Pipeline::Builder; its structure never changes afterwards,
/// which keeps concurrent use free of locking at the pipeline level.
class Pipeline final {
public:
    class Builder final {
    public:
        /// Appends a layer below the previously added ones (closer to the transport).
        Builder& add(std::unique_ptr<ILayer> layer);
        [[nodiscard]] Result<Pipeline> build();

    private:
        std::vector<std::unique_ptr<ILayer>> layers_;
        bool rejected_null_{false};
    };

    Pipeline(Pipeline&&) noexcept = default;
    Pipeline& operator=(Pipeline&&) noexcept = default;
    Pipeline(const Pipeline&) = delete;
    Pipeline& operator=(const Pipeline&) = delete;
    ~Pipeline() = default;

    [[nodiscard]] Result<Message> process_outbound(Message message);
    [[nodiscard]] Result<Message> process_inbound(Message message);
    [[nodiscard]] std::vector<std::string_view> layer_names() const;

private:
    explicit Pipeline(std::vector<std::unique_ptr<ILayer>> layers) noexcept;
    std::vector<std::unique_ptr<ILayer>> layers_;
};

}  // namespace msec
