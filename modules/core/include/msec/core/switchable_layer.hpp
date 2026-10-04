#pragma once

#include <atomic>
#include <memory>
#include <string>
#include <string_view>

#include "msec/core/error.hpp"
#include "msec/core/layer.hpp"

namespace msec {

/// Decorator that lets any layer be switched off at runtime: while disabled,
/// messages pass through untouched in both directions.
///
/// Pipelines are immutable, so features that must be toggled while traffic
/// flows are built in up front and wrapped in a SwitchableLayer. The switch is
/// a single atomic: it can be flipped from any thread, and a message already
/// inside the layer finishes with the setting it started with.
class SwitchableLayer final : public ILayer {
    struct PassKey {};

public:
    /// `name` overrides the inner layer's name, so the same kind of layer can
    /// appear twice in one pipeline (e.g. persistence above and below security).
    [[nodiscard]] static Result<std::unique_ptr<SwitchableLayer>> create(
        std::unique_ptr<ILayer> inner, bool enabled = true, std::string name = {});

    SwitchableLayer(PassKey /*key*/, std::unique_ptr<ILayer> inner, bool enabled,
                    std::string name) noexcept;

    void set_enabled(bool enabled) noexcept { enabled_.store(enabled, std::memory_order_relaxed); }
    [[nodiscard]] bool enabled() const noexcept { return enabled_.load(std::memory_order_relaxed); }
    [[nodiscard]] ILayer& inner() noexcept { return *inner_; }

    [[nodiscard]] std::string_view name() const noexcept override { return name_; }
    [[nodiscard]] Result<Message> on_outbound(Message message) override;
    [[nodiscard]] Result<Message> on_inbound(Message message) override;

private:
    std::unique_ptr<ILayer> inner_;
    std::atomic<bool> enabled_;
    std::string name_;
};

}  // namespace msec
