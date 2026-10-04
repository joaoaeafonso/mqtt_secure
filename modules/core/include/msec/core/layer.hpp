#pragma once

#include <string_view>

#include "msec/core/error.hpp"
#include "msec/core/message.hpp"

namespace msec {

/// A processing stage in the message pipeline.
///
/// The pipeline is ordered from the APPLICATION side (first) down to the
/// TRANSPORT side (last):
///
///     application ──outbound──▶ L0 ▶ L1 ▶ … ▶ Ln ──▶ MQTT
///     application ◀──inbound─── L0 ◀ L1 ◀ … ◀ Ln ◀── MQTT
///
/// A layer may transform the message (e.g. encrypt), observe it (e.g. store,
/// audit) or reject it by returning an Error, which stops processing.
///
/// Contract for implementers:
///  - must be thread-safe: on_inbound and on_outbound may run concurrently
///  - must not throw; report failure through the Result
///  - must be deterministic given injected dependencies (clock, RNG, …)
class ILayer {
public:
    virtual ~ILayer() = default;
    ILayer(const ILayer&) = delete;
    ILayer& operator=(const ILayer&) = delete;
    ILayer(ILayer&&) = delete;
    ILayer& operator=(ILayer&&) = delete;

    [[nodiscard]] virtual std::string_view name() const noexcept = 0;
    [[nodiscard]] virtual Result<Message> on_outbound(Message message) = 0;
    [[nodiscard]] virtual Result<Message> on_inbound(Message message) = 0;

protected:
    ILayer() = default;
};

}  // namespace msec
