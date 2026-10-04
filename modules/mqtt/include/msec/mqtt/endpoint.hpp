#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>

#include "msec/core/logger.hpp"
#include "msec/core/pipeline.hpp"
#include "msec/mqtt/mqtt_client.hpp"

namespace msec::mqtt {

struct EndpointStats {
    std::uint64_t published{0};
    std::uint64_t delivered{0};
    std::uint64_t rejected_inbound{0};   // security-relevant: tampering, replay, …
    std::uint64_t rejected_outbound{0};
};

/// Composition point between an MQTT transport and a layer pipeline.
///
///   publish():  Message ─▶ pipeline.outbound ─▶ client.publish
///   incoming:   client ─▶ pipeline.inbound ─▶ application handler
///
/// Inbound messages that any layer rejects are dropped, logged and counted;
/// they never reach the application.
class Endpoint final {
public:
    using ApplicationHandler = std::function<void(const Message&)>;
    /// Observes inbound messages a layer rejected (topic, reason), e.g. for metrics.
    using RejectionHandler = std::function<void(std::string_view topic, const Error& error)>;

    Endpoint(std::shared_ptr<IMqttClient> client, Pipeline pipeline,
             std::shared_ptr<ILogger> logger);
    ~Endpoint();

    Endpoint(const Endpoint&) = delete;
    Endpoint& operator=(const Endpoint&) = delete;
    Endpoint(Endpoint&&) = delete;
    Endpoint& operator=(Endpoint&&) = delete;

    [[nodiscard]] Status start(const ConnectionOptions& options);
    [[nodiscard]] Status stop();

    [[nodiscard]] Status publish(Message message);
    [[nodiscard]] Status subscribe(std::string_view filter, QoS qos);

    void on_message(ApplicationHandler handler);
    void on_rejected(RejectionHandler handler);
    [[nodiscard]] EndpointStats stats() const noexcept;

private:
    void handle_incoming(Message message);

    std::shared_ptr<IMqttClient> client_;
    Pipeline pipeline_;
    std::shared_ptr<ILogger> logger_;

    std::mutex handler_mutex_;
    ApplicationHandler app_handler_;
    RejectionHandler rejection_handler_;

    std::atomic<std::uint64_t> published_{0};
    std::atomic<std::uint64_t> delivered_{0};
    std::atomic<std::uint64_t> rejected_inbound_{0};
    std::atomic<std::uint64_t> rejected_outbound_{0};
};

}  // namespace msec::mqtt
