#include "msec/mqtt/endpoint.hpp"

#include <format>
#include <utility>

namespace msec::mqtt {
namespace {
constexpr std::string_view kComponent = "endpoint";
}

Endpoint::Endpoint(std::shared_ptr<IMqttClient> client, Pipeline pipeline,
                   std::shared_ptr<ILogger> logger)
    : client_{std::move(client)},
      pipeline_{std::move(pipeline)},
      logger_{logger ? std::move(logger) : std::make_shared<NullLogger>()} {}

Endpoint::~Endpoint() {
    if (client_) {
        // Detach before members are destroyed so no callback can observe a dead Endpoint.
        client_->set_message_handler({});
        if (client_->is_connected()) {
            (void)client_->disconnect();
        }
    }
}

Status Endpoint::start(const ConnectionOptions& options) {
    if (!client_) {
        return make_error(ErrorCode::InvalidState, "endpoint has no MQTT client");
    }
    client_->set_message_handler([this](Message m) { handle_incoming(std::move(m)); });
    return client_->connect(options);
}

Status Endpoint::stop() {
    client_->set_message_handler({});
    return client_->disconnect();
}

Status Endpoint::publish(Message message) {
    auto processed = pipeline_.process_outbound(std::move(message));
    if (!processed) {
        rejected_outbound_.fetch_add(1, std::memory_order_relaxed);
        logger_->log(LogLevel::Error, kComponent,
                     std::format("outbound rejected: {}", processed.error().message));
        return std::unexpected{std::move(processed.error())};
    }
    if (auto sent = client_->publish(*processed); !sent) {
        return sent;
    }
    published_.fetch_add(1, std::memory_order_relaxed);
    return {};
}

Status Endpoint::subscribe(std::string_view filter, QoS qos) {
    return client_->subscribe(filter, qos);
}

void Endpoint::on_message(ApplicationHandler handler) {
    const std::scoped_lock lock{handler_mutex_};
    app_handler_ = std::move(handler);
}

void Endpoint::on_rejected(RejectionHandler handler) {
    const std::scoped_lock lock{handler_mutex_};
    rejection_handler_ = std::move(handler);
}

EndpointStats Endpoint::stats() const noexcept {
    return {published_.load(), delivered_.load(), rejected_inbound_.load(),
            rejected_outbound_.load()};
}

void Endpoint::handle_incoming(Message message) {
    Rejected info{.topic = message.topic.str(),
                  .retained = message.retain,
                  .duplicate = message.duplicate};
    auto processed = pipeline_.process_inbound(std::move(message));
    if (!processed) {
        rejected_inbound_.fetch_add(1, std::memory_order_relaxed);
        logger_->log(LogLevel::Warn, kComponent,
                     std::format("inbound on '{}' rejected ({}): {}", info.topic,
                                 to_string(processed.error().code), processed.error().message));
        RejectionHandler observer;
        {
            const std::scoped_lock lock{handler_mutex_};
            observer = rejection_handler_;
        }
        if (observer) {
            observer(info, processed.error());
        }
        return;
    }
    ApplicationHandler handler;
    {
        const std::scoped_lock lock{handler_mutex_};
        handler = app_handler_;
    }
    if (handler) {
        handler(*processed);
    }
    delivered_.fetch_add(1, std::memory_order_relaxed);
}

}  // namespace msec::mqtt
