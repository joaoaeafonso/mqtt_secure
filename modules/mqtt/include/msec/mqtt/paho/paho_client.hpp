#pragma once

#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>

#include "msec/mqtt/mqtt_client.hpp"

namespace mqtt {
class async_client;  // Eclipse Paho C++, kept out of this header
}

namespace msec::mqtt::paho {

/// IMqttClient over Eclipse Paho C++ (TCP or TLS to a real broker).
///
/// Connects to ConnectionOptions::broker_uri ("tcp://host:1883",
/// "ssl://host:8883"); TlsOptions, username/password, keep-alive and
/// clean-session are mapped onto Paho's options. Each call blocks until the
/// broker acknowledges it (or `timeout` expires). Incoming messages are
/// delivered on Paho's callback thread; messages whose topic is not a valid
/// topic name are dropped.
class PahoClient final : public IMqttClient {
public:
    explicit PahoClient(std::chrono::milliseconds timeout = std::chrono::seconds{10});
    ~PahoClient() override;

    [[nodiscard]] Status connect(const ConnectionOptions& options) override;
    [[nodiscard]] Status disconnect() override;
    [[nodiscard]] bool is_connected() const noexcept override;
    [[nodiscard]] Status publish(const Message& message) override;
    [[nodiscard]] Status subscribe(std::string_view filter, QoS qos) override;
    [[nodiscard]] Status unsubscribe(std::string_view filter) override;
    void set_message_handler(MessageHandler handler) override;

private:
    void on_message(const std::string& topic, ByteView payload, QoS qos, bool retain);

    std::chrono::milliseconds timeout_;
    std::unique_ptr<::mqtt::async_client> client_;
    std::mutex handler_mutex_;
    std::shared_ptr<const MessageHandler> handler_;
};

}  // namespace msec::mqtt::paho
