#pragma once

#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>

#include "msec/mqtt/mqtt_client.hpp"

namespace mqtt {  // Eclipse Paho C++, kept out of this header
class async_client;
class token;
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
///
/// connect() may be called again at any time to switch broker, transport or
/// credentials: the current connection is closed first. Lifecycle calls are
/// serialized by a mutex. With TLS and verify_peer, the broker certificate must
/// chain to ca_file and match the host name in broker_uri.
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

    void close_locked();
    /// Waits for `token`, then parks it in last_token_ (see there).
    [[nodiscard]] bool wait(std::shared_ptr<::mqtt::token> token);

    std::chrono::milliseconds timeout_;
    mutable std::mutex client_mutex_;
    std::unique_ptr<::mqtt::async_client> client_;
    // Paho C++ 1.2 wakes a token's waiter before its callback thread is done
    // with the token (it still signals and unregisters it, under Paho's global
    // mutex), so dropping the token right after wait_for() is a use-after-free
    // race. The last waited-on token is kept until the next Paho call, which
    // takes that mutex and therefore returns only after the callback has left;
    // close_locked() releases it after destroying the client, which does too.
    std::shared_ptr<::mqtt::token> last_token_;
    std::mutex handler_mutex_;
    std::shared_ptr<const MessageHandler> handler_;
};

}  // namespace msec::mqtt::paho
