#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "msec/mqtt/mqtt_client.hpp"

namespace msec::mqtt {

class LoopbackClient;

/// In-process broker for tests and demos: synchronous, lossless, no network.
/// Lets the whole stack (pipeline + security + storage) be exercised
/// deterministically without a running Mosquitto instance.
class LoopbackBroker final : public std::enable_shared_from_this<LoopbackBroker> {
public:
    [[nodiscard]] static std::shared_ptr<LoopbackBroker> create();

    /// Routes a message to every matching subscriber (outside the lock).
    void route(const Message& message);

    void add_subscription(const std::shared_ptr<LoopbackClient>& client, std::string filter);
    void remove_subscription(const LoopbackClient* client, std::string_view filter);
    void remove_client(const LoopbackClient* client);

private:
    struct PassKey {};

public:
    explicit LoopbackBroker(PassKey /*key*/) {}

private:
    struct Subscription {
        std::weak_ptr<LoopbackClient> client;
        const LoopbackClient* identity;
        std::string filter;
    };
    std::mutex mutex_;
    std::vector<Subscription> subscriptions_;
};

class LoopbackClient final : public IMqttClient,
                             public std::enable_shared_from_this<LoopbackClient> {
    struct PassKey {};

public:
    [[nodiscard]] static std::shared_ptr<LoopbackClient> create(
        std::shared_ptr<LoopbackBroker> broker);

    LoopbackClient(PassKey /*key*/, std::shared_ptr<LoopbackBroker> broker);
    ~LoopbackClient() override;

    [[nodiscard]] Status connect(const ConnectionOptions& options) override;
    [[nodiscard]] Status disconnect() override;
    [[nodiscard]] bool is_connected() const noexcept override;
    [[nodiscard]] Status publish(const Message& message) override;
    [[nodiscard]] Status subscribe(std::string_view filter, QoS qos) override;
    [[nodiscard]] Status unsubscribe(std::string_view filter) override;
    void set_message_handler(MessageHandler handler) override;

    /// Called by the broker.
    void deliver(Message message);

private:
    std::shared_ptr<LoopbackBroker> broker_;
    std::atomic<bool> connected_{false};
    std::mutex handler_mutex_;
    std::shared_ptr<const MessageHandler> handler_;
};

}  // namespace msec::mqtt
