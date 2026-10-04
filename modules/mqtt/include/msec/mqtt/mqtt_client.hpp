#pragma once

#include <functional>
#include <string_view>

#include "msec/core/error.hpp"
#include "msec/core/message.hpp"
#include "msec/mqtt/connection_options.hpp"

namespace msec::mqtt {

using MessageHandler = std::function<void(Message)>;

/// Port to an MQTT transport. Concrete adapters (Eclipse Paho, libmosquitto,
/// the in-process LoopbackClient) live behind this interface so that no other
/// module ever depends on a specific MQTT library.
///
/// The message handler may be invoked from a library-owned thread.
class IMqttClient {
public:
    IMqttClient() = default;
    virtual ~IMqttClient() = default;
    IMqttClient(const IMqttClient&) = delete;
    IMqttClient& operator=(const IMqttClient&) = delete;
    IMqttClient(IMqttClient&&) = delete;
    IMqttClient& operator=(IMqttClient&&) = delete;

    [[nodiscard]] virtual Status connect(const ConnectionOptions& options) = 0;
    [[nodiscard]] virtual Status disconnect() = 0;
    [[nodiscard]] virtual bool is_connected() const noexcept = 0;

    [[nodiscard]] virtual Status publish(const Message& message) = 0;
    [[nodiscard]] virtual Status subscribe(std::string_view filter, QoS qos) = 0;
    [[nodiscard]] virtual Status unsubscribe(std::string_view filter) = 0;

    virtual void set_message_handler(MessageHandler handler) = 0;
};

}  // namespace msec::mqtt
