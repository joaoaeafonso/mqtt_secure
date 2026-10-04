#include "msec/mqtt/paho/paho_client.hpp"

#include <mqtt/async_client.h>

#include <format>
#include <string>
#include <utility>

namespace msec::mqtt::paho {
namespace {

Error to_error(ErrorCode code, std::string_view what, const ::mqtt::exception& e) {
    return Error{code, std::format("{}: {}", what, e.what())};
}

::mqtt::ssl_options make_ssl(const TlsOptions& tls) {
    auto builder = ::mqtt::ssl_options_builder{};
    builder.enable_server_cert_auth(tls.verify_peer);
    if (!tls.ca_file.empty()) {
        builder.trust_store(tls.ca_file.string());
    }
    if (!tls.client_cert_file.empty()) {
        builder.key_store(tls.client_cert_file.string());
    }
    if (!tls.client_key_file.empty()) {
        builder.private_key(tls.client_key_file.string());
    }
    return builder.finalize();
}

}  // namespace

PahoClient::PahoClient(std::chrono::milliseconds timeout) : timeout_{timeout} {}

PahoClient::~PahoClient() {
    if (is_connected()) {
        (void)disconnect();
    }
}

Status PahoClient::connect(const ConnectionOptions& options) {
    if (options.broker_uri.empty()) {
        return make_error(ErrorCode::InvalidArgument, "broker_uri is required");
    }
    try {
        client_ = std::make_unique<::mqtt::async_client>(options.broker_uri, options.client_id);
        client_->set_message_callback([this](::mqtt::const_message_ptr m) {
            const auto& payload = m->get_payload();
            on_message(m->get_topic(),
                       std::as_bytes(std::span{payload.data(), payload.size()}),
                       static_cast<QoS>(m->get_qos()), m->is_retained());
        });

        auto builder = ::mqtt::connect_options_builder{};
        builder.clean_session(options.clean_session)
            .keep_alive_interval(options.keep_alive)
            .connect_timeout(timeout_);
        if (options.username) {
            builder.user_name(*options.username);
        }
        if (options.password) {
            const auto secret = options.password->view();
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): byte → char view
            builder.password(::mqtt::binary(reinterpret_cast<const char*>(secret.data()),
                                            secret.size()));
        }
        if (options.tls) {
            builder.ssl(make_ssl(*options.tls));
        }
        if (!client_->connect(builder.finalize())->wait_for(timeout_)) {
            return make_error(ErrorCode::ConnectionFailed, "connect timed out");
        }
    } catch (const ::mqtt::exception& e) {
        return std::unexpected{to_error(ErrorCode::ConnectionFailed, "connect", e)};
    }
    return {};
}

Status PahoClient::disconnect() {
    if (!client_) {
        return {};
    }
    try {
        if (client_->is_connected()) {
            client_->disconnect()->wait_for(timeout_);
        }
    } catch (const ::mqtt::exception& e) {
        return std::unexpected{to_error(ErrorCode::ConnectionFailed, "disconnect", e)};
    }
    return {};
}

bool PahoClient::is_connected() const noexcept {
    return client_ && client_->is_connected();
}

Status PahoClient::publish(const Message& message) {
    if (!is_connected()) {
        return make_error(ErrorCode::NotConnected, "publish while disconnected");
    }
    try {
        auto token = client_->publish(message.topic.str(), message.payload.data(),
                                      message.payload.size(), static_cast<int>(message.qos),
                                      message.retain);
        if (!token->wait_for(timeout_)) {
            return make_error(ErrorCode::ConnectionFailed, "publish timed out");
        }
    } catch (const ::mqtt::exception& e) {
        return std::unexpected{to_error(ErrorCode::ConnectionFailed, "publish", e)};
    }
    return {};
}

Status PahoClient::subscribe(std::string_view filter, QoS qos) {
    if (!is_connected()) {
        return make_error(ErrorCode::NotConnected, "subscribe while disconnected");
    }
    try {
        auto token = client_->subscribe(std::string{filter}, static_cast<int>(qos));
        if (!token->wait_for(timeout_)) {
            return make_error(ErrorCode::ConnectionFailed, "subscribe timed out");
        }
        // MQTT signals a refused subscription with reason code 0x80, not an error.
        if (token->get_reason_code() >= 0x80) {
            return make_error(ErrorCode::PermissionDenied,
                              std::format("broker refused subscription to '{}'", filter));
        }
    } catch (const ::mqtt::exception& e) {
        return std::unexpected{to_error(ErrorCode::ConnectionFailed, "subscribe", e)};
    }
    return {};
}

Status PahoClient::unsubscribe(std::string_view filter) {
    if (!is_connected()) {
        return make_error(ErrorCode::NotConnected, "unsubscribe while disconnected");
    }
    try {
        client_->unsubscribe(std::string{filter})->wait_for(timeout_);
    } catch (const ::mqtt::exception& e) {
        return std::unexpected{to_error(ErrorCode::ConnectionFailed, "unsubscribe", e)};
    }
    return {};
}

void PahoClient::set_message_handler(MessageHandler handler) {
    auto shared = handler ? std::make_shared<const MessageHandler>(std::move(handler)) : nullptr;
    const std::scoped_lock lock{handler_mutex_};
    handler_ = std::move(shared);
}

void PahoClient::on_message(const std::string& topic, ByteView payload, QoS qos, bool retain) {
    std::shared_ptr<const MessageHandler> handler;
    {
        const std::scoped_lock lock{handler_mutex_};
        handler = handler_;
    }
    auto valid_topic = Topic::create(topic);
    if (!handler || !valid_topic) {
        return;
    }
    (*handler)(Message{.topic = std::move(*valid_topic),
                       .payload = Bytes(payload.begin(), payload.end()),
                       .qos = qos,
                       .retain = retain});
}

}  // namespace msec::mqtt::paho
