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
    builder.enable_server_cert_auth(tls.verify_peer).verify(tls.verify_peer);
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
    const std::scoped_lock lock{client_mutex_};
    close_locked();
}

bool PahoClient::wait(std::shared_ptr<::mqtt::token> token) {
    // Park first: wait_for() throws when the operation failed, and the token
    // must outlive its callback on that path too. Replacing last_token_ is safe
    // here because the Paho call that produced `token` already took the mutex.
    last_token_ = std::move(token);
    return last_token_->wait_for(timeout_);
}

void PahoClient::close_locked() {
    if (!client_) {
        return;
    }
    try {
        if (client_->is_connected()) {
            (void)wait(client_->disconnect());
        }
    } catch (const ::mqtt::exception&) {  // NOLINT(bugprone-empty-catch)
        // Closing anyway; nothing useful to report.
    }
    client_.reset();  // MQTTAsync_destroy: waits for Paho's callbacks to finish
    last_token_.reset();
}

Status PahoClient::connect(const ConnectionOptions& options) {
    if (options.broker_uri.empty()) {
        return make_error(ErrorCode::InvalidArgument, "broker_uri is required");
    }
    const std::scoped_lock lock{client_mutex_};
    close_locked();
    try {
        const int version = static_cast<int>(options.protocol);
        client_ = std::make_unique<::mqtt::async_client>(
            options.broker_uri, options.client_id, ::mqtt::create_options{version});
        client_->set_message_callback([this](const ::mqtt::const_message_ptr& m) {
            const auto& payload = m->get_payload();
            on_message(m->get_topic(),
                       std::as_bytes(std::span{payload.data(), payload.size()}),
                       static_cast<QoS>(m->get_qos()), m->is_retained(), m->is_duplicate());
        });

        auto builder = ::mqtt::connect_options_builder{};
        builder.mqtt_version(version);
        if (options.protocol == ProtocolVersion::V5) {
            builder.clean_start(options.clean_session);
        } else {
            builder.clean_session(options.clean_session);
        }
        builder.keep_alive_interval(options.keep_alive).connect_timeout(timeout_);
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
        if (!wait(client_->connect(builder.finalize()))) {
            client_.reset();
            return make_error(ErrorCode::ConnectionFailed, "connect timed out");
        }
    } catch (const ::mqtt::exception& e) {
        client_.reset();
        return std::unexpected{to_error(ErrorCode::ConnectionFailed, "connect", e)};
    }
    return {};
}

Status PahoClient::disconnect() {
    const std::scoped_lock lock{client_mutex_};
    close_locked();
    return {};
}

bool PahoClient::is_connected() const noexcept {
    const std::scoped_lock lock{client_mutex_};
    return client_ && client_->is_connected();
}

Status PahoClient::publish(const Message& message) {
    const std::scoped_lock lock{client_mutex_};
    if (!client_ || !client_->is_connected()) {
        return make_error(ErrorCode::NotConnected, "publish while disconnected");
    }
    try {
        if (!wait(client_->publish(message.topic.str(), message.payload.data(),
                                   message.payload.size(), static_cast<int>(message.qos),
                                   message.retain))) {
            return make_error(ErrorCode::ConnectionFailed, "publish timed out");
        }
    } catch (const ::mqtt::exception& e) {
        return std::unexpected{to_error(ErrorCode::ConnectionFailed, "publish", e)};
    }
    return {};
}

Status PahoClient::subscribe(std::string_view filter, QoS qos) {
    const std::scoped_lock lock{client_mutex_};
    if (!client_ || !client_->is_connected()) {
        return make_error(ErrorCode::NotConnected, "subscribe while disconnected");
    }
    try {
        if (!wait(client_->subscribe(std::string{filter}, static_cast<int>(qos)))) {
            return make_error(ErrorCode::ConnectionFailed, "subscribe timed out");
        }
        // MQTT signals a refused subscription with reason code 0x80, not an error.
        if (last_token_->get_reason_code() >= 0x80) {
            return make_error(ErrorCode::PermissionDenied,
                              std::format("broker refused subscription to '{}'", filter));
        }
    } catch (const ::mqtt::exception& e) {
        return std::unexpected{to_error(ErrorCode::ConnectionFailed, "subscribe", e)};
    }
    return {};
}

Status PahoClient::unsubscribe(std::string_view filter) {
    const std::scoped_lock lock{client_mutex_};
    if (!client_ || !client_->is_connected()) {
        return make_error(ErrorCode::NotConnected, "unsubscribe while disconnected");
    }
    try {
        (void)wait(client_->unsubscribe(std::string{filter}));
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

void PahoClient::on_message(const std::string& topic, ByteView payload, QoS qos, bool retain,
                            bool duplicate) {
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
                       .retain = retain,
                       .duplicate = duplicate});
}

}  // namespace msec::mqtt::paho
