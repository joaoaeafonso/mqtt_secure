#include "msec/mqtt/loopback_broker.hpp"

#include <algorithm>
#include <format>
#include <utility>

#include "msec/mqtt/topic_filter.hpp"

namespace msec::mqtt {

// ----------------------------------------------------------------- broker ---

std::shared_ptr<LoopbackBroker> LoopbackBroker::create(std::optional<AccessControlList> acl) {
    return std::make_shared<LoopbackBroker>(PassKey{}, std::move(acl));
}

Status LoopbackBroker::route(const Message& message, std::string_view publisher_id) {
    const std::string& topic = message.topic.str();
    if (acl_ && !acl_->can_publish(publisher_id, topic)) {
        return make_error(ErrorCode::PermissionDenied,
                          std::format("client '{}' may not publish to '{}'", publisher_id, topic));
    }
    std::vector<std::shared_ptr<LoopbackClient>> targets;
    {
        const std::scoped_lock lock{mutex_};
        for (const auto& sub : subscriptions_) {
            if (!topic_matches(sub.filter, topic) ||
                (acl_ && !acl_->can_read(sub.client_id, topic))) {
                continue;
            }
            auto client = sub.client.lock();
            if (client && std::ranges::find(targets, client) == targets.end()) {
                targets.push_back(std::move(client));
            }
        }
    }
    // Deliver without holding the lock so handlers may publish re-entrantly.
    for (const auto& client : targets) {
        client->deliver(message);
    }
    return {};
}

void LoopbackBroker::add_subscription(const std::shared_ptr<LoopbackClient>& client,
                                      std::string client_id, std::string filter) {
    const std::scoped_lock lock{mutex_};
    subscriptions_.push_back({client, client.get(), std::move(client_id), std::move(filter)});
}

void LoopbackBroker::remove_subscription(const LoopbackClient* client, std::string_view filter) {
    const std::scoped_lock lock{mutex_};
    std::erase_if(subscriptions_, [&](const Subscription& sub) {
        return sub.identity == client && sub.filter == filter;
    });
}

void LoopbackBroker::remove_client(const LoopbackClient* client) {
    const std::scoped_lock lock{mutex_};
    std::erase_if(subscriptions_,
                  [&](const Subscription& sub) { return sub.identity == client; });
}

// ----------------------------------------------------------------- client ---

std::shared_ptr<LoopbackClient> LoopbackClient::create(std::shared_ptr<LoopbackBroker> broker) {
    return std::make_shared<LoopbackClient>(PassKey{}, std::move(broker));
}

LoopbackClient::LoopbackClient(PassKey /*key*/, std::shared_ptr<LoopbackBroker> broker)
    : broker_{std::move(broker)} {}

LoopbackClient::~LoopbackClient() {
    if (broker_) {
        broker_->remove_client(this);
    }
}

Status LoopbackClient::connect(const ConnectionOptions& options) {
    if (!broker_) {
        return make_error(ErrorCode::ConnectionFailed, "no broker");
    }
    client_id_.store(std::make_shared<const std::string>(options.client_id));
    connected_.store(true);
    return {};
}

Status LoopbackClient::disconnect() {
    connected_.store(false);
    broker_->remove_client(this);
    return {};
}

bool LoopbackClient::is_connected() const noexcept { return connected_.load(); }

Status LoopbackClient::publish(const Message& message) {
    if (!connected_.load()) {
        return make_error(ErrorCode::NotConnected, "publish while disconnected");
    }
    return broker_->route(message, *client_id_.load());
}

Status LoopbackClient::subscribe(std::string_view filter, QoS /*qos*/) {
    if (!connected_.load()) {
        return make_error(ErrorCode::NotConnected, "subscribe while disconnected");
    }
    if (auto valid = validate_topic_filter(filter); !valid) {
        return valid;
    }
    broker_->add_subscription(shared_from_this(), *client_id_.load(), std::string{filter});
    return {};
}

Status LoopbackClient::unsubscribe(std::string_view filter) {
    broker_->remove_subscription(this, filter);
    return {};
}

void LoopbackClient::set_message_handler(MessageHandler handler) {
    auto shared = handler ? std::make_shared<const MessageHandler>(std::move(handler)) : nullptr;
    const std::scoped_lock lock{handler_mutex_};
    handler_ = std::move(shared);
}

void LoopbackClient::deliver(Message message) {
    std::shared_ptr<const MessageHandler> handler;
    {
        const std::scoped_lock lock{handler_mutex_};
        handler = handler_;
    }
    if (handler && connected_.load()) {
        (*handler)(std::move(message));
    }
}

}  // namespace msec::mqtt
