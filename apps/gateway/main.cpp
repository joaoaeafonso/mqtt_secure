// Composition root: the ONLY place that knows about concrete implementations.
// Everything else depends on interfaces, so swapping the loopback broker for a
// Paho/Mosquitto client, or the in-memory repo for SQLite, is a change here only.

#include <cstdlib>
#include <format>
#include <memory>
#include <string>
#include <vector>

#include "msec/core/clock.hpp"
#include "msec/core/logger.hpp"
#include "msec/data/in_memory_repository.hpp"
#include "msec/data/persistence_layer.hpp"
#include "msec/mqtt/endpoint.hpp"
#include "msec/mqtt/loopback_broker.hpp"
#include "msec/security/key_store.hpp"
#include "msec/security/openssl/aes_gcm_cipher.hpp"
#include "msec/security/openssl/random_source.hpp"
#include "msec/security/security_layer.hpp"

namespace {

using namespace msec;

constexpr security::KeyId kSensorKey = 1;

void fail(std::string_view what, const Error& error) {
    std::fputs(std::format("fatal: {}: {} ({})\n", what, error.message, to_string(error.code))
                   .c_str(),
               stderr);
    std::exit(EXIT_FAILURE);  // NOLINT(concurrency-mt-unsafe): single-threaded startup
}

template <typename T>
T require(Result<T> result, std::string_view what) {
    if (!result) {
        fail(what, result.error());
    }
    return std::move(*result);
}

void require(const Status& status, std::string_view what) {
    if (!status) {
        fail(what, status.error());
    }
}

}  // namespace

int main() {
    auto logger = std::make_shared<ConsoleLogger>(LogLevel::Info);
    auto clock = std::make_shared<SystemClock>();
    auto cipher = std::make_shared<security::openssl::AesGcmCipher>();
    auto rng = std::make_shared<security::openssl::RandomSource>();
    auto keys = std::make_shared<security::InMemoryKeyStore>();
    auto repository = std::make_shared<data::InMemoryMessageRepository>(1'000);

    // Pre-shared key provisioning. In a deployment this comes from a secure
    // element / provisioning service, never from code.
    SecureBuffer key{cipher->key_size()};
    require(rng->fill(key.mutable_view()), "generate key");
    require(keys->add(kSensorKey, std::move(key)), "store key");

    const security::SecurityDependencies deps{
        .cipher = cipher, .key_store = keys, .random = rng, .clock = clock};
    const security::SecurityConfig config{.sending_key_id = kSensorKey};

    auto broker = mqtt::LoopbackBroker::create();

    // Sensor: [security] ─▶ MQTT
    auto sensor_pipeline = require(
        Pipeline::Builder{}.add(require(security::SecurityLayer::create(config, deps), "sensor sec"))
            .build(),
        "sensor pipeline");
    mqtt::Endpoint sensor{mqtt::LoopbackClient::create(broker), std::move(sensor_pipeline), logger};

    // Gateway: app ◀─ [persistence] ◀─ [security] ◀─ MQTT
    auto gateway_pipeline = require(
        Pipeline::Builder{}
            .add(require(data::PersistenceLayer::create(repository, clock), "persistence"))
            .add(require(security::SecurityLayer::create(config, deps), "gateway sec"))
            .build(),
        "gateway pipeline");
    mqtt::Endpoint gateway{mqtt::LoopbackClient::create(broker), std::move(gateway_pipeline),
                           logger};

    gateway.on_message([&](const Message& m) {
        logger->log(LogLevel::Info, "gateway",
                    std::format("received {} = {}", m.topic.str(), bytes_to_string(m.payload)));
    });

    require(sensor.start({.client_id = "sensor-1"}), "sensor start");
    require(gateway.start({.client_id = "gateway"}), "gateway start");
    require(gateway.subscribe("sensors/#", QoS::AtLeastOnce), "subscribe");

    // An attacker with broker access records traffic.
    auto attacker = mqtt::LoopbackClient::create(broker);
    require(attacker->connect({.client_id = "mallory"}), "attacker connect");
    std::vector<Message> captured;
    attacker->set_message_handler([&](Message m) { captured.push_back(std::move(m)); });
    require(attacker->subscribe("sensors/#", QoS::AtMostOnce), "attacker subscribe");

    // 1. Legitimate traffic.
    for (const auto* reading : {"21.4", "21.5", "21.7"}) {
        require(sensor.publish(Message{.topic = require(Topic::create("sensors/room1/temp"), "topic"),
                                       .payload = to_bytes(reading)}),
                "publish");
    }

    // 2. Attacks.
    attacker->set_message_handler({});
    logger->log(LogLevel::Info, "demo",
                std::format("attacker sees ciphertext of {} bytes", captured.at(0).payload.size()));
    require(attacker->publish(captured.at(0)), "replay");  // replay
    Message forged = captured.at(1);
    forged.payload.back() ^= std::byte{0x01};
    require(attacker->publish(forged), "tamper");          // bit flip
    Message moved = captured.at(2);
    moved.topic = require(Topic::create("sensors/room2/temp"), "topic");
    require(attacker->publish(moved), "rebind");           // topic rebinding
    require(attacker->publish(Message{.topic = require(Topic::create("sensors/room1/temp"), "t"),
                                      .payload = to_bytes("99.9")}),
            "inject");                                      // plaintext injection

    const auto stats = gateway.stats();
    logger->log(LogLevel::Info, "demo",
                std::format("gateway delivered={} rejected={} stored={}", stats.delivered,
                            stats.rejected_inbound, repository->size()));
    return stats.delivered == 3 && stats.rejected_inbound == 4 ? EXIT_SUCCESS : EXIT_FAILURE;
}
