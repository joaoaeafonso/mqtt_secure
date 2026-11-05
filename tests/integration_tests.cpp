#include <memory>
#include <vector>

#include "msec/data/in_memory_repository.hpp"
#include "msec/data/persistence_layer.hpp"
#include "msec/mqtt/endpoint.hpp"
#include "msec/mqtt/loopback_broker.hpp"
#include "msec/security/key_store.hpp"
#include "msec/security/openssl/aes_gcm_cipher.hpp"
#include "msec/security/openssl/random_source.hpp"
#include "msec/security/security_layer.hpp"
#include "test_support.hpp"

namespace msec {
namespace {

/// Full stack: sensor ─▶ broker ─▶ gateway, plus an attacker on the broker.
class EndToEnd : public ::testing::Test {
protected:
    void SetUp() override {
        SecureBuffer key{32};
        ASSERT_TRUE(rng_->fill(key.mutable_view()).has_value());
        ASSERT_TRUE(keys_->add(1, std::move(key)).has_value());

        sensor_ = std::make_unique<mqtt::Endpoint>(
            mqtt::LoopbackClient::create(broker_), build(security_layer()), nullptr);

        auto persistence = data::PersistenceLayer::create(repo_, clock_);
        ASSERT_TRUE(persistence.has_value());
        gateway_ = std::make_unique<mqtt::Endpoint>(
            mqtt::LoopbackClient::create(broker_),
            build(std::move(*persistence), security_layer()), nullptr);

        ASSERT_TRUE(sensor_->start({}).has_value());
        ASSERT_TRUE(gateway_->start({}).has_value());
        ASSERT_TRUE(gateway_->subscribe("sensors/#", QoS::AtLeastOnce).has_value());
        gateway_->on_message([this](const Message& m) { received_.push_back(m); });
    }

    std::unique_ptr<ILayer> security_layer() {
        auto layer = security::SecurityLayer::create(
            {.sending_key_id = 1, .enforce_key_binding = false},
            {.cipher = cipher_, .key_store = keys_, .random = rng_, .clock = clock_});
        EXPECT_TRUE(layer.has_value());
        return layer ? std::move(*layer) : nullptr;
    }

    template <typename... Layers>
    static Pipeline build(Layers&&... layers) {
        Pipeline::Builder builder;
        (builder.add(std::forward<Layers>(layers)), ...);
        auto pipeline = builder.build();
        EXPECT_TRUE(pipeline.has_value());
        return std::move(*pipeline);
    }

    std::shared_ptr<mqtt::LoopbackBroker> broker_ = mqtt::LoopbackBroker::create();
    std::shared_ptr<security::openssl::AesGcmCipher> cipher_ =
        std::make_shared<security::openssl::AesGcmCipher>();
    std::shared_ptr<security::InMemoryKeyStore> keys_ =
        std::make_shared<security::InMemoryKeyStore>();
    std::shared_ptr<security::openssl::RandomSource> rng_ =
        std::make_shared<security::openssl::RandomSource>();
    std::shared_ptr<test::FakeClock> clock_ = std::make_shared<test::FakeClock>();
    std::shared_ptr<data::InMemoryMessageRepository> repo_ =
        std::make_shared<data::InMemoryMessageRepository>(100);

    std::unique_ptr<mqtt::Endpoint> sensor_;
    std::unique_ptr<mqtt::Endpoint> gateway_;
    std::vector<Message> received_;
};

TEST_F(EndToEnd, DeliversAndStoresDecryptedMessage) {
    ASSERT_TRUE(sensor_->publish(test::message("sensors/room1/temp", "21.5")).has_value());

    ASSERT_EQ(received_.size(), 1U);
    EXPECT_EQ(bytes_to_string(received_[0].payload), "21.5");
    EXPECT_EQ(repo_->size(), 1U);  // persistence sits above security => plaintext stored
    EXPECT_EQ(gateway_->stats().delivered, 1U);
}

TEST_F(EndToEnd, AttackerCannotReplayOrInject) {
    auto attacker = mqtt::LoopbackClient::create(broker_);
    ASSERT_TRUE(attacker->connect({}).has_value());
    std::vector<Message> captured;
    attacker->set_message_handler([&](Message m) { captured.push_back(std::move(m)); });
    ASSERT_TRUE(attacker->subscribe("sensors/#", QoS::AtMostOnce).has_value());

    ASSERT_TRUE(sensor_->publish(test::message("sensors/room1/temp", "21.5")).has_value());
    ASSERT_EQ(captured.size(), 1U);

    // The eavesdropper sees only ciphertext.
    EXPECT_EQ(bytes_to_string(captured[0].payload).find("21.5"), std::string::npos);

    std::vector<ErrorCode> reasons;
    gateway_->on_rejected([&](const mqtt::Endpoint::Rejected& rejected, const Error& error) {
        EXPECT_EQ(rejected.topic, "sensors/room1/temp");
        reasons.push_back(error.code);
    });

    attacker->set_message_handler({});
    ASSERT_TRUE(attacker->publish(captured[0]).has_value());                          // replay
    ASSERT_TRUE(attacker->publish(test::message("sensors/room1/temp", "99")).has_value());  // forge

    EXPECT_EQ(received_.size(), 1U);
    EXPECT_EQ(gateway_->stats().rejected_inbound, 2U);
    EXPECT_EQ(reasons, (std::vector<ErrorCode>{ErrorCode::ReplayDetected,
                                               ErrorCode::MalformedMessage}));
    EXPECT_EQ(repo_->size(), 1U);
}

}  // namespace
}  // namespace msec
