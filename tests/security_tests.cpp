#include <memory>

#include "msec/security/envelope.hpp"
#include "msec/security/key_store.hpp"
#include "msec/security/openssl/aes_gcm_cipher.hpp"
#include "msec/security/openssl/random_source.hpp"
#include "msec/security/replay_guard.hpp"
#include "msec/security/security_layer.hpp"
#include "test_support.hpp"

namespace msec::security {
namespace {

using namespace std::chrono_literals;
using test::message;

SecureBuffer random_key() {
    SecureBuffer key{32};
    openssl::RandomSource rng;
    EXPECT_TRUE(rng.fill(key.mutable_view()).has_value());
    return key;
}

// ------------------------------------------------------------- envelope ---

TEST(Envelope, RoundTrip) {
    const Envelope original{.header = {.version = 1, .key_id = 7, .sequence = 42,
                                       .timestamp_ms = -5},
                            .nonce = Bytes(12, std::byte{0xAB}),
                            .ciphertext = to_bytes("ciphertext")};
    const auto wire = envelope::serialize(original);
    ASSERT_TRUE(wire.has_value());
    const auto parsed = envelope::parse(*wire);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->header.key_id, 7U);
    EXPECT_EQ(parsed->header.sequence, 42U);
    EXPECT_EQ(parsed->header.timestamp_ms, -5);
    EXPECT_EQ(parsed->nonce, original.nonce);
    EXPECT_EQ(parsed->ciphertext, original.ciphertext);
}

TEST(Envelope, RejectsMalformedInput) {
    EXPECT_EQ(envelope::parse(to_bytes("short")).error().code, ErrorCode::MalformedMessage);
    auto wire = *envelope::serialize({.header = {.sequence = 1}, .nonce = Bytes(12),
                                      .ciphertext = to_bytes("x")});
    auto bad_magic = wire;
    bad_magic[0] = std::byte{'X'};
    EXPECT_FALSE(envelope::parse(bad_magic).has_value());
    wire.pop_back();  // remove all ciphertext
    EXPECT_FALSE(envelope::parse(wire).has_value());
}

// --------------------------------------------------------- replay guard ---

TEST(ReplayGuard, AcceptsFreshRejectsDuplicates) {
    ReplayGuard guard;
    EXPECT_TRUE(guard.check_and_record(1, 1).has_value());
    EXPECT_TRUE(guard.check_and_record(1, 2).has_value());
    EXPECT_EQ(guard.check_and_record(1, 2).error().code, ErrorCode::ReplayDetected);
}

TEST(ReplayGuard, ToleratesReorderingInsideWindow) {
    ReplayGuard guard;
    EXPECT_TRUE(guard.check_and_record(1, 10).has_value());
    EXPECT_TRUE(guard.check_and_record(1, 8).has_value());
    EXPECT_TRUE(guard.check_and_record(1, 9).has_value());
    EXPECT_FALSE(guard.check_and_record(1, 8).has_value());
}

TEST(ReplayGuard, RejectsTooOld) {
    ReplayGuard guard;
    EXPECT_TRUE(guard.check_and_record(1, 100).has_value());
    EXPECT_FALSE(guard.check_and_record(1, 100 - ReplayGuard::kWindowSize).has_value());
    EXPECT_TRUE(guard.check_and_record(1, 100 - ReplayGuard::kWindowSize + 1).has_value());
}

TEST(ReplayGuard, KeysAreIndependentAndBounded) {
    ReplayGuard guard{2};
    EXPECT_TRUE(guard.check_and_record(1, 5).has_value());
    EXPECT_TRUE(guard.check_and_record(2, 5).has_value());
    EXPECT_EQ(guard.check_and_record(3, 5).error().code, ErrorCode::CapacityExceeded);
}

// --------------------------------------------------------------- cipher ---

TEST(AesGcm, RoundTripAndTamperDetection) {
    const openssl::AesGcmCipher cipher;
    const auto key = random_key();
    const Bytes nonce(12, std::byte{1});
    const auto aad = to_bytes("aad");

    auto sealed = cipher.seal(key, nonce, to_bytes("hello"), aad);
    ASSERT_TRUE(sealed.has_value());
    EXPECT_EQ(sealed->size(), 5U + cipher.tag_size());

    auto opened = cipher.open(key, nonce, *sealed, aad);
    ASSERT_TRUE(opened.has_value());
    EXPECT_EQ(bytes_to_string(*opened), "hello");

    EXPECT_FALSE(cipher.open(key, nonce, *sealed, to_bytes("other")).has_value());
    (*sealed)[0] ^= std::byte{1};
    EXPECT_EQ(cipher.open(key, nonce, *sealed, aad).error().code,
              ErrorCode::AuthenticationFailed);
}

TEST(AesGcm, EmptyPlaintext) {
    const openssl::AesGcmCipher cipher;
    const auto key = random_key();
    const Bytes nonce(12);
    auto sealed = cipher.seal(key, nonce, {}, {});
    ASSERT_TRUE(sealed.has_value());
    auto opened = cipher.open(key, nonce, *sealed, {});
    ASSERT_TRUE(opened.has_value());
    EXPECT_TRUE(opened->empty());
}

// --------------------------------------------------------- security layer ---

class SecurityLayerTest : public ::testing::Test {
protected:
    void SetUp() override {
        ASSERT_TRUE(keys_->add(1, random_key()).has_value());
        sender_ = make_layer(1, clock_);
        receiver_ = make_layer(1, clock_);
    }

    std::unique_ptr<SecurityLayer> make_layer(KeyId key, std::shared_ptr<const IClock> clock) {
        auto layer = SecurityLayer::create(
            {.sending_key_id = key},
            {.cipher = cipher_, .key_store = keys_, .random = rng_, .clock = std::move(clock)});
        EXPECT_TRUE(layer.has_value());
        return layer ? std::move(*layer) : nullptr;
    }

    Message protect(std::string_view topic, std::string_view text) {
        auto out = sender_->on_outbound(message(topic, text));
        EXPECT_TRUE(out.has_value());
        return *out;
    }

    std::shared_ptr<openssl::AesGcmCipher> cipher_ = std::make_shared<openssl::AesGcmCipher>();
    std::shared_ptr<InMemoryKeyStore> keys_ = std::make_shared<InMemoryKeyStore>();
    std::shared_ptr<openssl::RandomSource> rng_ = std::make_shared<openssl::RandomSource>();
    std::shared_ptr<test::FakeClock> clock_ = std::make_shared<test::FakeClock>();
    std::unique_ptr<SecurityLayer> sender_;
    std::unique_ptr<SecurityLayer> receiver_;
};

TEST_F(SecurityLayerTest, RoundTripHidesPlaintext) {
    const auto wire = protect("sensors/t", "21.5C");
    EXPECT_EQ(bytes_to_string(wire.payload).find("21.5C"), std::string::npos);

    const auto plain = receiver_->on_inbound(wire);
    ASSERT_TRUE(plain.has_value());
    EXPECT_EQ(bytes_to_string(plain->payload), "21.5C");
}

TEST_F(SecurityLayerTest, RejectsTamperedCiphertext) {
    auto wire = protect("sensors/t", "21.5C");
    wire.payload.back() ^= std::byte{0x01};
    EXPECT_EQ(receiver_->on_inbound(wire).error().code, ErrorCode::AuthenticationFailed);
}

TEST_F(SecurityLayerTest, RejectsTamperedHeader) {
    auto wire = protect("sensors/t", "21.5C");
    wire.payload[14] ^= std::byte{0x02};  // seq 1 -> 3: valid format, but not what was signed
    EXPECT_EQ(receiver_->on_inbound(wire).error().code, ErrorCode::AuthenticationFailed);
}

TEST_F(SecurityLayerTest, RejectsTopicRebinding) {
    auto wire = protect("sensors/t", "21.5C");
    wire.topic = test::topic("actuators/door");
    EXPECT_EQ(receiver_->on_inbound(wire).error().code, ErrorCode::AuthenticationFailed);
}

TEST_F(SecurityLayerTest, RejectsReplay) {
    const auto wire = protect("sensors/t", "21.5C");
    ASSERT_TRUE(receiver_->on_inbound(wire).has_value());
    EXPECT_EQ(receiver_->on_inbound(wire).error().code, ErrorCode::ReplayDetected);
}

TEST_F(SecurityLayerTest, RejectsExpiredMessages) {
    const auto wire = protect("sensors/t", "21.5C");
    clock_->advance(61s);
    EXPECT_EQ(receiver_->on_inbound(wire).error().code, ErrorCode::MessageExpired);
}

TEST_F(SecurityLayerTest, RejectsMessagesFromTheFuture) {
    auto skewed = std::make_shared<test::FakeClock>(clock_->now() + 10s);
    auto skewed_sender = make_layer(1, skewed);
    const auto wire = skewed_sender->on_outbound(message("sensors/t", "x"));
    ASSERT_TRUE(wire.has_value());
    EXPECT_EQ(receiver_->on_inbound(*wire).error().code, ErrorCode::MessageExpired);
}

TEST_F(SecurityLayerTest, RejectsRevokedKey) {
    const auto wire = protect("sensors/t", "21.5C");
    ASSERT_TRUE(keys_->revoke(1).has_value());
    EXPECT_EQ(receiver_->on_inbound(wire).error().code, ErrorCode::AuthenticationFailed);
}

TEST_F(SecurityLayerTest, RejectsUnprotectedPayload) {
    EXPECT_EQ(receiver_->on_inbound(message("sensors/t", "plain text")).error().code,
              ErrorCode::MalformedMessage);
}

TEST_F(SecurityLayerTest, SequenceNumbersIncrease) {
    const auto first = envelope::parse(protect("t", "a").payload);
    const auto second = envelope::parse(protect("t", "b").payload);
    ASSERT_TRUE(first.has_value() && second.has_value());
    EXPECT_LT(first->header.sequence, second->header.sequence);
    EXPECT_NE(first->nonce, second->nonce);
}

TEST(SecurityLayerFactory, RejectsMissingDependencies) {
    EXPECT_FALSE(SecurityLayer::create({}, {}).has_value());
}

}  // namespace
}  // namespace msec::security
