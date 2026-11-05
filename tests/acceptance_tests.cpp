// Acceptance rules of the receiver, one test per rule of the design (report,
// Section 6): the verification order of Table 11, the anti-replay window, the
// mode policy, the key → topic restriction, the temporal validity limits (also
// per flow), the dependencies between mechanisms and the restart rule.
//
// Each test is written so that it FAILS if its rule is removed or moved: e.g.
// the order tests send messages that break two rules at once and check which
// rejection wins.

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "msec/security/envelope.hpp"
#include "msec/security/epoch_store.hpp"
#include "msec/security/key_policy.hpp"
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

constexpr KeyId kSensor1 = 1;
constexpr KeyId kSensor2 = 2;
constexpr KeyId kUnknown = 9;  // the sender has it, the receiver does not
constexpr std::uint32_t kStride = 1000;

SecureBuffer random_key() {
    SecureBuffer key{32};
    openssl::RandomSource rng;
    EXPECT_TRUE(rng.fill(key.mutable_view()).has_value());
    return key;
}

/// The error of a result that must have failed (never calls error() on a value).
template <typename T>
ErrorCode failure(const Result<T>& r) {
    EXPECT_FALSE(r.has_value()) << "expected a failure";
    return r.has_value() ? ErrorCode::Internal : r.error().code;
}

/// In-memory IEpochStore that can be told to fail.
class MemoryEpochStore final : public IEpochStore {
public:
    [[nodiscard]] Result<std::optional<std::uint32_t>> load() const override {
        if (fail_load) {
            return make_error(ErrorCode::StorageFailure, "disk gone");
        }
        return value;
    }
    [[nodiscard]] Status save(std::uint32_t epoch) override {
        if (fail_save) {
            return make_error(ErrorCode::StorageFailure, "disk full");
        }
        value = epoch;
        ++saves;
        return {};
    }

    std::optional<std::uint32_t> value;
    int saves{0};
    bool fail_load{false};
    bool fail_save{false};
};

class Acceptance : public ::testing::Test {
protected:
    void SetUp() override {
        for (const KeyId id : {kSensor1, kSensor2, kUnknown, kStride + kSensor1}) {
            const auto key = random_key();
            ASSERT_TRUE(sender_keys_->add(id, SecureBuffer{key.view()}).has_value());
            if (id != kUnknown) {
                ASSERT_TRUE(receiver_keys_->add(id, SecureBuffer{key.view()}).has_value());
            }
        }
        ASSERT_TRUE(policy_->allow_pattern("+/sensors/%u/#").has_value());
        ASSERT_TRUE(policy_->allow_pattern("+/actuators/%u/#").has_value());
        for (const KeyId id : {kSensor1, kSensor2, kUnknown, kStride + kSensor1}) {
            ASSERT_TRUE(policy_->set_owner(id, std::format("sensor-{}", id % kStride)).has_value());
        }
    }

    std::unique_ptr<SecurityLayer> sender(KeyId key, SecurityConfig config = {},
                                          std::shared_ptr<const IClock> clock = nullptr) {
        config.sending_key_id = key;
        config.enforce_key_binding = false;
        auto layer = SecurityLayer::create(
            config, {.cipher = cipher_,
                     .key_store = sender_keys_,
                     .random = rng_,
                     .clock = clock ? std::move(clock) : clock_});
        EXPECT_TRUE(layer.has_value());
        return layer ? std::move(*layer) : nullptr;
    }

    Result<std::unique_ptr<SecurityLayer>> try_receiver(
        SecurityConfig config = {}, std::shared_ptr<IEpochStore> epochs = nullptr) {
        if (epochs) {
            config.key_epoch_stride = kStride;
        }
        return SecurityLayer::create(config, {.cipher = cipher_,
                                              .key_store = receiver_keys_,
                                              .random = rng_,
                                              .clock = clock_,
                                              .authorization = policy_,
                                              .epoch_store = std::move(epochs)});
    }

    std::unique_ptr<SecurityLayer> receiver(SecurityConfig config = {},
                                            std::shared_ptr<IEpochStore> epochs = nullptr) {
        auto layer = try_receiver(std::move(config), std::move(epochs));
        EXPECT_TRUE(layer.has_value()) << layer.error().message;
        return layer ? std::move(*layer) : nullptr;
    }

    static Message seal(SecurityLayer& from, std::string_view topic, std::string_view text = "21.5C") {
        auto out = from.on_outbound(message(topic, text));
        EXPECT_TRUE(out.has_value());
        return *out;
    }

    static ErrorCode rejection(SecurityLayer& at, const Message& m) {
        auto r = at.on_inbound(m);
        EXPECT_FALSE(r.has_value()) << "accepted";
        return r ? ErrorCode::Internal : r.error().code;
    }

    static constexpr std::string_view kTopic1 = "open/sensors/sensor-1/temp";
    static constexpr std::string_view kTopic2 = "open/sensors/sensor-2/temp";

    std::shared_ptr<openssl::AesGcmCipher> cipher_ = std::make_shared<openssl::AesGcmCipher>();
    std::shared_ptr<openssl::RandomSource> rng_ = std::make_shared<openssl::RandomSource>();
    std::shared_ptr<test::FakeClock> clock_ = std::make_shared<test::FakeClock>();
    std::shared_ptr<InMemoryKeyStore> sender_keys_ = std::make_shared<InMemoryKeyStore>();
    std::shared_ptr<InMemoryKeyStore> receiver_keys_ = std::make_shared<InMemoryKeyStore>();
    std::shared_ptr<KeyTopicPolicy> policy_ = std::make_shared<KeyTopicPolicy>();
};

// --------------------------------------------- Table 11: verification order ---

// Row 1: format first. Plaintext (an injection) never reaches any other check.
TEST_F(Acceptance, Order1_FormatRejectsUnprotectedInput) {
    auto rx = receiver();
    EXPECT_EQ(rejection(*rx, message(kTopic1, "plain reading")), ErrorCode::MalformedMessage);
    auto truncated = seal(*sender(kSensor1), kTopic1);
    truncated.payload.resize(envelope::kFixedHeaderSize - 1);
    EXPECT_EQ(rejection(*rx, truncated), ErrorCode::MalformedMessage);
}

// Row 2 before row 3: a mode outside the policy is refused even when the
// message is also expired.
TEST_F(Acceptance, Order2_ModePolicyBeforeValidity) {
    auto tx = sender(kSensor1, {.protection = PayloadProtection::AuthenticateOnly});
    const auto m = seal(*tx, kTopic1);
    clock_->advance(61s);
    EXPECT_EQ(rejection(*receiver(), m), ErrorCode::ProtectionNotAccepted);
}

// Row 3 before row 4: an expired message is refused before any cryptography,
// so a tampered and expired message reports expiry, not a bad tag.
TEST_F(Acceptance, Order3_ValidityBeforeCryptography) {
    auto m = seal(*sender(kSensor1), kTopic1);
    m.payload.back() ^= std::byte{0x01};
    clock_->advance(61s);
    EXPECT_EQ(rejection(*receiver(), m), ErrorCode::MessageExpired);
    auto unknown = seal(*sender(kUnknown), kTopic1);
    clock_->advance(61s);
    EXPECT_EQ(rejection(*receiver(), unknown), ErrorCode::MessageExpired);
}

// Row 4: unknown key and bad tag fail identically (no oracle), and before the
// key → topic restriction (unauthenticated input cannot probe the policy).
TEST_F(Acceptance, Order4_SameFailureForUnknownKeyAndBadTag) {
    auto rx = receiver();
    auto tampered = seal(*sender(kSensor1), kTopic2);  // wrong topic AND bad tag
    tampered.payload.back() ^= std::byte{0x01};
    const auto bad_tag = rx->on_inbound(tampered);
    const auto unknown = rx->on_inbound(seal(*sender(kUnknown), kTopic2));
    ASSERT_FALSE(bad_tag.has_value());
    ASSERT_FALSE(unknown.has_value());
    EXPECT_EQ(bad_tag.error().code, ErrorCode::AuthenticationFailed);
    EXPECT_EQ(unknown.error().code, ErrorCode::AuthenticationFailed);
    EXPECT_EQ(bad_tag.error().message, unknown.error().message);
}

// Row 5 before row 6: a message refused by the restriction does not consume
// its sequence number, so a duplicate of it is still a restriction failure.
TEST_F(Acceptance, Order5_KeyTopicBeforeReplayWindow) {
    auto rx = receiver();
    const auto foreign = seal(*sender(kSensor2), kTopic1);  // sensor-2's key, sensor-1's topic
    EXPECT_EQ(rejection(*rx, foreign), ErrorCode::PermissionDenied);
    EXPECT_EQ(rejection(*rx, foreign), ErrorCode::PermissionDenied);
}

// Row 6 after row 4: forged sequence numbers do not move the window. If the
// window were updated before authentication, sequence 1 would fall out of it.
TEST_F(Acceptance, Order6_ForgedSequenceNumbersDoNotAdvanceTheWindow) {
    auto rx = receiver();
    const auto genuine = seal(*sender(kSensor1), kTopic1);  // sequence 1
    auto forged = genuine;
    forged.payload[15] = std::byte{0xFF};  // sequence 255: not what was authenticated
    EXPECT_EQ(rejection(*rx, forged), ErrorCode::AuthenticationFailed);
    EXPECT_TRUE(rx->on_inbound(genuine).has_value());
}

// ------------------------------------------------------- anti-replay window ---

TEST_F(Acceptance, WindowLimitsAndReordering) {
    auto tx = sender(kSensor1);
    std::vector<Message> sent;
    for (int i = 0; i < 70; ++i) {
        sent.push_back(seal(*tx, kTopic1));  // sequence i + 1
    }
    auto rx = receiver();
    ASSERT_TRUE(rx->on_inbound(sent[69]).has_value());   // highest = 70
    ASSERT_TRUE(rx->on_inbound(sent[68]).has_value());   // reordered, inside
    EXPECT_EQ(rejection(*rx, sent[68]), ErrorCode::ReplayDetected);
    ASSERT_TRUE(rx->on_inbound(sent[6]).has_value());    // 70 - 7 = 63 < w: last slot
    EXPECT_EQ(rejection(*rx, sent[5]), ErrorCode::ReplayDetected);  // 70 - 6 = 64 = w
    static_assert(ReplayGuard::kWindowSize == 64);
}

// --------------------------------------------------------------- mode policy ---

TEST_F(Acceptance, ModePolicyRejectsValidModesItDoesNotAccept) {
    auto rx = receiver();  // accepts Encrypt only
    auto tx = sender(kSensor1, {.protection = PayloadProtection::AuthenticateOnly});
    const auto readable = seal(*tx, kTopic1);
    EXPECT_EQ(rejection(*rx, readable), ErrorCode::ProtectionNotAccepted);
    ASSERT_TRUE(rx->set_accepted({PayloadProtection::Encrypt, PayloadProtection::AuthenticateOnly})
                    .has_value());
    EXPECT_TRUE(rx->on_inbound(readable).has_value());

    // Relabelling the mode without the key: the mode is in the AAD.
    auto relabelled = seal(*sender(kSensor2), kTopic2);
    relabelled.payload[3] = std::byte{2};
    EXPECT_EQ(rejection(*rx, relabelled), ErrorCode::AuthenticationFailed);
}

// ------------------------------------------------------ key → topic with %u ---

TEST_F(Acceptance, KeyTopicRestrictionUsesTheOwner) {
    auto rx = receiver();
    auto tx1 = sender(kSensor1);
    EXPECT_TRUE(rx->on_inbound(seal(*tx1, kTopic1)).has_value());
    EXPECT_TRUE(rx->on_inbound(seal(*tx1, "restricted/actuators/sensor-1/state")).has_value());
    EXPECT_EQ(rejection(*rx, seal(*tx1, kTopic2)), ErrorCode::PermissionDenied);
    EXPECT_EQ(rejection(*rx, seal(*tx1, "open/other/sensor-1")), ErrorCode::PermissionDenied);
}

// --------------------------------------------- temporal validity, Δa and Δs ---

TEST_F(Acceptance, ValidityLimitsAreInclusive) {
    auto rx = receiver({.enforce_replay_protection = false});
    auto tx = sender(kSensor1);
    const auto at_limit = seal(*tx, kTopic1);
    const auto past_limit = seal(*tx, kTopic1);
    clock_->advance(60s);                                  // age = Δa exactly
    EXPECT_TRUE(rx->on_inbound(at_limit).has_value());
    clock_->advance(1ms);                                  // age = Δa + 1 ms
    EXPECT_EQ(rejection(*rx, past_limit), ErrorCode::MessageExpired);

    auto ahead = std::make_shared<test::FakeClock>(clock_->now() + 5s);      // Δs exactly
    auto too_far = std::make_shared<test::FakeClock>(clock_->now() + 5001ms);
    EXPECT_TRUE(rx->on_inbound(seal(*sender(kSensor1, {}, ahead), kTopic1)).has_value());
    EXPECT_EQ(rejection(*rx, seal(*sender(kSensor1, {}, too_far), kTopic1)),
              ErrorCode::MessageExpired);
}

TEST_F(Acceptance, ValidityCanBeTightenedPerFlow) {
    // Commands to actuators: 5 s old at most, 1 s of skew; telemetry keeps 60 s / 5 s.
    auto rx = receiver({.freshness_rules = {{.filter = "+/actuators/#",
                                             .max_message_age = 5s,
                                             .max_clock_skew = 1s}}});
    auto tx = sender(kSensor1);
    const auto command = seal(*tx, "open/actuators/sensor-1/cmd");
    const auto reading = seal(*tx, kTopic1);
    clock_->advance(6s);
    EXPECT_EQ(rejection(*rx, command), ErrorCode::MessageExpired);
    EXPECT_TRUE(rx->on_inbound(reading).has_value());

    auto ahead = std::make_shared<test::FakeClock>(clock_->now() + 2s);
    auto early = sender(kSensor2, {}, ahead);  // another key: its own sequence numbers
    EXPECT_EQ(rejection(*rx, seal(*early, "open/actuators/sensor-2/cmd")),
              ErrorCode::MessageExpired);
    EXPECT_TRUE(rx->on_inbound(seal(*early, kTopic2)).has_value());
}

TEST_F(Acceptance, InvalidPerFlowRulesAreRefused) {
    EXPECT_FALSE(try_receiver({.freshness_rules = {{.filter = "a/#/b",
                                                    .max_message_age = 5s,
                                                    .max_clock_skew = 1s}}})
                     .has_value());
    EXPECT_FALSE(try_receiver({.freshness_rules = {{.filter = "a/#",
                                                    .max_message_age = 0s,
                                                    .max_clock_skew = 1s}}})
                     .has_value());
}

// ------------------------------------------------ dependencies (no silent no-op) ---

TEST_F(Acceptance, KeyBindingWithoutAPolicyIsRefused) {
    const SecurityDependencies no_policy{.cipher = cipher_, .key_store = receiver_keys_,
                                         .random = rng_, .clock = clock_};
    EXPECT_EQ(failure(SecurityLayer::create({}, no_policy)), ErrorCode::InvalidArgument);
    auto layer = SecurityLayer::create({.enforce_key_binding = false}, no_policy);
    ASSERT_TRUE(layer.has_value());
    EXPECT_EQ(failure((*layer)->set_enforce_key_binding(true)), ErrorCode::InvalidState);
    EXPECT_FALSE((*layer)->config().enforce_key_binding);
}

TEST_F(Acceptance, EpochStoreWithoutAStrideIsRefused) {
    auto store = std::make_shared<MemoryEpochStore>();
    auto layer = SecurityLayer::create({}, {.cipher = cipher_,
                                            .key_store = receiver_keys_,
                                            .random = rng_,
                                            .clock = clock_,
                                            .authorization = policy_,
                                            .epoch_store = store});
    EXPECT_EQ(failure(layer), ErrorCode::InvalidArgument);
}

// ------------------------------------------------------ restart: a new epoch ---

TEST_F(Acceptance, AfterARestartOnlyALaterEpochIsAccepted) {
    auto store = std::make_shared<MemoryEpochStore>();
    auto old_sender = sender(kSensor1);  // epoch 0
    const auto seen = seal(*old_sender, kTopic1);
    {
        auto before = receiver({}, store);
        EXPECT_EQ(before->minimum_epoch(), 0U);
        ASSERT_TRUE(before->on_inbound(seen).has_value());
        ASSERT_TRUE(before->on_inbound(seal(*old_sender, kTopic1)).has_value());
        EXPECT_EQ(store->value, 0U);
        EXPECT_EQ(store->saves, 1);  // once per epoch, not per message
    }
    // Restart: the replay window is empty, but the recorded epoch is not.
    auto after = receiver({}, store);
    EXPECT_EQ(after->minimum_epoch(), 1U);
    EXPECT_EQ(rejection(*after, seen), ErrorCode::ReplayDetected);
    EXPECT_EQ(rejection(*after, seal(*old_sender, kTopic1)), ErrorCode::ReplayDetected);

    // Senders resume once they rotate to epoch 1.
    auto rotated = sender(kStride + kSensor1);
    EXPECT_TRUE(after->on_inbound(seal(*rotated, kTopic1)).has_value());
    EXPECT_EQ(store->value, 1U);
}

TEST_F(Acceptance, EpochStorageFailuresFailClosed) {
    auto store = std::make_shared<MemoryEpochStore>();
    store->fail_save = true;
    auto rx = receiver({}, store);
    EXPECT_EQ(rejection(*rx, seal(*sender(kSensor1), kTopic1)), ErrorCode::StorageFailure);
    EXPECT_FALSE(store->value.has_value());
    store->fail_load = true;
    EXPECT_EQ(failure(try_receiver({}, store)), ErrorCode::StorageFailure);
}

TEST(FileEpochStore, RoundTripMissingAndCorrupt) {
    const auto dir = std::filesystem::temp_directory_path() /
                     std::format("msec-epoch-{}", ::testing::UnitTest::GetInstance()->random_seed());
    std::filesystem::create_directories(dir);
    const auto path = dir / "epoch";
    FileEpochStore store{path};
    auto missing = store.load();
    ASSERT_TRUE(missing.has_value());
    EXPECT_FALSE(missing->has_value());

    ASSERT_TRUE(store.save(41).has_value());
    ASSERT_TRUE(store.save(42).has_value());
    EXPECT_EQ(*store.load(), 42U);
    EXPECT_FALSE(std::filesystem::exists(path.string() + ".tmp"));

    std::ofstream{path} << "not a number\n";
    EXPECT_EQ(failure(store.load()), ErrorCode::StorageFailure);
    std::filesystem::remove_all(dir);
}

}  // namespace
}  // namespace msec::security
