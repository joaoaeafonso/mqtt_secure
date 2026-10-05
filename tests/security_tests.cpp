#include <fstream>
#include <map>
#include <memory>
#include <sstream>

#include "msec/security/envelope.hpp"
#include "msec/security/key_policy.hpp"
#include "msec/security/key_store.hpp"
#include "msec/security/openssl/aes_gcm_cipher.hpp"
#include "msec/security/openssl/ed25519_signer.hpp"
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

Bytes from_hex(std::string_view hex) {
    Bytes out;
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
        out.push_back(static_cast<std::byte>(std::stoi(std::string{hex.substr(i, 2)}, nullptr, 16)));
    }
    return out;
}

// ------------------------------------------------------------- envelope ---

TEST(Envelope, RoundTrip) {
    const Envelope original{.header = {.version = 2,
                                       .protection = PayloadProtection::AuthenticateOnly,
                                       .key_id = 7,
                                       .sequence = 42,
                                       .timestamp_ms = -5},
                            .nonce = Bytes(12, std::byte{0xAB}),
                            .ciphertext = to_bytes("ciphertext")};
    const auto wire = envelope::serialize(original);
    ASSERT_TRUE(wire.has_value());
    const auto parsed = envelope::parse(*wire);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->header.protection, PayloadProtection::AuthenticateOnly);
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
    auto bad_mode = wire;
    bad_mode[3] = std::byte{9};
    EXPECT_EQ(envelope::parse(bad_mode).error().code, ErrorCode::MalformedMessage);
    wire.pop_back();  // remove all ciphertext
    EXPECT_FALSE(envelope::parse(wire).has_value());
}

TEST(Envelope, SignaturesNeedNoNonce) {
    const Envelope original{.header = {.protection = PayloadProtection::Sign, .sequence = 1},
                            .ciphertext = to_bytes("payload+signature")};
    const auto parsed = envelope::parse(*envelope::serialize(original));
    ASSERT_TRUE(parsed.has_value());
    EXPECT_TRUE(parsed->nonce.empty());
    EXPECT_EQ(parsed->header.protection, PayloadProtection::Sign);
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

TEST(ReplayGuard, ForgettingAKeyFreesItsSlot) {
    ReplayGuard guard{1};
    EXPECT_TRUE(guard.check_and_record(1, 1).has_value());
    EXPECT_EQ(guard.check_and_record(2, 1).error().code, ErrorCode::CapacityExceeded);
    guard.forget(1);
    EXPECT_TRUE(guard.check_and_record(2, 1).has_value());
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

    std::unique_ptr<SecurityLayer> make_layer(KeyId key, std::shared_ptr<const IClock> clock,
                                              SecurityConfig config = {}) {
        config.sending_key_id = key;
        auto layer = SecurityLayer::create(
            config,
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

TEST_F(SecurityLayerTest, SendingKeyCanBeRotated) {
    ASSERT_TRUE(keys_->add(2, random_key()).has_value());
    sender_->set_sending_key(2);
    const auto wire = protect("sensors/t", "21.5C");
    EXPECT_EQ(envelope::parse(wire.payload)->header.key_id, 2U);
    EXPECT_TRUE(receiver_->on_inbound(wire).has_value());
    // The old key is revoked: whatever an attacker captured or stole with it is dead.
    const auto old = make_layer(1, clock_)->on_outbound(message("sensors/t", "x"));
    ASSERT_TRUE(keys_->revoke(1).has_value());
    receiver_->forget_key(1);
    EXPECT_EQ(receiver_->on_inbound(*old).error().code, ErrorCode::AuthenticationFailed);
}

TEST_F(SecurityLayerTest, SequenceNumbersIncrease) {
    const auto first = envelope::parse(protect("t", "a").payload);
    const auto second = envelope::parse(protect("t", "b").payload);
    ASSERT_TRUE(first.has_value() && second.has_value());
    EXPECT_LT(first->header.sequence, second->header.sequence);
    EXPECT_NE(first->nonce, second->nonce);
}

TEST_F(SecurityLayerTest, AuthenticateOnlyKeepsPayloadReadableButTamperProof) {
    const SecurityConfig config{.protection = PayloadProtection::AuthenticateOnly};
    auto sender = make_layer(1, clock_, config);
    auto receiver = make_layer(1, clock_, config);

    auto wire = sender->on_outbound(message("sensors/t", "21.5C"));
    ASSERT_TRUE(wire.has_value());
    EXPECT_NE(bytes_to_string(wire->payload).find("21.5C"), std::string::npos);

    const auto plain = receiver->on_inbound(*wire);
    ASSERT_TRUE(plain.has_value());
    EXPECT_EQ(bytes_to_string(plain->payload), "21.5C");

    auto tampered = *sender->on_outbound(message("sensors/t", "21.5C"));
    const auto at = bytes_to_string(tampered.payload).find("21.5C");
    tampered.payload[at] ^= std::byte{0x01};
    EXPECT_EQ(receiver->on_inbound(tampered).error().code, ErrorCode::AuthenticationFailed);

    auto moved = *sender->on_outbound(message("sensors/t", "21.5C"));
    moved.topic = test::topic("actuators/door");
    EXPECT_EQ(receiver->on_inbound(moved).error().code, ErrorCode::AuthenticationFailed);
}

TEST_F(SecurityLayerTest, ReceiverPolicyDecidesWhichModesAreAccepted) {
    auto auth_only = make_layer(1, clock_, {.protection = PayloadProtection::AuthenticateOnly});
    const auto from_auth_only = auth_only->on_outbound(message("sensors/t", "21.5C"));
    ASSERT_TRUE(from_auth_only.has_value());
    // A sender (or an attacker with a key) cannot downgrade below the policy.
    EXPECT_EQ(receiver_->on_inbound(*from_auth_only).error().code,
              ErrorCode::ProtectionNotAccepted);
    EXPECT_EQ(auth_only->on_inbound(protect("sensors/t", "21.5C")).error().code,
              ErrorCode::ProtectionNotAccepted);

    // A mixed fleet: accept both.
    ASSERT_TRUE(receiver_->set_accepted({PayloadProtection::Encrypt,
                                         PayloadProtection::AuthenticateOnly})
                    .has_value());
    EXPECT_TRUE(receiver_->on_inbound(*from_auth_only).has_value());
    EXPECT_TRUE(receiver_->on_inbound(protect("sensors/t", "21.5C")).has_value());
}

TEST_F(SecurityLayerTest, ModeFieldIsAuthenticated) {
    ASSERT_TRUE(receiver_->set_accepted({PayloadProtection::Encrypt,
                                         PayloadProtection::AuthenticateOnly})
                    .has_value());
    // Relabel an encrypted message as auth_only: the header is in the AAD.
    auto relabelled = protect("sensors/t", "21.5C");
    relabelled.payload[3] = std::byte{static_cast<std::uint8_t>(PayloadProtection::AuthenticateOnly)};
    EXPECT_EQ(receiver_->on_inbound(relabelled).error().code, ErrorCode::AuthenticationFailed);
}

TEST_F(SecurityLayerTest, ReplayProtectionCanBeDisabled) {
    auto receiver = make_layer(1, clock_, {.enforce_replay_protection = false});
    const auto wire = protect("sensors/t", "21.5C");
    ASSERT_TRUE(receiver->on_inbound(wire).has_value());
    EXPECT_TRUE(receiver->on_inbound(wire).has_value());
}

TEST_F(SecurityLayerTest, FreshnessCheckCanBeDisabled) {
    auto receiver = make_layer(1, clock_, {.enforce_freshness = false});
    const auto wire = protect("sensors/t", "21.5C");
    clock_->advance(61s);
    EXPECT_TRUE(receiver->on_inbound(wire).has_value());
}

TEST_F(SecurityLayerTest, DisabledChecksStillAuthenticate) {
    auto receiver =
        make_layer(1, clock_, {.enforce_freshness = false, .enforce_replay_protection = false});
    auto wire = protect("sensors/t", "21.5C");
    wire.payload.back() ^= std::byte{0x01};
    EXPECT_EQ(receiver->on_inbound(wire).error().code, ErrorCode::AuthenticationFailed);
}

TEST_F(SecurityLayerTest, SwitchesTakeEffectAtRuntime) {
    const auto wire = protect("sensors/t", "21.5C");
    ASSERT_TRUE(receiver_->on_inbound(wire).has_value());

    receiver_->set_enforce_replay_protection(false);
    EXPECT_TRUE(receiver_->on_inbound(wire).has_value());
    EXPECT_FALSE(receiver_->config().enforce_replay_protection);

    // Back on: the window kept its state, so the old message is still a replay.
    receiver_->set_enforce_replay_protection(true);
    EXPECT_EQ(receiver_->on_inbound(wire).error().code, ErrorCode::ReplayDetected);

    ASSERT_TRUE(sender_->set_protection(PayloadProtection::AuthenticateOnly).has_value());
    const auto readable = protect("sensors/t", "21.6C");
    EXPECT_NE(bytes_to_string(readable.payload).find("21.6C"), std::string::npos);
    EXPECT_EQ(receiver_->on_inbound(readable).error().code, ErrorCode::ProtectionNotAccepted);
    ASSERT_TRUE(receiver_->set_protection(PayloadProtection::AuthenticateOnly).has_value());
    EXPECT_TRUE(receiver_->on_inbound(readable).has_value());

    const auto stale = protect("sensors/t", "21.7C");
    clock_->advance(61s);
    EXPECT_EQ(receiver_->on_inbound(stale).error().code, ErrorCode::MessageExpired);
    receiver_->set_enforce_freshness(false);
    EXPECT_TRUE(receiver_->on_inbound(stale).has_value());
}

// ------------------------------------------- cross-language test vectors ---

/// Hands out a fixed byte string, so sealing is deterministic.
class FixedRandom final : public IRandomSource {
public:
    explicit FixedRandom(Bytes bytes) : bytes_{std::move(bytes)} {}
    [[nodiscard]] Status fill(MutableByteView out) noexcept override {
        for (std::size_t i = 0; i < out.size(); ++i) {
            out[i] = bytes_.at(i % bytes_.size());
        }
        return {};
    }

private:
    Bytes bytes_;
};

// tests/vectors/envelope_vectors.txt is produced by the Python sender
// (tools/loadgen/msec_envelope.py); both implementations must agree byte for byte.
TEST(EnvelopeVectors, CxxMatchesPythonByteForByte) {
    std::ifstream in{MSEC_ENVELOPE_VECTORS};
    ASSERT_TRUE(in) << MSEC_ENVELOPE_VECTORS;
    std::map<std::string, std::string> params;
    int vectors = 0;
    for (std::string line; std::getline(in, line);) {
        if (line.empty() || line.starts_with('#')) {
            continue;
        }
        std::istringstream fields{line};
        std::vector<std::string> f;
        for (std::string w; fields >> w;) {
            f.push_back(w);
        }
        if (f.size() == 2) {
            params[f[0]] = f[1];
            continue;
        }
        ASSERT_EQ(f.size(), 6U) << line;
        const auto& [name, mode_text, key_text, topic, payload_hex, envelope_hex] =
            std::tie(f[0], f[1], f[2], f[3], f[4], f[5]);
        const auto key_id = static_cast<KeyId>(std::stoul(key_text));
        const auto mode = mode_text == "encrypt"     ? PayloadProtection::Encrypt
                          : mode_text == "auth_only" ? PayloadProtection::AuthenticateOnly
                                                     : PayloadProtection::Sign;
        const Bytes payload = payload_hex == "-" ? Bytes{} : from_hex(payload_hex);

        auto aead = std::make_shared<InMemoryKeyStore>();
        auto priv = std::make_shared<InMemoryKeyStore>();
        auto pub = std::make_shared<InMemoryKeyStore>();
        const openssl::Ed25519Signer signer;
        const SecureBuffer sign_key{from_hex(params.at("sign_key"))};
        ASSERT_TRUE(aead->add(key_id, SecureBuffer{from_hex(params.at("aead_key"))}).has_value());
        ASSERT_TRUE(pub->add(key_id, SecureBuffer{*signer.public_key(sign_key)}).has_value());
        ASSERT_TRUE(priv->add(key_id, SecureBuffer{sign_key.view()}).has_value());
        auto clock = std::make_shared<test::FakeClock>(std::chrono::system_clock::time_point{
            std::chrono::milliseconds{std::stoll(params.at("timestamp_ms"))}});
        const SecurityDependencies deps{
            .cipher = std::make_shared<openssl::AesGcmCipher>(),
            .key_store = aead,
            .random = std::make_shared<FixedRandom>(from_hex(params.at("nonce"))),
            .clock = clock,
            .signer = std::make_shared<openssl::Ed25519Signer>(),
            .signing_keys = priv,
            .verify_keys = pub};
        auto layer = SecurityLayer::create({.sending_key_id = key_id, .protection = mode}, deps);
        ASSERT_TRUE(layer.has_value()) << name;

        const auto sealed = (*layer)->on_outbound(
            Message{.topic = test::topic(topic), .payload = payload});
        ASSERT_TRUE(sealed.has_value()) << name;
        EXPECT_EQ(sealed->payload, from_hex(envelope_hex)) << name;

        const auto opened = (*layer)->on_inbound(
            Message{.topic = test::topic(topic), .payload = from_hex(envelope_hex)});
        ASSERT_TRUE(opened.has_value()) << name << ": " << opened.error().message;
        EXPECT_EQ(opened->payload, payload) << name;
        ++vectors;
    }
    EXPECT_GE(vectors, 5);
}

TEST(SecurityLayerFactory, RejectsMissingDependencies) {
    EXPECT_FALSE(SecurityLayer::create({}, {}).has_value());
}

// --------------------------------------------------------------- Ed25519 ---

TEST(Ed25519, Rfc8032TestVector1) {
    const openssl::Ed25519Signer signer;
    const SecureBuffer secret{
        from_hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")};
    const auto expected_public =
        from_hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    const auto expected_signature = from_hex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e3970"
        "1cf9b46bd25bf5f0595bbe24655141438e7a100b");

    EXPECT_EQ(*signer.public_key(secret), expected_public);
    const auto signature = signer.sign(secret, {});
    ASSERT_TRUE(signature.has_value());
    EXPECT_EQ(*signature, expected_signature);
    EXPECT_TRUE(signer.verify(expected_public, {}, *signature).has_value());

    auto forged = *signature;
    forged[0] ^= std::byte{0x01};
    EXPECT_EQ(signer.verify(expected_public, {}, forged).error().code,
              ErrorCode::AuthenticationFailed);
    EXPECT_FALSE(signer.verify(expected_public, to_bytes("x"), *signature).has_value());
}

// ------------------------------------------------------- key → topic policy ---

TEST(KeyTopicPolicy, DeniesByDefault) {
    const KeyTopicPolicy policy;
    EXPECT_FALSE(policy.may_publish(1, "sensors/sensor-1/temp"));
}

TEST(KeyTopicPolicy, OwnerPatternBindsKeyToItsOwnSubtree) {
    KeyTopicPolicy policy;
    ASSERT_TRUE(policy.allow_pattern("+/sensors/%u/#").has_value());
    ASSERT_TRUE(policy.set_owner(1, "sensor-1").has_value());
    ASSERT_TRUE(policy.set_owner(7, "sensor-7").has_value());

    EXPECT_TRUE(policy.may_publish(1, "open/sensors/sensor-1/temp"));
    EXPECT_TRUE(policy.may_publish(7, "restricted/sensors/sensor-7/temp"));
    EXPECT_FALSE(policy.may_publish(7, "restricted/sensors/sensor-1/temp"));  // insider
    EXPECT_FALSE(policy.may_publish(9, "open/sensors/sensor-9/temp"));        // no owner

    policy.remove(7);
    EXPECT_FALSE(policy.may_publish(7, "restricted/sensors/sensor-7/temp"));
}

TEST(KeyTopicPolicy, KeyIdPatternAndExplicitRules) {
    KeyTopicPolicy policy;
    ASSERT_TRUE(policy.allow_pattern("devices/%k/#").has_value());
    ASSERT_TRUE(policy.allow(0, "actuators/#").has_value());
    EXPECT_TRUE(policy.may_publish(42, "devices/42/state"));
    EXPECT_FALSE(policy.may_publish(42, "devices/43/state"));
    EXPECT_TRUE(policy.may_publish(0, "actuators/door/cmd"));
    EXPECT_FALSE(policy.may_publish(1, "actuators/door/cmd"));
}

TEST(KeyTopicPolicy, RejectsInvalidRulesAndOwners) {
    KeyTopicPolicy policy;
    EXPECT_FALSE(policy.allow_pattern("a/#/b").has_value());
    EXPECT_FALSE(policy.allow(1, "a+").has_value());
    EXPECT_FALSE(policy.set_owner(1, "a/b").has_value());  // would widen the match
    EXPECT_FALSE(policy.set_owner(1, "#").has_value());
    EXPECT_FALSE(policy.set_owner(1, "").has_value());
}

// ------------------------------------------- signatures, binding in the layer ---

class SignedLayerTest : public ::testing::Test {
protected:
    void SetUp() override {
        const openssl::Ed25519Signer signer;
        auto secret = random_key();
        auto public_key = signer.public_key(secret);
        ASSERT_TRUE(public_key.has_value());
        ASSERT_TRUE(private_keys_->add(1, std::move(secret)).has_value());
        ASSERT_TRUE(public_keys_->add(1, SecureBuffer{*public_key}).has_value());
        ASSERT_TRUE(aead_keys_->add(1, random_key()).has_value());
        ASSERT_TRUE(policy_->allow_pattern("sensors/%u/#").has_value());
        ASSERT_TRUE(policy_->set_owner(1, "sensor-1").has_value());
    }

    std::unique_ptr<SecurityLayer> make(SecurityConfig config, bool with_signing_keys = true) {
        config.sending_key_id = 1;
        auto layer = SecurityLayer::create(
            config, {.cipher = std::make_shared<openssl::AesGcmCipher>(),
                     .key_store = aead_keys_,
                     .random = std::make_shared<openssl::RandomSource>(),
                     .clock = clock_,
                     .signer = std::make_shared<openssl::Ed25519Signer>(),
                     .signing_keys = with_signing_keys ? private_keys_ : nullptr,
                     .verify_keys = public_keys_,
                     .authorization = policy_});
        return layer ? std::move(*layer) : nullptr;
    }

    std::shared_ptr<InMemoryKeyStore> aead_keys_ = std::make_shared<InMemoryKeyStore>();
    std::shared_ptr<InMemoryKeyStore> private_keys_ = std::make_shared<InMemoryKeyStore>();
    std::shared_ptr<InMemoryKeyStore> public_keys_ = std::make_shared<InMemoryKeyStore>();
    std::shared_ptr<KeyTopicPolicy> policy_ = std::make_shared<KeyTopicPolicy>();
    std::shared_ptr<test::FakeClock> clock_ = std::make_shared<test::FakeClock>();
};

TEST_F(SignedLayerTest, SignedPayloadIsReadableVerifiableAndTamperProof) {
    auto sender = make({.protection = PayloadProtection::Sign});
    // The receiver holds only public keys: it can verify but never sign.
    auto receiver = make({.accept = ProtectionSet{PayloadProtection::Sign}},
                         /*with_signing_keys=*/false);
    ASSERT_TRUE(sender && receiver);

    auto wire = sender->on_outbound(message("sensors/sensor-1/t", "21.5C"));
    ASSERT_TRUE(wire.has_value());
    EXPECT_NE(bytes_to_string(wire->payload).find("21.5C"), std::string::npos);
    const auto plain = receiver->on_inbound(*wire);
    ASSERT_TRUE(plain.has_value());
    EXPECT_EQ(bytes_to_string(plain->payload), "21.5C");

    auto tampered = *sender->on_outbound(message("sensors/sensor-1/t", "21.5C"));
    tampered.payload[bytes_to_string(tampered.payload).find("21.5C")] ^= std::byte{0x01};
    EXPECT_EQ(receiver->on_inbound(tampered).error().code, ErrorCode::AuthenticationFailed);

    // Revoking the public key stops the device.
    auto later = *sender->on_outbound(message("sensors/sensor-1/t", "21.6C"));
    ASSERT_TRUE(public_keys_->revoke(1).has_value());
    EXPECT_EQ(receiver->on_inbound(later).error().code, ErrorCode::AuthenticationFailed);
}

TEST_F(SignedLayerTest, SendingSignaturesNeedsPrivateKeys) {
    auto receiver_only = make({.protection = PayloadProtection::Sign}, false);
    EXPECT_EQ(receiver_only, nullptr);
    auto aead = make({});
    ASSERT_TRUE(aead);
    EXPECT_TRUE(aead->set_accepted({PayloadProtection::Sign}).has_value());
    auto no_signer = SecurityLayer::create(
        {.protection = PayloadProtection::Sign},
        {.cipher = std::make_shared<openssl::AesGcmCipher>(), .key_store = aead_keys_,
         .random = std::make_shared<openssl::RandomSource>(), .clock = clock_});
    EXPECT_FALSE(no_signer.has_value());
}

TEST_F(SignedLayerTest, KeyMayOnlyPublishOnItsOwnersTopics) {
    auto sender = make({});
    auto receiver = make({});
    ASSERT_TRUE(sender && receiver);
    // Authentic (key 1 is valid) but on another device's topic: an insider.
    auto foreign = *sender->on_outbound(message("sensors/sensor-2/t", "99"));
    EXPECT_EQ(receiver->on_inbound(foreign).error().code, ErrorCode::PermissionDenied);
    EXPECT_TRUE(
        receiver->on_inbound(*sender->on_outbound(message("sensors/sensor-1/t", "21"))).has_value());

    receiver->set_enforce_key_binding(false);
    EXPECT_TRUE(receiver->on_inbound(foreign).has_value());
}

TEST_F(SignedLayerTest, RejectedBindingDoesNotConsumeTheSequenceNumber) {
    auto sender = make({});
    auto receiver = make({});
    ASSERT_TRUE(sender && receiver);
    auto foreign = *sender->on_outbound(message("sensors/sensor-2/t", "99"));
    EXPECT_EQ(receiver->on_inbound(foreign).error().code, ErrorCode::PermissionDenied);
    receiver->set_enforce_key_binding(false);
    EXPECT_TRUE(receiver->on_inbound(foreign).has_value());  // not recorded as seen before
}

}  // namespace
}  // namespace msec::security
