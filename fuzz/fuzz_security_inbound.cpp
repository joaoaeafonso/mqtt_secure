// The whole inbound security path on arbitrary payloads, accepting every
// protection mode, with key binding on. Nothing an attacker sends may crash it,
// and without the keys nothing may be accepted: forging an AES-GCM tag or an
// Ed25519 signature by chance is not something a fuzzer can do.
#include <cstdint>
#include <cstdlib>
#include <memory>

#include "msec/core/clock.hpp"
#include "msec/security/key_policy.hpp"
#include "msec/security/key_store.hpp"
#include "msec/security/openssl/aes_gcm_cipher.hpp"
#include "msec/security/openssl/ed25519_signer.hpp"
#include "msec/security/openssl/random_source.hpp"
#include "msec/security/security_layer.hpp"

namespace {

using namespace msec;
using namespace msec::security;

class FixedClock final : public IClock {
public:
    [[nodiscard]] std::chrono::system_clock::time_point now() const noexcept override {
        return std::chrono::system_clock::time_point{std::chrono::milliseconds{1'700'000'000'123}};
    }
};

std::unique_ptr<SecurityLayer> make_layer() {
    auto aead = std::make_shared<InMemoryKeyStore>();
    auto pub = std::make_shared<InMemoryKeyStore>();
    auto policy = std::make_shared<KeyTopicPolicy>();
    for (KeyId id : {0U, 7U}) {
        (void)aead->add(id, SecureBuffer{Bytes(32, std::byte{0x42})});
        (void)pub->add(id, SecureBuffer{Bytes(32, std::byte{0x17})});
        (void)policy->set_owner(id, "sensor-7");
    }
    (void)policy->allow_pattern("+/sensors/%u/#");
    auto layer = SecurityLayer::create(
        {.accept = ProtectionSet{PayloadProtection::Encrypt, PayloadProtection::AuthenticateOnly,
                                 PayloadProtection::Sign}},
        {.cipher = std::make_shared<openssl::AesGcmCipher>(),
         .key_store = aead,
         .random = std::make_shared<openssl::RandomSource>(),
         .clock = std::make_shared<FixedClock>(),
         .signer = std::make_shared<openssl::Ed25519Signer>(),
         .verify_keys = pub,
         .authorization = policy});
    if (!layer) {
        std::abort();
    }
    return std::move(*layer);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    static const auto layer = make_layer();
    static const auto topic = *Topic::create("open/sensors/sensor-7/temp");
    const ByteView input = std::as_bytes(std::span{data, size});
    const auto result = layer->on_inbound(Message{.topic = topic, .payload = {input.begin(), input.end()}});
    if (result) {
        std::abort();  // accepted a message nobody with the key produced
    }
    return 0;
}
