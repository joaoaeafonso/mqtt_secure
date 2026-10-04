// End-to-end cost of each security level over the in-process loopback broker:
//
//   sensor.publish ─▶ [sensor pipeline] ─▶ broker ─▶ [gateway pipeline] ─▶ app handler
//
// The loopback transport is synchronous, so one iteration is one complete
// publish → deliver round trip, and the numbers isolate the CPU cost of the
// layers themselves (no network, no TLS; see the README for what is left out).
//
// Before timing, each profile is also attacked once (eavesdrop, replay,
// tamper, topic rebinding, plaintext injection). The results are reported as
// 0/1 counters next to the timings, so every row shows both what a level costs
// and what it buys.

#include <benchmark/benchmark.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
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

constexpr security::KeyId kKeyId = 1;
constexpr std::string_view kTopic = "sensors/room1/temp";

enum class Persistence : std::uint8_t {
    None,
    Plaintext,  // [persistence, security]: stores decrypted messages
    AtRest,     // [security, persistence]: stores protected envelopes
};

struct Profile {
    std::string_view name;
    std::optional<security::SecurityConfig> security;  // nullopt: no security layer
    Persistence persistence{Persistence::None};
};

using security::PayloadProtection;
using security::SecurityConfig;

constexpr SecurityConfig kAeadOnly{.protection = PayloadProtection::Encrypt,
                                   .enforce_freshness = false,
                                   .enforce_replay_protection = false};

// Ordered from no protection to full protection; each step adds one guarantee.
const std::array kProfiles{
    Profile{.name = "0_baseline", .security = std::nullopt},
    Profile{.name = "1_persistence_only",
            .security = std::nullopt,
            .persistence = Persistence::Plaintext},
    Profile{.name = "2_auth_only",
            .security = SecurityConfig{.protection = PayloadProtection::AuthenticateOnly,
                                       .enforce_freshness = false,
                                       .enforce_replay_protection = false}},
    Profile{.name = "3_aead", .security = kAeadOnly},
    Profile{.name = "4_aead_freshness",
            .security = SecurityConfig{.enforce_freshness = true,
                                       .enforce_replay_protection = false}},
    Profile{.name = "5_aead_replay",
            .security = SecurityConfig{.enforce_freshness = false,
                                       .enforce_replay_protection = true}},
    Profile{.name = "6_full", .security = SecurityConfig{}},
    Profile{.name = "7_full_persist_plain",
            .security = SecurityConfig{},
            .persistence = Persistence::Plaintext},
    Profile{.name = "8_full_persist_at_rest",
            .security = SecurityConfig{},
            .persistence = Persistence::AtRest},
};

constexpr std::array<std::int64_t, 4> kPayloadSizes{16, 256, 4 * 1024, 64 * 1024};

template <typename T>
T unwrap(Result<T> result) {
    if (!result) {
        throw std::runtime_error{result.error().message};
    }
    return std::move(*result);
}

void unwrap(const Status& status) {
    if (!status) {
        throw std::runtime_error{status.error().message};
    }
}

/// Everything a single benchmark run needs: shared crypto dependencies, a
/// sensor endpoint (outbound pipeline) and a gateway endpoint (inbound pipeline).
class Testbed {
public:
    explicit Testbed(const Profile& profile) {
        SecureBuffer key{cipher_->key_size()};
        unwrap(rng_->fill(key.mutable_view()));
        unwrap(keys_->add(kKeyId, std::move(key)));

        sensor_.emplace(mqtt::LoopbackClient::create(broker_), make_pipeline(profile, false),
                        logger_);
        gateway_.emplace(mqtt::LoopbackClient::create(broker_), make_pipeline(profile, true),
                         logger_);
        gateway_->on_message([this](const Message& m) {
            ++delivered_;
            benchmark::DoNotOptimize(m.payload.data());
        });
        unwrap(sensor_->start({.client_id = "sensor"}));
        unwrap(gateway_->start({.client_id = "gateway"}));
        unwrap(gateway_->subscribe("sensors/#", QoS::AtLeastOnce));
    }

    [[nodiscard]] mqtt::Endpoint& sensor() { return *sensor_; }
    [[nodiscard]] std::uint64_t delivered() const noexcept { return delivered_; }
    [[nodiscard]] std::uint64_t rejected() const { return gateway_->stats().rejected_inbound; }
    [[nodiscard]] std::shared_ptr<mqtt::LoopbackBroker> broker() const { return broker_; }

private:
    Pipeline make_pipeline(const Profile& profile, bool is_gateway) {
        Pipeline::Builder builder;
        const bool persist = is_gateway && profile.persistence != Persistence::None;
        auto persistence = [&] {
            return unwrap(data::PersistenceLayer::create(repository_, clock_));
        };
        if (persist && profile.persistence == Persistence::Plaintext) {
            builder.add(persistence());
        }
        if (profile.security) {
            SecurityConfig config = *profile.security;
            config.sending_key_id = kKeyId;
            builder.add(unwrap(security::SecurityLayer::create(
                config, {.cipher = cipher_, .key_store = keys_, .random = rng_, .clock = clock_})));
        }
        if (persist && profile.persistence == Persistence::AtRest) {
            builder.add(persistence());
        }
        return unwrap(builder.build());
    }

    std::shared_ptr<ILogger> logger_ = std::make_shared<NullLogger>();
    std::shared_ptr<const IClock> clock_ = std::make_shared<SystemClock>();
    std::shared_ptr<security::openssl::AesGcmCipher> cipher_ =
        std::make_shared<security::openssl::AesGcmCipher>();
    std::shared_ptr<security::openssl::RandomSource> rng_ =
        std::make_shared<security::openssl::RandomSource>();
    std::shared_ptr<security::InMemoryKeyStore> keys_ =
        std::make_shared<security::InMemoryKeyStore>();
    std::shared_ptr<data::InMemoryMessageRepository> repository_ =
        std::make_shared<data::InMemoryMessageRepository>(1'000);
    std::shared_ptr<mqtt::LoopbackBroker> broker_ = mqtt::LoopbackBroker::create();

    std::optional<mqtt::Endpoint> sensor_;
    std::optional<mqtt::Endpoint> gateway_;
    std::uint64_t delivered_{0};
};

Message make_message(std::size_t payload_size) {
    Bytes payload(payload_size);
    for (std::size_t i = 0; i < payload.size(); ++i) {
        payload[i] = static_cast<std::byte>(i * 31U + 7U);
    }
    return Message{.topic = unwrap(Topic::create(kTopic)), .payload = std::move(payload)};
}

struct Probe {
    std::size_t wire_bytes{0};
    bool hides_payload{false};
    bool blocks_replay{false};
    bool blocks_tamper{false};
    bool blocks_rebind{false};
    bool blocks_injection{false};
};

/// Records one message as an attacker with broker access would see it, then
/// re-publishes modified copies and checks whether the gateway rejected each.
Probe probe(Testbed& bed, const Message& sample) {
    auto attacker = mqtt::LoopbackClient::create(bed.broker());
    unwrap(attacker->connect({.client_id = "mallory"}));
    std::vector<Message> captured;
    attacker->set_message_handler([&](Message m) { captured.push_back(std::move(m)); });
    unwrap(attacker->subscribe("sensors/#", QoS::AtMostOnce));
    unwrap(bed.sensor().publish(sample));
    unwrap(bed.sensor().publish(sample));
    unwrap(bed.sensor().publish(sample));
    attacker->set_message_handler({});
    if (captured.size() != 3) {
        throw std::runtime_error{"attacker did not observe traffic"};
    }

    Probe result{.wire_bytes = captured[0].payload.size()};
    result.hides_payload = std::ranges::search(captured[0].payload, sample.payload).empty();

    auto blocked = [&](const Message& attack) {
        const auto before = bed.rejected();
        unwrap(attacker->publish(attack));
        return bed.rejected() > before;
    };
    result.blocks_replay = blocked(captured[0]);

    Message tampered = captured[1];
    tampered.payload.back() ^= std::byte{0x01};
    result.blocks_tamper = blocked(tampered);

    Message moved = captured[2];
    moved.topic = unwrap(Topic::create("sensors/room2/temp"));
    result.blocks_rebind = blocked(moved);

    result.blocks_injection = blocked(make_message(sample.payload.size()));
    (void)attacker->disconnect();
    return result;
}

void run_profile(benchmark::State& state, const Profile& profile) {
    const auto payload_size = static_cast<std::size_t>(state.range(0));
    Testbed bed{profile};
    const Message sample = make_message(payload_size);
    const Probe security = probe(bed, sample);

    const std::uint64_t delivered_before = bed.delivered();
    for (auto _ : state) {
        if (auto ok = bed.sensor().publish(sample); !ok) {
            state.SkipWithError(ok.error().message);
            return;
        }
    }
    const auto delivered = bed.delivered() - delivered_before;
    if (delivered != static_cast<std::uint64_t>(state.iterations())) {
        state.SkipWithError("not every message reached the application");
        return;
    }

    state.SetItemsProcessed(state.iterations());
    state.SetBytesProcessed(state.iterations() * state.range(0));
    using benchmark::Counter;
    state.counters["wire_B"] = Counter(static_cast<double>(security.wire_bytes));
    state.counters["overhead_B"] =
        Counter(static_cast<double>(security.wire_bytes) - static_cast<double>(payload_size));
    state.counters["confid"] = security.hides_payload ? 1.0 : 0.0;
    state.counters["replay"] = security.blocks_replay ? 1.0 : 0.0;
    state.counters["tamper"] = security.blocks_tamper ? 1.0 : 0.0;
    state.counters["rebind"] = security.blocks_rebind ? 1.0 : 0.0;
    state.counters["inject"] = security.blocks_injection ? 1.0 : 0.0;
}

}  // namespace

int main(int argc, char** argv) {
    for (const auto& profile : kProfiles) {
        auto* bench = benchmark::RegisterBenchmark(std::string{profile.name},
                                                   [&profile](benchmark::State& state) {
                                                       run_profile(state, profile);
                                                   });
        for (const auto size : kPayloadSizes) {
            bench->Arg(size);
        }
        bench->ArgName("payload");
    }
    benchmark::Initialize(&argc, argv);
    if (benchmark::ReportUnrecognizedArguments(argc, argv)) {
        return 1;
    }
    benchmark::RunSpecifiedBenchmarks();
    benchmark::Shutdown();
    return 0;
}
