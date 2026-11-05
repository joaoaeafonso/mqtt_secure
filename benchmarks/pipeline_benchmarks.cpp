// End-to-end cost of each security level over the in-process loopback broker:
//
//   sensor.publish ─▶ [sensor pipeline] ─▶ broker (ACL?) ─▶ [gateway pipeline] ─▶ app handler
//                                                       └─▶ eavesdropper subscribed to '#'
//
// Two axes:
//   zone     where the traffic flows: a broker without ACL, the `open/` zone
//            (ACL allows everyone) or the `restricted/` zone (ACL allows only
//            the sensor to publish and the gateway to read)
//   profile  which payload-security / persistence layers the pipelines run
//
// The loopback transport is synchronous, so one iteration is one complete
// publish → deliver round trip, and the numbers isolate the CPU cost of the
// layers themselves (no network, no TLS; see the README for what is left out).
// An eavesdropper ("mallory") stays subscribed to '#' during the timed loop,
// so fan-out to a wildcard subscriber is part of the cost wherever the ACL
// lets it through.
//
// Before timing, each run is also attacked once (eavesdrop, replay, tamper,
// topic rebinding, plaintext injection). The results are reported as counters
// next to the timings, so every row shows both what a level costs and what it buys.

#include <benchmark/benchmark.h>

#if defined(__GLIBC__)
#include <malloc.h>
#endif

#include <algorithm>
#include <cstdlib>
#include <array>
#include <cstdint>
#include <format>
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
#include "msec/mqtt/access_control.hpp"
#include "msec/mqtt/endpoint.hpp"
#include "msec/mqtt/loopback_broker.hpp"
#include "msec/security/key_policy.hpp"
#include "msec/security/key_store.hpp"
#include "msec/security/openssl/aes_gcm_cipher.hpp"
#include "msec/security/openssl/chacha20_poly1305_cipher.hpp"
#include "msec/security/openssl/ed25519_signer.hpp"
#include "msec/security/openssl/random_source.hpp"
#include "msec/security/security_layer.hpp"

namespace {

using namespace msec;

constexpr security::KeyId kKeyId = 1;
constexpr std::string_view kSensorId = "sensor-1";
constexpr std::string_view kGatewayId = "gateway";
constexpr std::string_view kAttackerId = "mallory";

// ------------------------------------------------------------------ zones ---

struct Zone {
    std::string_view name;
    bool acl;
    std::string_view prefix;  // first topic level
};

const std::array kZones{
    Zone{.name = "noacl", .acl = false, .prefix = "open"},
    Zone{.name = "open", .acl = true, .prefix = "open"},
    Zone{.name = "restricted", .acl = true, .prefix = "restricted"},
};

// --------------------------------------------------------------- profiles ---

enum class Persistence : std::uint8_t {
    None,
    Plaintext,  // [persistence, security]: stores decrypted messages
    AtRest,     // [security, persistence]: stores protected envelopes
};

struct Profile {
    std::string_view name;
    std::optional<security::SecurityConfig> security;  // nullopt: no security layer
    Persistence persistence{Persistence::None};
    bool key_binding{false};  // a key → topic policy is installed
    security::AeadAlgorithm aead{security::AeadAlgorithm::Aes256Gcm};  // the key's algorithm
};

using security::PayloadProtection;
using security::SecurityConfig;

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
    Profile{.name = "3_aead",
            .security = SecurityConfig{.enforce_freshness = false,
                                       .enforce_replay_protection = false}},
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
    Profile{.name = "9_sign", .security = SecurityConfig{.protection = PayloadProtection::Sign}},
    Profile{.name = "10_full_key_binding", .security = SecurityConfig{}, .key_binding = true},
    // Report level K11 (payload part): K7/K8's envelope with ChaCha20-Poly1305
    // keys. Compare with 10_full_key_binding, also under OPENSSL_armcap=0.
    Profile{.name = "11_full_key_binding_chacha20",
            .security = SecurityConfig{},
            .key_binding = true,
            .aead = security::AeadAlgorithm::ChaCha20Poly1305},
};

constexpr std::array<std::int64_t, 4> kPayloadSizes{16, 256, 4 * 1024, 64 * 1024};

// ---------------------------------------------------------------- helpers ---

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

/// open/#       anyone may publish and read
/// restricted/  only sensor-1 publishes (its own room), only the gateway reads
mqtt::AccessControlList make_acl() {
    mqtt::AccessControlList acl;
    unwrap(acl.allow_all("open/#", mqtt::Access::ReadWrite));
    unwrap(acl.allow(std::string{kSensorId}, "restricted/sensors/room1/#", mqtt::Access::Write));
    unwrap(acl.allow(std::string{kGatewayId}, "restricted/sensors/#", mqtt::Access::Read));
    return acl;
}

Topic zone_topic(const Zone& zone, std::string_view room) {
    return unwrap(Topic::create(std::format("{}/sensors/{}/temp", zone.prefix, room)));
}

Message make_message(const Zone& zone, std::size_t payload_size) {
    Bytes payload(payload_size);
    for (std::size_t i = 0; i < payload.size(); ++i) {
        payload[i] = static_cast<std::byte>(i * 31U + 7U);
    }
    return Message{.topic = zone_topic(zone, "room1"), .payload = std::move(payload)};
}

// ---------------------------------------------------------------- testbed ---

/// Everything a single benchmark run needs: shared crypto dependencies, a
/// sensor endpoint (outbound pipeline), a gateway endpoint (inbound pipeline)
/// and an eavesdropper subscribed to '#'.
class Testbed {
public:
    Testbed(const Zone& zone, const Profile& profile)
        : profile_{profile},
          broker_{mqtt::LoopbackBroker::create(zone.acl ? std::optional{make_acl()}
                                                        : std::nullopt)} {
        SecureBuffer key{cipher_->key_size()};
        unwrap(rng_->fill(key.mutable_view()));
        unwrap(keys_->add(kKeyId, std::move(key), profile.aead));
        SecureBuffer signing_key{signer_->private_key_size()};
        unwrap(rng_->fill(signing_key.mutable_view()));
        unwrap(verify_keys_->add(kKeyId, SecureBuffer{unwrap(signer_->public_key(signing_key))}));
        unwrap(signing_keys_->add(kKeyId, std::move(signing_key)));
        unwrap(policy_->allow(kKeyId, "+/sensors/room1/#"));

        sensor_.emplace(mqtt::LoopbackClient::create(broker_), make_pipeline(false), logger_);
        gateway_.emplace(mqtt::LoopbackClient::create(broker_), make_pipeline(true), logger_);
        gateway_->on_message([this](const Message& m) {
            ++delivered_;
            benchmark::DoNotOptimize(m.payload.data());
        });
        unwrap(sensor_->start({.client_id = std::string{kSensorId}}));
        unwrap(gateway_->start({.client_id = std::string{kGatewayId}}));
        unwrap(gateway_->subscribe(std::format("{}/sensors/#", zone.prefix), QoS::AtLeastOnce));

        unwrap(attacker_->connect({.client_id = std::string{kAttackerId}}));
        attacker_->set_message_handler([this](Message m) {
            ++eavesdropped_;
            if (recording_) {
                captured_.push_back(std::move(m));
            }
        });
        unwrap(attacker_->subscribe("#", QoS::AtMostOnce));
    }

    /// Builds a fresh pipeline for this profile (gateway side includes persistence).
    Pipeline make_pipeline(bool is_gateway) {
        Pipeline::Builder builder;
        const bool persist = is_gateway && profile_.persistence != Persistence::None;
        auto persistence = [&] {
            return unwrap(data::PersistenceLayer::create(repository_, clock_));
        };
        if (persist && profile_.persistence == Persistence::Plaintext) {
            builder.add(persistence());
        }
        if (profile_.security) {
            SecurityConfig config = *profile_.security;
            config.sending_key_id = kKeyId;
            config.enforce_key_binding = profile_.key_binding;
            builder.add(unwrap(security::SecurityLayer::create(
                config, {.cipher = cipher_,
                         .key_store = keys_,
                         .random = rng_,
                         .clock = clock_,
                         .signer = signer_,
                         .signing_keys = signing_keys_,
                         .verify_keys = verify_keys_,
                         .authorization = profile_.key_binding ? policy_ : nullptr,
                         .more_ciphers = {chacha_}})));
        }
        if (persist && profile_.persistence == Persistence::AtRest) {
            builder.add(persistence());
        }
        return unwrap(builder.build());
    }

    [[nodiscard]] mqtt::Endpoint& sensor() { return *sensor_; }
    [[nodiscard]] mqtt::LoopbackClient& attacker() { return *attacker_; }
    [[nodiscard]] std::uint64_t delivered() const noexcept { return delivered_; }
    [[nodiscard]] std::uint64_t eavesdropped() const noexcept { return eavesdropped_; }
    [[nodiscard]] std::uint64_t rejected() const { return gateway_->stats().rejected_inbound; }

    void record(bool on) { recording_ = on; }
    [[nodiscard]] const std::vector<Message>& captured() const noexcept { return captured_; }

private:
    const Profile& profile_;
    std::shared_ptr<ILogger> logger_ = std::make_shared<NullLogger>();
    std::shared_ptr<const IClock> clock_ = std::make_shared<SystemClock>();
    std::shared_ptr<security::openssl::AesGcmCipher> cipher_ =
        std::make_shared<security::openssl::AesGcmCipher>();
    std::shared_ptr<security::openssl::ChaCha20Poly1305Cipher> chacha_ =
        std::make_shared<security::openssl::ChaCha20Poly1305Cipher>();
    std::shared_ptr<security::openssl::RandomSource> rng_ =
        std::make_shared<security::openssl::RandomSource>();
    std::shared_ptr<security::InMemoryKeyStore> keys_ =
        std::make_shared<security::InMemoryKeyStore>();
    std::shared_ptr<security::openssl::Ed25519Signer> signer_ =
        std::make_shared<security::openssl::Ed25519Signer>();
    std::shared_ptr<security::InMemoryKeyStore> signing_keys_ =
        std::make_shared<security::InMemoryKeyStore>();
    std::shared_ptr<security::InMemoryKeyStore> verify_keys_ =
        std::make_shared<security::InMemoryKeyStore>();
    std::shared_ptr<security::KeyTopicPolicy> policy_ =
        std::make_shared<security::KeyTopicPolicy>();
    std::shared_ptr<data::InMemoryMessageRepository> repository_ =
        std::make_shared<data::InMemoryMessageRepository>(1'000);
    std::shared_ptr<mqtt::LoopbackBroker> broker_;
    std::shared_ptr<mqtt::LoopbackClient> attacker_ = mqtt::LoopbackClient::create(broker_);

    std::optional<mqtt::Endpoint> sensor_;
    std::optional<mqtt::Endpoint> gateway_;
    std::uint64_t delivered_{0};
    std::uint64_t eavesdropped_{0};
    bool recording_{false};
    std::vector<Message> captured_;
};

// ------------------------------------------------------------------ probe ---

struct Probe {
    std::size_t wire_bytes{0};
    bool hides_payload{false};
    bool blocks_replay{false};
    bool blocks_tamper{false};
    bool blocks_rebind{false};
    bool blocks_injection{false};
    int stopped_by_acl{0};  // attacks the broker prevented (no material, or publish denied)
};

/// Lets the eavesdropper record three messages, then re-publishes modified
/// copies and checks whether each attack was stopped, by the broker (ACL) or
/// by the gateway pipeline.
Probe probe(const Zone& zone, Testbed& bed, const Message& sample) {
    Probe result;
    // Measured on a separate pipeline: in the restricted zone the attacker sees nothing.
    result.wire_bytes = unwrap(bed.make_pipeline(false).process_outbound(sample)).payload.size();

    bed.record(true);
    for (int i = 0; i < 3; ++i) {
        unwrap(bed.sensor().publish(sample));
    }
    bed.record(false);
    const auto& captured = bed.captured();

    auto blocked = [&](const Message& attack) {
        const auto before = bed.rejected();
        if (!bed.attacker().publish(attack)) {
            ++result.stopped_by_acl;
            return true;
        }
        return bed.rejected() > before;
    };

    if (captured.size() < 3) {  // ACL kept the traffic away: nothing to replay or modify
        result.hides_payload = true;
        result.blocks_replay = result.blocks_tamper = result.blocks_rebind = true;
        result.stopped_by_acl += 3;
    } else {
        result.hides_payload = std::ranges::search(captured[0].payload, sample.payload).empty();
        result.blocks_replay = blocked(captured[0]);

        Message tampered = captured[1];
        tampered.payload.back() ^= std::byte{0x01};
        result.blocks_tamper = blocked(tampered);

        Message moved = captured[2];
        moved.topic = zone_topic(zone, "room2");
        result.blocks_rebind = blocked(moved);
    }
    result.blocks_injection = blocked(make_message(zone, sample.payload.size()));
    return result;
}

// -------------------------------------------------------------- benchmark ---

void run(benchmark::State& state, const Zone& zone, const Profile& profile) {
    const auto payload_size = static_cast<std::size_t>(state.range(0));
    Testbed bed{zone, profile};
    const Message sample = make_message(zone, payload_size);
    const Probe security = probe(zone, bed, sample);

    const std::uint64_t delivered_before = bed.delivered();
    const std::uint64_t eavesdropped_before = bed.eavesdropped();
    for (auto _ : state) {
        if (auto ok = bed.sensor().publish(sample); !ok) {
            state.SkipWithError(ok.error().message);
            return;
        }
    }
    const auto iterations = static_cast<std::uint64_t>(state.iterations());
    if (bed.delivered() - delivered_before != iterations) {
        state.SkipWithError("not every message reached the application");
        return;
    }
    const auto leaked = bed.eavesdropped() - eavesdropped_before;

    state.SetItemsProcessed(state.iterations());
    state.SetBytesProcessed(state.iterations() * state.range(0));
    auto flag = [](bool on) { return on ? 1.0 : 0.0; };
    state.counters["wire_B"] = static_cast<double>(security.wire_bytes);
    state.counters["overhead_B"] =
        static_cast<double>(security.wire_bytes) - static_cast<double>(payload_size);
    state.counters["leak"] = static_cast<double>(leaked) / static_cast<double>(iterations);
    state.counters["confid"] = flag(security.hides_payload);
    state.counters["replay"] = flag(security.blocks_replay);
    state.counters["tamper"] = flag(security.blocks_tamper);
    state.counters["rebind"] = flag(security.blocks_rebind);
    state.counters["inject"] = flag(security.blocks_injection);
    state.counters["by_acl"] = security.stopped_by_acl;
}

/// With glibc's defaults, freeing the large per-message buffers can shrink the
/// heap and the next round trip faults the pages back in. Whether that happens
/// depends on heap layout left by earlier runs, which made 64 KiB results swing
/// ~3x depending on the --benchmark_filter used. Pinning the allocator makes runs
/// comparable; set MSEC_BENCH_DEFAULT_MALLOC=1 to measure with the defaults.
void pin_allocator() {
#if defined(__GLIBC__)
    if (std::getenv("MSEC_BENCH_DEFAULT_MALLOC") != nullptr) {  // NOLINT(concurrency-mt-unsafe)
        return;
    }
    constexpr int kNeverTrim = 1 << 30;
    constexpr int kNoMmapBelow = 16 * 1024 * 1024;
    mallopt(M_TRIM_THRESHOLD, kNeverTrim);
    mallopt(M_MMAP_THRESHOLD, kNoMmapBelow);
#endif
}

}  // namespace

int main(int argc, char** argv) {
    pin_allocator();
    for (const auto& zone : kZones) {
        for (const auto& profile : kProfiles) {
            auto* bench = benchmark::RegisterBenchmark(
                std::format("{}/{}", zone.name, profile.name),
                [&zone, &profile](benchmark::State& state) { run(state, zone, profile); });
            for (const auto size : kPayloadSizes) {
                bench->Arg(size);
            }
            bench->ArgName("payload");
        }
    }
    benchmark::Initialize(&argc, argv);
    if (benchmark::ReportUnrecognizedArguments(argc, argv)) {
        return 1;
    }
    benchmark::RunSpecifiedBenchmarks();
    benchmark::Shutdown();
    return 0;
}
