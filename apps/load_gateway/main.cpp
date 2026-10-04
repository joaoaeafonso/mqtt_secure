// Gateway for load tests against a real broker (e.g. Mosquitto) fed by the
// Python mock sensors in tools/loadgen.
//
//   sensors.py ─▶ mosquitto ─▶ PahoClient ─▶ [persistence?] ◀ [security?] ─▶ stats
//
// Sensors put their send time (u64 big-endian, ns since the Unix epoch) in the
// first 8 bytes of the plaintext, so end-to-end latency is measured after the
// pipeline has run (decryption included). Sensors and gateway must share a clock,
// i.e. run on the same host.
//
// Prints a line per --report interval while traffic flows, "READY" once
// subscribed, and a JSON summary on exit (SIGINT/SIGTERM or --duration).

#include <sys/resource.h>

#include <algorithm>
#include <atomic>
#include <charconv>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <format>
#include <fstream>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "msec/core/clock.hpp"
#include "msec/core/logger.hpp"
#include "msec/data/in_memory_repository.hpp"
#include "msec/data/persistence_layer.hpp"
#include "msec/mqtt/endpoint.hpp"
#include "msec/mqtt/paho/paho_client.hpp"
#include "msec/security/key_store.hpp"
#include "msec/security/openssl/aes_gcm_cipher.hpp"
#include "msec/security/openssl/random_source.hpp"
#include "msec/security/security_layer.hpp"

namespace {

using namespace msec;
using Clock = std::chrono::steady_clock;

std::atomic<bool> g_stop{false};

extern "C" void handle_signal(int /*signal*/) { g_stop.store(true); }

[[noreturn]] void die(std::string_view message) {
    std::fputs(std::format("load_gateway: {}\n", message).c_str(), stderr);
    std::exit(EXIT_FAILURE);  // NOLINT(concurrency-mt-unsafe): startup only
}

template <typename T>
T require(Result<T> result, std::string_view what) {
    if (!result) {
        die(std::format("{}: {}", what, result.error().message));
    }
    return std::move(*result);
}

void require(const Status& status, std::string_view what) {
    if (!status) {
        die(std::format("{}: {}", what, status.error().message));
    }
}

// ---------------------------------------------------------------- options ---

enum class Persistence : std::uint8_t { None, Plaintext, AtRest };

struct Options {
    std::string broker{"tcp://127.0.0.1:18830"};
    std::string client_id{"gateway"};
    std::string username{"gateway"};
    std::string profile{"full"};
    Persistence persistence{Persistence::None};
    std::string keys_file{};
    std::vector<std::string> subscriptions{};
    QoS qos{QoS::AtMostOnce};
    std::chrono::milliseconds report{1000};
    std::chrono::seconds duration{0};  // 0: until SIGINT/SIGTERM
    std::string json_out{};            // empty: summary to stdout
    bool verbose{false};
};

constexpr std::string_view kUsage = R"(usage: msec_load_gateway [options]
  --broker URI          broker URI (default tcp://127.0.0.1:18830)
  --client-id ID        MQTT client id (default gateway)
  --username NAME       MQTT username, used by the broker ACL (default gateway)
  --profile P           none | auth_only | aead | aead_freshness | aead_replay | full
  --persistence P       none | plain | at-rest              (default none)
  --keys FILE           key file from `loadgen.py keys` (required unless --profile none)
  --subscribe FILTER    repeatable (default open/# and restricted/sensors/#)
  --qos N               subscription QoS 0|1|2              (default 0)
  --report MS           progress line interval              (default 1000)
  --duration S          stop after S seconds                (default: on SIGINT)
  --json FILE           write the summary there instead of stdout
  --verbose             log every rejected message
)";

int parse_int(std::string_view text, std::string_view flag) {
    int value = 0;
    const auto [end, ec] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (ec != std::errc{} || end != text.data() + text.size() || value < 0) {
        die(std::format("{} expects a non-negative integer, got '{}'", flag, text));
    }
    return value;
}

Options parse_options(int argc, char** argv) {
    Options options;
    const std::vector<std::string_view> args(argv + 1, argv + argc);
    for (std::size_t i = 0; i < args.size(); ++i) {
        const std::string_view flag = args[i];
        if (flag == "--help" || flag == "-h") {
            std::fputs(kUsage.data(), stdout);
            std::exit(EXIT_SUCCESS);  // NOLINT(concurrency-mt-unsafe)
        }
        if (flag == "--verbose") {
            options.verbose = true;
            continue;
        }
        if (i + 1 >= args.size()) {
            die(std::format("{} needs a value\n{}", flag, kUsage));
        }
        const std::string value{args[++i]};
        if (flag == "--broker") {
            options.broker = value;
        } else if (flag == "--client-id") {
            options.client_id = value;
        } else if (flag == "--username") {
            options.username = value;
        } else if (flag == "--profile") {
            options.profile = value;
        } else if (flag == "--persistence") {
            if (value == "none") {
                options.persistence = Persistence::None;
            } else if (value == "plain") {
                options.persistence = Persistence::Plaintext;
            } else if (value == "at-rest") {
                options.persistence = Persistence::AtRest;
            } else {
                die(std::format("unknown persistence '{}'", value));
            }
        } else if (flag == "--keys") {
            options.keys_file = value;
        } else if (flag == "--subscribe") {
            options.subscriptions.push_back(value);
        } else if (flag == "--qos") {
            const int qos = parse_int(value, flag);
            if (qos > 2) {
                die("--qos must be 0, 1 or 2");
            }
            options.qos = static_cast<QoS>(qos);
        } else if (flag == "--report") {
            options.report = std::chrono::milliseconds{parse_int(value, flag)};
        } else if (flag == "--duration") {
            options.duration = std::chrono::seconds{parse_int(value, flag)};
        } else if (flag == "--json") {
            options.json_out = value;
        } else {
            die(std::format("unknown option '{}'\n{}", flag, kUsage));
        }
    }
    if (options.subscriptions.empty()) {
        options.subscriptions = {"open/#", "restricted/sensors/#"};
    }
    return options;
}

/// Same profile names as benchmarks/pipeline_benchmarks.cpp.
std::optional<security::SecurityConfig> security_profile(std::string_view name) {
    using security::PayloadProtection;
    using security::SecurityConfig;
    if (name == "none") {
        return std::nullopt;
    }
    if (name == "auth_only") {
        return SecurityConfig{.protection = PayloadProtection::AuthenticateOnly,
                              .enforce_freshness = false,
                              .enforce_replay_protection = false};
    }
    if (name == "aead") {
        return SecurityConfig{.enforce_freshness = false, .enforce_replay_protection = false};
    }
    if (name == "aead_freshness") {
        return SecurityConfig{.enforce_freshness = true, .enforce_replay_protection = false};
    }
    if (name == "aead_replay") {
        return SecurityConfig{.enforce_freshness = false, .enforce_replay_protection = true};
    }
    if (name == "full") {
        return SecurityConfig{};
    }
    die(std::format("unknown profile '{}'", name));
}

// ------------------------------------------------------------------- keys ---

std::optional<std::byte> hex_nibble(char c) {
    if (c >= '0' && c <= '9') {
        return static_cast<std::byte>(c - '0');
    }
    if (c >= 'a' && c <= 'f') {
        return static_cast<std::byte>(c - 'a' + 10);
    }
    if (c >= 'A' && c <= 'F') {
        return static_cast<std::byte>(c - 'A' + 10);
    }
    return std::nullopt;
}

/// "<key id> <hex key>" per line; '#' starts a comment. Returns the number of keys.
std::size_t load_keys(const std::string& path, security::InMemoryKeyStore& store,
                      std::size_t key_size) {
    std::ifstream in{path};
    if (!in) {
        die(std::format("cannot open key file '{}'", path));
    }
    std::size_t count = 0;
    std::string line;
    for (int line_no = 1; std::getline(in, line); ++line_no) {
        std::istringstream fields{line};
        std::string id_text;
        std::string hex;
        if (!(fields >> id_text) || id_text.starts_with('#')) {
            continue;
        }
        fields >> hex;
        const auto id = static_cast<security::KeyId>(parse_int(id_text, "key id"));
        if (hex.size() != key_size * 2) {
            die(std::format("{}:{}: key must be {} hex characters", path, line_no, key_size * 2));
        }
        Bytes raw(key_size);
        for (std::size_t i = 0; i < key_size; ++i) {
            const auto hi = hex_nibble(hex[2 * i]);
            const auto lo = hex_nibble(hex[2 * i + 1]);
            if (!hi || !lo) {
                die(std::format("{}:{}: invalid hex", path, line_no));
            }
            raw[i] = (*hi << 4U) | *lo;
        }
        require(store.add(id, SecureBuffer{raw}), std::format("{}:{}", path, line_no));
        secure_zero(raw);
        ++count;
    }
    return count;
}

// ------------------------------------------------------------------ stats ---

double cpu_seconds() {
    rusage usage{};
    getrusage(RUSAGE_SELF, &usage);
    auto seconds = [](const timeval& tv) {
        return static_cast<double>(tv.tv_sec) + static_cast<double>(tv.tv_usec) / 1e6;
    };
    return seconds(usage.ru_utime) + seconds(usage.ru_stime);
}

std::int64_t unix_ns() {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

/// Latency samples (µs) and payload bytes, fed from Paho's callback thread.
class Stats {
public:
    void record(const Message& message) {
        const auto now = Clock::now();
        std::optional<double> latency_us;
        if (message.payload.size() >= 8) {
            std::uint64_t sent_ns = 0;
            for (std::size_t i = 0; i < 8; ++i) {
                sent_ns = (sent_ns << 8U) | std::to_integer<std::uint64_t>(message.payload[i]);
            }
            latency_us = static_cast<double>(unix_ns() - static_cast<std::int64_t>(sent_ns)) / 1e3;
        }
        const std::scoped_lock lock{mutex_};
        if (!first_) {
            first_ = now;
            cpu_at_first_ = cpu_seconds();
        }
        last_ = now;
        ++messages_;
        bytes_ += message.payload.size();
        if (latency_us) {
            interval_.push_back(*latency_us);
            all_.push_back(*latency_us);
        }
    }

    struct Snapshot {
        std::uint64_t messages{0};
        std::uint64_t bytes{0};
        std::vector<double> latencies_us;
        std::optional<Clock::time_point> first;
        Clock::time_point last;
        double cpu_at_first{0};
    };

    /// Totals so far; moves out the latency samples gathered since the last call.
    Snapshot take_interval() {
        const std::scoped_lock lock{mutex_};
        return {messages_, bytes_, std::exchange(interval_, {}), first_, last_, cpu_at_first_};
    }

    Snapshot total() {
        const std::scoped_lock lock{mutex_};
        return {messages_, bytes_, all_, first_, last_, cpu_at_first_};
    }

private:
    std::mutex mutex_;
    std::uint64_t messages_{0};
    std::uint64_t bytes_{0};
    std::vector<double> interval_;
    std::vector<double> all_;
    std::optional<Clock::time_point> first_;
    Clock::time_point last_;
    double cpu_at_first_{0};
};

double percentile(std::vector<double>& samples, double p) {
    if (samples.empty()) {
        return 0;
    }
    const auto rank = static_cast<std::size_t>(p * static_cast<double>(samples.size() - 1));
    std::ranges::nth_element(samples, samples.begin() + static_cast<std::ptrdiff_t>(rank));
    return samples[rank];
}

class RejectionLogger final : public ILogger {
public:
    explicit RejectionLogger(bool verbose) : console_{LogLevel::Warn}, verbose_{verbose} {}
    void log(LogLevel level, std::string_view component,
             std::string_view message) noexcept override {
        if (verbose_ || level >= LogLevel::Error) {
            console_.log(level, component, message);
        }
    }

private:
    ConsoleLogger console_;
    bool verbose_;
};

}  // namespace

int main(int argc, char** argv) {
    const Options options = parse_options(argc, argv);
    const auto security_config = security_profile(options.profile);

    auto logger = std::make_shared<RejectionLogger>(options.verbose);
    auto clock = std::make_shared<SystemClock>();
    auto cipher = std::make_shared<security::openssl::AesGcmCipher>();
    auto keys = std::make_shared<security::InMemoryKeyStore>();
    auto repository = std::make_shared<data::InMemoryMessageRepository>(10'000);

    std::size_t key_count = 0;
    if (security_config) {
        if (options.keys_file.empty()) {
            die("--keys is required for this profile");
        }
        key_count = load_keys(options.keys_file, *keys, cipher->key_size());
        if (key_count == 0) {
            die("key file is empty");
        }
    }

    Pipeline::Builder builder;
    auto persistence = [&] {
        return require(data::PersistenceLayer::create(repository, clock), "persistence");
    };
    if (options.persistence == Persistence::Plaintext) {
        builder.add(persistence());
    }
    if (security_config) {
        auto config = *security_config;
        config.max_tracked_senders = std::max(config.max_tracked_senders, key_count);
        builder.add(require(
            security::SecurityLayer::create(
                config, {.cipher = cipher,
                         .key_store = keys,
                         .random = std::make_shared<security::openssl::RandomSource>(),
                         .clock = clock}),
            "security"));
    }
    if (options.persistence == Persistence::AtRest) {
        builder.add(persistence());
    }

    Stats stats;
    msec::mqtt::Endpoint gateway{std::make_shared<msec::mqtt::paho::PahoClient>(),
                                 require(builder.build(), "pipeline"), logger};
    gateway.on_message([&](const Message& m) { stats.record(m); });

    require(gateway.start({.broker_uri = options.broker,
                           .client_id = options.client_id,
                           .username = options.username.empty()
                                           ? std::nullopt
                                           : std::optional{options.username}}),
            std::format("connect to {}", options.broker));
    for (const auto& filter : options.subscriptions) {
        require(gateway.subscribe(filter, options.qos), std::format("subscribe '{}'", filter));
    }

    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);
    std::fputs(std::format("READY profile={} keys={} subscriptions={}\n", options.profile,
                           key_count, options.subscriptions.size())
                   .c_str(),
               stderr);

    const auto started = Clock::now();
    auto last_report = started;
    std::uint64_t last_messages = 0;
    double last_cpu = cpu_seconds();
    while (!g_stop.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds{50});
        const auto now = Clock::now();
        if (options.duration.count() > 0 && now - started >= options.duration) {
            break;
        }
        if (options.report.count() == 0 || now - last_report < options.report) {
            continue;
        }
        auto snap = stats.take_interval();
        const double secs = std::chrono::duration<double>(now - last_report).count();
        const double cpu = cpu_seconds();
        if (snap.messages != last_messages) {
            const auto ep = gateway.stats();
            std::fputs(std::format("rx {:>9.0f} msg/s  delivered {:>10}  rejected {:>6}  "
                                   "lat p50 {:>8.0f}us p99 {:>8.0f}us  cpu {:>5.1f}%\n",
                                   static_cast<double>(snap.messages - last_messages) / secs,
                                   ep.delivered, ep.rejected_inbound,
                                   percentile(snap.latencies_us, 0.50),
                                   percentile(snap.latencies_us, 0.99),
                                   100.0 * (cpu - last_cpu) / secs)
                           .c_str(),
                       stderr);
        }
        last_report = now;
        last_messages = snap.messages;
        last_cpu = cpu;
    }

    const double cpu_end = cpu_seconds();
    (void)gateway.stop();
    auto total = stats.total();
    const auto ep = gateway.stats();
    const double active_s =
        total.first ? std::chrono::duration<double>(total.last - *total.first).count() : 0.0;
    const double cpu_used = total.first ? cpu_end - total.cpu_at_first : 0.0;
    // N messages span N-1 inter-arrival gaps.
    const auto rate = [&](double count) { return active_s > 0 ? (count - 1) / active_s : 0.0; };

    const std::string summary = std::format(
        R"({{"profile":"{}","persistence":"{}","received":{},"delivered":{},"rejected":{},)"
        R"("active_s":{:.3f},"msg_per_s":{:.1f},"payload_mib_per_s":{:.3f},)"
        R"("latency_us":{{"p50":{:.1f},"p90":{:.1f},"p99":{:.1f},"p999":{:.1f},"max":{:.1f}}},)"
        R"("cpu_s":{:.3f},"cpu_pct":{:.1f},"cpu_us_per_msg":{:.2f}}})",
        options.profile,
        options.persistence == Persistence::None        ? "none"
        : options.persistence == Persistence::Plaintext ? "plain"
                                                        : "at-rest",
        ep.delivered + ep.rejected_inbound, ep.delivered, ep.rejected_inbound, active_s,
        rate(static_cast<double>(total.messages)),
        total.messages > 1 ? rate(static_cast<double>(total.messages)) *
                                 static_cast<double>(total.bytes) /
                                 static_cast<double>(total.messages) / (1024.0 * 1024.0)
                           : 0.0,
        percentile(total.latencies_us, 0.50), percentile(total.latencies_us, 0.90),
        percentile(total.latencies_us, 0.99), percentile(total.latencies_us, 0.999),
        total.latencies_us.empty() ? 0.0 : std::ranges::max(total.latencies_us), cpu_used,
        active_s > 0 ? 100.0 * cpu_used / active_s : 0.0,
        total.messages > 0 ? 1e6 * cpu_used / static_cast<double>(total.messages) : 0.0);

    if (options.json_out.empty()) {
        std::puts(summary.c_str());
    } else {
        std::ofstream{options.json_out} << summary << '\n';
    }
    return EXIT_SUCCESS;
}
