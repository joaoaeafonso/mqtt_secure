// Gateway for load tests against a real broker (Mosquitto), fed by the Python
// mock sensors in tools/loadgen. Every security feature is a setting that can
// be given on the command line and changed while traffic flows:
//
//   transport  plain | tls | mtls     (reconnects to the matching listener)
//   username / password               (broker authentication)
//   protection none | auth_only | encrypt
//   freshness  on | off
//   replay     on | off
//   persistence none | plain | at-rest
//
//   sensors ─▶ mosquitto ─▶ PahoClient ─▶ [persist-plain] ◀ [security] ◀ [persist-at-rest] ─▶ stats
//
// The pipeline is built once with every layer present, each wrapped in a
// SwitchableLayer, so changing a feature never rebuilds or pauses it.
//
// Sensors put their send time (u64 big-endian, ns since the Unix epoch) in the
// first 8 bytes of the plaintext, so latency is measured after the pipeline
// (decryption included); sensors and gateway must share a clock. Payloads with
// "FORGED!!" at offset 8 come from the attacker; re-delivered send times are
// replays. Both are counted when the gateway accepts them, so the effect of
// each switch on attacks is visible.
//
// Control (with --control stdin), one command per line:
//   set <key> <value>   any option below, without the leading "--"
//   reconnect           apply transport/credential settings
//   reset               start a new measurement window
//   summary             print the window's summary as a JSON line
//   quit
//
// Output: "READY" on stderr once started. Every --report interval a stats
// line (JSON on stdout with --stats json, text on stderr otherwise); the
// summary on exit.

#include <sys/resource.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <format>
#include <fstream>
#include <functional>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_set>
#include <vector>

#include "msec/core/clock.hpp"
#include "msec/core/logger.hpp"
#include "msec/core/switchable_layer.hpp"
#include "msec/data/in_memory_repository.hpp"
#include "msec/data/persistence_layer.hpp"
#include "msec/mqtt/endpoint.hpp"
#include "msec/mqtt/paho/paho_client.hpp"
#include "msec/security/key_store.hpp"
#include "msec/security/openssl/aes_gcm_cipher.hpp"
#include "msec/security/openssl/random_source.hpp"
#include "msec/security/security_layer.hpp"

namespace {

using msec::Error;
using msec::ErrorCode;
using msec::make_error;
using msec::Message;
using msec::QoS;
using msec::Result;
using msec::Status;
using Clock = std::chrono::steady_clock;
using namespace std::string_view_literals;

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

void warn(std::string_view message) {
    std::fputs(std::format("load_gateway: {}\n", message).c_str(), stderr);
}

// --------------------------------------------------------------- settings ---

enum class Transport : std::uint8_t { Plain, Tls, MutualTls };
enum class Protection : std::uint8_t { None, AuthOnly, Encrypt };
enum class Persistence : std::uint8_t { None, Plaintext, AtRest };

constexpr std::string_view to_string(Transport t) {
    return t == Transport::Plain ? "plain" : t == Transport::Tls ? "tls" : "mtls";
}
constexpr std::string_view to_string(Protection p) {
    return p == Protection::None ? "none" : p == Protection::AuthOnly ? "auth_only" : "encrypt";
}
constexpr std::string_view to_string(Persistence p) {
    return p == Persistence::None ? "none" : p == Persistence::Plaintext ? "plain" : "at-rest";
}

struct Settings {
    // transport
    std::string host{"127.0.0.1"};
    int port{18830};       // plain listener
    int tls_port{18831};   // TLS, server authenticated
    int mtls_port{18832};  // TLS, client certificate required
    Transport transport{Transport::Plain};
    std::string ca{};
    std::string cert{};
    std::string key{};
    std::string client_id{"gateway"};
    std::string username{"gateway"};
    std::string password{};
    std::vector<std::string> subscriptions{};
    QoS qos{QoS::AtMostOnce};
    // pipeline
    Protection protection{Protection::Encrypt};
    bool freshness{true};
    bool replay{true};
    Persistence persistence{Persistence::None};
    std::string keys_file{};
    // process
    std::chrono::milliseconds report{1000};
    std::chrono::seconds duration{0};  // 0: until SIGINT/SIGTERM/quit
    std::string json_out{};
    bool stats_json{false};
    bool control_stdin{false};
    bool verbose{false};
};

constexpr std::string_view kUsage = R"(usage: msec_load_gateway [--option value]...
transport (applied on connect / `reconnect`):
  --host H              broker host                         (127.0.0.1)
  --port N              plain listener port                 (18830)
  --tls-port N          TLS listener port                   (18831)
  --mtls-port N         mutual-TLS listener port            (18832)
  --transport T         plain | tls | mtls                  (plain)
  --ca FILE             CA certificate (tls, mtls)
  --cert FILE --key FILE  client certificate and key (mtls)
  --client-id ID        (gateway)      --username NAME    (gateway)
  --password PW         or --credentials FILE ("user password" lines)
  --subscribe FILTER    repeatable (default open/# and restricted/sensors/#)
  --qos N               subscription QoS 0|1|2              (0)
pipeline (applied immediately):
  --protection P        none | auth_only | encrypt          (encrypt)
  --freshness on|off    (on)          --replay on|off       (on)
  --persistence P       none | plain | at-rest              (none)
  --profile P           preset: none | auth_only | aead | aead_freshness | aead_replay | full
  --keys FILE           key file ("<key id> <hex>" lines); required unless protection is none
process:
  --report MS           stats interval                      (1000)
  --stats json|text     JSON lines on stdout or text on stderr (text)
  --control stdin       accept `set`/`reconnect`/`reset`/`summary`/`quit` on stdin
  --duration S          stop after S seconds                (until SIGINT)
  --json FILE           write the exit summary there instead of stdout
  --verbose             log every rejected message
)";

Result<int> parse_int(std::string_view text) {
    int value = 0;
    const auto [end, ec] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (ec != std::errc{} || end != text.data() + text.size() || value < 0) {
        return make_error(ErrorCode::InvalidArgument,
                          std::format("expected a non-negative integer, got '{}'", text));
    }
    return value;
}

Result<bool> parse_switch(std::string_view text) {
    if (text == "on" || text == "true" || text == "1") {
        return true;
    }
    if (text == "off" || text == "false" || text == "0") {
        return false;
    }
    return make_error(ErrorCode::InvalidArgument, std::format("expected on|off, got '{}'", text));
}

Result<std::string> read_password(const std::string& path, const std::string& username) {
    std::ifstream in{path};
    if (!in) {
        return make_error(ErrorCode::NotFound, std::format("cannot open '{}'", path));
    }
    std::string line;
    while (std::getline(in, line)) {
        std::istringstream fields{line};
        std::string user;
        std::string password;
        if (fields >> user >> password && user == username) {
            return password;
        }
    }
    return make_error(ErrorCode::NotFound,
                      std::format("no password for '{}' in '{}'", username, path));
}

template <typename Enum, std::size_t N>
Status set_enum(Enum& target, std::string_view value,
                const std::array<std::pair<std::string_view, Enum>, N>& names) {
    for (const auto& [name, e] : names) {
        if (name == value) {
            target = e;
            return {};
        }
    }
    return make_error(ErrorCode::InvalidArgument, std::format("invalid value '{}'", value));
}

Status set_int(int& target, std::string_view value) {
    auto v = parse_int(value);
    if (!v) {
        return std::unexpected{v.error()};
    }
    target = *v;
    return {};
}

Status set_switch(bool& target, std::string_view value) {
    auto v = parse_switch(value);
    if (!v) {
        return std::unexpected{v.error()};
    }
    target = *v;
    return {};
}

Status apply_profile(Settings& s, std::string_view value) {
    // Presets with the names used by benchmarks/pipeline_benchmarks.cpp.
    struct Preset {
        std::string_view name;
        Protection protection;
        bool freshness;
        bool replay;
    };
    constexpr std::array kPresets{
        Preset{"none", Protection::None, false, false},
        Preset{"auth_only", Protection::AuthOnly, false, false},
        Preset{"aead", Protection::Encrypt, false, false},
        Preset{"aead_freshness", Protection::Encrypt, true, false},
        Preset{"aead_replay", Protection::Encrypt, false, true},
        Preset{"full", Protection::Encrypt, true, true},
    };
    const auto* preset = std::ranges::find(kPresets, value, &Preset::name);
    if (preset == kPresets.end()) {
        return make_error(ErrorCode::InvalidArgument, std::format("unknown profile '{}'", value));
    }
    s.protection = preset->protection;
    s.freshness = preset->freshness;
    s.replay = preset->replay;
    return {};
}

/// Applies one option; the single place where option names are defined.
Status apply(Settings& s, std::string_view key, const std::string& value) {
    constexpr std::array kTransports{std::pair{"plain"sv, Transport::Plain},
                                     std::pair{"tls"sv, Transport::Tls},
                                     std::pair{"mtls"sv, Transport::MutualTls}};
    constexpr std::array kProtections{std::pair{"none"sv, Protection::None},
                                      std::pair{"auth_only"sv, Protection::AuthOnly},
                                      std::pair{"encrypt"sv, Protection::Encrypt}};
    constexpr std::array kPersistence{std::pair{"none"sv, Persistence::None},
                                      std::pair{"plain"sv, Persistence::Plaintext},
                                      std::pair{"at-rest"sv, Persistence::AtRest}};
    constexpr std::array kQos{std::pair{"0"sv, QoS::AtMostOnce},
                              std::pair{"1"sv, QoS::AtLeastOnce},
                              std::pair{"2"sv, QoS::ExactlyOnce}};

    if (key == "host") {
        s.host = value;
    } else if (key == "port") {
        return set_int(s.port, value);
    } else if (key == "tls_port") {
        return set_int(s.tls_port, value);
    } else if (key == "mtls_port") {
        return set_int(s.mtls_port, value);
    } else if (key == "transport") {
        return set_enum(s.transport, value, kTransports);
    } else if (key == "ca") {
        s.ca = value;
    } else if (key == "cert") {
        s.cert = value;
    } else if (key == "key") {
        s.key = value;
    } else if (key == "client_id") {
        s.client_id = value;
    } else if (key == "username") {
        s.username = value;
    } else if (key == "password") {
        s.password = value;
    } else if (key == "credentials") {
        auto password = read_password(value, s.username);
        if (!password) {
            return std::unexpected{password.error()};
        }
        s.password = std::move(*password);
    } else if (key == "subscribe") {
        s.subscriptions.push_back(value);
    } else if (key == "qos") {
        return set_enum(s.qos, value, kQos);
    } else if (key == "protection") {
        return set_enum(s.protection, value, kProtections);
    } else if (key == "freshness") {
        return set_switch(s.freshness, value);
    } else if (key == "replay") {
        return set_switch(s.replay, value);
    } else if (key == "persistence") {
        return set_enum(s.persistence, value, kPersistence);
    } else if (key == "profile") {
        return apply_profile(s, value);
    } else if (key == "keys") {
        s.keys_file = value;
    } else if (key == "report") {
        int ms = 0;
        if (auto ok = set_int(ms, value); !ok) {
            return ok;
        }
        s.report = std::chrono::milliseconds{ms};
    } else if (key == "duration") {
        int secs = 0;
        if (auto ok = set_int(secs, value); !ok) {
            return ok;
        }
        s.duration = std::chrono::seconds{secs};
    } else if (key == "json") {
        s.json_out = value;
    } else if (key == "stats") {
        if (value != "json" && value != "text") {
            return make_error(ErrorCode::InvalidArgument, "--stats expects json|text");
        }
        s.stats_json = value == "json";
    } else if (key == "control") {
        if (value != "stdin") {
            return make_error(ErrorCode::InvalidArgument, "--control expects stdin");
        }
        s.control_stdin = true;
    } else {
        return make_error(ErrorCode::InvalidArgument, std::format("unknown option '{}'", key));
    }
    return {};
}

bool is_transport_key(std::string_view key) {
    constexpr std::array kKeys{"host"sv,     "port"sv,     "tls_port"sv,    "mtls_port"sv,
                               "transport"sv, "ca"sv,      "cert"sv,        "key"sv,
                               "client_id"sv, "username"sv, "password"sv,   "credentials"sv,
                               "subscribe"sv, "qos"sv};
    return std::ranges::find(kKeys, key) != kKeys.end();
}

Settings parse_command_line(int argc, char** argv) {
    Settings settings;
    const std::vector<std::string_view> args(argv + 1, argv + argc);
    for (std::size_t i = 0; i < args.size(); ++i) {
        const std::string_view flag = args[i];
        if (flag == "--help" || flag == "-h") {
            std::fputs(kUsage.data(), stdout);
            std::exit(EXIT_SUCCESS);  // NOLINT(concurrency-mt-unsafe)
        }
        if (flag == "--verbose") {
            settings.verbose = true;
            continue;
        }
        if (!flag.starts_with("--") || i + 1 >= args.size()) {
            die(std::format("bad argument '{}'\n{}", flag, kUsage));
        }
        std::string key{flag.substr(2)};
        std::ranges::replace(key, '-', '_');
        if (auto ok = apply(settings, key, std::string{args[++i]}); !ok) {
            die(std::format("--{}: {}\n{}", key, ok.error().message, kUsage));
        }
    }
    if (settings.subscriptions.empty()) {
        settings.subscriptions = {"open/#", "restricted/sensors/#"};
    }
    return settings;
}

msec::mqtt::ConnectionOptions connection_options(const Settings& s) {
    const int port = s.transport == Transport::Plain ? s.port
                     : s.transport == Transport::Tls ? s.tls_port
                                                     : s.mtls_port;
    msec::mqtt::ConnectionOptions options{
        .broker_uri = std::format("{}://{}:{}", s.transport == Transport::Plain ? "tcp" : "ssl",
                                  s.host, port),
        .client_id = s.client_id};
    if (s.transport != Transport::Plain) {
        msec::mqtt::TlsOptions tls{.ca_file = s.ca};
        if (s.transport == Transport::MutualTls) {
            tls.client_cert_file = s.cert;
            tls.client_key_file = s.key;
        }
        options.tls = std::move(tls);
    }
    if (!s.username.empty()) {
        options.username = s.username;
    }
    if (!s.password.empty()) {
        options.password =
            msec::SecureBuffer{std::as_bytes(std::span{s.password.data(), s.password.size()})};
    }
    return options;
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
std::size_t load_keys(const std::string& path, msec::security::InMemoryKeyStore& store,
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
        const auto where = std::format("{}:{}", path, line_no);
        const auto id = static_cast<msec::security::KeyId>(require(parse_int(id_text), where));
        if (hex.size() != key_size * 2) {
            die(std::format("{}: key must be {} hex characters", where, key_size * 2));
        }
        msec::Bytes raw(key_size);
        for (std::size_t i = 0; i < key_size; ++i) {
            const auto hi = hex_nibble(hex[2 * i]);
            const auto lo = hex_nibble(hex[2 * i + 1]);
            if (!hi || !lo) {
                die(std::format("{}: invalid hex", where));
            }
            raw[i] = (*hi << 4U) | *lo;
        }
        require(store.add(id, msec::SecureBuffer{raw}), where);
        msec::secure_zero(raw);
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

double percentile(std::vector<double>& samples, double p) {
    if (samples.empty()) {
        return 0;
    }
    const auto rank = static_cast<std::size_t>(p * static_cast<double>(samples.size() - 1));
    std::ranges::nth_element(samples, samples.begin() + static_cast<std::ptrdiff_t>(rank));
    return samples[rank];
}

constexpr std::size_t kErrorCodes = static_cast<std::size_t>(ErrorCode::Internal) + 1;
constexpr std::string_view kForgedMarker = "FORGED!!";

/// Fed from Paho's callback thread; read by the main loop.
class Stats {
public:
    struct Counters {
        std::uint64_t delivered{0};
        std::uint64_t rejected{0};
        std::uint64_t bytes{0};
        std::uint64_t forged_accepted{0};
        std::uint64_t replays_accepted{0};
        std::array<std::uint64_t, kErrorCodes> rejected_by{};
    };

    struct Window {
        Counters counters;
        std::vector<double> latencies_us;
        std::optional<Clock::time_point> first;
        Clock::time_point last;
        double cpu_at_first{0};
    };

    void delivered(const Message& message) {
        const auto now = Clock::now();
        const auto& payload = message.payload;
        std::optional<std::uint64_t> sent_ns;
        if (payload.size() >= 8) {
            std::uint64_t ns = 0;
            for (std::size_t i = 0; i < 8; ++i) {
                ns = (ns << 8U) | std::to_integer<std::uint64_t>(payload[i]);
            }
            sent_ns = ns;
        }
        const bool forged =
            payload.size() >= 8 + kForgedMarker.size() &&
            std::ranges::equal(std::span{payload}.subspan(8, kForgedMarker.size()),
                               std::as_bytes(std::span{kForgedMarker}));

        const std::scoped_lock lock{mutex_};
        mark_activity(now);
        ++window_.delivered;
        window_.bytes += payload.size();
        if (forged) {
            ++window_.forged_accepted;
            return;
        }
        if (!sent_ns) {
            return;
        }
        const std::uint64_t fingerprint = *sent_ns ^ std::hash<std::string>{}(message.topic.str());
        if (!seen_.insert(fingerprint).second) {
            ++window_.replays_accepted;
            return;
        }
        seen_order_.push_back(fingerprint);
        if (seen_order_.size() > kSeenCapacity) {
            seen_.erase(seen_order_.front());
            seen_order_.pop_front();
        }
        const double latency_us =
            static_cast<double>(unix_ns() - static_cast<std::int64_t>(*sent_ns)) / 1e3;
        interval_latencies_.push_back(latency_us);
        window_latencies_.push_back(latency_us);
    }

    void rejected(const Error& error) {
        const std::scoped_lock lock{mutex_};
        mark_activity(Clock::now());
        ++window_.rejected;
        ++window_.rejected_by.at(static_cast<std::size_t>(error.code));
    }

    /// Counters since the last reset, plus latency samples since the last call.
    std::pair<Counters, std::vector<double>> take_interval() {
        const std::scoped_lock lock{mutex_};
        return {window_, std::exchange(interval_latencies_, {})};
    }

    Window window() {
        const std::scoped_lock lock{mutex_};
        return {window_, window_latencies_, first_, last_, cpu_at_first_};
    }

    void reset() {
        const std::scoped_lock lock{mutex_};
        window_ = {};
        interval_latencies_.clear();
        window_latencies_.clear();
        first_.reset();
    }

private:
    static constexpr std::size_t kSeenCapacity = 1U << 18U;

    void mark_activity(Clock::time_point now) {
        if (!first_) {
            first_ = now;
            cpu_at_first_ = cpu_seconds();
        }
        last_ = now;
    }

    std::mutex mutex_;
    Counters window_;
    std::vector<double> interval_latencies_;
    std::vector<double> window_latencies_;
    std::optional<Clock::time_point> first_;
    Clock::time_point last_;
    double cpu_at_first_{0};
    std::unordered_set<std::uint64_t> seen_;
    std::deque<std::uint64_t> seen_order_;
};

std::string rejected_by_json(const Stats::Counters& c) {
    std::string out = "{";
    for (std::size_t i = 0; i < kErrorCodes; ++i) {
        if (c.rejected_by.at(i) != 0) {
            out += std::format("{}\"{}\":{}", out.size() > 1 ? "," : "",
                               msec::to_string(static_cast<ErrorCode>(i)), c.rejected_by.at(i));
        }
    }
    return out + "}";
}

std::string settings_json(const Settings& s) {
    return std::format(
        R"("transport":"{}","username":"{}","protection":"{}","freshness":{},"replay":{},)"
        R"("persistence":"{}")",
        to_string(s.transport), s.username, to_string(s.protection), s.freshness, s.replay,
        to_string(s.persistence));
}

std::string summary_json(const Settings& settings, Stats::Window w, double cpu_now) {
    const double active_s =
        w.first ? std::chrono::duration<double>(w.last - *w.first).count() : 0.0;
    const double cpu_used = w.first ? cpu_now - w.cpu_at_first : 0.0;
    const auto& c = w.counters;
    const double messages = static_cast<double>(c.delivered + c.rejected);
    // N messages span N-1 inter-arrival gaps.
    const double msg_per_s =
        active_s > 0 ? (static_cast<double>(c.delivered) - 1) / active_s : 0.0;
    auto& lat = w.latencies_us;
    return std::format(
        R"({{"type":"summary",{},"received":{},"delivered":{},"rejected":{},"rejected_by":{},)"
        R"("forged_accepted":{},"replays_accepted":{},"active_s":{:.3f},"msg_per_s":{:.1f},)"
        R"("latency_us":{{"p50":{:.1f},"p90":{:.1f},"p99":{:.1f},"p999":{:.1f},"max":{:.1f}}},)"
        R"("cpu_s":{:.3f},"cpu_pct":{:.1f},"cpu_us_per_msg":{:.2f}}})",
        settings_json(settings), c.delivered + c.rejected, c.delivered, c.rejected,
        rejected_by_json(c), c.forged_accepted, c.replays_accepted, active_s, msg_per_s,
        percentile(lat, 0.50), percentile(lat, 0.90), percentile(lat, 0.99),
        percentile(lat, 0.999), lat.empty() ? 0.0 : std::ranges::max(lat), cpu_used,
        active_s > 0 ? 100.0 * cpu_used / active_s : 0.0,
        messages > 0 ? 1e6 * cpu_used / messages : 0.0);
}

void emit(const std::string& line) {
    std::fputs((line + "\n").c_str(), stdout);
    std::fflush(stdout);
}

class RejectionLogger final : public msec::ILogger {
public:
    explicit RejectionLogger(bool verbose) : console_{msec::LogLevel::Warn}, verbose_{verbose} {}
    void log(msec::LogLevel level, std::string_view component,
             std::string_view message) noexcept override {
        if (verbose_ || level >= msec::LogLevel::Error) {
            console_.log(level, component, message);
        }
    }

private:
    msec::ConsoleLogger console_;
    bool verbose_;
};

/// Reads control commands on a background thread; the main loop drains them.
class CommandQueue {
public:
    void start() {
        std::thread{[this] {
            std::string line;
            while (std::getline(std::cin, line)) {
                const std::scoped_lock lock{mutex_};
                lines_.push_back(line);
            }
            const std::scoped_lock lock{mutex_};
            lines_.emplace_back("quit");  // the controller went away
        }}.detach();
    }

    std::vector<std::string> drain() {
        const std::scoped_lock lock{mutex_};
        return std::exchange(lines_, {});
    }

private:
    std::mutex mutex_;
    std::vector<std::string> lines_;
};

// ---------------------------------------------------------------- gateway ---

/// Owns the endpoint and the switchable layers; applies settings to them.
class Gateway {
public:
    explicit Gateway(Settings settings) : settings_{std::move(settings)} {
        auto clock = std::make_shared<msec::SystemClock>();
        auto cipher = std::make_shared<msec::security::openssl::AesGcmCipher>();
        auto keys = std::make_shared<msec::security::InMemoryKeyStore>();
        auto repository = std::make_shared<msec::data::InMemoryMessageRepository>(10'000);

        std::size_t key_count = 0;
        if (!settings_.keys_file.empty()) {
            key_count = load_keys(settings_.keys_file, *keys, cipher->key_size());
        } else if (settings_.protection != Protection::None || settings_.control_stdin) {
            die("--keys is required (unless --protection none and no --control)");
        }

        msec::security::SecurityConfig config{};
        config.max_tracked_senders = std::max(config.max_tracked_senders, key_count);
        auto security_layer = require(
            msec::security::SecurityLayer::create(
                config, {.cipher = cipher,
                         .key_store = keys,
                         .random = std::make_shared<msec::security::openssl::RandomSource>(),
                         .clock = clock}),
            "security");
        security_ = security_layer.get();

        // Every feature is in the pipeline from the start, switched off until applied.
        auto switchable = [](std::unique_ptr<msec::ILayer> layer, std::string name) {
            return require(msec::SwitchableLayer::create(std::move(layer), false, std::move(name)),
                           "switchable layer");
        };
        auto persistence = [&] {
            return require(msec::data::PersistenceLayer::create(repository, clock), "persistence");
        };
        auto persist_plain = switchable(persistence(), "persistence-plain");
        auto security = switchable(std::move(security_layer), "security");
        auto persist_at_rest = switchable(persistence(), "persistence-at-rest");
        persist_plain_ = persist_plain.get();
        security_switch_ = security.get();
        persist_at_rest_ = persist_at_rest.get();

        msec::Pipeline::Builder builder;
        builder.add(std::move(persist_plain))
            .add(std::move(security))
            .add(std::move(persist_at_rest));
        client_ = std::make_shared<msec::mqtt::paho::PahoClient>();
        endpoint_.emplace(client_, require(builder.build(), "pipeline"),
                          std::make_shared<RejectionLogger>(settings_.verbose));
        endpoint_->on_message([this](const Message& m) { stats_.delivered(m); });
        endpoint_->on_rejected(
            [this](std::string_view /*topic*/, const Error& e) { stats_.rejected(e); });
        apply_pipeline();
        warn(std::format("{} sensor keys loaded", key_count));
    }

    Settings& settings() { return settings_; }
    Stats& stats() { return stats_; }
    [[nodiscard]] bool connected() const { return client_->is_connected(); }

    /// Pushes protection/freshness/replay/persistence into the live pipeline.
    void apply_pipeline() {
        using msec::security::PayloadProtection;
        security_switch_->set_enabled(settings_.protection != Protection::None);
        security_->set_protection(settings_.protection == Protection::AuthOnly
                                      ? PayloadProtection::AuthenticateOnly
                                      : PayloadProtection::Encrypt);
        security_->set_enforce_freshness(settings_.freshness);
        security_->set_enforce_replay_protection(settings_.replay);
        persist_plain_->set_enabled(settings_.persistence == Persistence::Plaintext);
        persist_at_rest_->set_enabled(settings_.persistence == Persistence::AtRest);
    }

    /// (Re)connects with the current transport settings and resubscribes.
    Status connect() {
        (void)endpoint_->stop();
        if (auto ok = endpoint_->start(connection_options(settings_)); !ok) {
            return ok;
        }
        for (const auto& filter : settings_.subscriptions) {
            if (auto ok = endpoint_->subscribe(filter, settings_.qos); !ok) {
                return ok;
            }
        }
        return {};
    }

    void disconnect() { (void)endpoint_->stop(); }

private:
    Settings settings_;
    Stats stats_;
    std::shared_ptr<msec::mqtt::paho::PahoClient> client_;
    std::optional<msec::mqtt::Endpoint> endpoint_;
    msec::security::SecurityLayer* security_{nullptr};
    msec::SwitchableLayer* security_switch_{nullptr};
    msec::SwitchableLayer* persist_plain_{nullptr};
    msec::SwitchableLayer* persist_at_rest_{nullptr};
};

void handle_command(Gateway& gateway, const std::string& line, Clock::time_point& last_connect) {
    auto& settings = gateway.settings();
    std::istringstream in{line};
    std::string verb;
    std::string key;
    std::string value;
    in >> verb >> key;
    std::getline(in >> std::ws, value);
    if (verb == "set") {
        if (key == "subscribe") {
            settings.subscriptions.clear();  // `set subscribe` replaces the list
        }
        if (auto ok = apply(settings, key, value); !ok) {
            warn(std::format("set {}: {}", key, ok.error().message));
        } else if (!is_transport_key(key)) {
            gateway.apply_pipeline();
        }
    } else if (verb == "reconnect") {
        last_connect = Clock::now();
        if (auto ok = gateway.connect(); !ok) {
            warn(std::format("reconnect: {}", ok.error().message));
        }
    } else if (verb == "reset") {
        gateway.stats().reset();
    } else if (verb == "summary") {
        emit(summary_json(settings, gateway.stats().window(), cpu_seconds()));
    } else if (verb == "quit") {
        g_stop.store(true);
    } else if (!verb.empty()) {
        warn(std::format("unknown command '{}'", verb));
    }
}

}  // namespace

int main(int argc, char** argv) {
    Gateway gateway{parse_command_line(argc, argv)};
    const auto& settings = gateway.settings();

    if (auto ok = gateway.connect(); !ok) {
        // With a controller attached, keep running and retry; standalone, fail fast.
        if (!settings.control_stdin) {
            die(std::format("connect: {}", ok.error().message));
        }
        warn(std::format("connect: {} (will retry)", ok.error().message));
    }

    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);
    CommandQueue commands;
    if (settings.control_stdin) {
        commands.start();
    }
    std::fputs(std::format("READY {}\n", settings_json(settings)).c_str(), stderr);

    const auto started = Clock::now();
    auto last_report = started;
    auto last_connect = started;
    std::uint64_t last_received = 0;
    double last_cpu = cpu_seconds();
    while (!g_stop.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds{20});
        const auto now = Clock::now();
        if (settings.duration.count() > 0 && now - started >= settings.duration) {
            break;
        }
        for (const auto& line : commands.drain()) {
            handle_command(gateway, line, last_connect);
        }

        // Keep the session up: the broker drops us when credentials or ACLs
        // change under our feet; reconnect with whatever is configured now.
        if (!gateway.connected() && now - last_connect > std::chrono::seconds{1}) {
            last_connect = now;
            if (auto ok = gateway.connect(); !ok && settings.verbose) {
                warn(std::format("reconnect: {}", ok.error().message));
            }
        }

        if (settings.report.count() == 0 || now - last_report < settings.report) {
            continue;
        }
        auto [counters, latencies] = gateway.stats().take_interval();
        const double secs = std::chrono::duration<double>(now - last_report).count();
        const double cpu = cpu_seconds();
        const std::uint64_t received = counters.delivered + counters.rejected;
        // A `reset` in between restarts the counters from zero.
        const std::uint64_t new_messages =
            received >= last_received ? received - last_received : received;
        const double rx_per_s = static_cast<double>(new_messages) / secs;
        const double cpu_pct = 100.0 * (cpu - last_cpu) / secs;
        const double p50 = percentile(latencies, 0.50);
        const double p99 = percentile(latencies, 0.99);
        if (settings.stats_json) {
            emit(std::format(
                R"({{"type":"stats","connected":{},{},"rx_per_s":{:.1f},"delivered":{},)"
                R"("rejected":{},"rejected_by":{},"forged_accepted":{},"replays_accepted":{},)"
                R"("lat_p50_us":{:.1f},"lat_p99_us":{:.1f},"cpu_pct":{:.1f}}})",
                gateway.connected(), settings_json(settings), rx_per_s, counters.delivered,
                counters.rejected, rejected_by_json(counters), counters.forged_accepted,
                counters.replays_accepted, p50, p99, cpu_pct));
        } else if (new_messages > 0) {
            std::fputs(std::format("rx {:>9.0f} msg/s  delivered {:>10}  rejected {:>6}  "
                                   "lat p50 {:>8.0f}us p99 {:>8.0f}us  cpu {:>5.1f}%\n",
                                   rx_per_s, counters.delivered, counters.rejected, p50, p99,
                                   cpu_pct)
                           .c_str(),
                       stderr);
        }
        last_report = now;
        last_received = received;
        last_cpu = cpu;
    }

    const double cpu_end = cpu_seconds();
    gateway.disconnect();
    const std::string summary = summary_json(settings, gateway.stats().window(), cpu_end);
    if (settings.json_out.empty()) {
        emit(summary);
    } else {
        std::ofstream{settings.json_out} << summary << '\n';
    }
    return EXIT_SUCCESS;
}
