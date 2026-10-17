// LD_PRELOAD shim: makes any dynamically linked OpenSSL program (mosquitto,
// msec_load_gateway via Paho) write its TLS session secrets to $SSLKEYLOGFILE
// in the NSS key log format, so Wireshark can decrypt captures of the lab.
//
//   SSLKEYLOGFILE=/tmp/keys LD_PRELOAD=.../libmsec_sslkeylog.so mosquitto -c ...
//
// Neither Mosquitto 2.0 nor Paho C exposes a key-log option, and OpenSSL 3.0
// does not read SSLKEYLOGFILE itself. Wrapping SSL_new is enough: OpenSSL
// reads the keylog callback from the SSL_CTX each time it derives a secret, so
// installing it on the context of every new connection catches TLS 1.2 and
// 1.3, client and server side.
//
// TEST USE ONLY. The secrets decrypt everything captured.

#include <dlfcn.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <unistd.h>

#include <cstdlib>
#include <cstring>
#include <string>

namespace {

using SslNew = SSL* (*)(SSL_CTX*);

// One write() per line on an O_APPEND descriptor: lines from the broker, the
// gateway and the Python clients never interleave mid-line.
void write_line(const SSL* /*ssl*/, const char* line) {
    const char* path = std::getenv("SSLKEYLOGFILE");  // NOLINT(concurrency-mt-unsafe): read-only
    if (path == nullptr || *path == '\0') {
        return;
    }
    const int fd = ::open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);  // NOLINT
    if (fd < 0) {
        return;
    }
    std::string text{line};
    text += '\n';
    if (::write(fd, text.data(), text.size()) < 0) {
        // Nothing sensible to do inside OpenSSL's callback; the line is lost.
    }
    (void)::close(fd);
}

SslNew real_ssl_new() {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): dlsym returns void*
    static const auto real = reinterpret_cast<SslNew>(::dlsym(RTLD_NEXT, "SSL_new"));
    return real;
}

}  // namespace

extern "C" SSL* SSL_new(SSL_CTX* ctx) {
    const SslNew real = real_ssl_new();
    if (real == nullptr) {
        return nullptr;
    }
    if (ctx != nullptr && SSL_CTX_get_keylog_callback(ctx) == nullptr) {
        SSL_CTX_set_keylog_callback(ctx, write_line);
    }
    return real(ctx);
}
