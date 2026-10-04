#include "msec/security/openssl/random_source.hpp"

#include <openssl/rand.h>

#include <climits>

namespace msec::security::openssl {

Status RandomSource::fill(MutableByteView out) {
    if (out.empty()) {
        return {};
    }
    if (out.size() > static_cast<std::size_t>(INT_MAX)) {
        return make_error(ErrorCode::InvalidArgument, "random request too large");
    }
    if (RAND_bytes(reinterpret_cast<unsigned char*>(out.data()),  // NOLINT
                   static_cast<int>(out.size())) != 1) {
        return make_error(ErrorCode::CryptoFailure, "RAND_bytes failed");
    }
    return {};
}

}  // namespace msec::security::openssl
