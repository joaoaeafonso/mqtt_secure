#pragma once

#include "msec/security/random_source.hpp"

namespace msec::security::openssl {

/// CSPRNG backed by OpenSSL RAND_bytes.
class RandomSource final : public IRandomSource {
public:
    [[nodiscard]] Status fill(MutableByteView out) override;
};

}  // namespace msec::security::openssl
