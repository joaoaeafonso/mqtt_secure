#pragma once

#include "msec/core/bytes.hpp"
#include "msec/core/error.hpp"

namespace msec::security {

/// Cryptographically secure random number generator.
class IRandomSource {
public:
    IRandomSource() = default;
    virtual ~IRandomSource() = default;
    IRandomSource(const IRandomSource&) = delete;
    IRandomSource& operator=(const IRandomSource&) = delete;
    IRandomSource(IRandomSource&&) = delete;
    IRandomSource& operator=(IRandomSource&&) = delete;

    [[nodiscard]] virtual Status fill(MutableByteView out) = 0;
};

}  // namespace msec::security
