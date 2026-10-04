#pragma once

#include <cstdint>

namespace msec::security {

/// Identifies a key (and, by convention, the single sender that owns it).
using KeyId = std::uint32_t;

}  // namespace msec::security
