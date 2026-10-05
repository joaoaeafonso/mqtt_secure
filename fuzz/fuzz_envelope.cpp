// envelope::parse on arbitrary bytes: must never crash, and whatever it
// accepts must serialize back to exactly the same bytes.
#include <algorithm>
#include <cstdint>
#include <cstdlib>

#include "msec/security/envelope.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    using namespace msec;
    const ByteView input = std::as_bytes(std::span{data, size});
    const auto parsed = security::envelope::parse(input);
    if (!parsed) {
        return 0;
    }
    const auto wire = security::envelope::serialize(*parsed);
    if (!wire || !std::ranges::equal(*wire, input)) {
        std::abort();  // parse/serialize disagree
    }
    return 0;
}
