#pragma once

#include <cstddef>

#include "msec/core/bytes.hpp"

namespace msec {

/// Overwrites memory with zeros in a way the optimiser may not elide.
void secure_zero(MutableByteView data) noexcept;

/// Owning buffer for secrets (keys, passwords).
///  - zeroed on destruction and on move-assignment
///  - non-copyable, so secrets are never silently duplicated
///  - fixed size after construction (no reallocation leaving stale copies)
class SecureBuffer final {
public:
    SecureBuffer() = default;
    explicit SecureBuffer(std::size_t size);
    explicit SecureBuffer(ByteView data);
    ~SecureBuffer();

    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;
    SecureBuffer(SecureBuffer&& other) noexcept;
    SecureBuffer& operator=(SecureBuffer&& other) noexcept;

    [[nodiscard]] ByteView view() const noexcept { return data_; }
    [[nodiscard]] MutableByteView mutable_view() noexcept { return data_; }
    [[nodiscard]] std::size_t size() const noexcept { return data_.size(); }
    [[nodiscard]] bool empty() const noexcept { return data_.empty(); }

private:
    Bytes data_;
};

}  // namespace msec
