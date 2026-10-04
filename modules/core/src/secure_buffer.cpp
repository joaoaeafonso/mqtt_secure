#include "msec/core/secure_buffer.hpp"

#include <atomic>
#include <utility>

namespace msec {

void secure_zero(MutableByteView data) noexcept {
    // Writes through a volatile pointer cannot be removed as dead stores.
    volatile std::byte* ptr = data.data();
    for (std::size_t i = 0; i < data.size(); ++i) {
        ptr[i] = std::byte{0};
    }
    std::atomic_signal_fence(std::memory_order_seq_cst);
}

SecureBuffer::SecureBuffer(std::size_t size) : data_(size, std::byte{0}) {}

SecureBuffer::SecureBuffer(ByteView data) : data_(data.begin(), data.end()) {}

SecureBuffer::~SecureBuffer() { secure_zero(data_); }

SecureBuffer::SecureBuffer(SecureBuffer&& other) noexcept : data_{std::move(other.data_)} {
    other.data_.clear();
}

SecureBuffer& SecureBuffer::operator=(SecureBuffer&& other) noexcept {
    if (this != &other) {
        secure_zero(data_);
        data_ = std::move(other.data_);
        other.data_.clear();
    }
    return *this;
}

}  // namespace msec
