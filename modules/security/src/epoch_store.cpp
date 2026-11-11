#include "msec/security/epoch_store.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <charconv>
#include <format>
#include <fstream>
#include <memory>
#include <string>
#include <system_error>

namespace msec::security {
namespace {

Status fsync_path(const std::filesystem::path& path, int flags) {
    const int fd = ::open(path.c_str(), flags | O_CLOEXEC);  // NOLINT(cppcoreguidelines-pro-type-vararg)
    if (fd < 0) {
        return make_error(ErrorCode::StorageFailure, std::format("cannot open '{}'", path.string()));
    }
    const bool ok = ::fsync(fd) == 0;
    ::close(fd);
    if (!ok) {
        return make_error(ErrorCode::StorageFailure, std::format("fsync '{}' failed", path.string()));
    }
    return {};
}

}  // namespace

Result<std::optional<std::uint32_t>> FileEpochStore::load() const {
    std::error_code ec;
    if (!std::filesystem::exists(path_, ec)) {
        return std::optional<std::uint32_t>{};
    }
    std::ifstream in{path_};
    if (!in) {
        return make_error(ErrorCode::StorageFailure, std::format("cannot read '{}'", path_.string()));
    }
    std::string text;
    std::getline(in, text);  // one number on the first line
    const auto end = text.find_last_not_of(" \t\r");
    text.erase(end == std::string::npos ? 0 : end + 1);  // drop trailing blanks
    std::uint32_t epoch = 0;
    const char* const last = std::to_address(text.end());
    const auto [ptr, err] = std::from_chars(std::to_address(text.begin()), last, epoch);
    if (err != std::errc{} || ptr != last || text.empty()) {
        // Fail closed: a corrupt record must not silently reset the floor.
        return make_error(ErrorCode::StorageFailure,
                          std::format("'{}' does not hold an epoch number", path_.string()));
    }
    return std::optional{epoch};
}

Status FileEpochStore::save(std::uint32_t epoch) {
    auto tmp = path_;
    tmp += ".tmp";
    {
        std::ofstream out{tmp, std::ios::trunc};
        out << epoch << '\n';
        out.flush();
        if (!out) {
            return make_error(ErrorCode::StorageFailure,
                              std::format("cannot write '{}'", tmp.string()));
        }
    }
    if (auto ok = fsync_path(tmp, O_RDONLY); !ok) {
        return ok;
    }
    std::error_code ec;
    std::filesystem::rename(tmp, path_, ec);
    if (ec) {
        return make_error(ErrorCode::StorageFailure,
                          std::format("cannot replace '{}': {}", path_.string(), ec.message()));
    }
    const auto dir = path_.has_parent_path() ? path_.parent_path() : std::filesystem::path{"."};
    return fsync_path(dir, O_RDONLY | O_DIRECTORY);
}

}  // namespace msec::security
