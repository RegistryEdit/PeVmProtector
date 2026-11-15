#pragma once

#include <cstdint>
#include <memory>
#include <span>

namespace pevm::pe {

// DiskImage must come from the caller's authenticated wrapper image. Expected
// executable bytes are reconstructed from disk, including ASLR fixups, before
// the initial loaded-image comparison. The manifest is kept on read-only pages.
class ExecutableImageGuard final {
public:
    ExecutableImageGuard(std::span<const std::uint8_t> DiskImage, const void* LoadedBase);
    ~ExecutableImageGuard();
    ExecutableImageGuard(const ExecutableImageGuard&) = delete;
    ExecutableImageGuard& operator=(const ExecutableImageGuard&) = delete;
    ExecutableImageGuard(ExecutableImageGuard&&) = delete;
    ExecutableImageGuard& operator=(ExecutableImageGuard&&) = delete;

    void Check() const;

private:
    struct State;
    std::unique_ptr<State> Data;
};

} // namespace pevm::pe
