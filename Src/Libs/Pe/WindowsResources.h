#pragma once

#include <memory>
#include <windows.h>

namespace pevm::platform {

struct VirtualAllocationDeleter {
    void operator()(void* Address) const noexcept {
        if (Address) VirtualFree(Address, 0, MEM_RELEASE);
    }
};

// Owns the base of an entire VirtualAlloc reservation. Subranges must not be
// adopted. A member owner also releases memory if its constructor throws.
using VirtualAllocation = std::unique_ptr<void, VirtualAllocationDeleter>;

} // namespace pevm::platform
