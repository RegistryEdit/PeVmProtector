#pragma once

#include "PeVmCrypto.h"
#include <cstdint>

namespace pevm::pe {

struct ReleaseImageStats {
    std::uint32_t DebugRecords{};
    std::uint64_t DebugBytes{};
    std::uint32_t CoffSymbols{};
    std::uint64_t CoffBytes{};
};

// Sanitizes a carrier image before layout, integrity tags and encryption are
// finalized. File size, section layout and all runtime RVAs stay unchanged.
// Unknown debug records and extended DLL characteristics are preserved.
// Validation completes before any byte is changed; unsafe ranges are rejected.
ReleaseImageStats StripDebugMetadata(crypto::Bytes& Image);

} // namespace pevm::pe
