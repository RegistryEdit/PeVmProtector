#pragma once

#include "PeImage.h"

namespace pevm::pe {

// Validate the complete on-disk x64 base-relocation table before any writes.
// Returned DIR64 target RVAs are owned values, so fixups cannot mutate the
// records still being traversed. ABSOLUTE padding entries produce no target.
std::vector<std::uint32_t> RelocationTargets(const ImageView& Image);

} // namespace pevm::pe
