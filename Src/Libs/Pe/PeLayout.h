#pragma once

#include "PeImage.h"

namespace pevm::pe {

struct SectionLayout {
    std::uint32_t VirtualAddress{}, VirtualSize{}, RawOffset{}, RawSize{};
};

// Value-only plan: it remains valid after the source vector is resized.
struct AppendLayout {
    std::size_t NtOffset{}, SectionTableOffset{};
    std::uint16_t OriginalSectionCount{};
    std::uint32_t FileSize{}, ImageSize{}, InitializedDataSize{};
    std::vector<SectionLayout> Sections;
};

// Computes every extent before the caller mutates or allocates output.
// Sections are initialized data, in the same raw and virtual order.
AppendLayout PlanAppendSections(const ImageView& Image, std::span<const std::uint64_t> Sizes);

} // namespace pevm::pe
