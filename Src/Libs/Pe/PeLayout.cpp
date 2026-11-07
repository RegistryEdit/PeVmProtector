#include "PeLayout.h"

#include <algorithm>
#include <limits>
#include <stdexcept>

namespace pevm::pe {
namespace {
std::uint32_t Narrow(std::uint64_t Value) {
    if (Value > std::numeric_limits<std::uint32_t>::max())
        throw std::runtime_error("appended PE layout exceeds 32-bit limits");
    return static_cast<std::uint32_t>(Value);
}
std::uint32_t Align(std::uint64_t Value, std::uint32_t Alignment) {
    // Narrow first so even a uint64_t input cannot wrap the rounding addition.
    const auto Bounded = Narrow(Value);
    return Narrow((std::uint64_t{Bounded} + Alignment - 1) / Alignment * Alignment);
}
}

AppendLayout PlanAppendSections(const ImageView& Image, std::span<const std::uint64_t> Sizes) {
    if (Sizes.empty() || Sizes.size() > 96U - Image.Info().Sections)
        throw std::runtime_error("invalid appended PE section count");
    AppendLayout Plan;
    Plan.NtOffset = Image.NtOffset();
    Plan.SectionTableOffset = Plan.NtOffset + 24 + Image.OptionalHeaderSize();
    Plan.OriginalSectionCount = Image.Info().Sections;
    const auto NewHeaders = Plan.SectionTableOffset + std::size_t{Plan.OriginalSectionCount} * 40;
    const auto HeaderBytes = Sizes.size() * 40;
    if (NewHeaders > Image.SizeOfHeaders() || HeaderBytes > Image.SizeOfHeaders() - NewHeaders)
        throw std::runtime_error("PE headers have no room for appended sections");
    const auto Padding = Image.FileBytes().subspan(NewHeaders, HeaderBytes);
    if (std::any_of(Padding.begin(), Padding.end(), [](auto Byte) { return Byte != 0; }))
        throw std::runtime_error("appended section headers would overwrite existing header data");
    // Rewriting a signed template would leave an invalid Authenticode claim.
    if (Image.Directory(4).Address != 0 || Image.Directory(4).Size != 0)
        throw std::runtime_error("signed PE templates are unsupported; use an unsigned template");

    auto RawEnd = Narrow(Image.FileBytes().size());
    auto VirtualEnd = Image.SizeOfImage();
    auto Initialized = Image.SizeOfInitializedData();
    Plan.Sections.reserve(Sizes.size());
    for (const auto Size : Sizes) {
        if (Size == 0) throw std::runtime_error("cannot append an empty PE section");
        SectionLayout Section;
        Section.VirtualSize = Narrow(Size);
        Section.RawSize = Align(Size, Image.FileAlignment());
        Section.RawOffset = Align(RawEnd, Image.FileAlignment());
        Section.VirtualAddress = Align(VirtualEnd, Image.SectionAlignment());
        if (Image.SectionAlignment() < 4096) {
            // Low-alignment images require equal raw offsets and RVAs.
            Section.RawOffset = Section.VirtualAddress = std::max(Section.RawOffset, Section.VirtualAddress);
        }
        RawEnd = Narrow(std::uint64_t{Section.RawOffset} + Section.RawSize);
        VirtualEnd = Align(std::uint64_t{Section.VirtualAddress} +
                           std::max(Section.VirtualSize, Section.RawSize), Image.SectionAlignment());
        Initialized = Narrow(std::uint64_t{Initialized} + Section.RawSize);
        Plan.Sections.push_back(Section);
    }
    Plan.FileSize = RawEnd;
    Plan.ImageSize = VirtualEnd;
    Plan.InitializedDataSize = Initialized;
    return Plan;
}
} // namespace pevm::pe
