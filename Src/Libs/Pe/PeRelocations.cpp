#include "PeRelocations.h"

#include <algorithm>
#include <limits>
#include <stdexcept>

namespace pevm::pe {
namespace {
std::uint32_t Read32(std::span<const std::uint8_t> Bytes, std::size_t At) {
    return std::uint32_t{Bytes[At]} | (std::uint32_t{Bytes[At + 1]} << 8) |
           (std::uint32_t{Bytes[At + 2]} << 16) | (std::uint32_t{Bytes[At + 3]} << 24);
}
}

std::vector<std::uint32_t> RelocationTargets(const ImageView& Image) {
    Image.RequireX64();
    const auto Table = Image.DirectoryBytes(5);
    std::vector<std::uint32_t> Targets;
    std::size_t At = 0;
    while (At < Table.size()) {
        if (Table.size() - At < 8) throw std::runtime_error("truncated relocation block header");
        const auto Page = Read32(Table, At);
        const auto Size = Read32(Table, At + 4);
        if (Size < 8 || Size > Table.size() - At || (Size - 8) % 2 != 0)
            throw std::runtime_error("invalid relocation block size");
        if (Page % 4096 != 0) throw std::runtime_error("unaligned relocation page RVA");
        for (std::size_t EntryAt = At + 8; EntryAt < At + Size; EntryAt += 2) {
            const auto Entry = std::uint16_t{Table[EntryAt]} | (std::uint16_t{Table[EntryAt + 1]} << 8);
            const auto Type = Entry >> 12;
            if (Type == 0) continue;
            if (Type != 10) throw std::runtime_error("unsupported x64 relocation type");
            const auto Target64 = std::uint64_t{Page} + (Entry & 0xfff);
            if (Target64 > std::numeric_limits<std::uint32_t>::max())
                throw std::runtime_error("relocation target RVA overflow");
            const auto Target = static_cast<std::uint32_t>(Target64);
            const auto* Section = Image.SectionAt(Target);
            // Header fixups are rejected: loader control metadata is immutable.
            if (!Section || 8 > std::max(Section->VirtualSize, Section->RawSize) - (Target - Section->VirtualAddress))
                throw std::runtime_error("relocation target is outside a mapped section");
            Targets.push_back(Target);
        }
        At += Size;
    }
    std::sort(Targets.begin(), Targets.end());
    for (std::size_t I = 1; I < Targets.size(); ++I)
        if (Targets[I] - Targets[I - 1] < 8)
            throw std::runtime_error("overlapping relocation targets");
    return Targets;
}
} // namespace pevm::pe
