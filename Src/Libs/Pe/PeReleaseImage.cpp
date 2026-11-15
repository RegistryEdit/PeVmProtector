#include "PeReleaseImage.h"
#include "PeImage.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <string_view>
#include <type_traits>
#include <vector>

namespace pevm::pe {
namespace {
constexpr std::size_t KDebugDirectory = 6;
constexpr std::size_t KDebugRecordBytes = 28;
constexpr std::size_t KCoffSymbolBytes = 18;

struct Range {
    std::size_t Offset{}, Size{};
};
void CheckRange(std::uint64_t Offset, std::uint64_t Size, std::size_t Limit) {
    if (Offset > Limit || Size > Limit - Offset)
        throw std::runtime_error("release debug metadata range is outside the file");
}
template<class T> T Read(std::span<const std::uint8_t> File, std::size_t At) {
    static_assert(std::is_unsigned_v<T>);
    CheckRange(At, sizeof(T), File.size());
    std::uint64_t Value{};
    for (std::size_t I = 0; I < sizeof(T); ++I) Value |= std::uint64_t{File[At + I]} << (I * 8);
    return static_cast<T>(Value);
}
void Write32(crypto::Bytes& File, std::size_t At, std::uint32_t Value) noexcept {
    for (std::size_t I = 0; I < 4; ++I) File[At + I] = static_cast<std::uint8_t>(Value >> (I * 8));
}
bool Overlaps(Range A, Range B) {
    return A.Size && B.Size && A.Offset < B.Offset + B.Size && B.Offset < A.Offset + A.Size;
}
Range FileRange(const ImageView& Image, std::span<const std::uint8_t> Slice) {
    if (Slice.empty()) return {};
    return {static_cast<std::size_t>(Slice.data() - Image.FileBytes().data()), Slice.size()};
}
void RequireSafeStorage(Range Candidate, const std::vector<Range>& Protected) {
    for (const auto Range : Protected) {
        if (Overlaps(Candidate, Range))
            throw std::runtime_error("release debug metadata overlaps headers, executable code or a runtime directory");
    }
}
bool RemovableDebugType(std::uint32_t Type) {
    // Explicit debugger-only metadata. Never infer removability from a name,
    // signature or an unknown type; type 20 carries loader security semantics.
    switch (Type) {
    case 1:  // COFF debug information
    case 2:  // CodeView / RSDS / NB10
    case 3:  // FPO debugger information
    case 4:  // MISC executable-name record
    case 7:  // OMAP_TO_SRC
    case 8:  // OMAP_FROM_SRC
    case 12: // VC_FEATURE
    case 13: // POGO
    case 17: // embedded portable PDB
    case 18: // SPGO
    case 19: // portable PDB checksum
        return true;
    default:
        // Preserve REPRO (16) as well: it can participate in build/signature
        // identity, and does not expose symbol names or a source/PDB path.
        return false;
    }
}
Range DebugDataRange(const ImageView& Image, std::span<const std::uint8_t> Record) {
    const auto Size = Read<std::uint32_t>(Record, 16);
    const auto Rva = Read<std::uint32_t>(Record, 20);
    const auto Raw = Read<std::uint32_t>(Record, 24);
    if (!Size) {
        if (Rva || Raw) throw std::runtime_error("zero-length debug record has a data address");
        return {};
    }
    Range Result;
    if (Raw) {
        CheckRange(Raw, Size, Image.FileBytes().size());
        Result = {Raw, Size};
        if (Rva && FileRange(Image, Image.FileBytesAtRva(Rva, Size)).Offset != Raw)
            throw std::runtime_error("debug record RVA and raw pointer disagree");
    } else {
        if (!Rva) throw std::runtime_error("debug record data address is missing");
        Result = FileRange(Image, Image.FileBytesAtRva(Rva, Size));
    }
    return Result;
}
Range CoffRange(const ImageView& Image, std::uint32_t Offset, std::uint32_t Count) {
    if (!Offset || !Count) {
        if (Offset || Count) throw std::runtime_error("inconsistent COFF symbol pointer/count");
        return {};
    }
    for (const auto& Section : Image.Sections()) {
        if (!Section.Name.empty() && Section.Name.front() == '/')
            throw std::runtime_error("COFF string table used by long section names cannot be stripped safely");
    }
    const auto File = Image.FileBytes();
    const auto SymbolBytes = std::uint64_t{Count} * KCoffSymbolBytes;
    CheckRange(Offset, SymbolBytes + 4, File.size());
    const auto StringsAt = static_cast<std::size_t>(std::uint64_t{Offset} + SymbolBytes);
    const auto StringBytes = Read<std::uint32_t>(File, StringsAt);
    if (StringBytes < 4) throw std::runtime_error("COFF string table length is invalid");
    CheckRange(StringsAt, StringBytes, File.size());
    const auto Strings = File.subspan(StringsAt, StringBytes);
    for (std::uint32_t I = 0; I < Count;) {
        const auto At = static_cast<std::size_t>(Offset) + static_cast<std::size_t>(I) * KCoffSymbolBytes;
        const auto Aux = File[At + 17];
        if (Aux > Count - I - 1) throw std::runtime_error("COFF auxiliary symbol records are truncated");
        if (Read<std::uint32_t>(File, At) == 0) {
            const auto NameAt = Read<std::uint32_t>(File, At + 4);
            if (NameAt < 4 || NameAt >= StringBytes ||
                std::find(Strings.begin() + NameAt, Strings.end(), std::uint8_t{0}) == Strings.end())
                throw std::runtime_error("COFF symbol name is outside the string table or unterminated");
        }
        I += static_cast<std::uint32_t>(Aux) + 1;
    }
    return {Offset, static_cast<std::size_t>(SymbolBytes + StringBytes)};
}
std::vector<Range> MergeRanges(std::vector<Range> Input) {
    std::sort(Input.begin(), Input.end(), [](Range A, Range B) { return A.Offset < B.Offset; });
    std::vector<Range> Output;
    for (const auto Range : Input) {
        if (!Range.Size) continue;
        if (!Output.empty() && Range.Offset <= Output.back().Offset + Output.back().Size) {
            auto& Last = Output.back();
            Last.Size = std::max(Last.Offset + Last.Size, Range.Offset + Range.Size) - Last.Offset;
        } else Output.push_back(Range);
    }
    return Output;
}
} // namespace

ReleaseImageStats StripDebugMetadata(crypto::Bytes& File) {
    const ImageView Image(File);
    const auto Bytes = Image.FileBytes();
    const auto SymbolOffset = Read<std::uint32_t>(Bytes, Image.NtOffset() + 12);
    const auto SymbolCount = Read<std::uint32_t>(Bytes, Image.NtOffset() + 16);
    const auto Symbols = CoffRange(Image, SymbolOffset, SymbolCount);
    const auto Debug = Image.DirectoryBytes(KDebugDirectory);
    if (Debug.size() % KDebugRecordBytes)
        throw std::runtime_error("release debug directory has a partial record");
    if (Debug.empty() && !Symbols.Size) return {};

    std::vector<Range> Protected{{0, Image.SizeOfHeaders()}};
    for (const auto& Section : Image.Sections()) {
        if (Section.Executable() && Section.RawSize) Protected.push_back({Section.RawOffset, Section.RawSize});
    }
    for (std::size_t I = 0; I < 16; ++I) {
        if (I != KDebugDirectory) {
            const auto Directory = Image.DirectoryBytes(I);
            if (!Directory.empty()) Protected.push_back(FileRange(Image, Directory));
        }
    }
    const auto Table = FileRange(Image, Debug);
    RequireSafeStorage(Table, Protected);
    RequireSafeStorage(Symbols, Protected);

    ReleaseImageStats Stats;
    Stats.CoffSymbols = SymbolCount;
    Stats.CoffBytes = Symbols.Size;
    std::vector<Range> Erase;
    std::vector<Range> DebugErase;
    std::vector<Range> RetainedData;
    std::vector<std::uint8_t> RetainedRecords;
    if (Symbols.Size) Erase.push_back(Symbols);
    for (std::size_t At = 0; At < Debug.size(); At += KDebugRecordBytes) {
        const auto Record = Debug.subspan(At, KDebugRecordBytes);
        const auto Data = DebugDataRange(Image, Record);
        if (Overlaps(Data, Table)) throw std::runtime_error("debug record data overlaps its directory");
        if (RemovableDebugType(Read<std::uint32_t>(Record, 12))) {
            RequireSafeStorage(Data, Protected);
            ++Stats.DebugRecords;
            if (Data.Size) {
                Erase.push_back(Data);
                DebugErase.push_back(Data);
            }
        } else {
            RetainedRecords.insert(RetainedRecords.end(), Record.begin(), Record.end());
            if (Data.Size) RetainedData.push_back(Data);
        }
    }
    if (Overlaps(Symbols, Table)) throw std::runtime_error("COFF symbols overlap the debug directory");
    for (const auto Candidate : Erase) {
        for (const auto Kept : RetainedData) {
            if (Overlaps(Candidate, Kept))
                throw std::runtime_error("removable symbols overlap retained debug data");
        }
    }
    for (const auto Range : MergeRanges(std::move(DebugErase))) Stats.DebugBytes += Range.Size;
    Stats.DebugBytes += std::uint64_t{Stats.DebugRecords} * KDebugRecordBytes;
    auto EraseRanges = MergeRanges(std::move(Erase));
    // All validation, span mapping, narrowing and allocations are complete.
    // The following stores cannot throw and leave all file/RVA extents intact.
    for (const auto Range : EraseRanges) {
        std::fill_n(File.begin() + Range.Offset, Range.Size, std::uint8_t{0});
    }
    if (Symbols.Size) {
        Write32(File, Image.NtOffset() + 12, 0);
        Write32(File, Image.NtOffset() + 16, 0);
    }
    if (Stats.DebugRecords) {
        std::fill_n(File.begin() + Table.Offset, Table.Size, std::uint8_t{0});
        std::copy(RetainedRecords.begin(), RetainedRecords.end(), File.begin() + Table.Offset);
        const auto DirectoryAt = Image.NtOffset() + 24 + (Image.Info().Pe64 ? 112 : 96) + KDebugDirectory * 8;
        if (RetainedRecords.empty()) Write32(File, DirectoryAt, 0);
        Write32(File, DirectoryAt + 4, static_cast<std::uint32_t>(RetainedRecords.size()));
    }
    return Stats;
}

} // namespace pevm::pe
