#include "PeImage.h"

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <type_traits>

namespace pevm::pe {
namespace {
void CheckRange(std::uint64_t Offset, std::uint64_t Size, std::uint64_t Limit, const char* Error) {
    if (Offset > Limit || Size > Limit - Offset) throw std::runtime_error(Error);
}
template<class T> T Read(std::span<const std::uint8_t> Bytes, std::size_t Offset) {
    static_assert(std::is_unsigned_v<T>);
    CheckRange(Offset, sizeof(T), Bytes.size(), "PE field truncated");
    std::uint64_t Value = 0;
    for (std::size_t I = 0; I < sizeof(T); ++I) Value |= std::uint64_t{Bytes[Offset + I]} << (I * 8);
    return static_cast<T>(Value);
}
bool PowerOfTwo(std::uint32_t Value) { return Value != 0 && (Value & (Value - 1)) == 0; }
bool Overlaps(std::uint32_t A, std::uint32_t ASize, std::uint32_t B, std::uint32_t BSize) {
    return ASize && BSize && std::uint64_t{A} < std::uint64_t{B} + BSize &&
           std::uint64_t{B} < std::uint64_t{A} + ASize;
}
}

ImageView::ImageView(std::span<const std::uint8_t> Input) : File(Input) {
    if (File.size() < 64 || File[0] != 'M' || File[1] != 'Z')
        throw std::runtime_error("input is not an MZ executable");
    Nt = Read<std::uint32_t>(File, 0x3c);
    if (Nt < 64 || Nt > std::numeric_limits<std::int32_t>::max())
        throw std::runtime_error("invalid e_lfanew");
    CheckRange(Nt, 24, File.size(), "invalid e_lfanew");
    if (Read<std::uint32_t>(File, Nt) != 0x4550) throw std::runtime_error("missing PE signature");
    Header.Machine = Read<std::uint16_t>(File, Nt + 4);
    Header.Sections = Read<std::uint16_t>(File, Nt + 6);
    if (Header.Sections == 0 || Header.Sections > 96) throw std::runtime_error("invalid PE section count");
    OptionalSize = Read<std::uint16_t>(File, Nt + 20);
    const auto Optional = Nt + 24;
    CheckRange(Optional, OptionalSize, File.size(), "invalid optional header");
    if (OptionalSize < 2) throw std::runtime_error("invalid optional header");
    const auto Magic = Read<std::uint16_t>(File, Optional);
    if (Magic != 0x10b && Magic != 0x20b) throw std::runtime_error("unsupported PE optional header");
    Header.Pe64 = Magic == 0x20b;
    const std::size_t FixedSize = Header.Pe64 ? 112 : 96;
    if (OptionalSize < FixedSize) throw std::runtime_error("optional header truncated");
    if ((Header.Machine == 0x14c && Header.Pe64) ||
        ((Header.Machine == 0x8664 || Header.Machine == 0xaa64) && !Header.Pe64))
        throw std::runtime_error("PE machine and optional header disagree");
    Header.EntryRva = Read<std::uint32_t>(File, Optional + 16);
    Header.Subsystem = Read<std::uint16_t>(File, Optional + 68);
    HeaderSize = Read<std::uint32_t>(File, Optional + 60);
    ImageSize = Read<std::uint32_t>(File, Optional + 56);
    InitializedDataSize = Read<std::uint32_t>(File, Optional + 8);
    const auto SectionAlignment = Read<std::uint32_t>(File, Optional + 32);
    const auto FileAlignment = Read<std::uint32_t>(File, Optional + 36);
    VirtualAlignment = SectionAlignment;
    RawAlignment = FileAlignment;
    if (!PowerOfTwo(SectionAlignment) || !PowerOfTwo(FileAlignment) || SectionAlignment < FileAlignment ||
        (SectionAlignment < 4096 ? FileAlignment != SectionAlignment : (FileAlignment < 512 || FileAlignment > 65536)))
        throw std::runtime_error("invalid PE alignment");
    if (HeaderSize == 0 || ImageSize == 0 || HeaderSize > ImageSize ||
        HeaderSize % FileAlignment || ImageSize % SectionAlignment)
        throw std::runtime_error("invalid PE image/header size");
    CheckRange(0, HeaderSize, File.size(), "PE headers truncated");
    const auto Table = Optional + OptionalSize;
    CheckRange(Table, std::uint64_t{Header.Sections} * 40, HeaderSize, "PE section table truncated");
    if (Header.EntryRva >= ImageSize) throw std::runtime_error("PE entry RVA outside image");
    const auto DirectoryCount = Read<std::uint32_t>(File, Optional + FixedSize - 4);
    if (DirectoryCount > (OptionalSize - FixedSize) / 8)
        throw std::runtime_error("PE data directories exceed optional header");

    SectionTable.reserve(Header.Sections);
    for (std::size_t I = 0; I < Header.Sections; ++I) {
        const auto At = Table + I * 40;
        Section S;
        for (std::size_t J = 0; J < 8 && File[At + J]; ++J) S.Name += static_cast<char>(File[At + J]);
        S.VirtualSize = Read<std::uint32_t>(File, At + 8);
        S.VirtualAddress = Read<std::uint32_t>(File, At + 12);
        S.RawSize = Read<std::uint32_t>(File, At + 16);
        S.RawOffset = Read<std::uint32_t>(File, At + 20);
        S.Characteristics = Read<std::uint32_t>(File, At + 36);
        const auto MappedSize = std::max(S.VirtualSize, S.RawSize);
        CheckRange(S.VirtualAddress, MappedSize, ImageSize, "PE section virtual range invalid");
        if (MappedSize && (S.VirtualAddress < HeaderSize || S.VirtualAddress % SectionAlignment))
            throw std::runtime_error("PE section virtual alignment/header overlap");
        if (S.RawSize) {
            CheckRange(S.RawOffset, S.RawSize, File.size(), "PE section raw range invalid");
            if (S.RawOffset < HeaderSize || S.RawOffset % FileAlignment || S.RawSize % FileAlignment)
                throw std::runtime_error("PE section raw alignment/header overlap");
            if (SectionAlignment < 4096 && S.RawOffset != S.VirtualAddress)
                throw std::runtime_error("low-alignment PE requires identical raw offsets and RVAs");
        }
        for (const auto& Previous : SectionTable) {
            if (Overlaps(S.VirtualAddress, MappedSize, Previous.VirtualAddress, std::max(Previous.VirtualSize, Previous.RawSize)) ||
                Overlaps(S.RawOffset, S.RawSize, Previous.RawOffset, Previous.RawSize))
                throw std::runtime_error("overlapping PE sections");
        }
        SectionTable.push_back(std::move(S));
    }
    for (std::size_t I = 0; I < std::min<std::size_t>(DirectoryCount, Directories.size()); ++I) {
        auto& D = Directories[I];
        D = {Read<std::uint32_t>(File, Optional + FixedSize + I * 8),
             Read<std::uint32_t>(File, Optional + FixedSize + I * 8 + 4)};
        // Some directories legitimately carry an address with a zero size.
        if (D.Size == 0) continue;
        if (D.Address == 0) throw std::runtime_error("PE directory size without address");
        CheckRange(D.Address, D.Size, I == 4 ? File.size() : ImageSize, "PE directory range invalid");
    }
}

DataDirectory ImageView::Directory(std::size_t Index) const {
    if (Index >= Directories.size()) throw std::out_of_range("PE directory index invalid");
    return Directories[Index];
}
std::span<const std::uint8_t> ImageView::DirectoryBytes(std::size_t Index) const {
    const auto D = Directory(Index);
    if (D.Size == 0) return {};
    if (Index == 4) return File.subspan(D.Address, D.Size);
    return FileBytesAtRva(D.Address, D.Size);
}
const Section* ImageView::SectionAt(std::uint32_t Rva) const {
    for (const auto& S : SectionTable)
        if (Rva >= S.VirtualAddress && Rva - S.VirtualAddress < std::max(S.VirtualSize, S.RawSize)) return &S;
    return nullptr;
}
std::span<const std::uint8_t> ImageView::FileTailAtRva(std::uint32_t Rva) const {
    if (Rva < HeaderSize) return File.subspan(Rva, HeaderSize - Rva);
    if (const auto* S = SectionAt(Rva)) {
        const auto Delta = Rva - S->VirtualAddress;
        if (Delta < S->RawSize) return File.subspan(std::size_t{S->RawOffset} + Delta, S->RawSize - Delta);
    }
    throw std::runtime_error("PE RVA is outside file-backed ranges (gap or zero-fill)");
}
std::span<const std::uint8_t> ImageView::FileBytesAtRva(std::uint32_t Rva, std::size_t Size) const {
    const auto Tail = FileTailAtRva(Rva);
    if (Size > Tail.size()) throw std::runtime_error("PE RVA range crosses file-backed boundary");
    return Tail.first(Size);
}
std::span<const std::uint8_t> ImageView::CodeAtRva(std::uint32_t Rva, std::size_t MaximumBytes) const {
    const auto* S = SectionAt(Rva);
    if (!S || !S->Executable()) throw std::runtime_error("PE function RVA is not in an executable section");
    const auto Tail = FileTailAtRva(Rva);
    return Tail.first(std::min(MaximumBytes, Tail.size()));
}
std::string ImageView::StringAtRva(std::uint32_t Rva) const {
    const auto Tail = FileTailAtRva(Rva);
    const auto End = std::find(Tail.begin(), Tail.end(), std::uint8_t{0});
    if (End == Tail.end()) throw std::runtime_error("unterminated PE string");
    return {reinterpret_cast<const char*>(Tail.data()), static_cast<std::size_t>(End - Tail.begin())};
}
void ImageView::RequireX64() const {
    if (!Header.Pe64 || Header.Machine != 0x8664)
        throw std::runtime_error("x64 decoder: PE32+ x64 executable required");
}
} // namespace pevm::pe
