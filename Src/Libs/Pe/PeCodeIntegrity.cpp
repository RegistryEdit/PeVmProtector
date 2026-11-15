#include "PeCodeIntegrity.h"
#include "PeImage.h"
#include "PeRelocations.h"
#include "PeVmCrypto.h"
#include <windows.h>
#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <new>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace pevm::pe {
namespace {
constexpr std::size_t KManifestBytes = 4096;
constexpr std::uint32_t KMaximumRanges = 96;
constexpr std::uint64_t KManifestMagic = 0x3145444F434D5650ULL;
struct ManifestHeader {
    std::uint64_t Magic{KManifestMagic};
    std::uintptr_t LoadedBase{};
    std::uint32_t Count{}, ImageBytes{}, RecordsBytes{}, Reserved{};
};
struct CodeRange {
    std::uint32_t Rva{}, Bytes{};
    crypto::Sha256Digest Digest{};
};
static_assert(sizeof(ManifestHeader) + KMaximumRanges * sizeof(CodeRange) <= KManifestBytes);

crypto::Sha256Digest CodeDigest(std::uint32_t Rva, std::uint32_t Size,
                              std::span<const std::uint8_t> Bytes) {
    crypto::Sha256 Hash;
    constexpr std::string_view Domain = "PeVmProtector-NativeCode-v1";
    Hash.Update({reinterpret_cast<const std::uint8_t*>(Domain.data()), Domain.size()});
    std::array<std::uint8_t, 8> Location{};
    for (unsigned I = 0; I < 4; ++I) {
        Location[I] = static_cast<std::uint8_t>(Rva >> (I * 8));
        Location[I + 4] = static_cast<std::uint8_t>(Size >> (I * 8));
    }
    Hash.Update(Location);
    Hash.Update(Bytes);
    return Hash.Finish();
}

void CheckPages(std::uintptr_t First, std::size_t Size, const void* Allocation,
                DWORD Type, DWORD Protection, const char* Error) {
    if (!First || !Size || Size > std::numeric_limits<std::uintptr_t>::max() - First)
        throw std::runtime_error(Error);
    const auto End = First + Size;
    for (auto At = First; At < End;) {
        MEMORY_BASIC_INFORMATION Page{};
        if (VirtualQuery(reinterpret_cast<const void*>(At), &Page, sizeof(Page)) != sizeof(Page) ||
            Page.State != MEM_COMMIT || Page.Type != Type || Page.AllocationBase != Allocation ||
            (Page.Protect & PAGE_GUARD) != 0 || (Page.Protect & 0xffU) != Protection)
            throw std::runtime_error(Error);
        const auto Region = reinterpret_cast<std::uintptr_t>(Page.BaseAddress);
        if (Region > At || Page.RegionSize > std::numeric_limits<std::uintptr_t>::max() - Region ||
            Region + Page.RegionSize <= At)
            throw std::runtime_error(Error);
        At = std::min(End, Region + Page.RegionSize);
    }
}
}

struct ExecutableImageGuard::State {
    void* Manifest{};
    ~State() { if (Manifest) VirtualFree(Manifest, 0, MEM_RELEASE); }
};

ExecutableImageGuard::ExecutableImageGuard(std::span<const std::uint8_t> DiskImage, const void* LoadedBase)
    : Data(std::make_unique<State>()) {
    const ImageView Image(DiskImage);
    Image.RequireX64();
    const auto Base = reinterpret_cast<std::uintptr_t>(LoadedBase);
    if (!Base || Image.SizeOfImage() > std::numeric_limits<std::uintptr_t>::max() - Base)
        throw std::runtime_error("invalid native code image base");
    std::uint64_t PreferredBase{};
    std::memcpy(&PreferredBase, DiskImage.data() + Image.NtOffset() + 24 + 24, sizeof(PreferredBase));
    const auto Delta = static_cast<std::uint64_t>(Base) - PreferredBase;
    const auto Relocations = RelocationTargets(Image); // Validate the entire table first.
    if (Delta != 0 && Image.Directory(IMAGE_DIRECTORY_ENTRY_BASERELOC).Size == 0)
        throw std::runtime_error("relocated native image lacks base relocations");

    std::vector<CodeRange> Ranges;
    for (const auto& Section : Image.Sections()) {
        if (!Section.Executable()) continue;
        if ((Section.Characteristics & (IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_DISCARDABLE)) != 0 ||
            (Section.Characteristics & IMAGE_SCN_MEM_READ) == 0)
            throw std::runtime_error("native executable section must be immutable and readable");
        const auto Size = std::max(Section.VirtualSize, Section.RawSize);
        if (!Size || Section.VirtualAddress > Image.SizeOfImage() || Size > Image.SizeOfImage() - Section.VirtualAddress)
            throw std::runtime_error("invalid native executable section range");
        // The normal Windows loader writes the IAT; such a layout cannot provide
        // an immutable executable-section baseline and is rejected explicitly.
        const auto Iat = Image.Directory(IMAGE_DIRECTORY_ENTRY_IAT);
        if (Iat.Size && std::uint64_t{Iat.Address} < std::uint64_t{Section.VirtualAddress} + Size &&
            std::uint64_t{Section.VirtualAddress} < std::uint64_t{Iat.Address} + Iat.Size)
            throw std::runtime_error("native executable section overlaps loader-written IAT");
        std::vector<std::uint8_t> Expected(Size, 0);
        if (Section.RawSize)
            std::copy_n(DiskImage.data() + Section.RawOffset, Section.RawSize, Expected.data());
        for (const auto Target : Relocations) {
            if (Target < Section.VirtualAddress || Target - Section.VirtualAddress >= Size) continue;
            const auto Offset = Target - Section.VirtualAddress;
            if (sizeof(std::uint64_t) > Size - Offset)
                throw std::runtime_error("native executable relocation crosses section boundary");
            std::uint64_t Value{};
            std::memcpy(&Value, Expected.data() + Offset, sizeof(Value));
            Value += Delta;
            std::memcpy(Expected.data() + Offset, &Value, sizeof(Value));
        }
        Ranges.push_back({Section.VirtualAddress, Size, CodeDigest(Section.VirtualAddress, Size, Expected)});
    }
    if (Ranges.empty() || Ranges.size() > KMaximumRanges)
        throw std::runtime_error("native image has no immutable executable sections");
    Data->Manifest = VirtualAlloc(nullptr, KManifestBytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!Data->Manifest) throw std::runtime_error("cannot allocate native integrity manifest");
    auto* Header = new (Data->Manifest) ManifestHeader;
    Header->LoadedBase = Base;
    Header->Count = static_cast<std::uint32_t>(Ranges.size());
    Header->ImageBytes = Image.SizeOfImage();
    Header->RecordsBytes = static_cast<std::uint32_t>(Ranges.size() * sizeof(CodeRange));
    std::memcpy(static_cast<std::uint8_t*>(Data->Manifest) + sizeof(ManifestHeader), Ranges.data(), Header->RecordsBytes);
    DWORD Old{};
    if (!VirtualProtect(Data->Manifest, KManifestBytes, PAGE_READONLY, &Old))
        throw std::runtime_error("cannot freeze native integrity manifest");
    Check(); // Reject a pre-existing memory patch before accepting any baseline.
}

ExecutableImageGuard::~ExecutableImageGuard() = default;

void ExecutableImageGuard::Check() const {
    if (!Data || !Data->Manifest) throw std::runtime_error("native integrity manifest missing");
    CheckPages(reinterpret_cast<std::uintptr_t>(Data->Manifest), KManifestBytes, Data->Manifest,
        MEM_PRIVATE, PAGE_READONLY, "native integrity manifest protection changed");
    const auto& Header = *static_cast<const ManifestHeader*>(Data->Manifest);
    if (Header.Magic != KManifestMagic || Header.Count == 0 || Header.Count > KMaximumRanges ||
        Header.Reserved != 0 || Header.RecordsBytes != Header.Count * sizeof(CodeRange) ||
        Header.ImageBytes == 0 || !Header.LoadedBase ||
        Header.ImageBytes > std::numeric_limits<std::uintptr_t>::max() - Header.LoadedBase)
        throw std::runtime_error("invalid native integrity manifest");
    const auto* Ranges = reinterpret_cast<const CodeRange*>(static_cast<const std::uint8_t*>(Data->Manifest) + sizeof(ManifestHeader));
    for (std::uint32_t I = 0; I < Header.Count; ++I) {
        const auto& Range = Ranges[I];
        if (!Range.Bytes || Range.Rva > Header.ImageBytes || Range.Bytes > Header.ImageBytes - Range.Rva)
            throw std::runtime_error("invalid native integrity code range");
        const auto Address = Header.LoadedBase + Range.Rva;
        CheckPages(Address, Range.Bytes, reinterpret_cast<const void*>(Header.LoadedBase),
            MEM_IMAGE, PAGE_EXECUTE_READ, "native executable image protection changed");
        const auto Actual = CodeDigest(Range.Rva, Range.Bytes,
            {reinterpret_cast<const std::uint8_t*>(Address), Range.Bytes});
        if (!crypto::ConstantEqual(Actual, Range.Digest))
            throw std::runtime_error("native executable image code mismatch");
    }
}

} // namespace pevm::pe
