#include "PeCodeIntegrity.h"
#include "PeImage.h"
#include "PeRelocations.h"
#include "FileIo.h"

#include <windows.h>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <exception>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {
volatile std::uint32_t MarkerSalt = 0x36a97d25U;

extern "C" __declspec(noinline) std::uint32_t PeVmCodeIntegrityMarker(std::uint32_t Value) {
    return Value ^ MarkerSalt;
}

void Check(unsigned& Checks, bool Condition, const char* Name) {
    if (!Condition) throw std::runtime_error(Name);
    ++Checks;
}

template<class F>
void Reject(unsigned& Checks, const char* Name, std::string_view Reason, F&& Action) {
    try {
        Action();
    } catch (const std::exception& Error) {
        if (std::string_view(Error.what()).find(Reason) == std::string_view::npos)
            throw std::runtime_error(std::string(Name) + ": unexpected rejection: " + Error.what());
        ++Checks;
        return;
    }
    throw std::runtime_error(std::string("accepted native code tampering: ") + Name);
}

// The marker is never called while modified. Every exit path restores its
// original byte and exact protection, including failed test assertions.
class MarkerPageScope final {
public:
    explicit MarkerPageScope(std::uintptr_t Address)
        : Byte(reinterpret_cast<volatile std::uint8_t*>(Address)), Original(*Byte) {
        if (!VirtualProtect(const_cast<std::uint8_t*>(Byte), 1, PAGE_EXECUTE_READWRITE, &Protection))
            throw std::runtime_error("cannot make integrity test marker writable");
    }
    ~MarkerPageScope() noexcept {
        DWORD Old{};
        if (!VirtualProtect(const_cast<std::uint8_t*>(Byte), 1, PAGE_EXECUTE_READWRITE, &Old))
            std::terminate();
        *Byte = Original;
        if (!FlushInstructionCache(GetCurrentProcess(), const_cast<std::uint8_t*>(Byte), 1) ||
            !VirtualProtect(const_cast<std::uint8_t*>(Byte), 1, Protection, &Old))
            std::terminate();
    }
    MarkerPageScope(const MarkerPageScope&) = delete;
    MarkerPageScope& operator=(const MarkerPageScope&) = delete;

    void PatchAndRestoreProtection() {
        *Byte = static_cast<std::uint8_t>(Original ^ 0x01U);
        DWORD Old{};
        if (!FlushInstructionCache(GetCurrentProcess(), const_cast<std::uint8_t*>(Byte), 1) ||
            !VirtualProtect(const_cast<std::uint8_t*>(Byte), 1, Protection, &Old))
            throw std::runtime_error("cannot prepare integrity test code patch");
    }

private:
    volatile std::uint8_t* Byte{};
    std::uint8_t Original{};
    DWORD Protection{};
};

class PrivateImageScope final {
public:
    explicit PrivateImageScope(std::size_t Size, DWORD Protection = PAGE_EXECUTE_READ) {
        Base = VirtualAlloc(nullptr, Size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (!Base) throw std::runtime_error("cannot allocate integrity test private image");
        DWORD Old{};
        if (!VirtualProtect(Base, Size, Protection, &Old)) {
            VirtualFree(Base, 0, MEM_RELEASE);
            Base = nullptr;
            throw std::runtime_error("cannot protect integrity test private image");
        }
    }
    ~PrivateImageScope() { if (Base) VirtualFree(Base, 0, MEM_RELEASE); }
    PrivateImageScope(const PrivateImageScope&) = delete;
    PrivateImageScope& operator=(const PrivateImageScope&) = delete;
    const void* Address() const { return Base; }

private:
    void* Base{};
};

void Write32(std::vector<std::uint8_t>& Bytes, std::size_t At, std::uint32_t Value) {
    for (unsigned I = 0; I < 4; ++I) Bytes.at(At + I) = static_cast<std::uint8_t>(Value >> (I * 8));
}

// Add one synthetic DIR64 target on the real marker's instruction bytes. Force
// a different preferred base and inversely adjust disk words while leaving the
// live image untouched. Retain every genuine executable fixup; data-section
// fixups are outside this guard's
// scope and need not occupy the synthetic test table.
std::vector<std::uint8_t> WithCodeRelocation(const pevm::pe::ImageView& Image,
                                          std::uintptr_t Base, std::uint32_t Rva) {
    const auto Directory = Image.Directory(IMAGE_DIRECTORY_ENTRY_BASERELOC);
    const auto* Storage = Image.SectionAt(Directory.Address);
    if (!Directory.Size || !Storage || Storage->Executable())
        throw std::runtime_error("integrity fixture requires non-executable relocation storage");
    std::vector<std::uint32_t> Targets;
    for (const auto Target : pevm::pe::RelocationTargets(Image)) {
        const auto* Section = Image.SectionAt(Target);
        if (Section && Section->Executable()) Targets.push_back(Target);
    }
    Targets.push_back(Rva);
    std::sort(Targets.begin(), Targets.end());
    for (std::size_t I = 1; I < Targets.size(); ++I) {
        if (Targets[I] - Targets[I - 1] < 8)
            throw std::runtime_error("integrity marker overlaps a real code relocation");
    }
    std::vector<std::uint8_t> Table;
    for (std::size_t First = 0; First < Targets.size();) {
        const auto Page = Targets[First] & ~std::uint32_t{4095};
        auto End = First + 1;
        while (End < Targets.size() && (Targets[End] & ~std::uint32_t{4095}) == Page) ++End;
        const auto Entries = End - First;
        const auto BlockBytes = 8 + ((Entries + 1) & ~std::size_t{1}) * 2;
        const auto At = Table.size();
        Table.resize(At + BlockBytes);
        Write32(Table, At, Page);
        Write32(Table, At + 4, static_cast<std::uint32_t>(BlockBytes));
        for (auto I = First; I < End; ++I) {
            const auto Entry = static_cast<std::uint16_t>(0xa000U | (Targets[I] & 0xfffU));
            const auto EntryAt = At + 8 + (I - First) * 2;
            Table[EntryAt] = static_cast<std::uint8_t>(Entry);
            Table[EntryAt + 1] = static_cast<std::uint8_t>(Entry >> 8);
        }
        First = End;
    }
    const auto Tail = Image.FileTailAtRva(Directory.Address);
    if (Table.size() > Tail.size()) throw std::runtime_error("integrity relocation fixture storage too small");
    const auto File = Image.FileBytes();
    std::vector<std::uint8_t> Result(File.begin(), File.end());
    const auto TableOffset = static_cast<std::size_t>(Tail.data() - File.data());
    std::copy(Table.begin(), Table.end(), Result.begin() + TableOffset);
    Write32(Result, Image.NtOffset() + 24 + 112 + IMAGE_DIRECTORY_ENTRY_BASERELOC * 8 + 4,
        static_cast<std::uint32_t>(Table.size()));

    const auto Preferred = static_cast<std::uint64_t>(Base) ^ (std::uint64_t{1} << 20);
    const auto Delta = static_cast<std::uint64_t>(Base) - Preferred;
    std::memcpy(Result.data() + Image.NtOffset() + 24 + 24, &Preferred, sizeof(Preferred));
    for (const auto Target : Targets) {
        std::uint64_t Live{};
        std::memcpy(&Live, reinterpret_cast<const void*>(Base + Target), sizeof(Live));
        const auto Expected = Live - Delta;
        const auto TargetBytes = Image.FileBytesAtRva(Target, sizeof(Expected));
        const auto TargetOffset = static_cast<std::size_t>(TargetBytes.data() - File.data());
        std::memcpy(Result.data() + TargetOffset, &Expected, sizeof(Expected));
    }
    return Result;
}
}

unsigned CodeIntegrityTests() {
    unsigned Checks{};
    std::vector<wchar_t> Path(32768);
    const auto Characters = GetModuleFileNameW(nullptr, Path.data(), static_cast<DWORD>(Path.size()));
    Check(Checks, Characters != 0 && Characters < Path.size(), "native test image path");
    const auto Disk = util::ReadFile(std::wstring(Path.data(), Characters));
    const pevm::pe::ImageView Image(Disk);
    const auto Base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
    Check(Checks, Base != 0, "native test image loaded base");
    pevm::pe::ExecutableImageGuard Guard(Disk, reinterpret_cast<const void*>(Base));
    Guard.Check();
    ++Checks; // Real Windows image and ASLR-normalized disk baseline are accepted.

    constexpr std::uint32_t MarkerInput = 0x513a6c84U;
    const auto MarkerResult = PeVmCodeIntegrityMarker(MarkerInput);
    Check(Checks, MarkerResult == (MarkerInput ^ MarkerSalt), "native test marker executes");
    const auto Marker = reinterpret_cast<std::uintptr_t>(&PeVmCodeIntegrityMarker);
    Check(Checks, Marker >= Base && Marker - Base <= std::numeric_limits<std::uint32_t>::max(),
        "native test marker RVA");
    const auto Rva = static_cast<std::uint32_t>(Marker - Base);
    const auto* Section = Image.SectionAt(Rva);
    Check(Checks, Section && Section->Executable(), "native test marker executable section");
    const auto MarkerFile = Image.FileBytesAtRva(Rva, 1);
    const auto FileOffset = static_cast<std::size_t>(MarkerFile.data() - Disk.data());

    auto WrongDisk = Disk;
    WrongDisk[FileOffset] ^= 0x01U;
    Reject(Checks, "disk baseline differs from loaded code", "native executable image code mismatch", [&] {
        pevm::pe::ExecutableImageGuard Invalid(WrongDisk, reinterpret_cast<const void*>(Base));
    });

    // Wrapper construction renames its native execution section to .vmp0.
    // Selection must follow executable characteristics rather than a name.
    auto Renamed = Disk;
    const auto SectionTable = Image.NtOffset() + 24 + Image.OptionalHeaderSize();
    for (std::size_t I = 0; I < Image.Sections().size(); ++I) {
        if (!Image.Sections()[I].Executable()) continue;
        std::fill_n(Renamed.data() + SectionTable + I * 40, 8, std::uint8_t{});
        std::memcpy(Renamed.data() + SectionTable + I * 40, ".vmp0", 5);
    }
    pevm::pe::ExecutableImageGuard RenamedGuard(Renamed, reinterpret_cast<const void*>(Base));
    RenamedGuard.Check();
    ++Checks;

    const auto RelocatedDisk = WithCodeRelocation(Image, Base, Rva);
    pevm::pe::ExecutableImageGuard RelocatedGuard(RelocatedDisk, reinterpret_cast<const void*>(Base));
    RelocatedGuard.Check();
    ++Checks; // An executable DIR64 field is reconstructed under forced ASLR.

    {
        MarkerPageScope Scope(Marker);
        Scope.PatchAndRestoreProtection();
        Reject(Checks, "in-memory byte patch with original RX protection", "native executable image code mismatch", [&] {
            Guard.Check();
        });
        Reject(Checks, "patched relocation bytes remain covered", "native executable image code mismatch", [&] {
            RelocatedGuard.Check();
        });
        Reject(Checks, "patch present before initial guard construction", "native executable image code mismatch", [&] {
            pevm::pe::ExecutableImageGuard Invalid(Disk, reinterpret_cast<const void*>(Base));
        });
    }
    Guard.Check();
    Check(Checks, PeVmCodeIntegrityMarker(MarkerInput) == MarkerResult, "native code restored after patch test");

    {
        MarkerPageScope Scope(Marker);
        Reject(Checks, "RWX permission without code change", "native executable image protection changed", [&] {
            Guard.Check();
        });
    }
    Guard.Check();
    Check(Checks, PeVmCodeIntegrityMarker(MarkerInput) == MarkerResult, "native protection restored after RWX test");

    {
        PrivateImageScope Private(Image.SizeOfImage());
        Reject(Checks, "private RX mapping cannot replace loader image", "native executable image protection changed", [&] {
            pevm::pe::ExecutableImageGuard Invalid(Disk, Private.Address());
        });
    }
    {
        PrivateImageScope Inaccessible(Image.SizeOfImage(), PAGE_NOACCESS);
        Reject(Checks, "inaccessible mapping is rejected before reading", "native executable image protection changed", [&] {
            pevm::pe::ExecutableImageGuard Invalid(Disk, Inaccessible.Address());
        });
    }
    return Checks;
}
