#include "PeImage.h"
#include "PeLayout.h"
#include "PeRelocations.h"
#include "PeTls.h"
#include "WindowsResources.h"
#include "PeVmContainer.h"
#include "X64Lifter.h"

#include <algorithm>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <windows.h>

namespace {
using pevm::pe::ImageView;
constexpr std::size_t Nt = 0x80, Optional = Nt + 24, Table = Optional + 240;
unsigned Checks{};
void Check(bool Condition, const char* Name) {
    if (!Condition) throw std::runtime_error(Name);
    ++Checks;
}
template<class F> void Reject(const char* Name, F&& Action) {
    try { Action(); } catch (const std::exception&) { ++Checks; return; }
    throw std::runtime_error(std::string("accepted invalid input: ") + Name);
}
void Put(Bytes& Data, std::size_t At, std::uint64_t Value, std::size_t Width = 4) {
    for (std::size_t I = 0; I < Width; ++I) Data.at(At + I) = static_cast<std::uint8_t>(Value >> (I * 8));
}
void Text(Bytes& Data, std::size_t At, const char* Value) {
    std::copy_n(Value, std::strlen(Value) + 1, Data.begin() + At);
}
Bytes MakePe(bool Pe64 = true) {
    Bytes Data(0x600);
    Data[0] = 'M'; Data[1] = 'Z';
    Put(Data, 0x3c, Nt);
    Put(Data, Nt, 0x4550);
    Put(Data, Nt + 4, Pe64 ? 0x8664 : 0x14c, 2);
    Put(Data, Nt + 6, 2, 2);
    Put(Data, Nt + 20, Pe64 ? 240 : 224, 2);
    Put(Data, Optional, Pe64 ? 0x20b : 0x10b, 2);
    Put(Data, Optional + 16, 0x1000);
    Put(Data, Optional + 32, 0x1000);
    Put(Data, Optional + 36, 0x200);
    Put(Data, Optional + 56, 0x3000);
    Put(Data, Optional + 60, 0x200);
    Put(Data, Optional + 68, 3, 2);
    Put(Data, Optional + (Pe64 ? 108 : 92), 16);
    const auto Sections = Optional + (Pe64 ? 240 : 224);
    for (unsigned I = 0; I < 2; ++I) {
        const auto At = Sections + I * 40;
        Text(Data, At, I ? ".rdata" : ".text");
        Put(Data, At + 8, 0x200);
        Put(Data, At + 12, 0x1000 + I * 0x1000);
        Put(Data, At + 16, 0x200);
        Put(Data, At + 20, 0x200 + I * 0x200);
        Put(Data, At + 36, I ? 0x40000040 : 0x60000020);
    }
    const Bytes Code{0x48, 0x89, 0xc8, 0xc3}; // mov rax,rcx; ret
    std::copy(Code.begin(), Code.end(), Data.begin() + 0x200);
    return Data;
}
void Directory(Bytes& Data, unsigned Index, std::uint32_t Rva, std::uint32_t Size) {
    Put(Data, Optional + 112 + Index * 8, Rva);
    Put(Data, Optional + 116 + Index * 8, Size);
}
Bytes WithFunctions() {
    auto Data = MakePe();
    Directory(Data, 3, 0x2000, 12);
    Put(Data, 0x400, 0x1000); Put(Data, 0x404, 0x1004); Put(Data, 0x408, 0x2100);
    Directory(Data, 0, 0x2040, 0xe0);
    Put(Data, 0x440 + 20, 3); Put(Data, 0x440 + 24, 3);
    Put(Data, 0x440 + 28, 0x2080); Put(Data, 0x440 + 32, 0x208c); Put(Data, 0x440 + 36, 0x2098);
    Put(Data, 0x480, 0x1000); Put(Data, 0x484, 0x20c0); Put(Data, 0x488, 0x2140);
    Put(Data, 0x48c, 0x20a0); Put(Data, 0x490, 0x20a8); Put(Data, 0x494, 0x20b0);
    Put(Data, 0x498, 0, 2); Put(Data, 0x49a, 1, 2); Put(Data, 0x49c, 2, 2);
    Text(Data, 0x4a0, "Alpha"); Text(Data, 0x4a8, "Forward"); Text(Data, 0x4b0, "Data");
    Text(Data, 0x4c0, "KERNEL32.Sleep");
    return Data;
}
void TlsTests() {
    constexpr std::uint64_t Base = 0x180000000ULL;
    const auto MakeTls = [&](unsigned Raw, unsigned Zero) {
        auto Data = MakePe();
        Put(Data, Optional + 24, Base, 8);
        Put(Data, Table + 40 + 36, IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_INITIALIZED_DATA);
        Directory(Data, 9, 0x2080, 40);
        Put(Data, 0x480, Base + 0x2020, 8); Put(Data, 0x488, Base + 0x2020 + Raw, 8);
        Put(Data, 0x490, Base + 0x2000, 8); Put(Data, 0x498, Base + 0x2040, 8);
        Put(Data, 0x4a0, Zero); Put(Data, 0x4a4, IMAGE_SCN_ALIGN_16BYTES);
        Put(Data, 0x440, Base + 0x1000, 8); Put(Data, 0x448, 0, 8);
        return Data;
    };
    Check(!pevm::pe::ReadTlsLayout(ImageView(MakePe())), "absent TLS");
    const auto Payload = MakeTls(16, 32);
    const auto Tls = pevm::pe::ReadTlsLayout(ImageView(Payload));
    Check(Tls && Tls->TemplateBytes == 16 && Tls->TotalBytes == 48 && Tls->IndexRva == 0x2000, "TLS template and zero fill");
    auto Stub = MakeTls(8, 0);
    const auto OriginalTemplate = ImageView(Stub).FileBytesAtRva(0x2020, 8);
    const Bytes TemplateCopy(OriginalTemplate.begin(), OriginalTemplate.end());
    pevm::pe::ConfigureWrapperTls(Stub, ImageView(Payload));
    Check(pevm::pe::ReadTlsLayout(ImageView(Stub))->TotalBytes == 48, "wrapper carrier reserves payload TLS");
    Check(std::equal(TemplateCopy.begin(), TemplateCopy.end(), ImageView(Stub).FileBytesAtRva(0x2020, 8).begin()), "TLS carrier does not expose payload template");
    const auto Invalid = [&](const char* Name, auto Modify) {
        auto Broken = Payload; Modify(Broken);
        Reject(Name, [&] { pevm::pe::ReadTlsLayout(ImageView(Broken)); });
    };
    Invalid("truncated TLS directory", [&](auto& Data) { Directory(Data, 9, 0x2080, 39); });
    Invalid("reversed TLS template", [&](auto& Data) { Put(Data, 0x488, Base + 0x2010, 8); });
    Invalid("TLS index outside image", [&](auto& Data) { Put(Data, 0x490, Base + 0x3000, 8); });
    Invalid("TLS callback in data", [&](auto& Data) { Put(Data, 0x440, Base + 0x2020, 8); });
    Invalid("unbounded TLS zero fill", [&](auto& Data) { Put(Data, 0x4a0, UINT32_MAX); });
}
void ParserTests() {
    const auto Data = MakePe();
    const ImageView Image(Data);
    Check(Image.Info().Pe64 && Image.Info().Sections == 2 && Image.Info().EntryRva == 0x1000, "PE metadata");
    Check(Image.FileBytesAtRva(0x1000, 4).data() == Data.data() + 0x200, "zero-copy RVA slice");
    Check(Image.FileBytesAtRva(0x80, 4)[0] == 'P', "header RVA");
    Check(Image.CodeAtRva(0x11ff, 4096).size() == 1, "code stops at raw section end");
    Reject("gap RVA", [&] { Image.FileBytesAtRva(0x1800, 1); });
    Reject("cross-section range", [&] { Image.FileBytesAtRva(0x11ff, 2); });
    Reject("non-executable RVA", [&] { Image.CodeAtRva(0x2000, 4); });
    Reject("header code", [&] { Image.CodeAtRva(0x80, 4); });
    const auto Pe32 = MakePe(false);
    Check(!ImageView(Pe32).Info().Pe64, "PE32 accepted by common parser");
    Reject("PE32 lifting", [&] { ImageView(Pe32).RequireX64(); });
    const auto Invalid = [&](const char* Name, auto Modify) {
        auto Broken = Data; Modify(Broken);
        Reject(Name, [&] { ImageView View(Broken); });
    };
    Invalid("negative NT offset", [](Bytes& D) { Put(D, 0x3c, 0xffffffff); });
    Invalid("NT offset inside DOS", [](Bytes& D) { Put(D, 0x3c, 2); });
    Invalid("NT offset beyond file", [](Bytes& D) { Put(D, 0x3c, 0x600); });
    Invalid("signature", [](Bytes& D) { Put(D, Nt, 0); });
    Invalid("short optional header", [](Bytes& D) { Put(D, Nt + 20, 70, 2); });
    Invalid("directory count overflows optional header", [](Bytes& D) { Put(D, Optional + 108, 17); });
    Invalid("machine mismatch", [](Bytes& D) { Put(D, Nt + 4, 0x14c, 2); });
    Invalid("section table beyond headers", [](Bytes& D) { Put(D, Nt + 6, 4, 2); });
    Invalid("zero sections", [](Bytes& D) { Put(D, Nt + 6, 0, 2); });
    Invalid("too many sections", [](Bytes& D) { Put(D, Nt + 6, 97, 2); });
    Invalid("raw section past file", [](Bytes& D) { Put(D, Table + 16, 0x1000); });
    Invalid("raw offset overflow", [](Bytes& D) { Put(D, Table + 20, 0xfffffe00); });
    Invalid("raw larger than image extent", [](Bytes& D) { Put(D, Table + 12, 0x3000); });
    Invalid("virtual section past image", [](Bytes& D) { Put(D, Table + 8, 0xffffffff); });
    Invalid("virtual overlap", [](Bytes& D) { Put(D, Table + 40 + 12, 0x1000); });
    Invalid("raw overlap", [](Bytes& D) { Put(D, Table + 40 + 20, 0x200); });
    Invalid("raw header overlap", [](Bytes& D) { Put(D, Table + 20, 0); });
    Invalid("invalid alignment", [](Bytes& D) { Put(D, Optional + 36, 3); });
    Invalid("entry outside image", [](Bytes& D) { Put(D, Optional + 16, 0x3000); });
    Invalid("directory outside image", [](Bytes& D) { Directory(D, 3, 0x2fff, 12); });
    Invalid("certificate beyond file", [](Bytes& D) { Directory(D, 4, 0x600, 8); });
    for (const std::size_t Size : {0U, 63U, 0x80U, 0x98U, 0x187U, 0x1ffU, 0x5ffU})
        Reject("truncated PE", [&] { ImageView View(std::span(Data).first(Size)); });
    auto ZeroFill = Data;
    Put(ZeroFill, Table + 8, 0x400);
    Reject("zero-fill RVA", [&] { ImageView(ZeroFill).FileBytesAtRva(0x1200, 1); });
    auto NoRaw = Data;
    Put(NoRaw, Table + 16, 0); Put(NoRaw, Table + 20, 0);
    Reject("BSS RVA", [&] { ImageView(NoRaw).FileBytesAtRva(0x1000, 1); });
    auto Certificate = Data;
    Certificate.resize(0x608, 0x5a); Directory(Certificate, 4, 0x600, 8);
    Check(ImageView(Certificate).DirectoryBytes(4).size() == 8, "certificate is a file offset");
    auto Absent = Data;
    Put(Absent, Optional + 108, 0); Directory(Absent, 3, 0xffffffff, 0xffffffff);
    Check(ImageView(Absent).DirectoryBytes(3).empty(), "directory count gates access");
    auto Native = Data; Put(Native, Optional + 68, 1, 2);
    Check(ParsePe(Native).Subsystem == 1, "native PE remains inspectable");
}
Bytes MakeAppendablePe() {
    auto Data = MakePe();
    Data.insert(Data.begin() + 0x200, 0x200, 0);
    Put(Data, Optional + 60, 0x400);
    Put(Data, Table + 20, 0x400); Put(Data, Table + 40 + 20, 0x600);
    return Data;
}
void LayoutTests() {
    using pevm::pe::PlanAppendSections;
    const auto Data = MakeAppendablePe();
    const std::array<std::uint64_t, 3> Sizes{1, 600, 513};
    const auto Plan = PlanAppendSections(ImageView(Data), Sizes);
    Check(Plan.FileSize == 0x1200 && Plan.ImageSize == 0x6000 && Plan.InitializedDataSize == 0xa00,
          "append plan accounts for raw padding and initialized data");
    auto Output = Data;
    Output.resize(Plan.FileSize);
    Put(Output, Nt + 6, 5, 2);
    Put(Output, Optional + 56, Plan.ImageSize);
    Put(Output, Optional + 8, Plan.InitializedDataSize);
    for (std::size_t I = 0; I < Plan.Sections.size(); ++I) {
        const auto& S = Plan.Sections[I];
        const auto At = Table + (2 + I) * 40;
        Put(Output, At + 8, S.VirtualSize); Put(Output, At + 12, S.VirtualAddress);
        Put(Output, At + 16, S.RawSize); Put(Output, At + 20, S.RawOffset);
        Put(Output, At + 36, 0x40000040);
    }
    Check(ImageView(Output).Info().Sections == 5, "materialized plan validates independently");
    auto Unsorted = Data;
    Put(Unsorted, Table + 12, 0x2000); Put(Unsorted, Table + 40 + 12, 0x1000);
    Check(PlanAppendSections(ImageView(Unsorted), Sizes).Sections[0].VirtualAddress == 0x3000,
          "append does not assume last section has highest RVA");
    auto Low = Data;
    Put(Low, Optional + 32, 0x200); Put(Low, Optional + 56, 0x800);
    Put(Low, Optional + 16, 0x400);
    Put(Low, Table + 12, 0x400); Put(Low, Table + 40 + 12, 0x600);
    const auto LowPlan = PlanAppendSections(ImageView(Low), Sizes);
    Check(LowPlan.Sections[1].VirtualAddress == 0xa00 && LowPlan.ImageSize == LowPlan.FileSize,
          "low-alignment append includes raw padding and equal RVA/file offsets");
    auto Overlay = Data; Overlay.resize(0x801, 0x5a);
    Check(PlanAppendSections(ImageView(Overlay), Sizes).Sections[0].RawOffset == 0xa00,
          "append preserves overlay and aligns EOF");
    const auto InvalidSize = [&](const char* Name, std::uint64_t Size) {
        const std::array<std::uint64_t, 1> Input{Size};
        Reject(Name, [&] { PlanAppendSections(ImageView(Data), Input); });
    };
    InvalidSize("zero appended size", 0);
    InvalidSize("size narrowing", 0x100000000ULL);
    InvalidSize("uint64 overflow input", UINT64_MAX);
    InvalidSize("raw alignment overflow", 0xffffffffULL);
    InvalidSize("cumulative virtual overflow", 0xffffe000ULL);
    const std::array<std::uint64_t, 2> Cumulative{0x80000000ULL, 0x80000000ULL};
    Reject("combined size overflow", [&] { PlanAppendSections(ImageView(Data), Cumulative); });
    Reject("empty append", [&] { PlanAppendSections(ImageView(Data), {}); });
    Reject("insufficient header space", [&] { const auto Small = MakePe(); PlanAppendSections(ImageView(Small), Sizes); });
    auto Occupied = Data; Occupied[Table + 80] = 1;
    Reject("occupied header padding", [&] { PlanAppendSections(ImageView(Occupied), Sizes); });
    auto Signed = Data; Signed.resize(0x808); Directory(Signed, 4, 0x800, 8);
    Reject("signed template", [&] { PlanAppendSections(ImageView(Signed), Sizes); });
    auto Initialized = Data; Put(Initialized, Optional + 8, 0xfffffe00);
    Reject("initialized data overflow", [&] { PlanAppendSections(ImageView(Initialized), Sizes); });
    const std::vector<std::uint64_t> TooMany(95, 1);
    Reject("appended section count limit", [&] { PlanAppendSections(ImageView(Data), TooMany); });
}
Bytes WithRelocations() {
    auto Data = MakePe();
    Directory(Data, 5, 0x2000, 12);
    Put(Data, 0x400, 0x1000); Put(Data, 0x404, 12);
    Put(Data, 0x408, 0xa001, 2); Put(Data, 0x40a, 0, 2);
    return Data;
}
void RelocationTests() {
    using pevm::pe::RelocationTargets;
    const auto Data = WithRelocations();
    Check(RelocationTargets(ImageView(Data)) == std::vector<std::uint32_t>{0x1001},
          "DIR64 relocation and ABSOLUTE padding; unaligned target allowed");
    const auto Absent = MakePe();
    Check(RelocationTargets(ImageView(Absent)).empty(), "absent relocation table");
    auto Sorted = Data; Put(Sorted, 0x408, 0xa010, 2); Put(Sorted, 0x40a, 0xa000, 2);
    Check(RelocationTargets(ImageView(Sorted)) == std::vector<std::uint32_t>{0x1000, 0x1010},
          "relocation targets captured and sorted before mutation");
    auto ZeroFill = Data; Put(ZeroFill, Table + 8, 0x400); Put(ZeroFill, 0x408, 0xa300, 2);
    Check(RelocationTargets(ImageView(ZeroFill)) == std::vector<std::uint32_t>{0x1300},
          "relocation to mapped zero-fill is valid");
    const auto Invalid = [&](const char* Name, auto Modify) {
        auto Broken = Data; Modify(Broken);
        Reject(Name, [&] { RelocationTargets(ImageView(Broken)); });
    };
    Invalid("truncated relocation header", [](Bytes& D) { Directory(D, 5, 0x2000, 7); });
    Invalid("trailing partial relocation block", [](Bytes& D) { Directory(D, 5, 0x2000, 13); });
    Invalid("undersized relocation block", [](Bytes& D) { Put(D, 0x404, 6); });
    Invalid("zero relocation block", [](Bytes& D) { Put(D, 0x404, 0); });
    Invalid("odd relocation entries", [](Bytes& D) { Put(D, 0x404, 11); });
    Invalid("relocation block exceeds directory", [](Bytes& D) { Put(D, 0x404, 14); });
    Invalid("unaligned relocation page", [](Bytes& D) { Put(D, 0x400, 0x1001); });
    Invalid("unsupported relocation type", [](Bytes& D) { Put(D, 0x408, 0x3000, 2); });
    Invalid("relocation target outside image", [](Bytes& D) { Put(D, 0x400, 0xfffff000); });
    Invalid("relocation target crosses section", [](Bytes& D) { Put(D, 0x408, 0xa1fc, 2); });
    Invalid("relocation target is in gap", [](Bytes& D) { Put(D, 0x408, 0xa800, 2); });
    Invalid("relocation target modifies headers", [](Bytes& D) { Put(D, 0x400, 0); });
    Invalid("duplicate fixups", [](Bytes& D) { Put(D, 0x40a, 0xa001, 2); });
    Invalid("overlapping fixups", [](Bytes& D) { Put(D, 0x40a, 0xa004, 2); });
    Invalid("relocation table crosses raw end", [](Bytes& D) { Directory(D, 5, 0x21fc, 12); });
}
void ResourceTests() {
    using pevm::platform::VirtualAllocation;
    static_assert(!std::is_copy_constructible_v<VirtualAllocation>);
    static_assert(std::is_nothrow_move_constructible_v<VirtualAllocation>);
    auto* Address = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!Address) throw std::runtime_error("test allocation failed");
    VirtualAllocation Owner(Address);
    MEMORY_BASIC_INFORMATION Info{};
    Check(VirtualQuery(Address, &Info, sizeof(Info)) != 0 && Info.State == MEM_COMMIT,
          "owned virtual allocation remains committed");
    auto Moved = std::move(Owner);
    Check(!Owner && Moved.get() == Address, "virtual allocation ownership transfer");
    Moved.reset();
    Check(VirtualQuery(Address, &Info, sizeof(Info)) != 0 && Info.State == MEM_FREE,
          "owner releases full reservation");
    struct FailingConstructor {
        VirtualAllocation Memory;
        explicit FailingConstructor(void*& Address) : Memory(VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) {
            Address = Memory.get();
            if (!Address) throw std::runtime_error("test allocation failed");
            throw std::runtime_error("failure after acquiring image memory");
        }
    };
    Address = nullptr;
    try { FailingConstructor Object(Address); } catch (const std::runtime_error&) {}
    Check(Address && VirtualQuery(Address, &Info, sizeof(Info)) != 0 && Info.State == MEM_FREE,
          "constructor exception releases member-owned allocation");
}
void LifterTests() {
    const auto Data = WithFunctions();
    const ImageView Image(Data);
    const auto Candidates = x64lift::ScanFunctions(Image, 0);
    Check(Candidates.size() == 1 && Candidates[0].Name == "Alpha" && Candidates[0].Size == 4,
          "forwarders/data exports excluded; function name merged");
    const auto Functions = x64lift::LiftPeFunctions(Image, {0x1000, 0x1000});
    Check(Functions.Functions.size() == 2, "batch shares immutable image");
    const auto Attempt = x64lift::LiftPeFunctionsTolerant(Image, {0x1000, 0x2000});
    Check(Attempt.Lifted.Functions.size() == 1 && Attempt.Failures.size() == 1, "per-function failure retained");
    auto Fragment = Data;
    // Same chained unwind flag as AegisNT's shared add-rsp/pop/ret epilogue.
    Fragment[0x500] = 1 | (UNW_FLAG_CHAININFO << 3);
    Reject("chained epilogue cannot be a VM entry", [&] {
        x64lift::LiftPeFunction(ImageView(Fragment), 0x1000);
    });
    const auto Skipped = x64lift::LiftPeFunctionsTolerant(ImageView(Fragment), {0x1000});
    Check(Skipped.Lifted.Functions.empty() && Skipped.Failures.size() == 1 &&
          Skipped.Failures[0].second.find("chained unwind") != std::string::npos,
          "automatic lifting retains chained-fragment skip reason");
    auto Cross = MakePe();
    Cross[0x3ff] = 0x48; Cross[0x400] = 0x89; Cross[0x401] = 0xc8; Cross[0x402] = 0xc3;
    Reject("decoder cannot consume next section", [&] { x64lift::LiftPeFunction(ImageView(Cross), 0x11ff); });
    Reject("branch before function cannot resume outside buffer", [] {
        x64lift::LiftRawCode({0xe9, 0xfa, 0xff, 0xff, 0xff}, 0x1000);
    });
    const auto Invalid = [&](const char* Name, auto Modify) {
        auto Broken = Data; Modify(Broken);
        Reject(Name, [&] { x64lift::ScanFunctions(ImageView(Broken), 0); });
    };
    Invalid("partial exception record", [](Bytes& D) { Directory(D, 3, 0x2000, 13); });
    Invalid("invalid function extent", [](Bytes& D) { Put(D, 0x404, 0x1000); });
    Invalid("export ordinal out of range", [](Bytes& D) { Put(D, 0x498, 3, 2); });
    Invalid("export table size overflow", [](Bytes& D) { Put(D, 0x440 + 20, 0xffffffff); });
    Invalid("unterminated export name", [](Bytes& D) { Put(D, 0x48c, 0x21ff); D[0x5ff] = 'X'; });
    Invalid("export names cross raw end", [](Bytes& D) { Put(D, 0x440 + 32, 0x21fc); });
}
void ContainerTests() {
    const auto Plain = MakePe();
    for (const bool Compressed : {false, true}) {
        auto Container = PackContainer(Plain, "snapshot-password", Compressed);
        Check(UnpackContainer(Container, "snapshot-password") == Plain, "memory container roundtrip");
        if (!Compressed) {
            Put(Container, offsetof(ContainerHeader, SectionCount), 3, 2);
            Reject("container section count mismatch", [&] { UnpackContainer(Container, "snapshot-password"); });
        }
    }
    Reject("invalid PE before packing", [&] { PackContainer(Bytes(64), "snapshot-password"); });
}
void FunctionNameTests() {
    auto Data = MakePe();
    Data.resize(0x680);
    Put(Data, Nt + 12, 0x600); Put(Data, Nt + 16, 2);
    // A long, decorated COFF function name followed by its function aux record.
    Put(Data, 0x604, 4); Put(Data, 0x608, 0x10);
    Put(Data, 0x60c, 1, 2); Put(Data, 0x60e, 0x20, 2);
    Put(Data, 0x610, IMAGE_SYM_CLASS_EXTERNAL, 1); Put(Data, 0x611, 1, 1);
    Put(Data, 0x616, 12);
    Put(Data, 0x624, 0x40); Text(Data, 0x628, "?Named@@YAHH@Z");
    const auto Functions = x64lift::ScanFunctions(ImageView(Data), 0);
    Check(Functions.size() == 1 && Functions[0].Rva == 0x1010 && Functions[0].Size == 12,
          "COFF function address and aux size");
    Check(Functions[0].Name.find("Named(int)") != std::string::npos && Functions[0].NameSource == "coff" &&
          Functions[0].DecoratedName == "?Named@@YAHH@Z", "COFF function demangled with original name");
    Check(x64lift::ScanFunctions(ImageView(Data), 16).empty(), "minimum size filters COFF functions");
    auto Broken = Data; Put(Broken, 0x611, 2, 1);
    Reject("COFF aux overrun", [&] { x64lift::ScanFunctions(ImageView(Broken), 0); });
    Broken = Data; Put(Broken, 0x604, 0x40);
    Reject("COFF string offset overrun", [&] { x64lift::ScanFunctions(ImageView(Broken), 0); });
    Broken = Data; Put(Broken, Nt + 16, UINT32_MAX);
    Reject("COFF table count overrun", [&] { x64lift::ScanFunctions(ImageView(Broken), 0); });
    Broken = Data; Put(Broken, 0x60c, 2, 2);
    Check(x64lift::ScanFunctions(ImageView(Broken), 0).empty(), "COFF non-code symbol excluded");
    auto Exports = WithFunctions();
    Text(Exports, 0x4a0, "A\"\\\n");
    x64lift::FunctionScanResult Result;
    Result.Functions = x64lift::ScanFunctions(ImageView(Exports), 0);
    Result.Diagnostics = {"line\nquote\"slash\\"};
    const auto Json = x64lift::FunctionScanJson(Result);
    Check(Json.find("A\\\"\\\\\\u000a") != std::string::npos &&
          Json.find("line\\u000aquote\\\"slash\\\\") != std::string::npos, "scan JSON escapes names and diagnostics");
    Exports = WithFunctions(); Put(Exports, 0x484, 0x1000);
    const auto Aliases = x64lift::ScanFunctions(ImageView(Exports), 0);
    Check(Aliases.size() == 1 && Aliases[0].Aliases.size() == 2, "export aliases share one selectable RVA");
    Exports = WithFunctions(); Put(Exports, 0x440 + 24, 0);
    const auto Ordinals = x64lift::ScanFunctions(ImageView(Exports), 0);
    Check(Ordinals.size() == 1 && Ordinals[0].Name.empty(), "ordinal-only export retained without invented name");
}
void FileTests() {
    namespace fs = std::filesystem;
    const auto Root = fs::temp_directory_path() / (L"pevm-io-test-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64()));
    if (!fs::create_directory(Root)) throw std::runtime_error("test directory creation failed");
    const auto Output = Root / L"输出.bin";
    const Bytes Old{1, 2, 3}, New(2 * 1024 * 1024 + 1, 0x5a);
    util::WriteFileAtomic(Output, Old);
    const auto Lock = CreateFileW(Output.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (Lock == INVALID_HANDLE_VALUE) throw std::runtime_error("test output lock failed");
    bool Rejected = false;
    try { util::WriteFileAtomic(Output, New); } catch (const std::exception&) { Rejected = true; }
    CloseHandle(Lock);
    Check(Rejected && util::ReadFile(Output) == Old, "failed commit preserves old output");
    util::WriteFileAtomic(Output, New);
    Check(util::ReadFile(Output) == New, "replacement and chunked write");
    std::size_t Entries = 0;
    for (const auto& Entry : fs::directory_iterator(Root)) { (void)Entry; ++Entries; }
    Check(Entries == 1, "staging files cleaned after success/failure");
    util::WriteFileAtomic(Output, {});
    Check(util::ReadFile(Output).empty(), "empty file commit");
    fs::remove(Output); fs::remove(Root);
}
}
int main() {
    try {
        ParserTests(); TlsTests(); LayoutTests(); RelocationTests(); ResourceTests(); LifterTests(); FunctionNameTests(); ContainerTests(); FileTests();
        std::cout << "PE architecture regression: " << Checks << " checks passed\n";
        return 0;
    } catch (const std::exception& Error) {
        std::cerr << "PE architecture regression failed: " << Error.what() << '\n';
        return 1;
    }
}
