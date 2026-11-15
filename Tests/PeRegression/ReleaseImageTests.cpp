#include "PeReleaseImage.h"
#include "PeImage.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <functional>
#include <stdexcept>
#include <string>
#include <windows.h>

namespace {
using Bytes = pevm::crypto::Bytes;
constexpr std::size_t KNt = 0x80, KOptional = KNt + 24;
unsigned Checks{};
void Check(bool Condition, const char* Name) {
    if (!Condition) throw std::runtime_error(Name);
    ++Checks;
}
void Put(Bytes& Data, std::size_t At, std::uint64_t Value, std::size_t Width = 4) {
    for (std::size_t I = 0; I < Width; ++I) Data.at(At + I) = static_cast<std::uint8_t>(Value >> (I * 8));
}
void Text(Bytes& Data, std::size_t At, const char* Value) {
    std::copy_n(Value, std::strlen(Value) + 1, Data.begin() + At);
}
std::size_t DirectoryAt(bool Pe64, unsigned Index) {
    return KOptional + (Pe64 ? 112 : 96) + Index * 8;
}
void Directory(Bytes& Data, bool Pe64, unsigned Index, std::uint32_t Rva, std::uint32_t Size) {
    const auto At = DirectoryAt(Pe64, Index);
    Put(Data, At, Rva); Put(Data, At + 4, Size);
}
Bytes MakePe(bool Pe64) {
    Bytes Data(0x800);
    Data[0] = 'M'; Data[1] = 'Z';
    Put(Data, 0x3c, KNt); Put(Data, KNt, 0x4550);
    Put(Data, KNt + 4, Pe64 ? 0x8664 : 0x14c, 2);
    Put(Data, KNt + 6, 2, 2); Put(Data, KNt + 20, Pe64 ? 240 : 224, 2);
    Put(Data, KOptional, Pe64 ? 0x20b : 0x10b, 2);
    Put(Data, KOptional + 16, 0x1000);
    Put(Data, KOptional + 32, 0x1000); Put(Data, KOptional + 36, 0x200);
    Put(Data, KOptional + 56, 0x3000); Put(Data, KOptional + 60, 0x200);
    Put(Data, KOptional + 68, 3, 2);
    Put(Data, KOptional + (Pe64 ? 108 : 92), 16);
    const auto Table = KOptional + (Pe64 ? 240 : 224);
    Text(Data, Table, ".text");
    Put(Data, Table + 8, 0x200); Put(Data, Table + 12, 0x1000);
    Put(Data, Table + 16, 0x200); Put(Data, Table + 20, 0x200);
    Put(Data, Table + 36, IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE);
    Text(Data, Table + 40, ".rdata");
    Put(Data, Table + 48, 0x400); Put(Data, Table + 52, 0x2000);
    Put(Data, Table + 56, 0x400); Put(Data, Table + 60, 0x400);
    Put(Data, Table + 76, IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ);
    Data[0x200] = 0xc3;
    Text(Data, 0x7c0, "KEEP-RUNTIME-DATA");
    // Runtime directories remain byte-for-byte unchanged after sanitizing.
    Directory(Data, Pe64, 1, 0x23e0, 16);
    std::fill_n(Data.begin() + 0x7e0, 16, std::uint8_t{0x31});
    Directory(Data, Pe64, 3, 0x23a0, 12);
    std::fill_n(Data.begin() + 0x7a0, 12, std::uint8_t{0x32});
    Directory(Data, Pe64, 5, 0x2380, 12);
    std::fill_n(Data.begin() + 0x780, 12, std::uint8_t{0x33});
    Directory(Data, Pe64, 9, 0x2340, Pe64 ? 40 : 24);
    std::fill_n(Data.begin() + 0x740, Pe64 ? 40 : 24, std::uint8_t{0x34});
    return Data;
}
void DebugRecord(Bytes& Data, unsigned Index, std::uint32_t Type, std::uint32_t Raw,
                 std::uint32_t Size, std::uint32_t Rva = 0) {
    const auto At = 0x440 + Index * 28;
    Put(Data, At + 12, Type); Put(Data, At + 16, Size);
    Put(Data, At + 20, Rva); Put(Data, At + 24, Raw);
}
Bytes WithDebug(bool Pe64) {
    auto Data = MakePe(Pe64);
    Directory(Data, Pe64, IMAGE_DIRECTORY_ENTRY_DEBUG, 0x2040, 84);
    DebugRecord(Data, 0, IMAGE_DEBUG_TYPE_CODEVIEW, 0x500, 64, 0x2100);
    Put(Data, 0x500, 0x53445352); // RSDS
    std::fill_n(Data.begin() + 0x504, 16, std::uint8_t{0xa5});
    Put(Data, 0x514, 1);
    Text(Data, 0x518, "C:\\build\\secret\\LicenseGate.pdb");
    DebugRecord(Data, 1, 12, 0x560, 20, 0x2160);
    std::fill_n(Data.begin() + 0x560, 20, std::uint8_t{0x42});
    DebugRecord(Data, 2, 13, 0x580, 24, 0x2180);
    std::fill_n(Data.begin() + 0x580, 24, std::uint8_t{0x43});
    return Data;
}
void AddCoff(Bytes& Data) {
    Data.resize(0x900, 0);
    Put(Data, KNt + 12, 0x800); Put(Data, KNt + 16, 2);
    Put(Data, 0x800, 0); Put(Data, 0x804, 4); // long symbol name
    Put(Data, 0x808, 0); Put(Data, 0x80c, 1, 2); Put(Data, 0x80e, 0x20, 2);
    Data[0x810] = 2; Data[0x811] = 1; // one auxiliary function-definition record
    Put(Data, 0x816, 1);
    constexpr char Name[] = "PrivateCheck";
    Put(Data, 0x824, 4 + sizeof(Name)); Text(Data, 0x828, Name);
    Text(Data, 0x8e0, "KEEP-OVERLAY");
}
bool Zero(const Bytes& Data, std::size_t Offset, std::size_t Size) {
    return std::all_of(Data.begin() + Offset, Data.begin() + Offset + Size,
                       [](auto Byte) { return Byte == 0; });
}
void RejectUnchanged(const char* Name, Bytes Data) {
    const auto Before = Data;
    bool Rejected{};
    try { pevm::pe::StripDebugMetadata(Data); } catch (const std::exception&) { Rejected = true; }
    Check(Rejected, Name);
    Check(Data == Before, "rejected sanitization must preserve original bytes");
}
void TypicalTests(bool Pe64) {
    auto Data = WithDebug(Pe64);
    AddCoff(Data);
    const auto Before = Data;
    const auto Stats = pevm::pe::StripDebugMetadata(Data);
    const pevm::pe::ImageView Image(Data);
    Check(Stats.DebugRecords == 3 && Stats.DebugBytes == 84 + 64 + 20 + 24,
          "debug records and erased byte accounting");
    Check(Stats.CoffSymbols == 2 && Stats.CoffBytes == 36 + 4 + sizeof("PrivateCheck"),
          "COFF symbol and string-table accounting");
    Check(Data.size() == Before.size(), "sanitization preserves file size");
    Check(!Image.Directory(IMAGE_DIRECTORY_ENTRY_DEBUG).Address &&
          !Image.Directory(IMAGE_DIRECTORY_ENTRY_DEBUG).Size, "all removable debug entries clear directory");
    Check(Zero(Data, 0x440, 84) && Zero(Data, 0x500, 64) && Zero(Data, 0x560, 20) && Zero(Data, 0x580, 24),
          "debug directory and actual CodeView/PDB bytes erased");
    Check(Zero(Data, KNt + 12, 8) && Zero(Data, 0x800, Stats.CoffBytes),
          "COFF header pointers, symbols and long-name bytes erased");
    Check(std::equal(Data.begin() + 0x200, Data.begin() + 0x400, Before.begin() + 0x200),
          "executable code remains unchanged");
    Check(std::equal(Data.begin() + 0x740, Data.begin() + 0x800, Before.begin() + 0x740),
          "TLS, relocation, exception and import data remain unchanged");
    Check(std::equal(Data.begin() + 0x8e0, Data.end(), Before.begin() + 0x8e0), "unrelated overlay preserved");
    const auto HeaderBefore = pevm::pe::ImageView(Before);
    for (std::size_t I = 0; I < Image.Sections().size(); ++I) {
        const auto& A = Image.Sections()[I]; const auto& B = HeaderBefore.Sections()[I];
        Check(A.Name == B.Name && A.VirtualAddress == B.VirtualAddress && A.VirtualSize == B.VirtualSize &&
              A.RawOffset == B.RawOffset && A.RawSize == B.RawSize && A.Characteristics == B.Characteristics,
              "section/RVA/raw layout preserved");
    }
    const auto Clean = Data;
    const auto Again = pevm::pe::StripDebugMetadata(Data);
    Check(Data == Clean && !Again.DebugRecords && !Again.DebugBytes && !Again.CoffSymbols && !Again.CoffBytes,
          "sanitization is idempotent");
}
void RetainedTests() {
    auto Data = WithDebug(true);
    Directory(Data, true, IMAGE_DIRECTORY_ENTRY_DEBUG, 0x2040, 4 * 28);
    DebugRecord(Data, 1, 20, 0x5a0, 4, 0x21a0); // EX_DLLCHARACTERISTICS
    DebugRecord(Data, 2, 0x1234, 0x5b0, 8, 0x21b0); // future/unknown loader semantics
    DebugRecord(Data, 3, 16, 0x5c0, 8, 0x21c0); // REPRO identity
    Put(Data, 0x5a0, 1); Put(Data, 0x5b0, 0x8877665544332211ULL, 8);
    Put(Data, 0x5c0, 0x1234567890abcdefULL, 8);
    const auto Before = Data;
    const auto Stats = pevm::pe::StripDebugMetadata(Data);
    const auto DebugDirectory = pevm::pe::ImageView(Data).Directory(IMAGE_DIRECTORY_ENTRY_DEBUG);
    Check(Stats.DebugRecords == 1 && DebugDirectory.Address == 0x2040 && DebugDirectory.Size == 3 * 28,
          "retained debug directory is compacted in place");
    Check(std::equal(Data.begin() + 0x440, Data.begin() + 0x440 + 3 * 28, Before.begin() + 0x440 + 28),
          "extended DLL characteristics, unknown types and REPRO record bytes preserved");
    Check(Zero(Data, 0x440 + 3 * 28, 28) && Zero(Data, 0x500, 64),
          "removed descriptor tail and CodeView bytes cleared");
    Check(std::equal(Data.begin() + 0x5a0, Data.begin() + 0x5c8, Before.begin() + 0x5a0),
          "retained debug data is not erased");
    const auto Once = Data;
    Check(!pevm::pe::StripDebugMetadata(Data).DebugRecords && Data == Once, "retained entries remain stable on retry");
    auto EmptyRecord = MakePe(true);
    Directory(EmptyRecord, true, IMAGE_DIRECTORY_ENTRY_DEBUG, 0x2040, 28);
    DebugRecord(EmptyRecord, 0, 16, 0, 0);
    const auto EmptyBefore = EmptyRecord;
    Check(!pevm::pe::StripDebugMetadata(EmptyRecord).DebugRecords && EmptyRecord == EmptyBefore,
          "zero-size REPRO record preserved");
    auto Overlay = WithDebug(true);
    Overlay.resize(0x900, 0);
    std::copy_n(Overlay.begin() + 0x500, 64, Overlay.begin() + 0x820);
    std::fill_n(Overlay.begin() + 0x500, 64, std::uint8_t{0});
    DebugRecord(Overlay, 0, 2, 0x820, 64); // file-only CodeView data, no mapped RVA
    Text(Overlay, 0x8c0, "UNRELATED-RSDS-MARKER-KEEP");
    const auto OverlayBefore = Overlay;
    Check(pevm::pe::StripDebugMetadata(Overlay).DebugRecords == 3 && Zero(Overlay, 0x820, 64),
          "file-only overlay CodeView data erased through its declared raw pointer");
    Check(std::equal(Overlay.begin() + 0x8c0, Overlay.end(), OverlayBefore.begin() + 0x8c0),
          "unreferenced RSDS-like overlay bytes are not globally scanned or erased");
}
void DebugTypeTests() {
    for (const auto Type : {1U, 2U, 3U, 4U, 7U, 8U, 12U, 13U, 17U, 18U, 19U}) {
        auto Data = WithDebug(true);
        DebugRecord(Data, 0, Type, 0x500, 64, 0x2100);
        const auto Stats = pevm::pe::StripDebugMetadata(Data);
        Check(Stats.DebugRecords == 3 && Zero(Data, 0x500, 64) &&
              !pevm::pe::ImageView(Data).Directory(IMAGE_DIRECTORY_ENTRY_DEBUG).Size,
              "each supported debugger-only type and its data is removed");
    }
    for (const auto Type : {0U, 5U, 6U, 9U, 10U, 11U, 14U, 15U, 16U, 20U, 0x1234U}) {
        auto Data = MakePe(true);
        Directory(Data, true, IMAGE_DIRECTORY_ENTRY_DEBUG, 0x2040, 28);
        DebugRecord(Data, 0, Type, 0x500, 4, 0x2100);
        Put(Data, 0x500, 0x12345678);
        const auto Before = Data;
        Check(!pevm::pe::StripDebugMetadata(Data).DebugRecords && Data == Before,
              "unselected or unknown debug types retain records and payloads");
    }
}
void InvalidTests() {
    const auto Source = WithDebug(true);
    auto Broken = Source; Put(Broken, 0x440 + 24, 0x7f0);
    RejectUnchanged("truncated debug payload rejected", Broken);
    Broken = Source; Put(Broken, 0x440 + 20, 0x2200);
    RejectUnchanged("inconsistent debug RVA and raw pointer rejected", Broken);
    Broken = Source; Directory(Broken, true, IMAGE_DIRECTORY_ENTRY_DEBUG, 0x2040, 85);
    RejectUnchanged("partial debug record rejected", Broken);
    Broken = Source; DebugRecord(Broken, 0, 2, 0x200, 64, 0x1000);
    RejectUnchanged("debug data in executable section rejected", Broken);
    Broken = Source; DebugRecord(Broken, 0, 2, 0x100, 64, 0x100);
    RejectUnchanged("debug data in PE headers rejected", Broken);
    Broken = Source; DebugRecord(Broken, 0, 2, 0x7a0, 12, 0x23a0);
    RejectUnchanged("debug data overlapping exception directory rejected", Broken);
    Broken = Source; DebugRecord(Broken, 0, 2, 0x780, 12, 0x2380);
    RejectUnchanged("debug data overlapping relocation directory rejected", Broken);
    Broken = Source; DebugRecord(Broken, 0, 2, 0x740, 40, 0x2340);
    RejectUnchanged("debug data overlapping TLS directory rejected", Broken);
    Broken = Source; DebugRecord(Broken, 0, 2, 0x7e0, 16, 0x23e0);
    RejectUnchanged("debug data overlapping import directory rejected", Broken);
    Broken = Source; Broken.resize(0x900, 0);
    Directory(Broken, true, IMAGE_DIRECTORY_ENTRY_SECURITY, 0x800, 16);
    DebugRecord(Broken, 0, 2, 0x800, 16);
    RejectUnchanged("debug data overlapping certificate directory rejected", Broken);
    Broken = Source; DebugRecord(Broken, 0, 2, 0x440, 28, 0x2040);
    RejectUnchanged("debug data overlapping its own directory rejected", Broken);
    Broken = Source; DebugRecord(Broken, 1, 20, 0x500, 64, 0x2100);
    RejectUnchanged("removal overlapping retained loader debug data rejected", Broken);
    Broken = Source; DebugRecord(Broken, 0, 2, 0, 0, 0x2100);
    RejectUnchanged("addressed zero-length debug data rejected", Broken);
    Broken = Source; Directory(Broken, true, IMAGE_DIRECTORY_ENTRY_DEBUG, 0x1000, 28);
    RejectUnchanged("debug directory in executable section rejected", Broken);
    Broken = Source; Directory(Broken, true, IMAGE_DIRECTORY_ENTRY_DEBUG, 0x80, 28);
    RejectUnchanged("debug directory in PE headers rejected", Broken);
    Broken = Source; AddCoff(Broken); Put(Broken, KNt + 16, UINT32_MAX);
    RejectUnchanged("COFF count overrun rejected", Broken);
    Broken = Source; AddCoff(Broken); Put(Broken, 0x824, 3);
    RejectUnchanged("short COFF string table rejected", Broken);
    Broken = Source; AddCoff(Broken); Put(Broken, 0x804, 999);
    RejectUnchanged("out-of-range COFF string name rejected", Broken);
    Broken = Source; AddCoff(Broken); Broken[0x811] = 2;
    RejectUnchanged("COFF auxiliary count overrun rejected", Broken);
    Broken = Source; AddCoff(Broken); Put(Broken, KNt + 12, 0);
    RejectUnchanged("inconsistent COFF pointer/count rejected", Broken);
    Broken = Source; AddCoff(Broken); Text(Broken, KOptional + 240 + 40, "/4");
    RejectUnchanged("COFF strings referenced by long section names rejected", Broken);
}
} // namespace

unsigned ReleaseImageTests() {
    Checks = 0;
    for (const bool Pe64 : {false, true}) {
        auto Empty = MakePe(Pe64);
        const auto Before = Empty;
        const auto Stats = pevm::pe::StripDebugMetadata(Empty);
        Check(Empty == Before && !Stats.DebugRecords && !Stats.DebugBytes && !Stats.CoffSymbols && !Stats.CoffBytes,
              "image without debug metadata remains unchanged");
        TypicalTests(Pe64);
    }
    RetainedTests();
    DebugTypeTests();
    InvalidTests();
    return Checks;
}
