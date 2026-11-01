#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>
#include <windows.h>

#include "PeVmContainer.h"
#include "VmProtect.h"
#include "X64Lifter.h"
#include "PeVmCrypto.h"
#include "PeVmLicense.h"
#include "WrapperFormat.h"

namespace fs = std::filesystem;
using Bytes = pevm::crypto::Bytes;
namespace crypto = pevm::crypto;

std::uint32_t AlignUp(std::uint32_t Value, std::uint32_t Alignment) {
    if (Alignment == 0) throw std::runtime_error("invalid PE alignment");
    const auto Remainder = Value % Alignment;
    if (Remainder == 0) return Value;
    if (Value > std::numeric_limits<std::uint32_t>::max() - (Alignment - Remainder)) {
        throw std::runtime_error("PE alignment overflow");
    }
    return Value + Alignment - Remainder;
}

struct EmbeddedImage {
    Bytes Image;
    std::uint32_t PayloadOffset{};
    std::uint32_t MetadataOffset{};
    VmpMetadata Metadata{};
};

EmbeddedImage AddVmpSection(Bytes Stub, std::span<const std::uint8_t> Payload,
                            std::span<const std::uint8_t> VmData,
                            std::uint64_t BuildId, std::string_view Watermark,
                            bool LicenseRequired, std::span<const std::uint8_t, 32> LicenseSecret) {
    if (Stub.size() < sizeof(IMAGE_DOS_HEADER)) throw std::runtime_error("stub DOS header missing");
    const auto Dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(Stub.data());
    if (Dos->e_magic != IMAGE_DOS_SIGNATURE || Dos->e_lfanew < 0 ||
        static_cast<std::size_t>(Dos->e_lfanew) > Stub.size() - sizeof(IMAGE_NT_HEADERS64)) {
        throw std::runtime_error("stub PE header invalid");
    }
    auto Nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(Stub.data() + Dos->e_lfanew);
    if (Nt->Signature != IMAGE_NT_SIGNATURE || Nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        throw std::runtime_error("stub must be PE32+");
    }
    if (Nt->FileHeader.NumberOfSections == 0) throw std::runtime_error("stub has no sections");
    auto Sections = IMAGE_FIRST_SECTION(Nt);
    bool RuntimeSectionFound = false;
    for (unsigned I = 0; I < Nt->FileHeader.NumberOfSections; ++I) {
        if (std::memcmp(Sections[I].Name, ".text", 5) == 0) {
            static constexpr std::array<std::uint8_t, 8> RuntimeName = {'.','v','m','p','0',0,0,0};
            std::copy(RuntimeName.begin(), RuntimeName.end(), Sections[I].Name);
            RuntimeSectionFound = true;
            break;
        }
    }
    if (!RuntimeSectionFound) throw std::runtime_error("stub runtime section not found");
    const auto NewHeaderOffset = reinterpret_cast<std::uint8_t*>(&Sections[Nt->FileHeader.NumberOfSections]) - Stub.data();
    const auto AddedSections = VmData.empty() ? 2U : 3U;
    if (NewHeaderOffset + sizeof(IMAGE_SECTION_HEADER) * AddedSections > Nt->OptionalHeader.SizeOfHeaders) {
        throw std::runtime_error("stub PE headers have no room for .vmp sections");
    }
    const auto& Last = Sections[Nt->FileHeader.NumberOfSections - 1];
    const auto VirtualAddress = AlignUp(Last.VirtualAddress +
        std::max(Last.Misc.VirtualSize, Last.SizeOfRawData), Nt->OptionalHeader.SectionAlignment);
    if (Payload.size() > std::numeric_limits<std::uint32_t>::max()) throw std::runtime_error("payload too large");
    const auto VirtualSize = static_cast<std::uint32_t>(Payload.size());
    const auto RawOffset = AlignUp(static_cast<std::uint32_t>(Stub.size()), Nt->OptionalHeader.FileAlignment);
    const auto RawSize = AlignUp(VirtualSize, Nt->OptionalHeader.FileAlignment);
    const auto VmDataOffset = RawOffset + RawSize;
    const auto VmDataRawSize = VmData.empty() ? 0U : AlignUp(static_cast<std::uint32_t>(VmData.size()), Nt->OptionalHeader.FileAlignment);
    const auto MetadataOffset = VmDataOffset + VmDataRawSize;
    const auto MetadataRawSize = AlignUp(static_cast<std::uint32_t>(sizeof(VmpMetadata)),
                                         Nt->OptionalHeader.FileAlignment);
    if (MetadataOffset > std::numeric_limits<std::uint32_t>::max() - MetadataRawSize) throw std::runtime_error("wrapped PE too large");
    Stub.resize(static_cast<std::size_t>(MetadataOffset) + MetadataRawSize, 0);

    // resize can relocate the vector, so reacquire all PE pointers.
    const auto MutableDos = reinterpret_cast<IMAGE_DOS_HEADER*>(Stub.data());
    Nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(Stub.data() + MutableDos->e_lfanew);
    Sections = IMAGE_FIRST_SECTION(Nt);
    const auto OriginalSectionCount = Nt->FileHeader.NumberOfSections;
    auto& NewSection = Sections[OriginalSectionCount];
    NewSection = {};
    static constexpr std::array<std::uint8_t, 8> Name = {'.','v','m','p','1',0,0,0};
    std::copy(Name.begin(), Name.end(), NewSection.Name);
    NewSection.Misc.VirtualSize = VirtualSize;
    NewSection.VirtualAddress = VirtualAddress;
    NewSection.SizeOfRawData = RawSize;
    NewSection.PointerToRawData = RawOffset;
    NewSection.Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
    const auto MetadataVirtualAddress = AlignUp(VirtualAddress + VirtualSize,
                                                Nt->OptionalHeader.SectionAlignment);
    auto& MetadataSection = Sections[OriginalSectionCount + 1];
    MetadataSection = {};
    static constexpr std::array<std::uint8_t, 8> MetadataName = {'.','v','m','p','2',0,0,0};
    std::copy(MetadataName.begin(), MetadataName.end(), MetadataSection.Name);
    MetadataSection.Misc.VirtualSize = sizeof(VmpMetadata);
    MetadataSection.VirtualAddress = MetadataVirtualAddress;
    MetadataSection.SizeOfRawData = MetadataRawSize;
    MetadataSection.PointerToRawData = MetadataOffset;
    MetadataSection.Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
    Nt->FileHeader.NumberOfSections += 2;
    Nt->OptionalHeader.SizeOfImage = AlignUp(MetadataVirtualAddress + sizeof(VmpMetadata),
                                              Nt->OptionalHeader.SectionAlignment);
    Nt->OptionalHeader.CheckSum = 0;
    std::copy(Payload.begin(), Payload.end(), Stub.begin() + RawOffset);

    if (!VmData.empty()) {
        const auto VmDataVirtualAddress = AlignUp(MetadataVirtualAddress + sizeof(VmpMetadata), Nt->OptionalHeader.SectionAlignment);
        auto& VmSection = Sections[OriginalSectionCount + 2];
        VmSection = {};
        static constexpr std::array<std::uint8_t, 8> VmName = {'.','v','m','p','3',0,0,0};
        std::copy(VmName.begin(), VmName.end(), VmSection.Name);
        VmSection.Misc.VirtualSize = static_cast<std::uint32_t>(VmData.size());
        VmSection.VirtualAddress = VmDataVirtualAddress;
        VmSection.SizeOfRawData = VmDataRawSize;
        VmSection.PointerToRawData = VmDataOffset;
        VmSection.Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
        Nt->FileHeader.NumberOfSections += 1;
        Nt->OptionalHeader.SizeOfImage = AlignUp(VmDataVirtualAddress + static_cast<std::uint32_t>(VmData.size()), Nt->OptionalHeader.SectionAlignment);
        std::copy(VmData.begin(), VmData.end(), Stub.begin() + VmDataOffset);
    }

    VmpMetadata Metadata{};
    Metadata.Magic = KVmpMetadataMagic;
    Metadata.Version = 4;
    Metadata.BuildId = BuildId;
    for (unsigned I = 0; I < OriginalSectionCount; ++I) {
        if (std::memcmp(Sections[I].Name, ".vmp0", 5) == 0) {
            Metadata.RuntimeRawOffset = Sections[I].PointerToRawData;
            Metadata.RuntimeRawSize = Sections[I].SizeOfRawData;
            break;
        }
    }
    Metadata.PayloadRawOffset = RawOffset;
    Metadata.PayloadRawSize = VirtualSize;
    if (Metadata.RuntimeRawSize == 0) throw std::runtime_error(".vmp0 runtime range missing");
    Metadata.RuntimeTag = VmpRegionTag(std::span(Stub).subspan(Metadata.RuntimeRawOffset,
                                                                Metadata.RuntimeRawSize),
                                       Metadata.BuildId, 0x30504D56ULL);
    Metadata.PayloadTag = VmpRegionTag(std::span(Stub).subspan(RawOffset, VirtualSize),
                                       Metadata.BuildId, 0x31504D56ULL);
    if (!VmData.empty()) {
        Metadata.VmDataRawOffset = VmDataOffset;
        Metadata.VmDataRawSize = static_cast<std::uint32_t>(VmData.size());
        Metadata.VmDataTag = VmpRegionTag(std::span(Stub).subspan(VmDataOffset, VmData.size()),
                                          Metadata.BuildId, 0x33504D56ULL);
    }
    const auto HandlerProfile = MakeHandlerProfile(Metadata.BuildId);
    for (std::size_t I = 0; I < Metadata.HandlerProfile.size(); ++I) {
        Metadata.HandlerProfile[I] = HandlerProfile[I];
    }
    // Customer watermark: XOR-obfuscated so it is not greppable in the file.
    Metadata.Watermark.fill(0);
    for (std::size_t I = 0; I < Watermark.size() && I + 1 < Metadata.Watermark.size(); ++I) {
        Metadata.Watermark[I] = static_cast<std::uint8_t>(Watermark[I]) ^ 0x5AU;
    }
    Metadata.LicenseRequired = LicenseRequired ? 1U : 0U;
    std::copy(LicenseSecret.begin(), LicenseSecret.end(), Metadata.LicenseSecret.begin());
    std::memcpy(Stub.data() + MetadataOffset, &Metadata, sizeof(Metadata));
    return {std::move(Stub), RawOffset, MetadataOffset, Metadata};
}

// Assembles the final runnable wrapper: appends the sealed build secret and
// the wrapper footer to an embedded stub image. Shared by wrap and the
// function-virtualization commands.
Bytes SealWrapper(EmbeddedImage Embedded, const Bytes& Payload,
                  std::string_view Password) {
    WrapperFooter Footer{};
    Footer.Magic = KWrapperMagic;
    Footer.Version = 2;
    Footer.PayloadSize = Payload.size();
    Footer.PayloadOffset = Embedded.PayloadOffset;
    Footer.StubSize = Embedded.Image.size();
    Footer.MetadataOffset = Embedded.MetadataOffset;
    Footer.MetadataSize = sizeof(VmpMetadata);
    Footer.SecretSize = static_cast<std::uint32_t>(Password.size());
    const auto Ticks = static_cast<std::uint64_t>(std::chrono::high_resolution_clock::now().time_since_epoch().count());
    for (std::size_t I = 0; I < Footer.Salt.size(); ++I) {
        Footer.Salt[I] = static_cast<std::uint8_t>(WrapperMix64(Ticks ^ (I * 0x9E3779B97F4A7C15ULL)) >> 32);
    }
    const auto Fingerprint = WrapperFingerprint(Embedded.Image, Payload, Footer.Salt);
    Bytes SealedSecret(Password.size());
    for (std::size_t I = 0; I < Password.size(); ++I) {
        SealedSecret[I] = static_cast<std::uint8_t>(Password[I]) ^ WrapperSecretByte(Fingerprint, I);
    }
    Footer.SecretTag = WrapperSecretTag(SealedSecret, Fingerprint);
    Bytes Wrapped = std::move(Embedded.Image);
    Wrapped.insert(Wrapped.end(), SealedSecret.begin(), SealedSecret.end());
    const auto* FooterBytes = reinterpret_cast<const std::uint8_t*>(&Footer);
    Wrapped.insert(Wrapped.end(), FooterBytes, FooterBytes + sizeof(Footer));
    return Wrapped;
}

std::uint64_t NewBuildId(std::size_t PayloadSize) {
    return WrapperMix64(static_cast<std::uint64_t>(
        std::chrono::high_resolution_clock::now().time_since_epoch().count()) ^ PayloadSize);
}

// Runnable wrappers host user-mode payloads only: the stub maps the image and
// calls its entry in-process, which makes no sense for a native driver.
// Driver (.sys) delivery is an external, trusted step - the protected artifact
// is the container.
// VMP-style licensing helpers. The secret is a 32-byte HMAC key supplied at
// protect time; keys are machine-locked and optionally expire.
std::array<std::uint8_t, 32> ParseLicenseSecret(std::string_view Text) {
    std::array<std::uint8_t, 32> Secret{};
    if (Text.size() != Secret.size() * 2) throw std::runtime_error("license secret must be 64 hex characters");
    auto Nibble = [](char C) -> unsigned {
        if (C >= '0' && C <= '9') return static_cast<unsigned>(C - '0');
        if (C >= 'a' && C <= 'f') return static_cast<unsigned>(C - 'a' + 10);
        if (C >= 'A' && C <= 'F') return static_cast<unsigned>(C - 'A' + 10);
        throw std::runtime_error("license secret must be 64 hex characters");
    };
    for (std::size_t I = 0; I < Secret.size(); ++I) {
        Secret[I] = static_cast<std::uint8_t>((Nibble(Text[I * 2]) << 4) | Nibble(Text[I * 2 + 1]));
    }
    return Secret;
}

std::uint32_t ParseMachineId(std::string_view Text) {
    if (Text.size() > 8) throw std::runtime_error("machine id must be up to 8 hex characters");
    return static_cast<std::uint32_t>(std::stoul(std::string(Text), nullptr, 16));
}

void CmdMachineId() {
    std::cout << "machine id: " << std::hex << std::setw(8) << std::setfill('0')
              << pevm::license::MachineId() << std::dec << "\n";
}

void CmdMakeLicense(std::string_view SecretText, std::uint32_t Days, std::uint32_t Machine) {
    const auto Secret = ParseLicenseSecret(SecretText);
    FILETIME Now{};
    GetSystemTimeAsFileTime(&Now);
    const auto Payload = pevm::license::MakePayload(Machine, Days,
                                                    (static_cast<std::uint64_t>(Now.dwHighDateTime) << 32) | Now.dwLowDateTime,
                                                    Secret);
    std::cout << pevm::license::FormatLicense(Payload) << "\n";
    if (Days != 0) {
        std::cout << "valid for " << Days << " days from now, locked to machine "
                  << std::hex << std::setw(8) << std::setfill('0') << Machine << std::dec << "\n";
    } else {
        std::cout << "unlimited validity, locked to machine "
                  << std::hex << std::setw(8) << std::setfill('0') << Machine << std::dec << "\n";
    }
}

void RejectNativePayload(const fs::path& Input) {
    const auto Pe=ParsePe(util::ReadFile(Input));
    if (Pe.Subsystem==KSubsystemNative) {
        throw std::runtime_error("native-subsystem (driver) payloads support container protection "
                                 "(pack/unpack/inspect) but not runnable wrappers; kernel loading stays external");
    }
}

void CmdWrap(const fs::path& Input, const fs::path& Output, std::string_view Password,
             const fs::path& StubPath, std::string_view Watermark, bool Compress,
             bool LicenseRequired, std::span<const std::uint8_t, 32> LicenseSecret) {
    RejectNativePayload(Input);
    if (!fs::exists(StubPath)) throw std::runtime_error("PeVmStub.exe not found beside pevm.exe");
    const auto TemporaryContainer = Output.string() + ".payload.tmp";
    try {
        CmdPack(Input, TemporaryContainer, Password, Compress);
        auto Stub = util::ReadFile(StubPath);
        const auto Payload = util::ReadFile(TemporaryContainer);
        const auto Embedded = AddVmpSection(std::move(Stub), Payload, {}, NewBuildId(Payload.size()),
                                            Watermark, LicenseRequired, LicenseSecret);
        util::WriteFileAtomic(Output, SealWrapper(std::move(Embedded), Payload, Password));
        fs::remove(TemporaryContainer);
        std::cout << "runnable wrapper: " << Input << " -> " << Output << "\n"
                  << "embedded payload: " << Payload.size() << " bytes\n";
    } catch (...) {
        std::error_code Error;
        fs::remove(TemporaryContainer, Error);
        throw;
    }
}

// Serializes a lifted multi-program set, packs the payload and seals the
// wrapper. Shared by protect-functions and protect-all.
void AssembleVirtualizedWrapper(const fs::path& Input, const fs::path& Output,
                                std::string_view Password, const x64lift::MultiLiftResult& Lifted,
                                std::uint64_t Seed, const fs::path& StubPath, bool AntiDisassembly,
                                bool Mutate, std::string_view Watermark, bool Compress,
                                bool LicenseRequired, std::span<const std::uint8_t, 32> LicenseSecret) {
    const auto BuildId = NewBuildId(0);
    auto Prepared = Lifted;
    if (Mutate) {
        for (auto& Function : Prepared.Functions) {
            x64lift::MutateProgram(Function.Program, Seed ^ Function.Program.EntryAddress);
        }
    }
    const auto VmData = x64lift::SerializeVmp3Multi(Prepared, Seed, Password,
                                                    MakeHandlerProfile(BuildId), AntiDisassembly);
    const auto TemporaryContainer = Output.string() + ".payload.tmp";
    try {
        CmdPack(Input, TemporaryContainer, Password, Compress);
        auto Stub = util::ReadFile(StubPath);
        const auto Payload = util::ReadFile(TemporaryContainer);
        const auto Embedded = AddVmpSection(std::move(Stub), Payload, VmData, BuildId, Watermark,
                                            LicenseRequired, LicenseSecret);
        util::WriteFileAtomic(Output, SealWrapper(std::move(Embedded), Payload, Password));
        fs::remove(TemporaryContainer);
        std::size_t TotalInstructions = 0;
        for (const auto& Function : Prepared.Functions) TotalInstructions += Function.Program.Instructions.size();
        std::cout << "virtualized wrapper: " << Input << " -> " << Output << "\n"
                  << "functions: " << Prepared.Functions.size() << "\n";
        for (const auto& Function : Prepared.Functions) {
            std::cout << "function RVA: 0x" << std::hex << Function.Program.EntryAddress << std::dec
                      << " (VM2 instructions: " << Function.Program.Instructions.size() << ")\n";
        }
        std::cout << ".vmp3 bytes: " << VmData.size() << "\n";
    } catch (...) {
        std::error_code Error;
        fs::remove(TemporaryContainer, Error);
        throw;
    }
}

void CmdVirtualizeFunctions(const fs::path& Input, const fs::path& Output,
                            std::string_view Password, const std::vector<std::uint32_t>& FunctionRvas,
                            std::uint64_t Seed, const fs::path& StubPath, bool AntiDisassembly,
                            bool Mutate, std::string_view Watermark, bool Compress,
                            bool LicenseRequired, std::span<const std::uint8_t, 32> LicenseSecret) {
    if (FunctionRvas.empty()) throw std::runtime_error("function virtualization requires at least one RVA");
    RejectNativePayload(Input);
    if (!fs::exists(StubPath)) throw std::runtime_error("PeVmStub.exe not found beside pevm.exe");
    const auto Lifted = x64lift::LiftPeFunctions(Input, FunctionRvas);
    AssembleVirtualizedWrapper(Input, Output, Password, Lifted, Seed, StubPath, AntiDisassembly,
                               Mutate, Watermark, Compress, LicenseRequired, LicenseSecret);
}

// VMP-style "virtualize everything": discover every function (.pdata and
// exports), lift each one, keep what succeeds and skip the rest with a
// reason. Functions touching memory operands are skipped unless the caller
// accepts VM-memory semantics (--allow-mem), because the lifted VM resolves
// memory through flat VM-space offsets, not native pointers.
void CmdVirtualizeAll(const fs::path& Input, const fs::path& Output,
                      std::string_view Password, std::uint64_t Seed, const fs::path& StubPath,
                      bool AntiDisassembly, bool AllowMemory, std::size_t MinimumBytes,
                      bool Mutate, std::string_view Watermark, bool Compress,
                      bool LicenseRequired, std::span<const std::uint8_t, 32> LicenseSecret) {
    if (!fs::exists(StubPath)) throw std::runtime_error("PeVmStub.exe not found beside pevm.exe");
    RejectNativePayload(Input);
    const auto Candidates = x64lift::ScanFunctions(Input, MinimumBytes);
    if (Candidates.empty()) throw std::runtime_error("no function candidates discovered (.pdata/exports)");

    std::vector<std::uint32_t> Rvas;
    for (const auto& Candidate : Candidates) Rvas.push_back(Candidate.Rva);
    auto Attempt = x64lift::LiftPeFunctionsTolerant(Input, Rvas);

    x64lift::MultiLiftResult Lifted;
    for (auto& Function : Attempt.Lifted.Functions) {
        const bool TouchesMemory = std::any_of(Function.Program.Instructions.begin(),
                                               Function.Program.Instructions.end(),
                                               [](const vmprotect::LiftedInstruction& Instruction) {
                                                   return Instruction.Op == vmprotect::LiftedOp::LoadMem ||
                                                          Instruction.Op == vmprotect::LiftedOp::StoreMem;
                                               });
        if (TouchesMemory && !AllowMemory) {
            Attempt.Failures.push_back({Function.Program.EntryAddress,
                                        "touches memory operands (VM memory semantics required, use --allow-mem)"});
        } else {
            Lifted.Functions.push_back(std::move(Function));
        }
    }
    if (Lifted.Functions.empty()) throw std::runtime_error("no function could be virtualized");

    AssembleVirtualizedWrapper(Input, Output, Password, Lifted, Seed, StubPath, AntiDisassembly,
                               Mutate, Watermark, Compress, LicenseRequired, LicenseSecret);
    std::cout << "skipped: " << Attempt.Failures.size() << "\n";
    for (const auto& [Rva, Reason] : Attempt.Failures) {
        std::cout << "  skipped RVA: 0x" << std::hex << Rva << std::dec << " - " << Reason << "\n";
    }
}

void CmdScanFunctions(const fs::path& Input, const fs::path& JsonPath, std::size_t MinimumBytes) {
    const auto Candidates = x64lift::ScanFunctions(Input, MinimumBytes);
    std::cout << "discovered functions: " << Candidates.size() << "\n";
    for (const auto& Candidate : Candidates) {
        std::cout << "RVA: 0x" << std::hex << Candidate.Rva << std::dec
                  << " size: " << Candidate.Size;
        if (!Candidate.Name.empty()) std::cout << " name: " << Candidate.Name;
        std::cout << "\n";
    }
    if (!JsonPath.empty()) {
        std::ofstream Json(JsonPath, std::ios::binary | std::ios::trunc);
        if (!Json) throw std::runtime_error("cannot create scan output");
        Json << "{\n  \"format\": \"pevm-scan-functions\",\n  \"functions\": [\n";
        for (std::size_t I = 0; I < Candidates.size(); ++I) {
            const auto& Candidate = Candidates[I];
            Json << "    {\"rva\":\"0x" << std::hex << Candidate.Rva << "\",\"size\":"
                 << std::dec << Candidate.Size << ",\"name\":\"" << Candidate.Name << "\"}"
                 << (I + 1 == Candidates.size() ? "\n" : ",\n");
        }
        Json << "  ]\n}\n";
        std::cout << "scan output: " << JsonPath << "\n";
    }
}

void InspectWrapper(std::span<const std::uint8_t> File) {
    if (File.size() < sizeof(WrapperFooter)) throw std::runtime_error("wrapper footer missing");
    WrapperFooter Footer{};
    std::memcpy(&Footer, File.data() + File.size() - sizeof(Footer), sizeof(Footer));
    if (Footer.Magic != KWrapperMagic || Footer.Version != 2) throw std::runtime_error("not a PeVmProtector wrapper");
    if (Footer.MetadataOffset > File.size() || Footer.MetadataSize > File.size() - Footer.MetadataOffset) {
        throw std::runtime_error("wrapper metadata range invalid");
    }
    VmpMetadata Metadata{};
    std::memcpy(&Metadata, File.data() + Footer.MetadataOffset, sizeof(Metadata));
    std::cout << "format: PeVmProtector runnable wrapper\n"
              << "stub bytes: " << Footer.StubSize << "\n"
              << "payload bytes: " << Footer.PayloadSize << "\n"
              << "build id: 0x" << std::hex << Metadata.BuildId << std::dec << "\n";
    std::string Watermark;
    for (const auto Byte : Metadata.Watermark) {
        if (Byte == 0) break;
        Watermark.push_back(static_cast<char>(Byte ^ 0x5A));
    }
    if (!Watermark.empty()) std::cout << "watermark: " << Watermark << "\n";
    if (Metadata.VmDataRawSize != 0) {
        if (Metadata.VmDataRawOffset > File.size() ||
            Metadata.VmDataRawSize > File.size() - Metadata.VmDataRawOffset ||
            Metadata.VmDataRawSize < sizeof(Vmp3Header)) {
            throw std::runtime_error(".vmp3 section range invalid");
        }
        Vmp3Header Vmp3{};
        std::memcpy(&Vmp3, File.data() + Metadata.VmDataRawOffset, sizeof(Vmp3));
        if (Vmp3.Magic != KVmp3Magic) {
            std::cout << ".vmp3: present but header unrecognized\n";
            return;
        }
        if (Vmp3.Version != 3 || Vmp3.FunctionCount == 0 ||
            Vmp3.FunctionCount > (Metadata.VmDataRawSize - sizeof(Vmp3)) / sizeof(Vmp3Entry)) {
            std::cout << ".vmp3: unsupported version " << Vmp3.Version << "\n";
            return;
        }
        const auto* Entries = reinterpret_cast<const Vmp3Entry*>(File.data() +
            Metadata.VmDataRawOffset + sizeof(Vmp3));
        std::cout << ".vmp3 version: " << Vmp3.Version << " (instruction table encrypted)\n"
                  << ".vmp3 functions: " << Vmp3.FunctionCount << "\n"
                  << ".vmp3 seed: 0x" << std::hex << Vmp3.Seed << std::dec << "\n"
                  << ".vmp3 decoy bytes: " << Vmp3.DecoySize << "\n";
        for (std::uint32_t I = 0; I < Vmp3.FunctionCount; ++I) {
            std::cout << ".vmp3 function[" << I << "] RVA: 0x" << std::hex << Entries[I].FunctionRva
                      << std::dec << " instructions: " << Entries[I].InstructionCount << "\n";
        }
    } else {
        std::cout << ".vmp3: not present (plain wrapped container)\n";
    }
}

void CmdInspect(const fs::path& Input) {
    const auto File=util::ReadFile(Input);
    if (File.size() >= 2 && File[0] == 'M' && File[1] == 'Z') {
        InspectWrapper(File);
        return;
    }
    const auto H=ParseContainer(File);
    std::cout<<"format: PEVM-PACK\n"
             <<"machine: 0x"<<std::hex<<H.Machine<<std::dec<<"\n"
             <<"subsystem: "<<SubsystemName(H.Subsystem)<<"\n"
             <<"sections: "<<H.SectionCount<<"\n"
             <<"entry RVA: 0x"<<std::hex<<H.EntryRva<<std::dec<<"\n"
             <<"original bytes: "<<H.OriginalSize<<"\n"
             <<"VM bytecode bytes: "<<H.ProgramSize<<"\n"
             <<"payload bytes: "<<H.PayloadSize<<"\n"
             <<"kdf: scrypt N=1<<"<<static_cast<unsigned>(H.KdfLogN)
             <<" r="<<static_cast<unsigned>(H.KdfR)
             <<" p="<<static_cast<unsigned>(H.KdfP)<<"\n"
             <<"nonce: "<<util::Hex(std::span(H.Nonce,8))<<"\n"
             <<"opcode map: "<<util::Hex(std::span(H.OpcodeMap,KOpcodeCount))<<"\n"
             <<"plain SHA-256: "<<util::Hex(std::span(H.PlainSha256,32))<<"\n";
}

const char* OpName(Op Operation) {
    switch(Operation) {
    case Op::MovI:return "MOVI"; case Op::Load64:return "LOAD64"; case Op::Xor:return "XOR";
    case Op::Add:return "ADD"; case Op::Mul:return "MUL"; case Op::Rol:return "ROL";
    case Op::Store64:return "STORE64"; case Op::Out64:return "OUT64"; case Op::XorI:return "XORI";
    case Op::AddI:return "ADDI"; case Op::Halt:return "HALT";
    }
    return "?";
}

void CmdVmDump(const fs::path& Input) {
    const auto File=util::ReadFile(Input);
    const auto H=ParseContainer(File);
    OpcodeMap Map{}; std::copy_n(H.OpcodeMap,KOpcodeCount,Map.begin());
    const auto Code=std::span(File).subspan(H.HeaderSize,H.ProgramSize);
    std::size_t Pc=0;
    auto Byte=[&](){ if(Pc>=Code.size()) throw std::runtime_error("bytecode truncated"); return Code[Pc++]; };
    auto Imm=[&](){ const auto V=util::LoadLe<std::uint64_t>(Code,Pc); Pc+=8; return V; };
    while(Pc<Code.size()) {
        const auto Start=Pc;
        const auto Encoded=Byte();
        const auto Op=DecodeOp(Encoded,Map);
        std::cout<<std::setw(4)<<std::setfill('0')<<std::hex<<Start<<"  "<<std::setw(2)
                 <<static_cast<unsigned>(Encoded)<<"  "<<std::left<<std::setfill(' ')<<std::setw(8)<<OpName(Op)<<std::right;
        switch(Op) {
        case Op::MovI: case Op::XorI: case Op::AddI: {
            const auto R=Byte(); const auto V=Imm(); std::cout<<" r"<<static_cast<unsigned>(R)<<", 0x"<<V; break;
        }
        case Op::Load64: case Op::Rol: case Op::Store64: {
            const auto R=Byte(), V=Byte(); std::cout<<" r"<<static_cast<unsigned>(R)<<", "<<std::dec<<static_cast<unsigned>(V)<<std::hex; break;
        }
        case Op::Xor: case Op::Add: case Op::Mul: {
            const auto D=Byte(),S=Byte(); std::cout<<" r"<<static_cast<unsigned>(D)<<", r"<<static_cast<unsigned>(S); break;
        }
        case Op::Out64: std::cout<<" r"<<static_cast<unsigned>(Byte()); break;
        case Op::Halt: break;
        }
        std::cout<<"\n";
    }
    std::cout<<std::dec;
}

void SelfTest() {
    const std::string Pass="correct horse battery staple";
    const std::array<std::uint8_t,8> Nonce={1,2,3,4,5,6,7,8};
    const auto Program=KeyProgram();
    const auto Key=DeriveKey(Pass,Nonce,Program,KIdentityMap,KDefaultKdf);
    Bytes Data(1027);
    for(std::size_t I=0;I<Data.size();++I) Data[I]=static_cast<std::uint8_t>((I*131+17)&0xff);
    const auto Original=Data;
    crypto::XteaCtr(Data,Key,util::LoadLe<std::uint64_t>(Nonce,0));
    if(Data==Original) throw std::runtime_error("cipher self-test did not transform data");
    crypto::XteaCtr(Data,Key,util::LoadLe<std::uint64_t>(Nonce,0));
    if(Data!=Original) throw std::runtime_error("cipher round-trip failed");
    const std::string Abc="abc";
    const auto Hash=crypto::Sha256::Digest(std::span(reinterpret_cast<const std::uint8_t*>(Abc.data()),Abc.size()));
    if(util::Hex(Hash)!="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") {
        throw std::runtime_error("SHA-256 self-test failed");
    }
    // RFC 7914 scrypt test vectors.
    {
        const auto Empty = crypto::Scrypt({}, {}, 16, 1, 1, 64);
        if (crypto::Hex(Empty) !=
            "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442"
            "fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906") {
            throw std::runtime_error("scrypt self-test (RFC 7914 #1) failed");
        }
        const auto Password = std::span(reinterpret_cast<const std::uint8_t*>("password"), 8);
        const auto Salt = std::span(reinterpret_cast<const std::uint8_t*>("NaCl"), 4);
        const auto Vector2 = crypto::Scrypt(Password, Salt, 1024, 8, 16, 64);
        if (crypto::Hex(Vector2) !=
            "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162"
            "2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640") {
            throw std::runtime_error("scrypt self-test (RFC 7914 #2) failed");
        }
    }
    // LZSS round-trip: a highly compressible pattern must actually shrink;
    // pseudo-random data must survive regardless of expansion.
    {
        Bytes Compressible;
        for (std::size_t I = 0; I < 1000; ++I) {
            Compressible.push_back(static_cast<std::uint8_t>((I / 97) ^ ((I % 13) * 7)));
        }
        const auto Compressed = crypto::LzssCompress(Compressible);
        try {
            if (crypto::LzssDecompress(Compressed, Compressible.size()) != Compressible) {
                throw std::runtime_error("round-trip mismatch");
            }
        } catch (const std::exception& Error) {
            std::ostringstream Dump;
            Dump << std::hex << std::setfill('0');
            for (std::size_t I = 0; I < Compressed.size() && I < 32; ++I) {
                Dump << std::setw(2) << static_cast<unsigned>(Compressed[I]) << ' ';
            }
            throw std::runtime_error(std::string("LZSS compressible: ") + Error.what() + " stream[" +
                                     std::to_string(Compressed.size()) + "]: " + Dump.str());
        }
        if (Compressed.size() >= Compressible.size()) {
            throw std::runtime_error("LZSS failed to shrink compressible data");
        }
        Bytes Random;
        std::uint64_t State = 0x243F6A8885A308D3ULL;
        for (std::size_t I = 0; I < 50000; ++I) {
            State = State * 6364136223846793005ULL + 1442695040888963407ULL;
            Random.push_back(static_cast<std::uint8_t>(State >> 33));
        }
        const auto Stored = crypto::LzssCompress(Random);
        try {
            if (crypto::LzssDecompress(Stored, Random.size()) != Random) {
                throw std::runtime_error("LZSS round-trip failed on random data");
            }
        } catch (const std::exception&) {
            throw std::runtime_error("LZSS corrupt on RANDOM data");
        }
    }
    std::cout<<"self-test: OK\nVM bytecode: "<<Program.size()<<" bytes\nkey fingerprint: "
             <<std::hex<<std::setfill('0')<<std::setw(8)<<Key[0]<<std::dec<<"\n";
}

void Usage() {
    std::cout<<"PeVmProtector\n"
             <<"  pevm pack <input.exe> <output.pvm> <password> [--compress]\n"
             <<"  pevm wrap <input.exe> <output.exe> <password> [watermark] [--compress] [--license --license-secret=<64hex>]\n"
             <<"  pevm machine-id\n"
             <<"  pevm make-license <secret-hex-64> [days] [--machine=<hex8>]\n"
             <<"  pevm protect-function <input.exe> <output.exe> <password> <function-rva> [seed] [--anti-disasm]\n"
             <<"  pevm protect-functions <input.exe> <output.exe> <password> <rva> [rva...] [--seed=N] [--anti-disasm]\n"
             <<"  pevm protect-all <input.exe> <output.exe> <password> [seed] [--anti-disasm] [--allow-mem] [--min-bytes=N] [--mutate] [--watermark=text]\n"
             <<"  pevm scan-functions <input.exe> [json-out] [--min-bytes=N]\n"
             <<"  pevm unpack <input.pvm> <output.exe> <password>\n"
             <<"  pevm inspect <input.pvm>\n"
             <<"  pevm vm-dump <input.pvm>\n"
             <<"  pevm vm-demo <password>\n"
             <<"  pevm virtualize-demo <0..20> [seed] [--trace]\n"
             <<"  pevm call-memory-demo <input> [seed] [--trace]\n"
             <<"  pevm vm2-self-test\n"
             <<"  pevm lift-x64 <input.exe> <function-rva> <output.json> [seed] [--rcx=N] [--rdx=N] [--r8=N] [--r9=N] [--trace]\n"
             <<"  pevm lift-raw <hex-bytes> <entry-rva> [seed] [--rcx=N] [--rdx=N] [--r8=N] [--r9=N] [--trace]\n"
             <<"  pevm lift-x64-multi <input.exe> <output.json> <rva> [rva...]\n"
             <<"  pevm self-test\n";
}

#ifndef PEVM_NO_CLI_MAIN
int main(int Argc,char** Argv) {
    try {
        if(Argc<2){ Usage(); return 2; }
        const std::string Cmd=Argv[1];
        if(Cmd=="pack" && Argc>=5 && Argc<=6) {
            const bool Compress = Argc == 6 && std::string_view(Argv[5]) == "--compress";
            CmdPack(Argv[2],Argv[3],Argv[4],Compress);
        }
        else if(Cmd=="machine-id" && Argc==2) CmdMachineId();
        else if(Cmd=="make-license" && Argc>=3 && Argc<=5) {
            std::uint32_t Days = Argc >= 4 ? static_cast<std::uint32_t>(std::stoul(Argv[3], nullptr, 0)) : 0;
            std::uint32_t Machine = pevm::license::MachineId();
            for (int I = 4; I < Argc; ++I) {
                const std::string_view Arg = Argv[I];
                if (Arg.starts_with("--machine=")) Machine = ParseMachineId(Argv[I] + 10);
                else throw std::runtime_error("unknown make-license option");
            }
            CmdMakeLicense(Argv[2], Days, Machine);
        }
        else if(Cmd=="wrap" && Argc>=5 && Argc<=8) {
            const auto StubPath = fs::absolute(Argv[0]).parent_path() / "PeVmStub.exe";
            std::string_view Watermark;
            bool Compress = false, LicenseRequired = false;
            std::array<std::uint8_t, 32> LicenseSecret{};
            for (int I = 5; I < Argc; ++I) {
                const std::string_view Arg = Argv[I];
                if (Arg == "--compress") Compress = true;
                else if (Arg == "--license") LicenseRequired = true;
                else if (Arg.starts_with("--license-secret=")) LicenseSecret = ParseLicenseSecret(Argv[I] + 17);
                else Watermark = Arg;
            }
            CmdWrap(Argv[2],Argv[3],Argv[4],StubPath,Watermark,Compress,LicenseRequired,LicenseSecret);
        }
        else if(Cmd=="protect-function" && Argc>=6 && Argc<=13) {
            const auto StubPath = fs::absolute(Argv[0]).parent_path() / "PeVmStub.exe";
            const auto Rva = static_cast<std::uint32_t>(std::stoul(Argv[5], nullptr, 0));
            std::uint64_t Seed = 0xC001D00D5EED1234ULL;
            bool AntiDisassembly = false, Mutate = false, Compress = false, LicenseRequired = false;
            std::string Watermark;
            std::array<std::uint8_t, 32> LicenseSecret{};
            for (int I = 6; I < Argc; ++I) {
                const std::string_view Arg = Argv[I];
                if (Arg == "--anti-disasm") AntiDisassembly = true;
                else if (Arg == "--mutate") Mutate = true;
                else if (Arg == "--compress") Compress = true;
                else if (Arg == "--license") LicenseRequired = true;
                else if (Arg.starts_with("--watermark=")) Watermark = Argv[I] + 12;
                else if (Arg.starts_with("--license-secret=")) LicenseSecret = ParseLicenseSecret(Argv[I] + 17);
                else Seed = std::stoull(Argv[I], nullptr, 0);
            }
            CmdVirtualizeFunctions(Argv[2], Argv[3], Argv[4], {Rva}, Seed, StubPath, AntiDisassembly,
                                   Mutate, Watermark, Compress, LicenseRequired, LicenseSecret);
        }
        else if(Cmd=="protect-functions" && Argc>=7) {
            const auto StubPath = fs::absolute(Argv[0]).parent_path() / "PeVmStub.exe";
            std::vector<std::uint32_t> Rvas;
            std::uint64_t Seed = 0xC001D00D5EED1234ULL;
            bool AntiDisassembly = false, Mutate = false, Compress = false, LicenseRequired = false;
            std::string Watermark;
            std::array<std::uint8_t, 32> LicenseSecret{};
            for (int I = 5; I < Argc; ++I) {
                const std::string_view Arg = Argv[I];
                if (Arg == "--anti-disasm") AntiDisassembly = true;
                else if (Arg == "--mutate") Mutate = true;
                else if (Arg == "--compress") Compress = true;
                else if (Arg == "--license") LicenseRequired = true;
                else if (Arg.starts_with("--watermark=")) Watermark = Argv[I] + 12;
                else if (Arg.starts_with("--license-secret=")) LicenseSecret = ParseLicenseSecret(Argv[I] + 17);
                else if (Arg.starts_with("--seed=")) Seed = std::stoull(Argv[I] + 7, nullptr, 0);
                else Rvas.push_back(static_cast<std::uint32_t>(std::stoul(Argv[I], nullptr, 0)));
            }
            CmdVirtualizeFunctions(Argv[2], Argv[3], Argv[4], Rvas, Seed, StubPath, AntiDisassembly,
                                   Mutate, Watermark, Compress, LicenseRequired, LicenseSecret);
        }
        else if(Cmd=="protect-all" && Argc>=6 && Argc<=15) {
            const auto StubPath = fs::absolute(Argv[0]).parent_path() / "PeVmStub.exe";
            std::uint64_t Seed = 0xC001D00D5EED1234ULL;
            bool AntiDisassembly = false, AllowMemory = false, Mutate = false, Compress = false, LicenseRequired = false;
            std::string Watermark;
            std::array<std::uint8_t, 32> LicenseSecret{};
            std::size_t MinimumBytes = 16;
            for (int I = 5; I < Argc; ++I) {
                const std::string_view Arg = Argv[I];
                if (Arg == "--anti-disasm") AntiDisassembly = true;
                else if (Arg == "--allow-mem") AllowMemory = true;
                else if (Arg == "--mutate") Mutate = true;
                else if (Arg == "--compress") Compress = true;
                else if (Arg == "--license") LicenseRequired = true;
                else if (Arg.starts_with("--watermark=")) Watermark = Argv[I] + 12;
                else if (Arg.starts_with("--license-secret=")) LicenseSecret = ParseLicenseSecret(Argv[I] + 17);
                else if (Arg.starts_with("--min-bytes=")) MinimumBytes = std::stoull(Argv[I] + 12, nullptr, 0);
                else Seed = std::stoull(Argv[I], nullptr, 0);
            }
            CmdVirtualizeAll(Argv[2], Argv[3], Argv[4], Seed, StubPath, AntiDisassembly, AllowMemory,
                             MinimumBytes, Mutate, Watermark, Compress, LicenseRequired, LicenseSecret);
        }
        else if(Cmd=="scan-functions" && Argc>=3 && Argc<=6) {
            std::string JsonPath;
            std::size_t MinimumBytes = 16;
            for (int I = 3; I < Argc; ++I) {
                const std::string_view Arg = Argv[I];
                if (Arg.starts_with("--min-bytes=")) MinimumBytes = std::stoull(Argv[I] + 12, nullptr, 0);
                else JsonPath = Argv[I];
            }
            CmdScanFunctions(Argv[2], JsonPath, MinimumBytes);
        }
        else if(Cmd=="unpack" && Argc==5) CmdUnpack(Argv[2],Argv[3],Argv[4]);
        else if(Cmd=="inspect" && Argc==3) CmdInspect(Argv[2]);
        else if(Cmd=="vm-dump" && Argc==3) CmdVmDump(Argv[2]);
        else if(Cmd=="vm-demo" && Argc==3) {
            const std::array<std::uint8_t,8> Nonce={0x10,0x32,0x54,0x76,0x98,0xba,0xdc,0xfe};
            const auto Code=KeyProgram(); const auto Key=DeriveKey(Argv[2],Nonce,Code,KIdentityMap,KDefaultKdf);
            std::cout<<"bytecode bytes: "<<Code.size()<<"\nkey words: ";
            for(auto X:Key) std::cout<<std::hex<<std::setfill('0')<<std::setw(8)<<X<<' ';
            std::cout<<std::dec<<"\n";
        }
        else if(Cmd=="virtualize-demo" && Argc>=3 && Argc<=5) {
            const auto Input=std::stoull(Argv[2]);
            std::uint64_t Seed=0xC001D00D5EED1234ULL;
            bool Trace=false;
            for(int I=3;I<Argc;++I) {
                if(std::string_view(Argv[I])=="--trace") Trace=true;
                else Seed=std::stoull(Argv[I],nullptr,0);
            }
            const auto Result=vmprotect::RunDemo(Input,Seed,Trace);
            std::cout<<"virtualized factorial("<<Input<<") = "<<Result<<"\n";
        }
        else if(Cmd=="call-memory-demo" && Argc>=3 && Argc<=5) {
            const auto Input=std::stoull(Argv[2]);
            std::uint64_t Seed=0xC001D00D5EED1234ULL;
            bool Trace=false;
            for(int I=3;I<Argc;++I) {
                if(std::string_view(Argv[I])=="--trace") Trace=true;
                else Seed=std::stoull(Argv[I],nullptr,0);
            }
            const auto Result=vmprotect::RunCallMemoryDemo(Input,Seed,Trace);
            std::cout<<"virtualized call/memory("<<Input<<") = "<<Result<<"\n";
        }
        else if(Cmd=="vm2-self-test" && Argc==2) vmprotect::SelfTest();
        else if(Cmd=="lift-x64" && Argc>=5 && Argc<=11) {
            const auto Rva=static_cast<std::uint32_t>(std::stoul(Argv[3],nullptr,0));
            std::uint64_t Seed=0xC001D00D5EED1234ULL;
            std::uint64_t Rcx=0;
            std::uint64_t Rdx=0, R8=0, R9=0;
            bool Trace=false;
            for(int I=5;I<Argc;++I) {
                if(std::string_view(Argv[I])=="--trace") Trace=true;
                else if(std::string_view(Argv[I]).starts_with("--rcx=")) Rcx=std::stoull(Argv[I]+6,nullptr,0);
                else if(std::string_view(Argv[I]).starts_with("--rdx=")) Rdx=std::stoull(Argv[I]+6,nullptr,0);
                else if(std::string_view(Argv[I]).starts_with("--r8=")) R8=std::stoull(Argv[I]+5,nullptr,0);
                else if(std::string_view(Argv[I]).starts_with("--r9=")) R9=std::stoull(Argv[I]+5,nullptr,0);
                else Seed=std::stoull(Argv[I],nullptr,0);
            }
            const auto Result=x64lift::LiftPeFunction(Argv[2],Rva);
            x64lift::WriteManifest(Argv[4],Result);
            vmprotect::VmBridgeContext Context{};
            Context.Registers[1]=Rcx;
            Context.Registers[2]=Rdx;
            Context.Registers[8]=R8;
            Context.Registers[9]=R9;
            vmprotect::InvokeLiftedProgram(Result.Program,Context,Seed,Trace);
            std::cout<<"lifted native blocks: "<<Result.BasicBlockCount<<"\n"
                     <<"lifted VM2 instructions: "<<Result.Program.Instructions.size()<<"\n"
                     <<"bridge smoke RAX: 0x"<<std::hex<<Context.Registers[0]<<std::dec<<"\n"
                     <<"manifest: "<<Argv[4]<<"\n";
        }
        else if(Cmd=="lift-x64-multi" && Argc>=5) {
            std::vector<std::uint32_t> Rvas;
            for (int I = 4; I < Argc; ++I) Rvas.push_back(static_cast<std::uint32_t>(std::stoul(Argv[I], nullptr, 0)));
            const auto Result = x64lift::LiftPeFunctions(Argv[2], Rvas);
            std::ofstream Manifest(Argv[3], std::ios::binary | std::ios::trunc);
            if (!Manifest) throw std::runtime_error("cannot create multi-lift manifest");
            Manifest << Result.Json;
            std::cout << "multi-function lift: " << Result.Functions.size() << " functions\n"
                      << "manifest: " << Argv[3] << "\n";
        }
        else if(Cmd=="lift-raw" && Argc>=4 && Argc<=10) {
            // Lifts a bare machine-code blob given as hex; FunctionRva names
            // the entry boundary. Direct channel for ISA decode testing.
            const auto Code = util::FromHex(Argv[2]);
            const auto Rva = static_cast<std::uint32_t>(std::stoul(Argv[3], nullptr, 0));
            std::uint64_t Seed = 0xC001D00D5EED1234ULL;
            std::uint64_t Rcx=0, Rdx=0, R8=0, R9=0;
            bool Trace=false;
            for(int I=4;I<Argc;++I) {
                if(std::string_view(Argv[I])=="--trace") Trace=true;
                else if(std::string_view(Argv[I]).starts_with("--rcx=")) Rcx=std::stoull(Argv[I]+6,nullptr,0);
                else if(std::string_view(Argv[I]).starts_with("--rdx=")) Rdx=std::stoull(Argv[I]+6,nullptr,0);
                else if(std::string_view(Argv[I]).starts_with("--r8=")) R8=std::stoull(Argv[I]+5,nullptr,0);
                else if(std::string_view(Argv[I]).starts_with("--r9=")) R9=std::stoull(Argv[I]+5,nullptr,0);
                else Seed=std::stoull(Argv[I],nullptr,0);
            }
            const auto Result = x64lift::LiftRawCode(Code, Rva);
            vmprotect::VmBridgeContext Context{};
            Context.Registers[1]=Rcx;
            Context.Registers[2]=Rdx;
            Context.Registers[8]=R8;
            Context.Registers[9]=R9;
            vmprotect::InvokeLiftedProgram(Result.Program,Context,Seed,Trace);
            std::cout<<"lifted VM2 instructions: "<<Result.Program.Instructions.size()<<"\n"
                     <<"raw bridge RAX: 0x"<<std::hex<<Context.Registers[0]<<std::dec<<"\n";
        }
        else if(Cmd=="self-test" && Argc==2) SelfTest();
        else { Usage(); return 2; }
        return 0;
    } catch(const std::exception& E) {
        std::cerr<<"error: "<<E.what()<<"\n";
        return 1;
    }
}
#endif
