#include "VmImageCodec.h"
#include "PeLayout.h"
#include "PeRelocations.h"
#include "PeTls.h"
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
#include <optional>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>
#include <windows.h>

#include "PeVmContainer.h"
#include "BuildLog.h"
#include "VmProtect.h"
#include "X64Lifter.h"
#include "PeVmCrypto.h"
#include "PeVmLicense.h"
#include "LicenseCommands.h"
#include "WrapperFormat.h"

namespace fs = std::filesystem;
using Bytes = pevm::crypto::Bytes;
namespace crypto = pevm::crypto;

struct EmbeddedImage {
    Bytes Image;
    std::uint32_t PayloadOffset{};
    std::uint32_t MetadataOffset{};
    VmpMetadata Metadata{};
};

EmbeddedImage AddVmpSection(Bytes Stub, std::span<const std::uint8_t> Payload,
                            std::span<const std::uint8_t> VmData,
                            std::uint64_t BuildId, std::string_view Watermark,
                            const LicensePolicy& License) {
    pevm::pe::AppendLayout Layout;
    std::optional<pevm::pe::TlsLayout> CarrierTls;
    Bytes CarrierTemplate;
    std::uint32_t TlsAlignment = 1;
    {
        const pevm::pe::ImageView StubImage(Stub);
        StubImage.RequireX64();
        if (StubImage.OptionalHeaderSize() < sizeof(IMAGE_OPTIONAL_HEADER64))
            throw std::runtime_error("stub requires a full PE32+ optional header");
        CarrierTls = pevm::pe::ReadTlsLayout(StubImage);
        std::uint64_t MetadataBytes = sizeof(VmpMetadata);
        if (CarrierTls && CarrierTls->Directory.SizeOfZeroFill) {
            const auto AlignmentCode = (CarrierTls->Directory.Characteristics & IMAGE_SCN_ALIGN_MASK) >> 20;
            TlsAlignment = AlignmentCode ? 1U << (AlignmentCode - 1) : 1;
            MetadataBytes += TlsAlignment - 1ULL + CarrierTls->TotalBytes;
            const auto Template = StubImage.FileBytesAtRva(CarrierTls->TemplateRva, CarrierTls->TemplateBytes);
            CarrierTemplate.assign(Template.begin(), Template.end());
        }
        const std::array<std::uint64_t, 3> Sizes = {Payload.size(), MetadataBytes, VmData.size()};
        Layout = pevm::pe::PlanAppendSections(StubImage, std::span(Sizes).first(VmData.empty() ? 2 : 3));
    }
    // The borrowed view is gone. All layout arithmetic has been checked.
    Stub.resize(Layout.FileSize, 0);
    auto* Nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(Stub.data() + Layout.NtOffset);
    auto* Sections = reinterpret_cast<IMAGE_SECTION_HEADER*>(Stub.data() + Layout.SectionTableOffset);
    const auto OriginalSectionCount = Layout.OriginalSectionCount;
    bool RuntimeSectionFound = false;
    for (unsigned I = 0; I < OriginalSectionCount; ++I) {
        static constexpr std::array<std::uint8_t, 8> TextName = {'.','t','e','x','t',0,0,0};
        if (std::memcmp(Sections[I].Name, TextName.data(), TextName.size()) == 0) {
            static constexpr std::array<std::uint8_t, 8> RuntimeName = {'.','v','m','p','0',0,0,0};
            std::copy(RuntimeName.begin(), RuntimeName.end(), Sections[I].Name);
            RuntimeSectionFound = true;
            break;
        }
    }
    if (!RuntimeSectionFound) throw std::runtime_error("stub runtime section not found");
    for (std::size_t I = 0; I < Layout.Sections.size(); ++I) {
        const auto& Placement = Layout.Sections[I];
        auto& Section = Sections[OriginalSectionCount + I];
        Section = {};
        const std::array<std::uint8_t, 8> Name = {'.','v','m','p',static_cast<std::uint8_t>('1' + I),0,0,0};
        std::copy(Name.begin(), Name.end(), Section.Name);
        Section.Misc.VirtualSize = Placement.VirtualSize;
        Section.VirtualAddress = Placement.VirtualAddress;
        Section.SizeOfRawData = Placement.RawSize;
        Section.PointerToRawData = Placement.RawOffset;
        Section.Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
    }
    Nt->FileHeader.NumberOfSections = static_cast<WORD>(OriginalSectionCount + Layout.Sections.size());
    Nt->OptionalHeader.SizeOfImage = Layout.ImageSize;
    Nt->OptionalHeader.SizeOfInitializedData = Layout.InitializedDataSize;
    Nt->OptionalHeader.CheckSum = 0;
    const auto RawOffset = Layout.Sections[0].RawOffset;
    const auto VirtualSize = Layout.Sections[0].VirtualSize;
    const auto MetadataOffset = Layout.Sections[1].RawOffset;
    const auto VmDataOffset = VmData.empty() ? 0U : Layout.Sections[2].RawOffset;
    if (CarrierTls && CarrierTls->Directory.SizeOfZeroFill) {
        // The Windows loader uses the raw TLS VA interval, so reserve actual
        // mapped template bytes instead of relying on SizeOfZeroFill alone.
        const auto Begin = static_cast<std::uint64_t>(Layout.Sections[1].VirtualAddress) + sizeof(VmpMetadata);
        const auto TlsRva = (Begin + TlsAlignment - 1) / TlsAlignment * TlsAlignment;
        const auto TlsRaw = MetadataOffset + static_cast<std::size_t>(TlsRva - Layout.Sections[1].VirtualAddress);
        std::copy(CarrierTemplate.begin(), CarrierTemplate.end(), Stub.begin() + TlsRaw);
        const pevm::pe::ImageView Expanded(Stub);
        const auto Directory = Expanded.FileBytesAtRva(Expanded.Directory(IMAGE_DIRECTORY_ENTRY_TLS).Address,
                                                       sizeof(IMAGE_TLS_DIRECTORY64));
        auto Tls = CarrierTls->Directory;
        Tls.StartAddressOfRawData = Nt->OptionalHeader.ImageBase + TlsRva;
        Tls.EndAddressOfRawData = Tls.StartAddressOfRawData + CarrierTls->TotalBytes;
        Tls.SizeOfZeroFill = 0;
        std::memcpy(Stub.data() + (Directory.data() - Stub.data()), &Tls, sizeof(Tls));
    }
    std::copy(Payload.begin(), Payload.end(), Stub.begin() + RawOffset);
    if (!VmData.empty()) std::copy(VmData.begin(), VmData.end(), Stub.begin() + VmDataOffset);

    VmpMetadata Metadata{};
    Metadata.Magic = KVmpMetadataMagic;
    Metadata.Version = KVmpMetadataVersion;
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
    Metadata.License = License;
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
Bytes ReadWrapperPayload(const fs::path& Input, pevm::build::Log& Log) {
    Log.Step("Inspect input PE");
    auto Plain = util::ReadFile(Input);
    const auto Pe = Log.InputInfo(Plain);
    if (Pe.Subsystem==KSubsystemNative) {
        throw std::runtime_error("native-subsystem (driver) payloads support container protection "
                                 "(pack/unpack/inspect) but not runnable wrappers; kernel loading stays external");
    }
    const pevm::pe::ImageView Image(Plain);
    Image.RequireX64();
    if (Image.OptionalHeaderSize() < sizeof(IMAGE_OPTIONAL_HEADER64))
        throw std::runtime_error("runnable wrappers require a full PE32+ optional header");
    if (Pe.Subsystem != KSubsystemGui && Pe.Subsystem != KSubsystemConsole)
        throw std::runtime_error("runnable wrappers require a GUI or console payload");
    // Use the runtime's relocation policy before producing a runnable artifact.
    (void)pevm::pe::RelocationTargets(Image);
    (void)pevm::pe::ReadTlsLayout(Image);
    Log.Detail("input snapshot", "one immutable read reused by build stages");
    return Plain;
}

void LogProtectionOptions(pevm::build::Log& Log, bool Virtualize, bool AntiDisassembly,
                          bool Mutate, std::string_view Watermark, bool Compress,
                          const LicensePolicy& License) {
    Log.Step("Configure protection");
    Log.Detail("function virtualization", Virtualize ? "enabled" : "off");
    Log.Detail("instruction mutation", Mutate ? "enabled" : "off");
    Log.Detail("anti-disassembly decoys", AntiDisassembly ? "enabled" : "off");
    Log.Detail("payload compression", Compress ? "LZSS requested" : "off");
    Log.Detail("watermark", Watermark.empty() ? "off" :
        pevm::build::Number(std::min<std::size_t>(Watermark.size(), 63)) + " bytes embedded" +
        (Watermark.size() > 63 ? " (truncated to metadata capacity)" : ""));
    Log.Detail("license", License.Required ? "required; ECDSA P-256 / SHA-256; product and device bound" : "off");
    if (License.Required) {
        Log.Detail("license public key fingerprint", crypto::Hex(crypto::Sha256::Digest(License.PublicKey)));
        Log.Detail("license product digest", crypto::Hex(License.ProductId));
    }
}

void LogWrapperLayout(pevm::build::Log& Log, const VmpMetadata& Metadata) {
    Log.Detail("build id", pevm::build::Hex(Metadata.BuildId));
    Log.Detail("runtime section", ".vmp0 | file offset=" + pevm::build::Hex(Metadata.RuntimeRawOffset) +
               " | " + pevm::build::Size(Metadata.RuntimeRawSize));
    Log.Detail("payload section", ".vmp1 | file offset=" + pevm::build::Hex(Metadata.PayloadRawOffset) +
               " | " + pevm::build::Size(Metadata.PayloadRawSize));
    Log.Detail("metadata", pevm::build::Size(sizeof(Metadata)));
    if (Metadata.VmDataRawSize) Log.Detail("VM section", ".vmp3 | file offset=" +
        pevm::build::Hex(Metadata.VmDataRawOffset) + " | " + pevm::build::Size(Metadata.VmDataRawSize));
}

void AssemblePlainWrapper(std::span<const std::uint8_t> Plain, const fs::path& Output,
                          std::string_view Password, const fs::path& StubPath,
                          std::string_view Watermark, bool Compress,
                          const LicensePolicy& License, pevm::build::Log& Log) {
    Log.Step("Check loader availability");
    if (!fs::exists(StubPath)) throw std::runtime_error("PeVmStub.exe not found beside pevm.exe");
    Log.Detail("loader", fs::absolute(StubPath).lexically_normal().string());
    const auto Payload = PackContainer(Plain, Password, Compress, &Log);
    Log.Step("Embed encrypted payload into loader");
    auto Stub = util::ReadFile(StubPath);
    pevm::pe::ConfigureWrapperTls(Stub, pevm::pe::ImageView(Plain));
    Log.Detail("loader size", pevm::build::Size(Stub.size()));
    const auto OriginalSize = ParseContainer(Payload).OriginalSize;
    auto Embedded = AddVmpSection(std::move(Stub), Payload, {}, NewBuildId(Payload.size()),
                                        Watermark, License);
    LogWrapperLayout(Log, Embedded.Metadata);
    Log.Step("Seal wrapper and write executable");
    const auto Wrapped = SealWrapper(std::move(Embedded), Payload, Password);
    pevm::pe::ImageView Verified(Wrapped);
    util::WriteFileAtomic(Output, Wrapped);
    Log.Finish(Wrapped, OriginalSize);
}

void CmdWrap(const fs::path& Input, const fs::path& Output, std::string_view Password,
             const fs::path& StubPath, std::string_view Watermark, bool Compress,
             const LicensePolicy& License) {
    pevm::build::Log Log("wrap", Input, Output);
    const auto Plain = ReadWrapperPayload(Input, Log);
    LogProtectionOptions(Log, false, false, false, Watermark, Compress, License);
    AssemblePlainWrapper(Plain, Output, Password, StubPath, Watermark, Compress, License, Log);
}

// Serializes a lifted multi-program set, packs the payload and seals the
// wrapper. Shared by protect-functions and protect-all.
void AssembleVirtualizedWrapper(std::span<const std::uint8_t> Plain, const fs::path& Output,
                                std::string_view Password, const x64lift::MultiLiftResult& Lifted,
                                std::uint64_t Seed, const fs::path& StubPath, bool AntiDisassembly,
                                bool Mutate, std::string_view Watermark, bool Compress,
                                const LicensePolicy& License, pevm::build::Log& Log) {
    Log.Step("Prepare virtualized functions");
    const auto BuildId = NewBuildId(0);
    auto Prepared = Lifted;
    for (const auto& Function : Prepared.Functions) {
        if (Function.NativeBytes < 5) throw std::runtime_error("function too short for the 5-byte VM entry bridge");
    }
    if (Mutate) {
        for (auto& Function : Prepared.Functions) {
            x64lift::MutateProgram(Function.Program, Seed ^ Function.Program.EntryAddress);
        }
    }
    std::size_t TotalBefore = 0, TotalAfter = 0, Blocks = 0;
    Log.Detail("functions", pevm::build::Number(Prepared.Functions.size()));
    for (std::size_t I = 0; I < Prepared.Functions.size(); ++I) {
        const auto& Function = Prepared.Functions[I];
        const auto Before = Lifted.Functions[I].Program.Instructions.size();
        const auto After = Function.Program.Instructions.size();
        TotalBefore += Before;
        TotalAfter += After;
        Blocks += Function.BasicBlockCount;
        Log.Detail("function RVA", pevm::build::Hex(Function.Program.EntryAddress) +
            " | blocks=" + pevm::build::Number(Function.BasicBlockCount) +
            " | VM instructions=" + pevm::build::Number(Before) + " -> " + pevm::build::Number(After) +
            (Function.Program.ResumeAddress ? " | mode=native-EH-fragment | resume="+pevm::build::Hex(Function.Program.ResumeAddress) : " | mode=full-function"));
    }
    Log.Detail("basic blocks", pevm::build::Number(Blocks));
    Log.Detail("total VM instructions", pevm::build::Number(TotalBefore) + " -> " + pevm::build::Number(TotalAfter));
    Log.Step("Encrypt and serialize VM program");
    std::vector<vmprotect::CompilationStats> CompiledStats;
    const auto VmData = x64lift::SerializeVmp3Multi(Prepared, Seed, Password,
                                                    MakeHandlerProfile(BuildId), AntiDisassembly, &CompiledStats);
    Log.Detail("VM program size", pevm::build::Size(VmData.size()));
    Log.Detail("VM authentication", "HMAC-SHA256 | 32-byte tag | header + entries + ciphertext + decoys");
    Log.Detail("VM key separation", "encryption / authentication / per-function seeds");
    Log.Detail("VM runtime checks", "instruction boundaries + register maps + instruction tags + CFI + fuel");
    Log.Detail("VM code layout", "shuffled basic blocks with linked fallthrough paths");
    Log.Detail("VM decoding", "per-instruction rolling state and handler selection");
    for (std::size_t I = 0; I < CompiledStats.size(); ++I) {
        const auto& Stats = CompiledStats[I];
        Log.Detail("compiled function RVA", pevm::build::Hex(Prepared.Functions[I].Program.EntryAddress) +
            " | blocks=" + pevm::build::Number(Stats.BasicBlocks) +
            " | relocated=" + pevm::build::Number(Stats.RelocatedBlocks) +
            " | link instructions=" + pevm::build::Number(Stats.LinkInstructions) +
            " | bytecode instructions=" + pevm::build::Number(Stats.BytecodeInstructions) +
            " | encrypted bytes=" + pevm::build::Number(Stats.BytecodeBytes));
    }
    const auto Payload = PackContainer(Plain, Password, Compress, &Log);
    Log.Step("Embed payload and VM program into loader");
    auto Stub = util::ReadFile(StubPath);
    pevm::pe::ConfigureWrapperTls(Stub, pevm::pe::ImageView(Plain));
    Log.Detail("loader", fs::absolute(StubPath).lexically_normal().string());
    Log.Detail("loader size", pevm::build::Size(Stub.size()));
    const auto OriginalSize = ParseContainer(Payload).OriginalSize;
    auto Embedded = AddVmpSection(std::move(Stub), Payload, VmData, BuildId, Watermark,
                                        License);
    LogWrapperLayout(Log, Embedded.Metadata);
    Log.Step("Seal wrapper and write executable");
    const auto Wrapped = SealWrapper(std::move(Embedded), Payload, Password);
    pevm::pe::ImageView Verified(Wrapped);
    util::WriteFileAtomic(Output, Wrapped);
    Log.Finish(Wrapped, OriginalSize);
}

void CmdVirtualizeFunctions(const fs::path& Input, const fs::path& Output,
                            std::string_view Password, const std::vector<std::uint32_t>& FunctionRvas,
                            std::uint64_t Seed, const fs::path& StubPath, bool AntiDisassembly,
                            bool Mutate, std::string_view Watermark, bool Compress,
                            const LicensePolicy& License) {
    pevm::build::Log Log(FunctionRvas.size() == 1 ? "protect-function" : "protect-functions", Input, Output);
    if (FunctionRvas.empty()) throw std::runtime_error("function virtualization requires at least one RVA");
    const auto Plain = ReadWrapperPayload(Input, Log);
    LogProtectionOptions(Log, true, AntiDisassembly, Mutate, Watermark, Compress, License);
    Log.Step("Lift selected functions");
    Log.Detail("requested count", pevm::build::Number(FunctionRvas.size()));
    if (!fs::exists(StubPath)) throw std::runtime_error("PeVmStub.exe not found beside pevm.exe");
    const pevm::pe::ImageView Image(Plain);
    const auto Lifted = x64lift::LiftPeFunctions(Image, FunctionRvas);
    AssembleVirtualizedWrapper(Plain, Output, Password, Lifted, Seed, StubPath, AntiDisassembly,
                               Mutate, Watermark, Compress, License, Log);
}

// VMP-style "virtualize everything": discover every function (.pdata and
// exports), lift each one, keep what succeeds and skip the rest with a
// reason. Protected functions use native pointers and a per-call VM stack;
// standalone lift-raw execution retains bounded flat-memory semantics.
void CmdVirtualizeAll(const fs::path& Input, const fs::path& Output,
                      std::string_view Password, std::uint64_t Seed, const fs::path& StubPath,
                      bool AntiDisassembly, bool AllowMemory, std::size_t MinimumBytes,
                      bool Mutate, std::string_view Watermark, bool Compress,
                      const LicensePolicy& License) {
    pevm::build::Log Log("protect-all", Input, Output);
    const auto Plain = ReadWrapperPayload(Input, Log);
    LogProtectionOptions(Log, true, AntiDisassembly, Mutate, Watermark, Compress, License);
    Log.Step("Discover function candidates");
    Log.Detail("minimum function bytes", pevm::build::Number(MinimumBytes));
    Log.Detail("VM memory operands", "native pointers and isolated VM stack");
    (void)AllowMemory; // retained as a compatible CLI option
    if (!fs::exists(StubPath)) throw std::runtime_error("PeVmStub.exe not found beside pevm.exe");
    const pevm::pe::ImageView Image(Plain);
    const auto Candidates = x64lift::ScanFunctions(Image, MinimumBytes);
    Log.Detail("candidates", pevm::build::Number(Candidates.size()));

    std::vector<std::uint32_t> Rvas;
    for (const auto& Candidate : Candidates) Rvas.push_back(Candidate.Rva);
    Log.Step("Lift and filter function candidates");
    auto Attempt = x64lift::LiftPeFunctionsTolerant(Image, Rvas);

    x64lift::MultiLiftResult Lifted;
    for (auto& Function : Attempt.Lifted.Functions) {
        if (Function.NativeBytes < 5) {
            Attempt.Failures.push_back({Function.Program.EntryAddress,
                                        "function too short for the 5-byte VM entry bridge"});
        } else {
            Lifted.Functions.push_back(std::move(Function));
        }
    }
    Log.Detail("selected", pevm::build::Number(Lifted.Functions.size()));
    const auto Fragments=std::count_if(Lifted.Functions.begin(),Lifted.Functions.end(),[](const auto& F){return F.Program.ResumeAddress!=0;});
    Log.Detail("full VM functions",pevm::build::Number(Lifted.Functions.size()-Fragments));
    Log.Detail("native EH fragments",pevm::build::Number(Fragments));
    Log.Detail("selection rate", pevm::build::Ratio(Lifted.Functions.size(), Candidates.size()) + " of discovered candidates");
    Log.Detail("skipped", pevm::build::Number(Attempt.Failures.size()));
    for (const auto& [Rva, Reason] : Attempt.Failures) {
        Log.Detail("skipped RVA", pevm::build::Hex(Rva) + " - " + Reason);
    }
    if (Lifted.Functions.empty()) {
        Log.Detail("function virtualization", "0 functions; no eligible VM entries; encrypted wrapper only");
        Log.Detail("instruction mutation", "not applied (no VM functions)");
        Log.Detail("anti-disassembly decoys", "not applied (no VM functions)");
        AssemblePlainWrapper(Plain, Output, Password, StubPath, Watermark, Compress, License, Log);
        return;
    }
    AssembleVirtualizedWrapper(Plain, Output, Password, Lifted, Seed, StubPath, AntiDisassembly,
                               Mutate, Watermark, Compress, License, Log);
}

void CmdScanFunctions(const fs::path& Input, const fs::path& JsonPath, std::size_t MinimumBytes,
                      const fs::path& PdbPath) {
    const auto Result = x64lift::ScanFunctionDetails(Input, MinimumBytes, PdbPath);
    const auto& Candidates = Result.Functions;
    if (!Result.SymbolFile.empty()) std::cout << "symbols: " << Result.SymbolFile << "\n";
    for (const auto& Diagnostic : Result.Diagnostics) std::cout << "symbols: " << Diagnostic << "\n";
    std::cout << "discovered functions: " << Candidates.size() << "\n";
    for (const auto& Candidate : Candidates) {
        std::cout << "RVA: 0x" << std::hex << Candidate.Rva << std::dec
                  << " size: " << Candidate.Size;
        if (!Candidate.Name.empty()) std::cout << " name: " << Candidate.Name << " [" << Candidate.NameSource << "]";
        std::cout << "\n";
    }
    if (!JsonPath.empty()) {
        const auto Json = x64lift::FunctionScanJson(Result);
        util::WriteFileAtomic(JsonPath, {reinterpret_cast<const std::uint8_t*>(Json.data()), Json.size()});
        std::cout << "scan output: " << JsonPath << "\n";
    }
}

void InspectWrapper(std::span<const std::uint8_t> File) {
    if (File.size() < sizeof(WrapperFooter)) throw std::runtime_error("wrapper footer missing");
    WrapperFooter Footer{};
    std::memcpy(&Footer, File.data() + File.size() - sizeof(Footer), sizeof(Footer));
    if (Footer.Magic != KWrapperMagic || Footer.Version != 2) throw std::runtime_error("not a PeVmProtector wrapper");
    if (Footer.MetadataSize != sizeof(VmpMetadata) || Footer.MetadataOffset > File.size() || Footer.MetadataSize > File.size() - Footer.MetadataOffset) {
        throw std::runtime_error("wrapper metadata range invalid");
    }
    VmpMetadata Metadata{};
    std::memcpy(&Metadata, File.data() + Footer.MetadataOffset, sizeof(Metadata));
    if (Metadata.Magic != KVmpMetadataMagic || Metadata.Version != KVmpMetadataVersion) {
        throw std::runtime_error("unsupported wrapper metadata; rebuild with signed licensing");
    }
    pevm::license::ValidatePolicy(Metadata.License);
    if (Metadata.License.Required != 0) {
        std::cout << "license: ECDSA P-256\n"
                  << "license key id: " << crypto::Hex(crypto::Sha256::Digest(Metadata.License.PublicKey)) << "\n"
                  << "license product hash: " << crypto::Hex(Metadata.License.ProductId) << "\n";
    }
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
        if (Vmp3.Version != pevm::KVmImageVersion || Vmp3.FunctionCount == 0 ||
            Vmp3.FunctionCount > (Metadata.VmDataRawSize - sizeof(Vmp3)) / sizeof(Vmp3Entry)) {
            std::cout << ".vmp3: unsupported version " << Vmp3.Version << "\n";
            return;
        }
        const auto* Entries = reinterpret_cast<const Vmp3Entry*>(File.data() +
            Metadata.VmDataRawOffset + sizeof(Vmp3));
        std::cout << ".vmp3 version: " << Vmp3.Version << " (instruction table encrypted)\n"
                  << "VM authentication: HMAC-SHA256 (entire image, verified before decryption)\n"
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
             <<"  pevm wrap <input.exe> <output.exe> <password> [--watermark=text] [--compress] [--license --license-public-key=<file> --license-product=<id>]\n"
             <<"  pevm license-machine-id\n"
             <<"  pevm license-keygen <private-file> <public-file>\n"
             <<"  pevm license-export-public <private-file> <public-file>\n"
             <<"  pevm license-issue <private-file> [days=30] --machine=<64hex> --product=<id> [--output=<file>]\n"
             <<"  pevm license-verify <public-file> <license-file> --product=<id> [--machine=<64hex>]\n"
             <<"  pevm protect-function <input.exe> <output.exe> <password> <function-rva> [seed] [--anti-disasm]\n"
             <<"  pevm protect-functions <input.exe> <output.exe> <password> <rva> [rva...] [--seed=N] [--anti-disasm]\n"
             <<"  pevm protect-all <input.exe> <output.exe> <password> [seed] [--anti-disasm] [--allow-mem] [--min-bytes=N] [--mutate] [--watermark=text]\n"
             <<"    wrap/protect-* license options: --license --license-public-key=<file> --license-product=<id>\n"
             <<"  pevm scan-functions <input.exe> [json-out] [--min-bytes=N] [--pdb=local.pdb]\n"
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
        else if(Cmd=="license-machine-id" && Argc==2) std::cout << "machine id: " << crypto::Hex(pevm::license::MachineId()) << "\n";
        else if(Cmd=="license-keygen" && Argc==4) {
            pevm::license::GenerateKeyFiles(Argv[2], Argv[3]);
            std::cout << "signing key saved (DPAPI protected)\npublic key: " << Argv[3] << "\n";
        }
        else if(Cmd=="license-export-public" && Argc==4) {
            pevm::license::ExportPublicKeyFile(Argv[2], Argv[3]);
            std::cout << "public key: " << Argv[3] << "\n";
        }
        else if(Cmd=="license-issue" && Argc>=3) licensecli::MakeLicense(Argc, Argv);
        else if(Cmd=="license-verify" && Argc>=4) licensecli::VerifyLicense(Argc, Argv);
        else if(Cmd=="wrap" && Argc>=5) {
            const auto StubPath = fs::absolute(Argv[0]).parent_path() / "PeVmStub.exe";
            std::string_view Watermark;
            bool Compress = false;
            licensecli::Options License;
            for (int I = 5; I < Argc; ++I) {
                const std::string_view Arg = Argv[I];
                if (Arg == "--compress") Compress = true;
                else if (License.Parse(Arg)) {}
                else if (Arg.starts_with("--watermark=")) Watermark = Arg.substr(12);
                else if (Arg.starts_with("--")) throw std::runtime_error("unknown wrap option");
                else if (Watermark.empty()) Watermark = Arg;
                else throw std::runtime_error("duplicate watermark");
            }
            CmdWrap(Argv[2],Argv[3],Argv[4],StubPath,Watermark,Compress,License.Resolve());
        }
        else if(Cmd=="protect-function" && Argc>=6) {
            const auto StubPath = fs::absolute(Argv[0]).parent_path() / "PeVmStub.exe";
            const auto Rva = static_cast<std::uint32_t>(std::stoul(Argv[5], nullptr, 0));
            std::uint64_t Seed = 0xC001D00D5EED1234ULL;
            bool AntiDisassembly = false, Mutate = false, Compress = false;
            std::string Watermark;
            licensecli::Options License;
            for (int I = 6; I < Argc; ++I) {
                const std::string_view Arg = Argv[I];
                if (Arg == "--anti-disasm") AntiDisassembly = true;
                else if (Arg == "--mutate") Mutate = true;
                else if (Arg == "--compress") Compress = true;
                else if (License.Parse(Arg)) {}
                else if (Arg.starts_with("--watermark=")) Watermark = Argv[I] + 12;
                else Seed = std::stoull(Argv[I], nullptr, 0);
            }
            CmdVirtualizeFunctions(Argv[2], Argv[3], Argv[4], {Rva}, Seed, StubPath, AntiDisassembly,
                                   Mutate, Watermark, Compress, License.Resolve());
        }
        else if(Cmd=="protect-functions" && Argc>=7) {
            const auto StubPath = fs::absolute(Argv[0]).parent_path() / "PeVmStub.exe";
            std::vector<std::uint32_t> Rvas;
            std::uint64_t Seed = 0xC001D00D5EED1234ULL;
            bool AntiDisassembly = false, Mutate = false, Compress = false;
            std::string Watermark;
            licensecli::Options License;
            for (int I = 5; I < Argc; ++I) {
                const std::string_view Arg = Argv[I];
                if (Arg == "--anti-disasm") AntiDisassembly = true;
                else if (Arg == "--mutate") Mutate = true;
                else if (Arg == "--compress") Compress = true;
                else if (License.Parse(Arg)) {}
                else if (Arg.starts_with("--watermark=")) Watermark = Argv[I] + 12;
                else if (Arg.starts_with("--seed=")) Seed = std::stoull(Argv[I] + 7, nullptr, 0);
                else Rvas.push_back(static_cast<std::uint32_t>(std::stoul(Argv[I], nullptr, 0)));
            }
            CmdVirtualizeFunctions(Argv[2], Argv[3], Argv[4], Rvas, Seed, StubPath, AntiDisassembly,
                                   Mutate, Watermark, Compress, License.Resolve());
        }
        else if(Cmd=="protect-all" && Argc>=5) {
            const auto StubPath = fs::absolute(Argv[0]).parent_path() / "PeVmStub.exe";
            std::uint64_t Seed = 0xC001D00D5EED1234ULL;
            bool AntiDisassembly = false, AllowMemory = false, Mutate = false, Compress = false;
            std::string Watermark;
            licensecli::Options License;
            std::size_t MinimumBytes = 16;
            for (int I = 5; I < Argc; ++I) {
                const std::string_view Arg = Argv[I];
                if (Arg == "--anti-disasm") AntiDisassembly = true;
                else if (Arg == "--allow-mem") AllowMemory = true;
                else if (Arg == "--mutate") Mutate = true;
                else if (Arg == "--compress") Compress = true;
                else if (License.Parse(Arg)) {}
                else if (Arg.starts_with("--watermark=")) Watermark = Argv[I] + 12;
                else if (Arg.starts_with("--min-bytes=")) MinimumBytes = std::stoull(Argv[I] + 12, nullptr, 0);
                else Seed = std::stoull(Argv[I], nullptr, 0);
            }
            CmdVirtualizeAll(Argv[2], Argv[3], Argv[4], Seed, StubPath, AntiDisassembly, AllowMemory,
                             MinimumBytes, Mutate, Watermark, Compress, License.Resolve());
        }
        else if(Cmd=="scan-functions" && Argc>=3 && Argc<=6) {
            std::string JsonPath;
            std::size_t MinimumBytes = 0;
            fs::path PdbPath;
            for (int I = 3; I < Argc; ++I) {
                const std::string_view Arg = Argv[I];
                if (Arg.starts_with("--min-bytes=")) MinimumBytes = std::stoull(Argv[I] + 12, nullptr, 0);
                else if (Arg.starts_with("--pdb=")) PdbPath = Argv[I] + 6;
                else if (!Arg.starts_with("--") && JsonPath.empty()) JsonPath = Argv[I];
                else throw std::runtime_error("unknown or duplicate scan-functions argument");
            }
            CmdScanFunctions(Argv[2], JsonPath, MinimumBytes, PdbPath);
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
