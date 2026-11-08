#include "X64Lifter.h"
#include "FileIo.h"

#include <windows.h>
#include <dbghelp.h>
#include <algorithm>
#include <cstring>
#include <exception>
#include <map>
#include <mutex>
#include <sstream>
#include <stdexcept>

#pragma comment(lib, "dbghelp.lib")

namespace x64lift {
namespace {
using pevm::pe::ImageView;
using CandidateMap = std::map<std::uint32_t, FunctionCandidate>;
std::mutex SymbolMutex; // DbgHelp is process-global and single-threaded.

template<class T> T Read(std::span<const std::uint8_t> Data, std::size_t At) {
    if (At > Data.size() || sizeof(T) > Data.size() - At)
        throw std::runtime_error("function metadata truncated");
    T Value{};
    std::memcpy(&Value, Data.data() + At, sizeof(Value));
    return Value;
}

std::string CString(std::span<const std::uint8_t> Data) {
    const auto End = std::find(Data.begin(), Data.end(), 0);
    if (End == Data.end()) throw std::runtime_error("unterminated function metadata string");
    return {reinterpret_cast<const char*>(Data.data()), static_cast<std::size_t>(End - Data.begin())};
}

void SetName(FunctionCandidate& Candidate, const std::string& Name, const char* Source) {
    if (Name.empty()) return;
    if (std::find(Candidate.Aliases.begin(), Candidate.Aliases.end(), Name) == Candidate.Aliases.end())
        Candidate.Aliases.push_back(Name);
    if (!Candidate.Name.empty()) return; // Keep a stable primary name, retaining all aliases.
    Candidate.DecoratedName = Name;
    char Display[8192]{};
    Candidate.Name = UnDecorateSymbolName(Name.c_str(), Display, sizeof(Display), UNDNAME_COMPLETE)
        ? Display : Name;
    Candidate.NameSource = Source;
}

FunctionCandidate* AddCandidate(const ImageView& Image, CandidateMap& Candidates,
                                std::uint32_t Rva, std::uint32_t Size = 0) {
    const auto* Section = Image.SectionAt(Rva);
    if (!Rva || !Section || !Section->Executable()) return nullptr;
    // Symbols are advisory. Never accept an address/extent outside file-backed code.
    if (Rva - Section->VirtualAddress >= Section->RawSize) return nullptr;
    if (Size && (Size > Section->RawSize - (Rva - Section->VirtualAddress) ||
                 std::uint64_t{Rva} + Size > Image.SizeOfImage())) return nullptr;
    auto& Candidate = Candidates[Rva];
    Candidate.Rva = Rva;
    if (!Candidate.Size) Candidate.Size = Size;
    return &Candidate;
}

CandidateMap ScanImage(const ImageView& Image) {
    Image.RequireX64();
    CandidateMap Candidates;
    const auto Exceptions = Image.DirectoryBytes(IMAGE_DIRECTORY_ENTRY_EXCEPTION);
    if (Exceptions.size() % 12) throw std::runtime_error("PE exception table has a partial record");
    for (std::size_t At = 0; At < Exceptions.size(); At += 12) {
        const auto Begin = Read<std::uint32_t>(Exceptions, At);
        const auto End = Read<std::uint32_t>(Exceptions, At + 4);
        const auto* Section = Image.SectionAt(Begin);
        if (End <= Begin || !Section || !Section->Executable() || Image.SectionAt(End - 1) != Section)
            throw std::runtime_error("PE exception function range invalid");
        Image.FileBytesAtRva(Begin, End - Begin);
        AddCandidate(Image, Candidates, Begin, End - Begin);
    }
    const auto Exports = Image.DirectoryBytes(IMAGE_DIRECTORY_ENTRY_EXPORT);
    if (!Exports.empty()) {
        if (Exports.size() < sizeof(IMAGE_EXPORT_DIRECTORY)) throw std::runtime_error("PE export directory truncated");
        const auto Count = Read<std::uint32_t>(Exports, 20);
        const auto NameCount = Read<std::uint32_t>(Exports, 24);
        if (NameCount && !Count) throw std::runtime_error("PE export names without functions");
        const auto Functions = Count ? Image.FileBytesAtRva(Read<std::uint32_t>(Exports, 28), std::size_t{Count} * 4) : std::span<const std::uint8_t>{};
        const auto Names = NameCount ? Image.FileBytesAtRva(Read<std::uint32_t>(Exports, 32), std::size_t{NameCount} * 4) : std::span<const std::uint8_t>{};
        const auto Ordinals = NameCount ? Image.FileBytesAtRva(Read<std::uint32_t>(Exports, 36), std::size_t{NameCount} * 2) : std::span<const std::uint8_t>{};
        const auto Directory = Image.Directory(IMAGE_DIRECTORY_ENTRY_EXPORT);
        const auto IsForwarder = [&](std::uint32_t Rva) {
            return Rva >= Directory.Address && Rva - Directory.Address < Directory.Size;
        };
        for (std::size_t I = 0; I < Count; ++I) {
            const auto Rva = Read<std::uint32_t>(Functions, I * 4);
            if (!IsForwarder(Rva)) AddCandidate(Image, Candidates, Rva);
        }
        for (std::size_t I = 0; I < NameCount; ++I) {
            const auto Ordinal = Read<std::uint16_t>(Ordinals, I * 2);
            if (Ordinal >= Count) throw std::runtime_error("PE export ordinal outside function table");
            const auto Name = Image.StringAtRva(Read<std::uint32_t>(Names, I * 4));
            const auto Rva = Read<std::uint32_t>(Functions, std::size_t{Ordinal} * 4);
            if (!IsForwarder(Rva)) {
                if (auto* Candidate = AddCandidate(Image, Candidates, Rva)) SetName(*Candidate, Name, "export");
            }
        }
    }

    const auto File = Image.FileBytes();
    const auto Offset = Read<std::uint32_t>(File, Image.NtOffset() + 12);
    const auto Count = Read<std::uint32_t>(File, Image.NtOffset() + 16);
    if (Count) {
        if (!Offset || Offset > File.size() || Count > (File.size() - Offset) / IMAGE_SIZEOF_SYMBOL)
            throw std::runtime_error("PE COFF symbol table truncated");
        const auto StringAt = std::size_t{Offset} + std::size_t{Count} * IMAGE_SIZEOF_SYMBOL;
        const auto StringSize = Read<std::uint32_t>(File, StringAt);
        if (StringSize < 4 || StringSize > File.size() - StringAt)
            throw std::runtime_error("PE COFF string table truncated");
        const auto Strings = File.subspan(StringAt, StringSize);
        for (std::size_t I = 0; I < Count;) {
            const auto At = Offset + I * IMAGE_SIZEOF_SYMBOL;
            const auto Aux = Read<std::uint8_t>(File, At + 17);
            if (Aux >= Count - I) throw std::runtime_error("PE COFF auxiliary records truncated");
            const auto SectionIndex = Read<std::int16_t>(File, At + 12);
            const auto Type = Read<std::uint16_t>(File, At + 14);
            const auto Storage = Read<std::uint8_t>(File, At + 16);
            if ((Type & 0x30) == 0x20 && SectionIndex > 0 &&
                static_cast<std::size_t>(SectionIndex) <= Image.Sections().size() &&
                (Storage == IMAGE_SYM_CLASS_EXTERNAL || Storage == IMAGE_SYM_CLASS_STATIC)) {
                std::string Name;
                if (Read<std::uint32_t>(File, At) == 0) {
                    const auto NameAt = Read<std::uint32_t>(File, At + 4);
                    if (NameAt < 4 || NameAt >= Strings.size()) throw std::runtime_error("PE COFF name offset invalid");
                    Name = CString(Strings.subspan(NameAt));
                } else {
                    const auto Bytes = File.subspan(At, 8);
                    Name.assign(reinterpret_cast<const char*>(Bytes.data()),
                                static_cast<std::size_t>(std::find(Bytes.begin(), Bytes.end(), 0) - Bytes.begin()));
                }
                const auto& Section = Image.Sections()[SectionIndex - 1];
                const auto Value = Read<std::uint32_t>(File, At + 8);
                const auto Size = Aux ? Read<std::uint32_t>(File, At + IMAGE_SIZEOF_SYMBOL + 4) : 0;
                if (Value < Section.RawSize) {
                    if (auto* Candidate = AddCandidate(Image, Candidates, Section.VirtualAddress + Value, Size))
                        SetName(*Candidate, Name, "coff");
                }
            }
            I += 1 + Aux;
        }
    }
    return Candidates;
}

struct PdbIdentity {
    GUID Guid{};
    DWORD Age{};
    std::string Path;
    bool Present{};
};

PdbIdentity ReadPdbIdentity(const ImageView& Image) {
    const auto Debug = Image.DirectoryBytes(IMAGE_DIRECTORY_ENTRY_DEBUG);
    if (Debug.size() % sizeof(IMAGE_DEBUG_DIRECTORY)) throw std::runtime_error("PE debug table truncated");
    for (std::size_t At = 0; At < Debug.size(); At += sizeof(IMAGE_DEBUG_DIRECTORY)) {
        if (Read<DWORD>(Debug, At + 12) != IMAGE_DEBUG_TYPE_CODEVIEW) continue;
        const auto Size = Read<DWORD>(Debug, At + 16);
        const auto Raw = Read<DWORD>(Debug, At + 24);
        const auto File = Image.FileBytes();
        if (Raw > File.size() || Size > File.size() - Raw) throw std::runtime_error("PE CodeView record truncated");
        const auto Record = Raw ? File.subspan(Raw, Size) : Image.FileBytesAtRva(Read<DWORD>(Debug, At + 20), Size);
        if (Size < 4 || Read<DWORD>(Record, 0) != 0x53445352) continue; // RSDS
        PdbIdentity Identity;
        Identity.Guid = Read<GUID>(Record, 4);
        Identity.Age = Read<DWORD>(Record, 20);
        if (Size <= 24) throw std::runtime_error("PE CodeView path missing");
        Identity.Path = CString(Record.subspan(24));
        Identity.Present = true;
        return Identity;
    }
    return {};
}

struct SymbolSession {
    HANDLE Handle = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    DWORD Options = SymGetOptions();
    bool Initialized{};
    SymbolSession() {
        SymSetOptions(SYMOPT_EXACT_SYMBOLS | SYMOPT_FAIL_CRITICAL_ERRORS | SYMOPT_NO_PROMPTS |
                      SYMOPT_IGNORE_NT_SYMPATH | SYMOPT_DISABLE_SYMSRV_AUTODETECT);
        if (Handle) Initialized = SymInitializeW(Handle, L"", FALSE) != FALSE;
    }
    ~SymbolSession() {
        if (Initialized) SymCleanup(Handle);
        SymSetOptions(Options);
        if (Handle) CloseHandle(Handle);
    }
};

struct SymbolContext {
    const ImageView& Image;
    CandidateMap& Candidates;
    DWORD64 Base;
    std::exception_ptr Error;
};

BOOL CALLBACK CollectSymbol(PSYMBOL_INFO Symbol, ULONG Size, PVOID User) {
    auto& Context = *static_cast<SymbolContext*>(User);
    try {
        if (Symbol->Address < Context.Base || Symbol->Address - Context.Base > UINT32_MAX) return TRUE;
        const auto Rva = static_cast<std::uint32_t>(Symbol->Address - Context.Base);
        // SymTagFunction=5, SymTagPublicSymbol=10. An untyped public symbol
        // may name an already known entry, but must not invent a new function.
        if (Symbol->Tag != 5 && !(Symbol->Tag == 10 &&
            ((Symbol->Flags & SYMFLAG_FUNCTION) || Context.Candidates.contains(Rva)))) return TRUE;
        if (auto* Candidate = AddCandidate(Context.Image, Context.Candidates, Rva, Size))
            SetName(*Candidate, std::string(Symbol->Name, Symbol->NameLen), "pdb");
        return TRUE;
    } catch (...) {
        Context.Error = std::current_exception();
        return FALSE;
    }
}

bool LoadPdb(const ImageView& Image, CandidateMap& Candidates, const PdbIdentity& Identity,
             const std::filesystem::path& Path, std::string& Error) {
    SymbolSession Session;
    if (!Session.Initialized) { Error = "DbgHelp initialization failed"; return false; }
    // Load the local PDB itself, never the PE or a symbol server search path.
    const auto Base = SymLoadModuleExW(Session.Handle, nullptr, Path.c_str(), nullptr,
                                      0x10000000, Image.SizeOfImage(), nullptr, 0);
    IMAGEHLP_MODULEW64 Module{};
    Module.SizeOfStruct = sizeof(Module);
    if (!Base || !SymGetModuleInfoW64(Session.Handle, Base, &Module) || Module.SymType != SymPdb) {
        Error = "DbgHelp could not read PDB";
        return false;
    }
    if (Module.PdbAge != Identity.Age || std::memcmp(&Module.PdbSig70, &Identity.Guid, sizeof(GUID))) {
        Error = "PDB GUID/age does not match input PE";
        return false;
    }
    // Commit only after successful enumeration, so a partial load cannot leak names.
    auto Updated = Candidates;
    SymbolContext Context{Image, Updated, Base, {}};
    const auto Success = SymEnumSymbols(Session.Handle, Base, nullptr, CollectSymbol, &Context);
    if (Context.Error) std::rethrow_exception(Context.Error);
    if (!Success) { Error = "PDB function enumeration failed"; return false; }
    Candidates = std::move(Updated);
    return true;
}

std::vector<FunctionCandidate> Filter(CandidateMap Candidates, std::size_t MinimumBytes) {
    std::vector<FunctionCandidate> Result;
    for (auto& [Rva, Candidate] : Candidates)
        // Preserve the existing export policy: explicitly exported entries are
        // included even when smaller than the heuristic .pdata threshold.
        if (Candidate.NameSource == "export" || !Candidate.Size || Candidate.Size >= MinimumBytes)
            Result.push_back(std::move(Candidate));
    return Result;
}

std::string JsonString(const std::string& Value) {
    std::string Result = "\"";
    constexpr char Hex[] = "0123456789abcdef";
    for (const unsigned char Ch : Value) {
        if (Ch == '"' || Ch == '\\') { Result += '\\'; Result += Ch; }
        else if (Ch < 32) { Result += "\\u00"; Result += Hex[Ch >> 4]; Result += Hex[Ch & 15]; }
        else Result += Ch;
    }
    return Result + '"';
}
} // namespace

std::vector<FunctionCandidate> ScanFunctions(const ImageView& Image, std::size_t MinimumBytes) {
    const std::lock_guard Lock(SymbolMutex);
    return Filter(ScanImage(Image), MinimumBytes);
}

std::vector<FunctionCandidate> ScanFunctions(const std::filesystem::path& Input, std::size_t MinimumBytes) {
    return ScanFunctionDetails(Input, MinimumBytes).Functions;
}

FunctionScanResult ScanFunctionDetails(const std::filesystem::path& Input, std::size_t MinimumBytes,
                                      const std::filesystem::path& PdbPath) {
    const auto Data = util::ReadFile(Input);
    const ImageView Image(Data);
    const std::lock_guard Lock(SymbolMutex);
    auto Candidates = ScanImage(Image);
    FunctionScanResult Result;
    const auto Identity = ReadPdbIdentity(Image);
    if (!Identity.Present && !PdbPath.empty()) throw std::runtime_error("input has no RSDS identity to verify the supplied PDB");
    if (Identity.Present) {
        const auto InputPath = std::filesystem::absolute(Input);
        std::vector<std::filesystem::path> Paths;
        if (!PdbPath.empty()) Paths.push_back(std::filesystem::absolute(PdbPath));
        else {
            auto Sibling = InputPath; Sibling.replace_extension(L".pdb");
            Paths.push_back(Sibling);
            const std::filesystem::path Recorded(std::u8string(Identity.Path.begin(), Identity.Path.end()));
            Paths.push_back(InputPath.parent_path() / Recorded.filename());
            if (Recorded.is_absolute()) Paths.push_back(Recorded);
        }
        std::vector<std::filesystem::path> Tried;
        for (const auto& Path : Paths) {
            if (std::find(Tried.begin(), Tried.end(), Path) != Tried.end()) continue;
            Tried.push_back(Path);
            // Do not follow embedded UNC/network paths or symbol-server hints.
            const auto Native = Path.wstring();
            if (Native.starts_with(L"\\\\") || GetDriveTypeW(Path.root_path().c_str()) == DRIVE_REMOTE) {
                if (!PdbPath.empty()) throw std::runtime_error("PDB must be a local file");
                continue;
            }
            std::error_code Ec;
            if (!std::filesystem::is_regular_file(Path, Ec)) {
                if (!PdbPath.empty()) throw std::runtime_error("PDB file not found");
                continue;
            }
            std::string Error;
            if (LoadPdb(Image, Candidates, Identity, Path, Error)) {
                const auto Utf8 = Path.u8string();
                Result.SymbolFile.assign(Utf8.begin(), Utf8.end());
                break;
            }
            if (!PdbPath.empty()) throw std::runtime_error(Error);
            Result.Diagnostics.push_back(Error);
        }
        if (Result.SymbolFile.empty()) Result.Diagnostics.push_back("No matching local PDB loaded; place the build's PDB beside the PE or select it explicitly.");
    } else Result.Diagnostics.push_back("No RSDS PDB reference; names come from exports and COFF symbols where present.");
    Result.Functions = Filter(std::move(Candidates), MinimumBytes);
    return Result;
}

std::string FunctionScanJson(const FunctionScanResult& Result) {
    std::ostringstream Json;
    Json << "{\n  \"format\": \"pevm-scan-functions\",\n  \"symbolFile\": " << JsonString(Result.SymbolFile)
         << ",\n  \"diagnostics\": [";
    for (std::size_t I = 0; I < Result.Diagnostics.size(); ++I)
        Json << (I ? "," : "") << JsonString(Result.Diagnostics[I]);
    Json << "],\n  \"functions\": [\n";
    for (std::size_t I = 0; I < Result.Functions.size(); ++I) {
        const auto& Candidate = Result.Functions[I];
        Json << "    {\"rva\":\"0x" << std::hex << Candidate.Rva << "\",\"size\":" << std::dec << Candidate.Size
             << ",\"name\":" << JsonString(Candidate.Name) << ",\"decoratedName\":" << JsonString(Candidate.DecoratedName)
             << ",\"nameSource\":" << JsonString(Candidate.NameSource) << ",\"aliases\":[";
        for (std::size_t J = 0; J < Candidate.Aliases.size(); ++J)
            Json << (J ? "," : "") << JsonString(Candidate.Aliases[J]);
        Json << "]}" << (I + 1 == Result.Functions.size() ? "\n" : ",\n");
    }
    Json << "  ]\n}\n";
    return Json.str();
}
} // namespace x64lift
