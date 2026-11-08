#include "VmImageCodec.h"
#include "PeRelocations.h"
#include "PeTls.h"
#include "WindowsResources.h"
#include <windows.h>

#include <array>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cctype>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <intrin.h>
#include <limits>
#include <span>
#include <stdexcept>
#include <string>
#include <tlhelp32.h>
#include <atomic>
#include <memory>
#include <mutex>
#include <set>
#include <vector>

#include "PeVmContainer.h"
#include "PeVmCrypto.h"
#include "PeVmLicense.h"
#include "LicenseRuntime.h"
#include "VmProtect.h"
#include "WrapperFormat.h"

namespace Fs = std::filesystem;
using Bytes = std::vector<std::uint8_t>;

// Compile-time encoded diagnostic text: the binary carries only the XOR
// form (consteval forces immediate evaluation), the plaintext is
// reassembled on demand in a temporary buffer. The key is derived from the
// literal length so every site encodes differently; Reveal reads through
// volatile so the optimizer cannot fold the plaintext back into the binary.
template <std::size_t N>   // N = literal length including the terminating nul
consteval auto EncodeText(const char (&Text)[N]) {
    constexpr auto Key = static_cast<std::uint8_t>(N * 131U + 7U);
    std::array<std::uint8_t, N - 1> Out{};
    for (std::size_t I = 0; I < N - 1; ++I) {
        Out[I] = static_cast<std::uint8_t>(Text[I] ^ (Key + static_cast<std::uint8_t>(I * 37U)));
    }
    return Out;
}

__declspec(noinline) std::string Reveal(const std::uint8_t* Encoded, std::size_t Size) {
    const auto Key = static_cast<std::uint8_t>((Size + 1U) * 131U + 7U);
    std::string Out(Size, '\0');
    for (std::size_t I = 0; I < Size; ++I) {
        volatile const std::uint8_t* Source = Encoded + I;
        Out[I] = static_cast<char>(*Source ^ (Key + static_cast<std::uint8_t>(I * 37U)));
    }
    return Out;
}

#define PEVM_TEXT(Literal) Reveal(EncodeText(Literal).data(), sizeof(Literal) - 1)

// Wide-string variant for environment variable and window class names, so
// the development escape hatches and check targets are not grep-able either.
template <std::size_t N>   // N = literal length in wchar_t including the nul
consteval auto EncodeWideText(const wchar_t (&Text)[N]) {
    constexpr auto Key = static_cast<std::uint16_t>(N * 131U + 7U);
    std::array<std::uint16_t, N - 1> Out{};
    for (std::size_t I = 0; I < N - 1; ++I) {
        Out[I] = static_cast<std::uint16_t>(Text[I] ^ (Key + static_cast<std::uint16_t>(I * 37U)));
    }
    return Out;
}

__declspec(noinline) std::wstring RevealWide(const std::uint16_t* Encoded, std::size_t Size) {
    const auto Key = static_cast<std::uint16_t>((Size + 1U) * 131U + 7U);
    std::wstring Out(Size, L'\0');
    for (std::size_t I = 0; I < Size; ++I) {
        volatile const std::uint16_t* Source = Encoded + I;
        Out[I] = static_cast<wchar_t>(*Source ^ (Key + static_cast<std::uint16_t>(I * 37U)));
    }
    return Out;
}

#define PEVM_WTEXT(Literal) RevealWide(EncodeWideText(Literal).data(), sizeof(Literal) / sizeof(wchar_t) - 1)

// Sensitive APIs are resolved at runtime without touching the loader module
// list APIs: the PEB loader entries are walked directly and module/export
// names are matched by FNV-1a hash, so neither the import table nor the
// binary carries the resolved names.
constexpr std::uint32_t AnsiApiHash(const char* Name) {
    std::uint32_t Hash = 0x811C9DC5U;
    while (*Name != '\0') {
        Hash ^= static_cast<std::uint8_t>(*Name++);
        Hash *= 0x01000193U;
    }
    return Hash;
}

constexpr std::uint32_t WideModuleHash(const wchar_t* Name) {
    std::uint32_t Hash = 0x811C9DC5U;
    while (*Name != L'\0') {
        std::uint32_t C = static_cast<std::uint32_t>(*Name++);
        if (C >= L'A' && C <= L'Z') C += 32U;
        Hash ^= C;
        Hash *= 0x01000193U;
    }
    return Hash;
}

inline constexpr std::uint32_t KKernel32Module = WideModuleHash(L"kernel32.dll");
inline constexpr std::uint32_t KNtdllModule = WideModuleHash(L"ntdll.dll");
inline constexpr std::uint32_t KUser32Module = WideModuleHash(L"user32.dll");

// Local mirror of UNICODE_STRING to avoid pulling in winternl.h.
struct RawUnicodeString {
    std::uint16_t Length;
    std::uint16_t MaximumLength;
    std::uint16_t Padding[2];
    const wchar_t* Buffer;
};

std::uint32_t HashLoaderEntryName(const RawUnicodeString& Name) {
    std::uint32_t Hash = 0x811C9DC5U;
    const auto Count = static_cast<std::size_t>(Name.Length / sizeof(wchar_t));
    for (std::size_t I = 0; I < Count; ++I) {
        std::uint32_t C = static_cast<std::uint32_t>(Name.Buffer[I]);
        if (C >= L'A' && C <= L'Z') C += 32U;
        Hash ^= C;
        Hash *= 0x01000193U;
    }
    return Hash;
}

// Forwarder strings carry no ".dll" suffix, loader entries do; FNV is not
// composable so the suffix is folded in with a fresh loop.
std::uint32_t HashModuleNameWithSuffix(const char* Begin, const char* End) {
    std::uint32_t Hash = 0x811C9DC5U;
    for (const char* P = Begin; P != End; ++P) {
        std::uint32_t C = static_cast<std::uint8_t>(*P);
        if (C >= 'A' && C <= 'Z') C += 32U;
        Hash ^= C;
        Hash *= 0x01000193U;
    }
    for (const char* P = ".dll"; *P != '\0'; ++P) {
        Hash ^= static_cast<std::uint8_t>(*P);
        Hash *= 0x01000193U;
    }
    return Hash;
}

// Hidden kernel32 APIs the import resolver itself needs. Resolved once,
// lazily; the IAT still carries no reference to them.
void* ResolveApiHashed(std::uint32_t ModuleHash, std::uint32_t NameHash, int Depth);
void* ExportByHash(const std::uint8_t* Base, std::uint32_t NameHash, int Depth);

// Forwarder targets are loaded explicitly instead of matched against the
// loader list: API-set modules (and modules not yet loaded) would otherwise
// fail the BaseDllName hash match even though LoadLibraryA resolves them.
void* ResolveForwarder(const char* Forwarder, int Depth);

// Walks the export table of a mapped module and returns the function whose
// ANSI name hashes to NameHash. Forwarded exports ("MODULE.Func") are
// followed through another loader-list lookup; any structural anomaly fails
// closed. Forwarders are essential here: kernel32 forwards VirtualAlloc and
// friends to KERNELBASE, so a lookup that stops at a forwarder breaks every
// import of a real payload.
void* ExportByHash(const std::uint8_t* Base, std::uint32_t NameHash, int Depth) {
    if (Base == nullptr) return nullptr;
    const auto Dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(Base);
    if (Dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    const auto Nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(Base + Dos->e_lfanew);
    if (Nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;
    const auto& Directory = Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (Directory.VirtualAddress == 0 || Directory.Size < sizeof(IMAGE_EXPORT_DIRECTORY)) return nullptr;
    const auto Exports = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(Base + Directory.VirtualAddress);
    const auto Names = reinterpret_cast<const std::uint32_t*>(Base + Exports->AddressOfNames);
    const auto Ordinals = reinterpret_cast<const std::uint16_t*>(Base + Exports->AddressOfNameOrdinals);
    const auto Functions = reinterpret_cast<const std::uint32_t*>(Base + Exports->AddressOfFunctions);
    for (std::uint32_t I = 0; I < Exports->NumberOfNames; ++I) {
        const auto* Name = reinterpret_cast<const char*>(Base + Names[I]);
        if (AnsiApiHash(Name) != NameHash) continue;
        const auto Ordinal = Ordinals[I];
        if (Ordinal >= Exports->NumberOfFunctions) return nullptr;
        const auto Rva = Functions[Ordinal];
        if (Rva == 0) return nullptr;
        if (Rva >= Directory.VirtualAddress && Rva < Directory.VirtualAddress + Directory.Size) {
            return ResolveForwarder(reinterpret_cast<const char*>(Base + Rva), Depth);
        }
        return const_cast<std::uint8_t*>(Base) + Rva;
    }
    return nullptr;
}

// Resolves an export by ordinal (payload imports snap by ordinal). Ordinal
// slots can be forwarders too, so the same follow logic applies.
void* ExportByOrdinal(const std::uint8_t* Base, std::uint16_t Ordinal, int Depth) {
    if (Base == nullptr) return nullptr;
    const auto Dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(Base);
    const auto Nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(Base + Dos->e_lfanew);
    const auto& Directory = Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (Directory.VirtualAddress == 0 || Directory.Size < sizeof(IMAGE_EXPORT_DIRECTORY)) return nullptr;
    const auto Exports = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(Base + Directory.VirtualAddress);
    const auto Functions = reinterpret_cast<const std::uint32_t*>(Base + Exports->AddressOfFunctions);
    const auto Index = static_cast<std::uint32_t>(Ordinal - Exports->Base);
    if (Index >= Exports->NumberOfFunctions) return nullptr;
    const auto Rva = Functions[Index];
    if (Rva == 0) return nullptr;
    if (Rva >= Directory.VirtualAddress && Rva < Directory.VirtualAddress + Directory.Size) {
        return ResolveForwarder(reinterpret_cast<const char*>(Base + Rva), Depth);
    }
    return const_cast<std::uint8_t*>(Base) + Rva;
}

// Resolves an export by plain name (payload imports snap by name).
void* ExportByName(const std::uint8_t* Base, const char* Name) {
    return ExportByHash(Base, AnsiApiHash(Name), 4);
}

__declspec(noinline) void* ResolveApiHashed(std::uint32_t ModuleHash, std::uint32_t NameHash, int Depth) {
    const auto Peb = reinterpret_cast<const std::uint8_t*>(__readgsqword(0x60));
    if (Peb == nullptr) return nullptr;
    const auto Ldr = *reinterpret_cast<std::uint8_t* const*>(Peb + 0x18);
    if (Ldr == nullptr) return nullptr;
    const auto Head = reinterpret_cast<const LIST_ENTRY*>(Ldr + 0x10);
    for (auto Node = Head->Flink; Node != nullptr && Node != Head; Node = Node->Flink) {
        const auto Entry = reinterpret_cast<const std::uint8_t*>(Node);
        const auto Base = *reinterpret_cast<std::uint8_t* const*>(Entry + 0x30);
        const auto Name = reinterpret_cast<const RawUnicodeString*>(Entry + 0x58);
        if (Base == nullptr || Name->Buffer == nullptr) continue;
        if (HashLoaderEntryName(*Name) != ModuleHash) continue;
        return ExportByHash(Base, NameHash, Depth);
    }
    return nullptr;
}

void* ResolveApi(std::uint32_t ModuleHash, std::uint32_t NameHash) {
    return ResolveApiHashed(ModuleHash, NameHash, 4);
}

template <typename Fn>
Fn Api(std::uint32_t ModuleHash, std::uint32_t NameHash) {
    return reinterpret_cast<Fn>(ResolveApi(ModuleHash, NameHash));
}

#define PEVM_API(FnType, Module, Name) Api<FnType>(Module, AnsiApiHash(Name))

// Hidden kernel32 APIs the import resolver itself needs. Resolved once,
// lazily; the IAT still carries no reference to them.
using LoadLibraryAFn = HMODULE(WINAPI*)(const char*);
using GetProcAddressFn = FARPROC(WINAPI*)(HMODULE, const char*);
const struct HiddenApis {
    LoadLibraryAFn LoadLibrary;
    GetProcAddressFn GetProc;
} &HiddenApisRef() {
    static const HiddenApis Apis = {
        Api<LoadLibraryAFn>(KKernel32Module, AnsiApiHash("LoadLibraryA")),
        Api<GetProcAddressFn>(KKernel32Module, AnsiApiHash("GetProcAddress")),
    };
    return Apis;
}

// Forwarder targets are loaded explicitly instead of matched against the
// loader list: API-set modules (and modules not yet loaded) would otherwise
// fail the BaseDllName hash match even though LoadLibraryA resolves them.
void* ResolveForwarder(const char* Forwarder, int Depth) {
    if (Depth <= 0) return nullptr;
    const auto* Dot = Forwarder;
    while (*Dot != '\0' && *Dot != '.') ++Dot;
    if (*Dot != '.' || Dot == Forwarder || Dot[1] == '\0') return nullptr;
    const auto& Apis = HiddenApisRef();
    if (Apis.LoadLibrary == nullptr) return nullptr;
    std::string ModuleName(Forwarder, Dot);
    ModuleName += ".dll";
    const auto Base = reinterpret_cast<const std::uint8_t*>(Apis.LoadLibrary(ModuleName.c_str()));
    if (Base == nullptr) return nullptr;
    return ExportByHash(Base, AnsiApiHash(Dot + 1), Depth - 1);
}

using NtQuerySystemInformationFn = LONG(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
using CheckRemoteDebuggerPresentFn = BOOL(WINAPI*)(HANDLE, PBOOL);
using GetThreadContextFn = BOOL(WINAPI*)(HANDLE, LPCONTEXT);
using CreateToolhelp32SnapshotFn = HANDLE(WINAPI*)(DWORD, DWORD);
using Process32FirstWFn = BOOL(WINAPI*)(HANDLE, LPPROCESSENTRY32W);
using Process32NextWFn = BOOL(WINAPI*)(HANDLE, LPPROCESSENTRY32W);
using OutputDebugStringWFn = void(WINAPI*)(const wchar_t*);
using CloseHandleFn = BOOL(WINAPI*)(HANDLE);
using FindWindowWFn = HWND(WINAPI*)(const wchar_t*, const wchar_t*);
using VirtualAllocFn = LPVOID(WINAPI*)(LPVOID, SIZE_T, DWORD, DWORD);
using VirtualProtectFn = BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD);
using AddVectoredExceptionHandlerFn = void*(WINAPI*)(ULONG, PVECTORED_EXCEPTION_HANDLER);
using RemoveVectoredExceptionHandlerFn = ULONG(WINAPI*)(void*);

namespace {

Bytes ReadFile(const Fs::path& Path) {
    std::ifstream File(Path, std::ios::binary | std::ios::ate);
    if (!File) throw std::runtime_error(PEVM_TEXT("cannot open wrapper"));
    const auto Size = File.tellg();
    if (Size < 0) throw std::runtime_error(PEVM_TEXT("cannot determine wrapper size"));
    Bytes Data(static_cast<std::size_t>(Size));
    File.seekg(0);
    if (!Data.empty()) File.read(reinterpret_cast<char*>(Data.data()), static_cast<std::streamsize>(Data.size()));
    if (!File) throw std::runtime_error(PEVM_TEXT("cannot read wrapper"));
    return Data;
}

Fs::path SelfPath() {
    std::array<wchar_t, 32768> Buffer{};
    const auto Size = GetModuleFileNameW(nullptr, Buffer.data(), static_cast<DWORD>(Buffer.size()));
    if (Size == 0 || Size == Buffer.size()) throw std::runtime_error(PEVM_TEXT("cannot resolve wrapper path"));
    return std::wstring(Buffer.data(), Size);
}

// Runtime hardening. Every check fails closed with the same generic message
// so a failed check is indistinguishable from an integrity violation.
// PEVM_ALLOW_DEBUGGER is the documented development/CI escape hatch;
// PEVM_TEST_FAKE_DEBUGGER simulates a triggered check for plumbing tests.
[[noreturn]] void IntegrityFailure() {
    throw std::runtime_error(PEVM_TEXT("loader integrity check failed"));
}

constexpr bool NtSuccess(LONG Status) { return Status >= 0; }

// Direct PEB reads (not the APIs, which a debugger can hook): BeingDebugged
// and the heap flags a debugger injects.
void CheckPebDebugFlags() {
    const auto Peb = reinterpret_cast<const std::uint8_t*>(__readgsqword(0x60));
    if (Peb == nullptr) return;
    if (Peb[0x2] != 0) IntegrityFailure();
    if ((*reinterpret_cast<const std::uint32_t*>(Peb + 0xBC) & 0x70U) != 0) IntegrityFailure();
}

void CheckRemoteDebugger() {
    const auto Check = PEVM_API(CheckRemoteDebuggerPresentFn, KKernel32Module,
                                "CheckRemoteDebuggerPresent");
    if (Check == nullptr) return;
    BOOL RemotePresent = FALSE;
    if (Check(GetCurrentProcess(), &RemotePresent) && RemotePresent) IntegrityFailure();
}

// NtQueryInformationProcess triple check: debug port, debug object handle and
// the NoDebugInherit flag (0 while a debugger is attached).
void CheckDebugObjects() {
    using NtQueryInformationProcessFn = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    const auto Query = PEVM_API(NtQueryInformationProcessFn, KNtdllModule,
                                "NtQueryInformationProcess");
    if (Query == nullptr) return;
    ULONG_PTR Port = 0;
    if (NtSuccess(Query(GetCurrentProcess(), 7, &Port, sizeof(Port), nullptr)) && Port != 0) IntegrityFailure();
    HANDLE DebugObject = nullptr;
    if (NtSuccess(Query(GetCurrentProcess(), 0x1E, &DebugObject, sizeof(DebugObject), nullptr)) &&
        DebugObject != nullptr) {
        IntegrityFailure();
    }
    ULONG DebugFlags = 0;
    if (NtSuccess(Query(GetCurrentProcess(), 0x1F, &DebugFlags, sizeof(DebugFlags), nullptr)) &&
        DebugFlags == 0) {
        IntegrityFailure();
    }
}

// Kernel-level debug state (SystemKernelDebuggerInformation): catches kernel
// debuggers that never show up in usermode PEB/handle checks.
void CheckKernelDebugger() {
    const auto Query = PEVM_API(NtQuerySystemInformationFn, KNtdllModule,
                                "NtQuerySystemInformation");
    if (Query == nullptr) return;
    std::uint8_t State[2]{};
    if (NtSuccess(Query(0x23 /*SystemKernelDebuggerInformation*/, State, sizeof(State), nullptr))) {
        if ((State[0] & 1U) != 0) IntegrityFailure();   // KdDebuggerEnabled
    }
}

void CheckHardwareBreakpoints() {
    const auto Get = PEVM_API(GetThreadContextFn, KKernel32Module, "GetThreadContext");
    if (Get == nullptr) return;
    CONTEXT Context{};
    Context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (Get(GetCurrentThread(), &Context)) {
        if (Context.Dr0 != 0 || Context.Dr1 != 0 || Context.Dr2 != 0 || Context.Dr3 != 0 ||
            (Context.Dr7 & 0xFFU) != 0) {
            IntegrityFailure();
        }
    }
}

// Coarse scan of the process list for well-known debugger executables.
void CheckDebuggerProcesses() {
    static constexpr std::array<std::wstring_view, 8> Known = {
        L"x64dbg", L"x32dbg", L"ollydbg", L"ida64", L"ida32", L"windbg", L"dnspy", L"cheatengine"};
    const auto Snapshot = PEVM_API(CreateToolhelp32SnapshotFn, KKernel32Module,
                                   "CreateToolhelp32Snapshot");
    const auto First = PEVM_API(Process32FirstWFn, KKernel32Module, "Process32FirstW");
    const auto Next = PEVM_API(Process32NextWFn, KKernel32Module, "Process32NextW");
    const auto Close = PEVM_API(CloseHandleFn, KKernel32Module, "CloseHandle");
    if (Snapshot == nullptr || First == nullptr || Next == nullptr || Close == nullptr) return;
    const auto Handle = Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Handle == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32W Entry{};
    Entry.dwSize = sizeof(Entry);
    if (First(Handle, &Entry)) {
        do {
            std::wstring Lower(Entry.szExeFile);
            std::transform(Lower.begin(), Lower.end(), Lower.begin(), ::towlower);
            for (const auto Name : Known) {
                if (Lower.find(Name) != std::wstring::npos) {
                    Close(Handle);
                    IntegrityFailure();
                }
            }
        } while (Next(Handle, &Entry));
    }
    Close(Handle);
}

// OutputDebugString resets the last error to zero when a debugger consumes
// the message; without one the previous error survives.
void CheckOutputDebugString() {
    const auto Output = PEVM_API(OutputDebugStringWFn, KKernel32Module, "OutputDebugStringW");
    if (Output == nullptr) return;
    SetLastError(0x1337);
    Output(PEVM_WTEXT(L"PeVmProtector").c_str());
    if (GetLastError() == 0) IntegrityFailure();
}

// Window scan for classic debugger main windows (best effort; user32 may not
// be mapped in console-subsystem processes).
void CheckDebuggerWindows() {
    const auto Find = PEVM_API(FindWindowWFn, KUser32Module, "FindWindowW");
    if (Find == nullptr) return;
    if (Find(PEVM_WTEXT(L"OLLYDBG").c_str(), nullptr) != nullptr) IntegrityFailure();
    if (Find(PEVM_WTEXT(L"x64dbgClass").c_str(), nullptr) != nullptr) IntegrityFailure();
    if (Find(PEVM_WTEXT(L"x32dbgClass").c_str(), nullptr) != nullptr) IntegrityFailure();
}

// Without a debugger the breakpoint exception reaches our own handler; one
// that swallows first-chance breakpoints leaves it undelivered.
void CheckInt3Delivery() {
    bool Delivered = false;
    __try { __debugbreak(); }
    __except (EXCEPTION_EXECUTE_HANDLER) { Delivered = true; }
    if (!Delivered) IntegrityFailure();
}

// CloseHandle with a bogus handle raises STATUS_INVALID_HANDLE only when a
// debugger is attached and forwards the exception into this frame.
__declspec(noinline) bool ProbeInvalidHandle(CloseHandleFn Close) {
    bool Raised = false;
    __try {
        Close(reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(0x12341234ULL)));
    } __except (GetExceptionCode() == STATUS_INVALID_HANDLE ? EXCEPTION_EXECUTE_HANDLER
                                                            : EXCEPTION_CONTINUE_SEARCH) {
        Raised = true;
    }
    return Raised;
}

void CheckInvalidHandleException() {
    const auto Close = PEVM_API(CloseHandleFn, KKernel32Module, "CloseHandle");
    if (Close == nullptr) return;
    if (ProbeInvalidHandle(Close)) IntegrityFailure();
}

// High-resolution millisecond stopwatch for the timing budgets.
class Stopwatch {
public:
    Stopwatch() { QueryPerformanceCounter(&Start); }
    std::uint64_t Milliseconds() const {
        LARGE_INTEGER Now, Frequency;
        QueryPerformanceCounter(&Now);
        QueryPerformanceFrequency(&Frequency);
        return static_cast<std::uint64_t>((Now.QuadPart - Start.QuadPart) * 1000ULL / Frequency.QuadPart);
    }
private:
    LARGE_INTEGER Start{};
};

// A trivial loop completes in microseconds; tracing inflates it by orders
// of magnitude. The budget is deliberately generous (false-positive safe).
void CheckTimingAnomaly() {
    Stopwatch Clock;
    volatile std::uint64_t Accumulator = 0;
    for (unsigned I = 0; I < 200000U; ++I) Accumulator += I;
    if (Clock.Milliseconds() > 2000) IntegrityFailure();
}

// Best-effort hardening: removes this thread from the debugger's event list.
void HideThreadFromDebugger() {
    using NtSetInformationThreadFn = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG);
    if (const auto Set = PEVM_API(NtSetInformationThreadFn, KNtdllModule,
                                  "NtSetInformationThread")) {
        (void)Set(GetCurrentThread(), 0x11U /*ThreadHideFromDebugger*/, nullptr, 0);
    }
}

// Thin wrappers so every memory/vectored-handler call site goes through the
// hidden resolution path instead of the import table.
BOOL HideProtect(LPVOID Address, SIZE_T Size, DWORD NewProtection, PDWORD OldProtection) {
    const auto Protect = PEVM_API(VirtualProtectFn, KKernel32Module, "VirtualProtect");
    return Protect != nullptr && Protect(Address, Size, NewProtection, OldProtection);
}

LPVOID HideAlloc(LPVOID Address, SIZE_T Size, DWORD Type, DWORD Protection) {
    const auto Alloc = PEVM_API(VirtualAllocFn, KKernel32Module, "VirtualAlloc");
    return Alloc != nullptr ? Alloc(Address, Size, Type, Protection) : nullptr;
}

void* HideVectoredAdd(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler) {
    const auto Add = PEVM_API(AddVectoredExceptionHandlerFn, KKernel32Module,
                              "AddVectoredExceptionHandler");
    return Add != nullptr ? Add(First, Handler) : nullptr;
}

void HideVectoredRemove(void* Handle) {
    const auto Remove = PEVM_API(RemoveVectoredExceptionHandlerFn, KKernel32Module,
                                 "RemoveVectoredExceptionHandler");
    if (Remove != nullptr) (void)Remove(Handle);
}

// Environment probing also goes through the hidden resolution path; the
// variable names themselves are decoded on demand via PEVM_WTEXT.
DWORD HideGetEnv(const wchar_t* Name) {
    using GetEnvironmentVariableWFn = DWORD(WINAPI*)(const wchar_t*, wchar_t*, DWORD);
    const auto Get = PEVM_API(GetEnvironmentVariableWFn, KKernel32Module, "GetEnvironmentVariableW");
    return Get != nullptr ? Get(Name, nullptr, 0) : 0;
}

// Scan loaded modules for known analysis/injection DLLs (Sandboxie, Cheat
// Engine usermode helpers). Reuses the loader-list walk, so it costs nothing
// beyond the walk itself.
void CheckInjectedModules() {
    static constexpr std::array<std::wstring_view, 5> Known = {
        L"sbiedll", L"speedhack", L"dbk", L"dbvm", L"ollydbg"};
    const auto Peb = reinterpret_cast<const std::uint8_t*>(__readgsqword(0x60));
    if (Peb == nullptr) return;
    const auto Ldr = *reinterpret_cast<std::uint8_t* const*>(Peb + 0x18);
    if (Ldr == nullptr) return;
    const auto Head = reinterpret_cast<const LIST_ENTRY*>(Ldr + 0x10);
    for (auto Node = Head->Flink; Node != nullptr && Node != Head; Node = Node->Flink) {
        const auto Entry = reinterpret_cast<const std::uint8_t*>(Node);
        const auto Name = reinterpret_cast<const RawUnicodeString*>(Entry + 0x58);
        if (Name->Buffer == nullptr) continue;
        std::wstring Lower(Name->Buffer, Name->Length / sizeof(wchar_t));
        std::transform(Lower.begin(), Lower.end(), Lower.begin(), ::towlower);
        for (const auto Marker : Known) {
            if (Lower.find(Marker) != std::wstring::npos) IntegrityFailure();
        }
    }
}

// Non-throwing light predicates for the watchdog: a hit cannot unwind into
// the main thread's handler, so the watchdog exits the process directly.
bool DebuggerLightHit() {
    const auto Peb = reinterpret_cast<const std::uint8_t*>(__readgsqword(0x60));
    if (Peb != nullptr) {
        if (Peb[0x2] != 0) return true;
        if ((*reinterpret_cast<const std::uint32_t*>(Peb + 0xBC) & 0x70U) != 0) return true;
    }
    using NtQueryInformationProcessFn = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    const auto Query = PEVM_API(NtQueryInformationProcessFn, KNtdllModule, "NtQueryInformationProcess");
    if (Query != nullptr) {
        ULONG_PTR Port = 0;
        if (NtSuccess(Query(GetCurrentProcess(), 7, &Port, sizeof(Port), nullptr)) && Port != 0) return true;
    }
    return false;
}

std::atomic<bool> GWatchdogStop{false};

DWORD WINAPI WatchdogThread(void*) {
    using TerminateProcessFn = BOOL(WINAPI*)(HANDLE, UINT);
    while (!GWatchdogStop.load(std::memory_order_relaxed)) {
        if (DebuggerLightHit()) {
            const auto Kill = PEVM_API(TerminateProcessFn, KKernel32Module, "TerminateProcess");
            if (Kill != nullptr) (void)Kill(GetCurrentProcess(), 1U);
            ExitProcess(1U);
        }
        Sleep(250);
    }
    return 0;
}

void StartWatchdog() {
    // The escape hatch disables the watchdog too, not just the startup
    // checks: development/CI runs must stay attachable end to end.
    if (HideGetEnv(PEVM_WTEXT(L"PEVM_ALLOW_DEBUGGER").c_str()) != 0) return;
    using CreateThreadFn = HANDLE(WINAPI*)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE,
                                           LPVOID, DWORD, LPDWORD);
    const auto Create = PEVM_API(CreateThreadFn, KKernel32Module, "CreateThread");
    if (Create == nullptr) return;
    GWatchdogStop.store(false);
    const auto Thread = Create(nullptr, 0, WatchdogThread, nullptr, 0, nullptr);
    if (Thread != nullptr) CloseHandle(Thread);
}

void RunAntiDebugChecks(bool Light = false) {
    if (HideGetEnv(PEVM_WTEXT(L"PEVM_ALLOW_DEBUGGER").c_str()) != 0) return;
    if (HideGetEnv(PEVM_WTEXT(L"PEVM_TEST_FAKE_DEBUGGER").c_str()) != 0) IntegrityFailure();
    CheckPebDebugFlags();
    CheckRemoteDebugger();
    CheckDebugObjects();
    CheckKernelDebugger();
    CheckHardwareBreakpoints();
    if (Light) return;
    CheckDebuggerProcesses();
    CheckDebuggerWindows();
    CheckInjectedModules();
    CheckOutputDebugString();
    CheckInt3Delivery();
    CheckInvalidHandleException();
    CheckTimingAnomaly();
    HideThreadFromDebugger();
}

// Unpacking (scrypt) plus manual mapping should complete in well under a
// second on supported hardware; single-stepping through it under a debugger
// blows past this generous budget.
constexpr std::uint64_t KUnpackBudgetMs = 10000;

std::string RecoverBuildSecret(std::span<const std::uint8_t> Image, const WrapperFooter& Footer,
                               std::size_t PayloadOffset, std::size_t SecretOffset) {
    if (Footer.StubSize != SecretOffset || Footer.SecretSize > Image.size() - SecretOffset) {
        throw std::runtime_error(PEVM_TEXT("wrapper layout invalid"));
    }
    const auto Stub = Image.first(static_cast<std::size_t>(Footer.StubSize));
    const auto Payload = Image.subspan(PayloadOffset, static_cast<std::size_t>(Footer.PayloadSize));
    const auto Sealed = Image.subspan(SecretOffset, Footer.SecretSize);
    const auto Fingerprint = WrapperFingerprint(Stub, Payload, Footer.Salt);
    if (Footer.SecretTag != WrapperSecretTag(Sealed, Fingerprint)) {
        throw std::runtime_error(PEVM_TEXT("wrapper secret integrity failed"));
    }
    std::string Secret(Footer.SecretSize, '\0');
    for (std::size_t I = 0; I < Secret.size(); ++I) {
        Secret[I] = static_cast<char>(Sealed[I] ^ WrapperSecretByte(Fingerprint, I));
    }
    return Secret;
}

VmpMetadata ValidateProtectionMetadata(std::span<const std::uint8_t> Image, const WrapperFooter& Footer) {
    if (Footer.MetadataSize != sizeof(VmpMetadata) || Footer.MetadataOffset > Image.size() ||
        Footer.MetadataSize > Image.size() - static_cast<std::size_t>(Footer.MetadataOffset)) {
        throw std::runtime_error(PEVM_TEXT(".vmp2 metadata range invalid"));
    }
    VmpMetadata Metadata{};
    std::memcpy(&Metadata, Image.data() + Footer.MetadataOffset, sizeof(Metadata));
    if (Metadata.Magic != KVmpMetadataMagic || Metadata.Version != KVmpMetadataVersion) {
        throw std::runtime_error(PEVM_TEXT(".vmp2 metadata invalid"));
    }
    pevm::license::ValidatePolicy(Metadata.License);
    const auto ValidateRange = [&](std::uint32_t Offset, std::uint32_t Size, const char* Name) {
        if (Offset > Image.size() || Size > Image.size() - Offset) {
            throw std::runtime_error(std::string(Name) + PEVM_TEXT(" range invalid"));
        }
    };
    ValidateRange(Metadata.RuntimeRawOffset, Metadata.RuntimeRawSize, ".vmp0");
    ValidateRange(Metadata.PayloadRawOffset, Metadata.PayloadRawSize, ".vmp1");
    const auto RuntimeTag = VmpRegionTag(Image.subspan(Metadata.RuntimeRawOffset,
                                                       Metadata.RuntimeRawSize),
                                         Metadata.BuildId, 0x30504D56ULL);
    const auto PayloadTag = VmpRegionTag(Image.subspan(Metadata.PayloadRawOffset,
                                                       Metadata.PayloadRawSize),
                                         Metadata.BuildId, 0x31504D56ULL);
    if (RuntimeTag != Metadata.RuntimeTag) throw std::runtime_error(PEVM_TEXT(".vmp0 integrity violation"));
    if (PayloadTag != Metadata.PayloadTag) throw std::runtime_error(PEVM_TEXT(".vmp1 integrity violation"));
    if (Metadata.PayloadRawOffset != Footer.PayloadOffset ||
        Metadata.PayloadRawSize != Footer.PayloadSize) {
        throw std::runtime_error(PEVM_TEXT(".vmp1/footer mismatch"));
    }
    if (Metadata.VmDataRawSize != 0) {
        ValidateRange(Metadata.VmDataRawOffset, Metadata.VmDataRawSize, ".vmp3");
        const auto VmDataTag = VmpRegionTag(Image.subspan(Metadata.VmDataRawOffset,
                                                          Metadata.VmDataRawSize),
                                             Metadata.BuildId, 0x33504D56ULL);
        if (VmDataTag != Metadata.VmDataTag) throw std::runtime_error(PEVM_TEXT(".vmp3 integrity violation"));
    }
    return Metadata;
}

struct VmProgram {
    vmprotect::CompiledProgram Compiled;
    std::uint32_t EntryAddress{};
    std::uint32_t ResumeAddress{};
    bool NeedsStack{};
};

// Digest over a lifted program so the bridge can detect runtime patching of
// the in-memory vector: per-instruction VM tags are computed during assembly
// and therefore cannot catch a modification made before InvokeLiftedProgram.
std::uint64_t ProgramDigest(const vmprotect::LiftedProgram& Program) {
    std::uint64_t Hash = 0xCBF29CE484222325ULL ^ Program.EntryAddress;
    auto Add = [&](std::uint64_t Value) { Hash = WrapperMix64(Hash ^ Value); };
    for (const auto& Instruction : Program.Instructions) {
        Add((static_cast<std::uint64_t>(static_cast<std::uint8_t>(Instruction.Op)) << 56) ^
            (static_cast<std::uint64_t>(Instruction.Dst) << 48) ^
            (static_cast<std::uint64_t>(Instruction.Src) << 40) ^ Instruction.Immediate);
        Add((static_cast<std::uint64_t>(Instruction.Address) << 32) ^ Instruction.Target);
        Add(Instruction.Width);
    }
    return WrapperMix64(Hash ^ Program.ResumeAddress);
}

std::vector<VmProgram> GVirtualizedPrograms;
std::uint64_t GVmImageBase{};
// Construct before BindTls replaces this image's TLS template. Function-local
// static guards use the CRT thread epoch, which belongs to the payload after
// that switch and can incorrectly skip a first-time initialization.
struct VmBridgeTrace {
    std::mutex Mutex;
    std::vector<std::uint8_t> Seen;
    std::ofstream Log;
    bool Enabled{};
} GVmBridgeTrace;
struct VmStackPool {
    std::vector<std::unique_ptr<std::uint8_t[]>> Frames;
    std::size_t Depth{};
};
DWORD GVmStackSlot = FLS_OUT_OF_INDEXES;
void NTAPI ReleaseVmStacks(void* Pointer) { delete static_cast<VmStackPool*>(Pointer); }
struct VmStackLease {
    static constexpr std::size_t Size = 64 * 1024 + 8192;
    VmStackPool* Pool{};
    std::uint8_t* Data{};
    VmStackLease() {
        Pool = static_cast<VmStackPool*>(FlsGetValue(GVmStackSlot));
        if (!Pool) {
            auto NewPool = std::make_unique<VmStackPool>();
            if (!FlsSetValue(GVmStackSlot, NewPool.get())) throw std::runtime_error("VM stack slot unavailable");
            Pool = NewPool.release();
        }
        if (Pool->Depth == Pool->Frames.size()) Pool->Frames.emplace_back(new std::uint8_t[Size]);
        Data = Pool->Frames[Pool->Depth++].get();
    }
    ~VmStackLease() { --Pool->Depth; }
};
extern "C" void PeVmNativeEntry();

extern "C" void VirtualizedFunctionBridge(vmprotect::VmBridgeContext* State,
                                           std::uint32_t Index) noexcept(false) {
    if (Index >= GVirtualizedPrograms.size()) {
        throw std::runtime_error(PEVM_TEXT("VM bridge function index invalid"));
    }
    if (GVmBridgeTrace.Enabled) {
        const std::lock_guard Lock(GVmBridgeTrace.Mutex);
        if (!GVmBridgeTrace.Seen[Index]) {
            GVmBridgeTrace.Seen[Index] = 1;
            GVmBridgeTrace.Log << "VM2 bridge invoked index=" << Index << "\n";
            GVmBridgeTrace.Log.flush();
        }
    }
    const auto& Virtualized = GVirtualizedPrograms[static_cast<std::size_t>(Index)];
    auto& Context = *State;
    const auto NativeSp = Context.Registers[4];
    const auto* Tib = reinterpret_cast<const NT_TIB*>(NtCurrentTeb());
    const auto StackTop = reinterpret_cast<std::uint64_t>(Tib->StackBase);
    const auto StackBottom = reinterpret_cast<std::uint64_t>(Tib->StackLimit);
    if (NativeSp < StackBottom || NativeSp >= StackTop)
        throw std::runtime_error("VM entry stack is outside thread stack");
    if(Virtualized.ResumeAddress || !Virtualized.NeedsStack) {
        // The thunk pushed a synthetic return address. The fragment sees the
        // original native RSP and cannot modify it or touch stack memory.
        Context.Registers[4]=NativeSp+(Virtualized.ResumeAddress?8:0);
        vmprotect::RunConfig Config;
        Config.NativeMemory=true; Config.NativeContext=&Context; Config.ImageBase=GVmImageBase;
        vmprotect::InvokeCompiledProgram(Virtualized.Compiled,Context,false,Config);
        Context.Registers[4]=NativeSp;
        return;
    }
    // Locals and saved registers live on a separate VM stack, so interpreted
    // prologues cannot overwrite the active C++ interpreter's own frames.
    VmStackLease Stack;
    const auto Lower = reinterpret_cast<std::uint64_t>(Stack.Data);
    const auto VmSp = ((Lower + 64 * 1024) & ~15ULL) | (NativeSp & 15);
    const auto Incoming = (std::min)(std::uint64_t{4096}, StackTop - NativeSp);
    std::memcpy(reinterpret_cast<void*>(VmSp), reinterpret_cast<const void*>(NativeSp), static_cast<std::size_t>(Incoming));
    Context.Registers[4] = VmSp;
    vmprotect::RunConfig Config;
    Config.NativeMemory = true;
    Config.ImageBase = GVmImageBase;
    Config.NativeContext = &Context;
    Config.StackLower = Lower;
    Config.StackUpper = Lower + VmStackLease::Size;
    vmprotect::InvokeCompiledProgram(Virtualized.Compiled, Context, false, Config);
    Context.Registers[4] = NativeSp;
}

void LoadVmp3(std::span<const std::uint8_t> Data, std::string_view BuildSecret,
              std::span<const std::uint8_t> HandlerProfile) {
    auto Decoded = pevm::DecodeVmImage(Data, BuildSecret, HandlerProfile);
    std::vector<VmProgram> Programs;
    Programs.reserve(Decoded.size());
    for (auto& Function : Decoded) {
        VmProgram Virtualized{};
        const auto Digest = ProgramDigest(Function.Program);
        // Exercise the same ingestion-integrity gate before freezing the image.
        if (HideGetEnv(PEVM_WTEXT(L"PEVM_TEST_CORRUPT_VM").c_str()) != 0 && Programs.empty())
            Function.Program.Instructions.front().Immediate ^= 1ULL;
        if (ProgramDigest(Function.Program) != Digest) IntegrityFailure();
        Virtualized.EntryAddress = Function.Program.EntryAddress;
        Virtualized.ResumeAddress = Function.Program.ResumeAddress;
        Virtualized.NeedsStack=std::any_of(Function.Program.Instructions.begin(),Function.Program.Instructions.end(),[](const auto& I) {
            using O=vmprotect::LiftedOp;
            return I.Op==O::Push || I.Op==O::Pop || I.Op==O::Call || I.Op==O::NativeCall || I.Dst==4 || I.Src==4;
        });
        Virtualized.Compiled = vmprotect::CompileLiftedProgram(Function.Program, Function.Seed);
        Programs.push_back(std::move(Virtualized));
    }
    // Publish only after every function has passed decoding and compilation.
    GVmBridgeTrace.Seen.assign(Programs.size(), 0);
    GVirtualizedPrograms = std::move(Programs);
}

// At-rest encryption for the payload's executable sections. Every page
// faults in through the vectored handler on first execution and stays
// decrypted afterwards: the goal is that a dump of a running (or suspended)
// process does not yield a fully plaintext code image, not per-execution
// re-encryption.
class TextVault {
public:
    void Seal(std::uint8_t* ImageBase, const IMAGE_NT_HEADERS64* Nt, std::string_view Secret) {
        using namespace pevm::crypto;
        Sha256 Hash;
        static constexpr std::array<std::uint8_t, 13> Domain = {'P','E','V','M','-','T','E','X','T','-','v','1',0};
        Hash.Update(Domain);
        Hash.Update(std::span(reinterpret_cast<const std::uint8_t*>(Secret.data()), Secret.size()));
        const auto Material = Hash.Finish();
        for (std::size_t I = 0; I < 4; ++I) {
            Key_[I] = static_cast<std::uint32_t>(Material[I * 4]) |
                      (static_cast<std::uint32_t>(Material[I * 4 + 1]) << 8) |
                      (static_cast<std::uint32_t>(Material[I * 4 + 2]) << 16) |
                      (static_cast<std::uint32_t>(Material[I * 4 + 3]) << 24);
        }
        std::memcpy(&Nonce_, Material.data() + 16, sizeof(Nonce_));
        const auto Sections = IMAGE_FIRST_SECTION(Nt);
        for (unsigned I = 0; I < Nt->FileHeader.NumberOfSections; ++I) {
            const auto& Section = Sections[I];
            if ((Section.Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0 || Section.Misc.VirtualSize == 0) continue;
            const auto First = reinterpret_cast<std::uintptr_t>(ImageBase + Section.VirtualAddress) & ~0xFFFULL;
            const auto End = (reinterpret_cast<std::uintptr_t>(ImageBase + Section.VirtualAddress) +
                              Section.Misc.VirtualSize + 0xFFFULL) & ~0xFFFULL;
            const auto Pages = static_cast<std::size_t>((End - First) / 0x1000);
            if (Pages == 0) continue;
            // The section is still execute/read from ProtectSections; the
            // in-place encryption needs write access first.
            DWORD WritableProtection = 0;
            if (!HideProtect(reinterpret_cast<LPVOID>(First), End - First, PAGE_READWRITE, &WritableProtection)) {
                throw std::runtime_error(PEVM_TEXT("cannot unlock code pages"));
            }
            for (std::size_t P = 0; P < Pages; ++P) {
                auto* Page = reinterpret_cast<std::uint8_t*>(First + P * 0x1000);
                Bytes Buffer(Page, Page + 0x1000);
                XteaCtr(Buffer, Key_, PageNonce(P));
                std::memcpy(Page, Buffer.data(), Buffer.size());
            }
            FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<LPCVOID>(First), End - First);
            DWORD OldProtection = 0;
            if (!HideProtect(reinterpret_cast<LPVOID>(First), End - First, PAGE_NOACCESS, &OldProtection)) {
                throw std::runtime_error(PEVM_TEXT("cannot seal code pages"));
            }
            Ranges_.push_back({reinterpret_cast<std::uint8_t*>(First), Pages});
            States_.push_back(std::make_unique<std::atomic<char>[]>(Pages));
            TotalPages_ += Pages;
        }
        if (!Ranges_.empty()) {
            Vectored_ = HideVectoredAdd(1, Fault);
            if (Vectored_ == nullptr) throw std::runtime_error(PEVM_TEXT("cannot arm code page handler"));
            FlushInstructionCache(GetCurrentProcess(), nullptr, 0);
        }
    }

    ~TextVault() {
        if (Vectored_ != nullptr) HideVectoredRemove(Vectored_);
    }

    static TextVault Instance;

private:
    struct Range {
        std::uint8_t* Base;
        std::size_t Pages;
    };

    std::uint64_t PageNonce(std::size_t Index) const {
        return Nonce_ ^ ((static_cast<std::uint64_t>(Index) + 1ULL) * 0x9E3779B97F4A7C15ULL);
    }

    // Decrypts the page containing FaultAddress. Returns the page state after
    // the call: 2 = decrypted (fault can be continued), 0/1 = not ours or a
    // genuine fault inside an already decrypted page.
    char DecryptPage(std::uintptr_t FaultAddress) {
        for (std::size_t R = 0; R < Ranges_.size(); ++R) {
            const auto& Range = Ranges_[R];
            const auto Begin = reinterpret_cast<std::uintptr_t>(Range.Base);
            if (FaultAddress < Begin || FaultAddress >= Begin + Range.Pages * 0x1000ULL) continue;
            const auto Page = (FaultAddress - Begin) / 0x1000ULL;
            auto& State = States_[R][Page];
            char Expected = 0;
            if (State.compare_exchange_strong(Expected, 1)) {
                auto* PageBytes = Range.Base + Page * 0x1000ULL;
                // The page is NOACCESS while encrypted: unlock for read/write
                // before touching it, then converge to execute/read.
                DWORD OldProtection = 0;
                if (!HideProtect(PageBytes, 0x1000, PAGE_READWRITE, &OldProtection)) {
                    State.store(0, std::memory_order_release);
                    return 0;
                }
                Bytes Buffer(PageBytes, PageBytes + 0x1000);
                pevm::crypto::XteaCtr(Buffer, Key_, PageNonce(Page));
                std::memcpy(PageBytes, Buffer.data(), Buffer.size());
                FlushInstructionCache(GetCurrentProcess(), PageBytes, 0x1000);
                HideProtect(PageBytes, 0x1000, PAGE_EXECUTE_READ, &OldProtection);
                State.store(2, std::memory_order_release);
                return 2;
            }
            // Another thread is decrypting this page right now; wait for it.
            if (Expected == 1) {
                while (State.load(std::memory_order_acquire) == 1) Sleep(0);
                return State.load(std::memory_order_acquire) == 2 ? 2 : 0;
            }
            // Already decrypted: a fault inside an accessible page is genuine
            // and must reach the other handlers instead of replaying forever.
            return 0;
        }
        return 0;
    }

    static LONG CALLBACK Fault(PEXCEPTION_POINTERS Info) {
        if (Info->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION ||
            Info->ExceptionRecord->NumberParameters < 2) {
            return EXCEPTION_CONTINUE_SEARCH;
        }
        if (Instance.DecryptPage(Info->ExceptionRecord->ExceptionInformation[1]) == 2) {
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        return EXCEPTION_CONTINUE_SEARCH;
    }

    pevm::crypto::XteaKey Key_{};
    std::uint64_t Nonce_{};
    std::vector<Range> Ranges_;
    std::vector<std::unique_ptr<std::atomic<char>[]>> States_;
    std::size_t TotalPages_{};
    void* Vectored_{};
};

TextVault TextVault::Instance;


DWORD SectionProtection(DWORD Characteristics) {
    const bool Execute = (Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    const bool Read = (Characteristics & IMAGE_SCN_MEM_READ) != 0;
    const bool Write = (Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
    if (Execute) {
        if (Write) return PAGE_EXECUTE_READWRITE;
        return Read ? PAGE_EXECUTE_READ : PAGE_EXECUTE;
    }
    if (Write) return PAGE_READWRITE;
    return Read ? PAGE_READONLY : PAGE_NOACCESS;
}

struct PayloadTlsContext {
    std::uint8_t* Base{};
    IMAGE_TLS_DIRECTORY64 Directory{};
    DWORD Index{};

    void Notify(DWORD Reason, PVOID Reserved) const {
        if (Reason == DLL_PROCESS_ATTACH || Reason == DLL_THREAD_ATTACH) {
            auto** Slots = reinterpret_cast<std::uint8_t**>(__readgsqword(0x58));
            auto* Block = Slots[Index];
            const auto Size = static_cast<std::size_t>(Directory.EndAddressOfRawData - Directory.StartAddressOfRawData);
            if (Size) std::memcpy(Block, reinterpret_cast<const void*>(Directory.StartAddressOfRawData), Size);
            if (Directory.SizeOfZeroFill) std::memset(Block + Size, 0, Directory.SizeOfZeroFill);
        }
        if (!Directory.AddressOfCallBacks) return;
        auto* Callbacks = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(Directory.AddressOfCallBacks);
        for (; *Callbacks; ++Callbacks) (*Callbacks)(Base, Reason, Reserved);
    }
};

std::atomic<const PayloadTlsContext*> GPayloadTls{};
void NTAPI DispatchPayloadTls(PVOID, DWORD Reason, PVOID Reserved) {
    if (const auto* Context = GPayloadTls.load(std::memory_order_acquire)) Context->Notify(Reason, Reserved);
}

struct PayloadImageRange { std::uint8_t* Base{}; std::size_t Size{}; };
std::atomic<const PayloadImageRange*> GPayloadImageRange{};
PVOID NTAPI PayloadPcToFileHeader(PVOID Pc, PVOID* ImageBase) {
    if (const auto* Range = GPayloadImageRange.load(std::memory_order_acquire)) {
        const auto Address = reinterpret_cast<std::uintptr_t>(Pc);
        const auto Base = reinterpret_cast<std::uintptr_t>(Range->Base);
        if (Address >= Base && Address - Base < Range->Size) {
            *ImageBase = Range->Base;
            return Range->Base;
        }
    }
    using LookupFn = PVOID(NTAPI*)(PVOID, PVOID*);
    const auto Lookup = PEVM_API(LookupFn, KNtdllModule, "RtlPcToFileHeader");
    return Lookup ? Lookup(Pc, ImageBase) : nullptr;
}

class MappedImage {
public:
    explicit MappedImage(std::span<const std::uint8_t> File) {
        const pevm::pe::ImageView Parsed(File);
        Parsed.RequireX64();
        TlsLayout = pevm::pe::ReadTlsLayout(Parsed);
        if (Parsed.OptionalHeaderSize() < sizeof(IMAGE_OPTIONAL_HEADER64))
            throw std::runtime_error("payload requires a full PE32+ optional header");
        const auto Nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(File.data() + Parsed.NtOffset());
        FixupTargets = pevm::pe::RelocationTargets(Parsed);
        HasRelocationTable = Parsed.Directory(IMAGE_DIRECTORY_ENTRY_BASERELOC).Size != 0;
        PreferredBase = Nt->OptionalHeader.ImageBase;
        NtHeaders = Nt;
        Base = static_cast<std::uint8_t*>(HideAlloc(reinterpret_cast<LPVOID>(Nt->OptionalHeader.ImageBase),
                                                    Nt->OptionalHeader.SizeOfImage,
                                                    MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        if (!Base) {
            Base = static_cast<std::uint8_t*>(HideAlloc(nullptr, Nt->OptionalHeader.SizeOfImage,
                                                        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        }
        if (!Base) throw std::runtime_error(PEVM_TEXT("cannot allocate mapped image"));
        ImageMemory.reset(Base);
        if (Nt->OptionalHeader.SizeOfHeaders > File.size()) throw std::runtime_error(PEVM_TEXT("payload headers truncated"));
        std::memcpy(Base, File.data(), Nt->OptionalHeader.SizeOfHeaders);

        const auto Sections = IMAGE_FIRST_SECTION(Nt);
        for (unsigned I = 0; I < Nt->FileHeader.NumberOfSections; ++I) {
            const auto& Section = Sections[I];
            if (Section.VirtualAddress > Nt->OptionalHeader.SizeOfImage ||
                Section.Misc.VirtualSize > Nt->OptionalHeader.SizeOfImage - Section.VirtualAddress) {
                throw std::runtime_error(PEVM_TEXT("section virtual range invalid"));
            }
            if (Section.SizeOfRawData != 0) {
                if (Section.PointerToRawData > File.size() ||
                    Section.SizeOfRawData > File.size() - Section.PointerToRawData) {
                    throw std::runtime_error(PEVM_TEXT("section raw range invalid"));
                }
                const auto Source = File.data() + Section.PointerToRawData;
                auto* Destination = Base + Section.VirtualAddress;
                std::memcpy(Destination, Source, Section.SizeOfRawData);
                // Re-read and compare every copied section: catches mapping
                // corruption (or concurrent tampering) before protection is
                // applied and any of it executes.
                if (std::memcmp(Destination, Source, Section.SizeOfRawData) != 0) {
                    throw std::runtime_error(PEVM_TEXT("mapped section verification failed"));
                }
            }
        }
        NtHeaders = reinterpret_cast<const IMAGE_NT_HEADERS64*>(Base + Parsed.NtOffset());
        EntryPointRva = NtHeaders->OptionalHeader.AddressOfEntryPoint;
        if (std::memcmp(Base, File.data(), NtHeaders->OptionalHeader.SizeOfHeaders) != 0) {
            throw std::runtime_error(PEVM_TEXT("mapped header verification failed"));
        }
        ImageRange = {Base, NtHeaders->OptionalHeader.SizeOfImage};
    }

    ~MappedImage() {
        if (ThunkExceptionsRegistered) RtlDeleteFunctionTable(ThunkFunctions.data());
        for (const auto& Hook : ImageLookupHooks) {
            DWORD Old = 0;
            if (HideProtect(Hook.Slot, sizeof(*Hook.Slot), PAGE_READWRITE, &Old)) {
                *Hook.Slot = Hook.Original;
                DWORD Ignored = 0;
                HideProtect(Hook.Slot, sizeof(*Hook.Slot), Old, &Ignored);
            }
        }
        if (GPayloadImageRange.load(std::memory_order_acquire) == &ImageRange)
            GPayloadImageRange.store(nullptr, std::memory_order_release);
        if (GPayloadTls.load(std::memory_order_acquire) == &TlsContext) {
            GPayloadTls.store(nullptr, std::memory_order_release);
            DWORD Old = 0;
            if (HideProtect(WrapperCallbacks, SavedCallbacks.size() * sizeof(PIMAGE_TLS_CALLBACK), PAGE_READWRITE, &Old)) {
                std::copy(SavedCallbacks.begin(), SavedCallbacks.end(), WrapperCallbacks);
                DWORD Ignored = 0;
                HideProtect(WrapperCallbacks, SavedCallbacks.size() * sizeof(PIMAGE_TLS_CALLBACK), Old, &Ignored);
            }
            auto** Slots = reinterpret_cast<std::uint8_t**>(__readgsqword(0x58));
            std::copy(SavedWrapperTls.begin(), SavedWrapperTls.end(), Slots[TlsContext.Index]);
        }
        if (FunctionTable) RtlDeleteFunctionTable(FunctionTable);
        // Member owners release the thunk and image after unwind deregistration.
    }

    void Prepare() {
        ApplyRelocations();
        ResolveImports();
        RegisterExceptions();
        BindTls();
        ProtectSections();
        FlushInstructionCache(GetCurrentProcess(), Base, NtHeaders->OptionalHeader.SizeOfImage);
        if (TlsLayout) TlsContext.Notify(DLL_PROCESS_ATTACH, nullptr);
    }

    // A relative entry jump preserves every input register. Each nearby
    // thunk supplies an index and calls the common ABI-aware assembly entry.
    void InstallVmBridge(std::uint32_t FunctionRva, std::uint64_t Index, std::uint32_t ResumeRva=0) {
        if (FunctionRva >= NtHeaders->OptionalHeader.SizeOfImage ||
            NtHeaders->OptionalHeader.SizeOfImage - FunctionRva < 5 || Index > UINT32_MAX)
            throw std::runtime_error(PEVM_TEXT("VM bridge RVA/index invalid"));
        auto* Target = Base + FunctionRva;
        if (!ThunkBase) {
            const auto Center = reinterpret_cast<std::uintptr_t>(Base) & ~0xffffULL;
            // Windows allocations use 64 KiB granularity. Keep the complete
            // thunk arena within rel32 reach of every payload code address.
            for (std::uintptr_t Delta = 0x10000; Delta < 0x60000000 && !ThunkBase; Delta += 0x10000) {
                for (const bool Above : {true, false}) {
                    if (!Above && Delta >= Center) continue;
                    const auto Address = Above ? Center + Delta : Center - Delta;
                    ThunkBase = static_cast<std::uint8_t*>(HideAlloc(reinterpret_cast<void*>(Address), ThunkPageBytes,
                        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
                    if (ThunkBase) break;
                }
            }
            if (!ThunkBase) throw std::runtime_error(PEVM_TEXT("cannot allocate nearby VM bridge arena"));
            ThunkMemory.reset(ThunkBase);
        }
        constexpr std::size_t Slot = 64;
        if (ThunkUsed + Slot > ThunkPageBytes) throw std::runtime_error(PEVM_TEXT("VM bridge arena exhausted"));
        auto* Thunk = ThunkBase + ThunkUsed;
        const auto Displacement = reinterpret_cast<std::intptr_t>(Thunk) - reinterpret_cast<std::intptr_t>(Target + 5);
        if (Displacement < INT32_MIN || Displacement > INT32_MAX)
            throw std::runtime_error(PEVM_TEXT("VM bridge is outside relative jump range"));
        std::array<std::uint8_t, 25> Code = {
            0x68,0,0,0,0,                 // push index
            0xff,0x15,6,0,0,0,            // call qword [rip+6]
            0x48,0x8d,0x64,0x24,8,0xc3,  // lea rsp,[rsp+8]; ret
            0,0,0,0,0,0,0,0
        };
        const auto Entry = reinterpret_cast<std::uint64_t>(&PeVmNativeEntry);
        const auto EntryIndex = static_cast<std::uint32_t>(Index);
        std::memcpy(Code.data() + 1, &EntryIndex, 4);
        std::memcpy(Code.data() + 17, &Entry, 8);
        const auto Prefix=ResumeRva?6U:0U;
        if(ResumeRva) {
            if(ResumeRva>=NtHeaders->OptionalHeader.SizeOfImage || ResumeRva<FunctionRva+5)
                throw std::runtime_error("VM fragment resume RVA invalid");
            // push [rip+34] installs the native continuation without changing
            // any GPR or flags. The common thunk returns directly to it.
            constexpr std::uint8_t PushResume[]{0xff,0x35,34,0,0,0};
            std::memcpy(Thunk,PushResume,6);
            const auto Resume=reinterpret_cast<std::uint64_t>(Base+ResumeRva);
            std::memcpy(Thunk+40,&Resume,8);
            // Drop the synthetic frame and JMP to the continuation. RET
            // would consume an unmatched return on CET shadow-stack systems.
            const std::uint8_t FragmentCode[]{0x68,0,0,0,0,0xff,0x15,15,0,0,0,
                0x48,0x8d,0x64,0x24,16,0xff,0x25,12,0,0,0};
            std::memcpy(Thunk+6,FragmentCode,sizeof(FragmentCode));
            std::memcpy(Thunk+7,&EntryIndex,4);
            std::memcpy(Thunk+32,&Entry,8);
        } else {
            std::memcpy(Thunk,Code.data(),Code.size());
        }
        constexpr std::array<std::uint8_t,8> Unwind{1,5,1,0,5,2,0,0}; // allocate 8 bytes for index
        std::memcpy(Thunk + 48, Unwind.data(), Unwind.size());
        ThunkFunctions.push_back({static_cast<DWORD>(ThunkUsed+Prefix),static_cast<DWORD>(ThunkUsed+(ResumeRva?28:17)),
                                  static_cast<DWORD>(ThunkUsed+48)});
        DWORD Old;
        if (!HideProtect(Target,5,PAGE_EXECUTE_READWRITE,&Old)) throw std::runtime_error(PEVM_TEXT("cannot patch VM entry"));
        std::array<std::uint8_t,5> Patch{0xe9};
        const auto Relative = static_cast<std::int32_t>(Displacement);
        std::memcpy(Patch.data()+1,&Relative,4);
        std::memcpy(Target,Patch.data(),Patch.size());
        if (std::memcmp(Target,Patch.data(),Patch.size())) throw std::runtime_error(PEVM_TEXT("VM bridge patch verification failed"));
        DWORD Ignored;
        HideProtect(Target,5,Old,&Ignored);
        FlushInstructionCache(GetCurrentProcess(),Target,5);
        ThunkUsed += Slot;
    }

    // Drops the thunk page to execute/read after every bridge is installed.
    // VirtualProtect granularity is one page, so per-thunk protection would
    // freeze the whole page and break later thunk writes in the same page.
    void SealBridges() {
        if (!ThunkBase || ThunkUsed == 0) return;
        if (!RtlAddFunctionTable(ThunkFunctions.data(), static_cast<DWORD>(ThunkFunctions.size()),
                                 reinterpret_cast<DWORD64>(ThunkBase)))
            throw std::runtime_error(PEVM_TEXT("cannot register VM bridge unwind table"));
        ThunkExceptionsRegistered = true;
        DWORD Ignored = 0;
        HideProtect(ThunkBase, ThunkUsed, PAGE_EXECUTE_READ, &Ignored);
        FlushInstructionCache(GetCurrentProcess(), ThunkBase, ThunkUsed);
    }

    [[noreturn]] void RunEntryPoint() {
        const auto Entry = reinterpret_cast<DWORD(*)()>(Base + EntryPointRva);
        ExitProcess(Entry());
    }

    // Access for the code-page vault (sealing runs outside the class).
    std::uint8_t* ImageBase() const { return Base; }
    const IMAGE_NT_HEADERS64* NtHeadersView() const { return NtHeaders; }

private:
    // Declared first, released last; raw pointers below only borrow these owners.
    pevm::platform::VirtualAllocation ImageMemory;
    pevm::platform::VirtualAllocation ThunkMemory;
    std::vector<std::uint32_t> FixupTargets;
    std::uint64_t PreferredBase{};
    bool HasRelocationTable{};
    std::uint8_t* Base{};
    const IMAGE_NT_HEADERS64* NtHeaders{};
    std::uint32_t EntryPointRva{};
    PRUNTIME_FUNCTION FunctionTable{};
    std::uint8_t* ThunkBase{};
    std::size_t ThunkUsed{};
    std::vector<RUNTIME_FUNCTION> ThunkFunctions;
    bool ThunkExceptionsRegistered{};
    static constexpr std::size_t ThunkPageBytes = 1024 * 1024;
    std::optional<pevm::pe::TlsLayout> TlsLayout;
    PayloadTlsContext TlsContext;
    PIMAGE_TLS_CALLBACK* WrapperCallbacks{};
    std::vector<PIMAGE_TLS_CALLBACK> SavedCallbacks;
    Bytes SavedWrapperTls;
    PayloadImageRange ImageRange;
    struct ImageLookupHook { ULONGLONG* Slot; ULONGLONG Original; };
    std::vector<ImageLookupHook> ImageLookupHooks;

    IMAGE_DATA_DIRECTORY Directory(std::size_t Index) const {
        if (Index >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES || Index >= NtHeaders->OptionalHeader.NumberOfRvaAndSizes) return {};
        return NtHeaders->OptionalHeader.DataDirectory[Index];
    }

    void ApplyRelocations() {
        // Unsigned subtraction intentionally computes the modulo-2^64 delta.
        const auto Delta = reinterpret_cast<std::uint64_t>(Base) - PreferredBase;
        if (Delta == 0) return;
        if (!HasRelocationTable) throw std::runtime_error(PEVM_TEXT("payload cannot be relocated"));
        for (const auto Rva : FixupTargets) {
            std::uint64_t Value;
            std::memcpy(&Value, Base + Rva, sizeof(Value));
            Value += Delta;
            std::memcpy(Base + Rva, &Value, sizeof(Value));
        }
    }

    void ResolveImports() {
        GPayloadImageRange.store(&ImageRange, std::memory_order_release);
        const auto& Data = Directory(IMAGE_DIRECTORY_ENTRY_IMPORT);
        if (Data.VirtualAddress == 0) return;
        // Even payload dependency resolution avoids GetProcAddress as the
        // primary path: module loading goes through a hidden LoadLibraryA
        // and imports are looked up directly in the loaded module's export
        // table. The hidden real GetProcAddress is kept as a last-resort
        // fallback for anything the hand-rolled walker misses (API-set
        // quirks, export suffixes, exotic forwarders).
        using LoadLibraryAFn = HMODULE(WINAPI*)(const char*);
        const auto Load = PEVM_API(LoadLibraryAFn, KKernel32Module, "LoadLibraryA");
        const auto GetProc = HiddenApisRef().GetProc;
        if (Load == nullptr) throw std::runtime_error(PEVM_TEXT("cannot load import machinery"));
        auto Descriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(Base + Data.VirtualAddress);
        for (; Descriptor->Name != 0; ++Descriptor) {
            const auto* DllName = reinterpret_cast<const char*>(Base + Descriptor->Name);
            const auto ModuleBase = reinterpret_cast<const std::uint8_t*>(Load(DllName));
            if (ModuleBase == nullptr) {
                throw std::runtime_error(std::string(PEVM_TEXT("cannot load imported DLL: ")) + DllName);
            }
            // MSVC's throw runtime obtains the ThrowInfo image base through
            // RtlPcToFileHeader. Private mappings are absent from the OS module
            // list, even with a registered unwind table; teach only the CRT's
            // imported lookup about this range and delegate all other PCs.
            std::string ModuleName(DllName);
            std::transform(ModuleName.begin(), ModuleName.end(), ModuleName.begin(),
                           [](unsigned char C) { return static_cast<char>(std::tolower(C)); });
            if (ModuleName.starts_with("vcruntime")) BindCrtImageLookup(ModuleBase);
            auto Lookup = reinterpret_cast<IMAGE_THUNK_DATA64*>(Base +
                (Descriptor->OriginalFirstThunk ? Descriptor->OriginalFirstThunk : Descriptor->FirstThunk));
            auto Address = reinterpret_cast<IMAGE_THUNK_DATA64*>(Base + Descriptor->FirstThunk);
            for (; Lookup->u1.AddressOfData != 0; ++Lookup, ++Address) {
                void* Function = nullptr;
                const char* FuncName = nullptr;
                std::uint16_t FuncOrdinal = 0;
                const bool ByOrdinal = IMAGE_SNAP_BY_ORDINAL64(Lookup->u1.Ordinal);
                if (ByOrdinal) {
                    FuncOrdinal = static_cast<std::uint16_t>(IMAGE_ORDINAL64(Lookup->u1.Ordinal));
                    Function = ExportByOrdinal(ModuleBase, FuncOrdinal, 4);
                } else {
                    const auto Import = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(Base + Lookup->u1.AddressOfData);
                    FuncName = Import->Name;
                    Function = ExportByName(ModuleBase, FuncName);
                    if (std::strcmp(FuncName, "RtlPcToFileHeader") == 0) Function = PayloadPcToFileHeader;
                }
                // Last-resort fallback: the real GetProcAddress handles every
                // edge case the walker may miss.
                if (Function == nullptr && GetProc != nullptr) {
                    Function = reinterpret_cast<void*>(ByOrdinal
                        ? GetProc(reinterpret_cast<HMODULE>(const_cast<std::uint8_t*>(ModuleBase)),
                                  reinterpret_cast<const char*>(static_cast<std::uintptr_t>(FuncOrdinal)))
                        : GetProc(reinterpret_cast<HMODULE>(const_cast<std::uint8_t*>(ModuleBase)), FuncName));
                }
                if (Function == nullptr) {
                    throw std::runtime_error(std::string(PEVM_TEXT("cannot resolve imported function: ")) +
                                             DllName + "!" + (ByOrdinal ? "#" + std::to_string(FuncOrdinal) : FuncName));
                }
                Address->u1.Function = reinterpret_cast<ULONGLONG>(Function);
            }
        }
    }

    void BindCrtImageLookup(const std::uint8_t* Module) {
        const auto* Nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(Module +
            reinterpret_cast<const IMAGE_DOS_HEADER*>(Module)->e_lfanew);
        const auto Data = Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (!Data.VirtualAddress) return;
        const auto* Descriptor = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(Module + Data.VirtualAddress);
        for (; Descriptor->Name; ++Descriptor) {
            if (!Descriptor->OriginalFirstThunk) continue;
            const auto* Lookup = reinterpret_cast<const IMAGE_THUNK_DATA64*>(Module + Descriptor->OriginalFirstThunk);
            auto* Address = reinterpret_cast<IMAGE_THUNK_DATA64*>(const_cast<std::uint8_t*>(Module) + Descriptor->FirstThunk);
            for (; Lookup->u1.AddressOfData; ++Lookup, ++Address) {
                if (IMAGE_SNAP_BY_ORDINAL64(Lookup->u1.Ordinal)) continue;
                const auto* Import = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(Module + Lookup->u1.AddressOfData);
                if (std::strcmp(Import->Name, "RtlPcToFileHeader") != 0) continue;
                if (Address->u1.Function == reinterpret_cast<ULONGLONG>(PayloadPcToFileHeader)) continue;
                ImageLookupHooks.push_back({&Address->u1.Function, Address->u1.Function});
                DWORD Old = 0;
                if (!HideProtect(&Address->u1.Function, sizeof(Address->u1.Function), PAGE_READWRITE, &Old))
                    throw std::runtime_error(PEVM_TEXT("cannot bind CRT image lookup"));
                Address->u1.Function = reinterpret_cast<ULONGLONG>(PayloadPcToFileHeader);
                DWORD Ignored = 0;
                HideProtect(&Address->u1.Function, sizeof(Address->u1.Function), Old, &Ignored);
            }
        }
    }

    void RegisterExceptions() {
        const auto& Data = Directory(IMAGE_DIRECTORY_ENTRY_EXCEPTION);
        if (Data.VirtualAddress == 0 || Data.Size == 0) return;
        FunctionTable = reinterpret_cast<PRUNTIME_FUNCTION>(Base + Data.VirtualAddress);
        const auto Count = Data.Size / sizeof(RUNTIME_FUNCTION);
        if (Count > std::numeric_limits<DWORD>::max()) throw std::runtime_error(PEVM_TEXT("x64 unwind table too large"));
        if (!RtlAddFunctionTable(FunctionTable, static_cast<DWORD>(Count), reinterpret_cast<DWORD64>(Base))) {
            FunctionTable = nullptr;
            throw std::runtime_error(PEVM_TEXT("cannot register x64 unwind table"));
        }
    }

    void ProtectSections() {
        DWORD OldProtection = 0;
        HideProtect(Base, NtHeaders->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &OldProtection);
        const auto Sections = IMAGE_FIRST_SECTION(NtHeaders);
        for (unsigned I = 0; I < NtHeaders->FileHeader.NumberOfSections; ++I) {
            const auto& Section = Sections[I];
            const auto Size = std::max<std::size_t>(Section.Misc.VirtualSize, Section.SizeOfRawData);
            if (Size == 0) continue;
            if (!HideProtect(Base + Section.VirtualAddress, Size,
                                SectionProtection(Section.Characteristics), &OldProtection)) {
                throw std::runtime_error(PEVM_TEXT("cannot apply section protection"));
            }
        }
    }

    void BindTls() {
        if (!TlsLayout) return;
        const auto Wrapper = reinterpret_cast<const std::uint8_t*>(GetModuleHandleW(nullptr));
        const auto WrapperNt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(Wrapper +
            reinterpret_cast<const IMAGE_DOS_HEADER*>(Wrapper)->e_lfanew);
        const auto Data = WrapperNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
        if (!Data.VirtualAddress || Data.Size < sizeof(IMAGE_TLS_DIRECTORY64))
            throw std::runtime_error(PEVM_TEXT("wrapper static TLS carrier missing; rebuild protected program"));
        const auto* Tls = reinterpret_cast<const IMAGE_TLS_DIRECTORY64*>(Wrapper + Data.VirtualAddress);
        const auto RawSize = static_cast<std::size_t>(Tls->EndAddressOfRawData - Tls->StartAddressOfRawData);
        if (RawSize + Tls->SizeOfZeroFill < TlsLayout->TotalBytes || !Tls->AddressOfCallBacks)
            throw std::runtime_error(PEVM_TEXT("wrapper static TLS carrier too small; rebuild protected program"));
        TlsContext.Base = Base;
        TlsContext.Directory = *reinterpret_cast<const IMAGE_TLS_DIRECTORY64*>(Base + Directory(IMAGE_DIRECTORY_ENTRY_TLS).VirtualAddress);
        TlsContext.Index = *reinterpret_cast<const DWORD*>(Tls->AddressOfIndex);
        *reinterpret_cast<DWORD*>(Base + TlsLayout->IndexRva) = TlsContext.Index;
        auto** Slots = reinterpret_cast<std::uint8_t**>(__readgsqword(0x58));
        SavedWrapperTls.assign(Slots[TlsContext.Index], Slots[TlsContext.Index] + RawSize);
        WrapperCallbacks = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(Tls->AddressOfCallBacks);
        for (auto* Callback = WrapperCallbacks; *Callback; ++Callback) SavedCallbacks.push_back(*Callback);
        SavedCallbacks.push_back(nullptr);
        // The wrapper's CRT TLS guard shares this slot. Its callbacks must not
        // run before the payload's constructors or after its destructors.
        DWORD Old = 0;
        if (!HideProtect(WrapperCallbacks, 2 * sizeof(PIMAGE_TLS_CALLBACK), PAGE_READWRITE, &Old))
            throw std::runtime_error(PEVM_TEXT("cannot install TLS notifications"));
        WrapperCallbacks[0] = DispatchPayloadTls;
        WrapperCallbacks[1] = nullptr;
        DWORD Ignored = 0;
        HideProtect(WrapperCallbacks, 2 * sizeof(PIMAGE_TLS_CALLBACK), Old, &Ignored);
        GPayloadTls.store(&TlsContext, std::memory_order_release);
    }
};

[[noreturn]] void RunWrapped() {
    RunAntiDebugChecks();
    const auto WrapperPath = SelfPath();
    const auto Image = ReadFile(WrapperPath);
    if (Image.size() < sizeof(WrapperFooter)) throw std::runtime_error(PEVM_TEXT("wrapper footer missing"));
    WrapperFooter Footer{};
    std::memcpy(&Footer, Image.data() + Image.size() - sizeof(Footer), sizeof(Footer));
    if (Footer.Magic != KWrapperMagic || Footer.Version != 2) throw std::runtime_error(PEVM_TEXT("unsupported wrapper version"));
    const auto TrailerSize = static_cast<std::uint64_t>(sizeof(Footer)) + Footer.SecretSize;
    if (TrailerSize > Image.size()) throw std::runtime_error(PEVM_TEXT("invalid wrapper sizes"));
    const auto PayloadOffset = static_cast<std::size_t>(Footer.PayloadOffset);
    const auto SecretOffset = Image.size() - sizeof(Footer) - Footer.SecretSize;
    if (Footer.PayloadOffset > Image.size() || Footer.PayloadSize > Image.size() - PayloadOffset ||
        Footer.StubSize != SecretOffset) throw std::runtime_error(PEVM_TEXT("invalid wrapper payload location"));
    const auto Metadata = ValidateProtectionMetadata(Image, Footer);
    if (Metadata.License.Required != 0) pevm::activation::EnsureLicense(Metadata.License, WrapperPath,
        HideGetEnv(PEVM_WTEXT(L"PEVM_TEST_NO_DIALOG").c_str()) == 0);
    auto Password = RecoverBuildSecret(Image, Footer, PayloadOffset, SecretOffset);

    const auto WrapperDirectory = WrapperPath.parent_path();
    SetDllDirectoryW(WrapperDirectory.c_str());
    SetCurrentDirectoryW(WrapperDirectory.c_str());
    const Stopwatch UnpackClock;
    auto Plain = UnpackContainer(std::span(Image).subspan(PayloadOffset,
                                                          static_cast<std::size_t>(Footer.PayloadSize)),
                                 Password);
    MappedImage Payload(Plain);
    if (UnpackClock.Milliseconds() > KUnpackBudgetMs) IntegrityFailure();
    // Re-run the cheap debugger checks now that the payload exists: a
    // debugger that attached (or a race) during unpacking is still caught.
    RunAntiDebugChecks(true);
    // Light watchdog thread for the rest of the process lifetime: catches
    // debuggers that attach after startup. Hits exit fast (a foreign thread
    // cannot unwind into the loader's handler).
    StartWatchdog();
    SecureZeroMemory(Plain.data(), Plain.size());
    Plain.clear();
    Plain.shrink_to_fit();
    GVmStackSlot = FlsAlloc(ReleaseVmStacks);
    if (GVmStackSlot == FLS_OUT_OF_INDEXES) throw std::runtime_error("VM stack slot allocation failed");
    GVmBridgeTrace.Enabled = Metadata.VmDataRawSize != 0 &&
        HideGetEnv(PEVM_WTEXT(L"PEVM_TEST_VM_BRIDGE_LOG").c_str()) != 0;
    if (GVmBridgeTrace.Enabled) {
        GVmBridgeTrace.Log.open(WrapperPath.wstring() + L".vmbridge-hit",
                               std::ios::binary | std::ios::trunc);
    }
    Payload.Prepare();
    GVmImageBase = reinterpret_cast<std::uint64_t>(Payload.ImageBase());
    if (Metadata.VmDataRawSize != 0) {
        LoadVmp3(std::span(Image).subspan(Metadata.VmDataRawOffset, Metadata.VmDataRawSize),
                 Password, Metadata.HandlerProfile);
        for (std::size_t I = 0; I < GVirtualizedPrograms.size(); ++I) {
            Payload.InstallVmBridge(GVirtualizedPrograms[I].EntryAddress, I, GVirtualizedPrograms[I].ResumeAddress);
        }
        Payload.SealBridges();
    }
    // CRT TLS guards, resources and exception handlers continue to inspect
    // the mapped PE headers after startup, so keep them read-only.
    TextVault::Instance.Seal(Payload.ImageBase(), Payload.NtHeadersView(), Password);
    // Everything below this point runs without the wrapper image or the
    // metadata (they hold the region tags and handler profile).
    SecureZeroMemory(const_cast<std::uint8_t*>(Image.data()), Image.size());
    SecureZeroMemory(const_cast<VmpMetadata*>(&Metadata), sizeof(Metadata));
    SecureZeroMemory(Password.data(), Password.size());
    Password.clear();
    // Test-only residency hook: lets a debugger attach and inspect the
    // at-rest (sealed) state of the mapped payload before the entry runs.
    if (HideGetEnv(PEVM_WTEXT(L"PEVM_TEST_HOLD").c_str()) != 0) Sleep(20000);
    Payload.RunEntryPoint();
}

} // namespace

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    try { RunWrapped(); }
    catch (const pevm::activation::Cancelled&) { return ERROR_CANCELLED; }
    catch (const std::exception& Error) {
        if (HideGetEnv(PEVM_WTEXT(L"PEVM_TEST_ERROR_LOG").c_str()) != 0) {
            const auto Path = SelfPath().wstring() + L".loader-error.txt";
            std::ofstream Log(Path, std::ios::binary | std::ios::trunc);
            Log << Error.what();
        }
        if (HideGetEnv(PEVM_WTEXT(L"PEVM_TEST_NO_DIALOG").c_str()) == 0) {
            MessageBoxA(nullptr, Error.what(), PEVM_TEXT("PeVmProtector loader error").c_str(), MB_ICONERROR);
        }
        return 1;
    }
}
