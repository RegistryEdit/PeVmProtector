#include <windows.h>

#include <array>
#include <algorithm>
#include <cstddef>
#include <cstdint>
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
#include <vector>

#include "PeVmContainer.h"
#include "PeVmCrypto.h"
#include "PeVmLicense.h"
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
    if (Metadata.Magic != KVmpMetadataMagic || Metadata.Version != 4) {
        throw std::runtime_error(PEVM_TEXT(".vmp2 metadata invalid"));
    }
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
    vmprotect::LiftedProgram Program;
    std::uint64_t Seed{};
    std::uint64_t Digest{};
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
    }
    return Hash;
}

std::vector<VmProgram> GVirtualizedPrograms;

extern "C" std::uint64_t VirtualizedFunctionBridge(std::uint64_t Rcx, std::uint64_t Rdx,
                                                    std::uint64_t R8, std::uint64_t R9,
                                                    std::uint32_t Index) noexcept(false) {
    if (HideGetEnv(PEVM_WTEXT(L"PEVM_TEST_VM_BRIDGE_LOG").c_str()) != 0) {
        static std::ofstream Log(SelfPath().wstring() + L".vmbridge-hit",
                                 std::ios::binary | std::ios::trunc);
        Log << "VM2 bridge invoked index=" << Index << "\n";
        Log.flush();
    }
    if (Index >= GVirtualizedPrograms.size()) {
        throw std::runtime_error(PEVM_TEXT("VM bridge function index invalid"));
    }
    const auto& Virtualized = GVirtualizedPrograms[static_cast<std::size_t>(Index)];
    if (ProgramDigest(Virtualized.Program) != Virtualized.Digest) {
        IntegrityFailure();
    }
    vmprotect::VmBridgeContext Context{};
    Context.Registers[1] = Rcx;
    Context.Registers[2] = Rdx;
    Context.Registers[8] = R8;
    Context.Registers[9] = R9;
    vmprotect::InvokeLiftedProgram(Virtualized.Program, Context, Virtualized.Seed, false);
    return Context.Registers[0];
}

void LoadVmp3(std::span<const std::uint8_t> Data, std::string_view BuildSecret,
              std::span<const std::uint8_t> HandlerProfile) {
    using namespace pevm::crypto;
    if (Data.size() < sizeof(Vmp3Header)) throw std::runtime_error(PEVM_TEXT(".vmp3 header truncated"));
    Vmp3Header Header{}; std::memcpy(&Header, Data.data(), sizeof(Header));
    if (Header.Magic != KVmp3Magic || Header.Version != 3) {
        throw std::runtime_error(PEVM_TEXT(".vmp3 header invalid (unsupported version)"));
    }
    if (Header.FunctionCount == 0 ||
        Header.FunctionCount > (Data.size() - sizeof(Vmp3Header)) / sizeof(Vmp3Entry)) {
        throw std::runtime_error(PEVM_TEXT(".vmp3 entry table invalid"));
    }
    const auto EntriesBytes = static_cast<std::size_t>(Header.FunctionCount) * sizeof(Vmp3Entry);
    const auto Entries = reinterpret_cast<const Vmp3Entry*>(Data.data() + sizeof(Vmp3Header));
    std::size_t TotalInstructions = 0;
    for (std::size_t I = 0; I < Header.FunctionCount; ++I) {
        TotalInstructions = std::max<std::size_t>(
            TotalInstructions, static_cast<std::size_t>(Entries[I].InstructionOffset) +
                                   Entries[I].InstructionCount);
    }
    const auto TableSize = TotalInstructions * sizeof(Vmp3Instruction);
    if (sizeof(Vmp3Header) + EntriesBytes + TableSize + 16 > Data.size()) {
        throw std::runtime_error(PEVM_TEXT(".vmp3 instruction table invalid"));
    }
    Bytes Table(TableSize);
    std::memcpy(Table.data(), Data.data() + sizeof(Vmp3Header) + EntriesBytes,
                static_cast<std::size_t>(TableSize));

    Sha256 KeyHash;
    static constexpr std::array<std::uint8_t, 13> KeyDomain = {'P','E','V','M','-','V','M','P','3','-','v','3',0};
    KeyHash.Update(KeyDomain);
    KeyHash.Update(std::span(reinterpret_cast<const std::uint8_t*>(BuildSecret.data()), BuildSecret.size()));
    KeyHash.Update(std::span(reinterpret_cast<const std::uint8_t*>(&Header.Seed), sizeof(Header.Seed)));
    KeyHash.Update(HandlerProfile);
    const auto KeyMaterial = KeyHash.Finish();
    XteaKey Key{};
    for (std::size_t I = 0; I < 4; ++I) {
        Key[I] = static_cast<std::uint32_t>(KeyMaterial[I * 4]) |
                 (static_cast<std::uint32_t>(KeyMaterial[I * 4 + 1]) << 8) |
                 (static_cast<std::uint32_t>(KeyMaterial[I * 4 + 2]) << 16) |
                 (static_cast<std::uint32_t>(KeyMaterial[I * 4 + 3]) << 24);
    }
    XteaCtr(Table, Key, Header.Seed);

    Sha256 TagHash;
    static constexpr std::array<std::uint8_t, 13> TagDomain = {'P','E','V','M','-','V','M','P','3','-','T','A','G'};
    TagHash.Update(TagDomain);
    TagHash.Update(std::span(KeyMaterial).subspan(16, 16));
    TagHash.Update(Table);
    const auto TagFull = TagHash.Finish();
    if (!ConstantEqual(std::span(TagFull).first(16),
                       Data.subspan(sizeof(Header) + EntriesBytes + static_cast<std::size_t>(TableSize), 16))) {
        throw std::runtime_error(PEVM_TEXT(".vmp3 integrity violation"));
    }

    GVirtualizedPrograms.clear();
    GVirtualizedPrograms.reserve(Header.FunctionCount);
    const auto* Instructions = reinterpret_cast<const Vmp3Instruction*>(Table.data());
    for (std::size_t F = 0; F < Header.FunctionCount; ++F) {
        const auto& Entry = Entries[F];
        if (static_cast<std::size_t>(Entry.InstructionOffset) + Entry.InstructionCount > TotalInstructions) {
            throw std::runtime_error(PEVM_TEXT(".vmp3 entry range invalid"));
        }
        VmProgram Virtualized{};
        Virtualized.Program.EntryAddress = Entry.FunctionRva;
        Virtualized.Seed = Header.Seed;
        Virtualized.Program.Instructions.reserve(Entry.InstructionCount);
        for (std::uint32_t I = 0; I < Entry.InstructionCount; ++I) {
            const auto& Record = Instructions[Entry.InstructionOffset + I];
            if (Record.Op >= static_cast<std::uint8_t>(vmprotect::LiftedOp::Count)) {
                throw std::runtime_error(PEVM_TEXT(".vmp3 opcode invalid"));
            }
            Virtualized.Program.Instructions.push_back({static_cast<vmprotect::LiftedOp>(Record.Op),
                Record.Dst, Record.Src, Record.Immediate, Record.Address, Record.Target});
        }
        Virtualized.Digest = ProgramDigest(Virtualized.Program);
        GVirtualizedPrograms.push_back(std::move(Virtualized));
    }
    // Test-only hook: corrupts the first loaded program AFTER its digest is
    // computed, so the bridge's per-call verification must reject the run.
    if (HideGetEnv(PEVM_WTEXT(L"PEVM_TEST_CORRUPT_VM").c_str()) != 0 && !GVirtualizedPrograms.empty()) {
        auto& First = GVirtualizedPrograms.front().Program;
        if (!First.Instructions.empty()) First.Instructions.front().Immediate ^= 1ULL;
    }
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

class MappedImage {
public:
    explicit MappedImage(std::span<const std::uint8_t> File) {
        if (File.size() < sizeof(IMAGE_DOS_HEADER)) throw std::runtime_error(PEVM_TEXT("payload DOS header missing"));
        const auto Dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(File.data());
        if (Dos->e_magic != IMAGE_DOS_SIGNATURE || Dos->e_lfanew < 0) throw std::runtime_error(PEVM_TEXT("payload DOS header invalid"));
        if (static_cast<std::size_t>(Dos->e_lfanew) > File.size() - sizeof(IMAGE_NT_HEADERS64)) {
            throw std::runtime_error(PEVM_TEXT("payload NT header truncated"));
        }
        const auto Nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(File.data() + Dos->e_lfanew);
        if (Nt->Signature != IMAGE_NT_SIGNATURE || Nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
            Nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
            throw std::runtime_error(PEVM_TEXT("only x64 PE32+ payloads are supported"));
        }
        NtHeaders = Nt;
        Base = static_cast<std::uint8_t*>(HideAlloc(reinterpret_cast<LPVOID>(Nt->OptionalHeader.ImageBase),
                                                    Nt->OptionalHeader.SizeOfImage,
                                                    MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        if (!Base) {
            Base = static_cast<std::uint8_t*>(HideAlloc(nullptr, Nt->OptionalHeader.SizeOfImage,
                                                        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        }
        if (!Base) throw std::runtime_error(PEVM_TEXT("cannot allocate mapped image"));
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
        NtHeaders = reinterpret_cast<const IMAGE_NT_HEADERS64*>(Base + Dos->e_lfanew);
        EntryPointRva = NtHeaders->OptionalHeader.AddressOfEntryPoint;
        if (std::memcmp(Base, File.data(), NtHeaders->OptionalHeader.SizeOfHeaders) != 0) {
            throw std::runtime_error(PEVM_TEXT("mapped header verification failed"));
        }
    }

    ~MappedImage() {
        if (FunctionTable) RtlDeleteFunctionTable(FunctionTable);
        if (ThunkBase) VirtualFree(ThunkBase, 0, MEM_RELEASE);
        if (Base) VirtualFree(Base, 0, MEM_RELEASE);
    }

    void Prepare() {
        ApplyRelocations();
        ResolveImports();
        RegisterExceptions();
        ProtectSections();
        RunTlsCallbacks();
        FlushInstructionCache(GetCurrentProcess(), Base, NtHeaders->OptionalHeader.SizeOfImage);
    }

    // Installs one bridge trampoline per virtualized function. The original
    // entry is patched with the same 12-byte `mov rax, imm64; jmp rax` hop
    // into a freshly generated thunk; the thunk pushes the function index as
    // the fifth argument (mov dword [rsp+0x20]) and calls the shared bridge,
    // so one C++ bridge dispatches every virtualized function by index.
    void InstallVmBridge(std::uint32_t FunctionRva, std::uint64_t Index) {
        if (FunctionRva >= NtHeaders->OptionalHeader.SizeOfImage ||
            NtHeaders->OptionalHeader.SizeOfImage - FunctionRva < 12) throw std::runtime_error(PEVM_TEXT("VM bridge RVA invalid"));
        if (Index > 0xFFFFFFFFULL) throw std::runtime_error(PEVM_TEXT("VM bridge function index overflow"));
        auto* Target = Base + FunctionRva;
        if (Target[0] == 0x48 && Target[1] == 0xB8) throw std::runtime_error(PEVM_TEXT("VM bridge already installed"));
        if (!ThunkBase) {
            ThunkBase = static_cast<std::uint8_t*>(HideAlloc(nullptr, ThunkPageBytes,
                                                             MEM_RESERVE | MEM_COMMIT,
                                                             PAGE_EXECUTE_READWRITE));
            if (!ThunkBase) throw std::runtime_error(PEVM_TEXT("cannot allocate VM bridge thunk page"));
        }
        if (ThunkUsed + 29 > ThunkPageBytes) throw std::runtime_error(PEVM_TEXT("VM bridge thunk page exhausted"));
        const auto Thunk = ThunkBase + ThunkUsed;
        const auto Bridge = reinterpret_cast<std::uint64_t>(&VirtualizedFunctionBridge);
        // The thunk passes the function index as the fifth integer argument
        // (mov dword [rsp+0x20] inside the 0x28-byte frame) and reaches the
        // bridge through an absolute rax call: the thunk page can be
        // allocated anywhere in the address space, so rel32 is not usable.
        // The bridge reads the index as a 32-bit value because only the low
        // half of the argument slot is written here.
        std::array<std::uint8_t, 29> Code{};
        Code[0] = 0x48; Code[1] = 0x83; Code[2] = 0xEC; Code[3] = 0x28;      // sub rsp, 0x28
        Code[4] = 0xC7; Code[5] = 0x44; Code[6] = 0x24; Code[7] = 0x20;      // mov dword [rsp+0x20], imm32
        for (unsigned I = 0; I < 4; ++I) Code[8 + I] = static_cast<std::uint8_t>(Index >> (I * 8));
        Code[12] = 0x48; Code[13] = 0xB8;                                    // movabs rax, imm64 (bridge)
        for (unsigned I = 0; I < 8; ++I) Code[14 + I] = static_cast<std::uint8_t>(Bridge >> (I * 8));
        Code[22] = 0xFF; Code[23] = 0xD0;                                    // call rax
        Code[24] = 0x48; Code[25] = 0x83; Code[26] = 0xC4; Code[27] = 0x28;  // add rsp, 0x28
        Code[28] = 0xC3;                                                     // ret
        DWORD OldProtection = 0;
        if (!HideProtect(Target, 12, PAGE_EXECUTE_READWRITE, &OldProtection)) throw std::runtime_error(PEVM_TEXT("VM bridge cannot unlock target"));
        const std::array<std::uint8_t, 2> MovRax = {0x48, 0xB8}; std::memcpy(Target, MovRax.data(), MovRax.size());
        const auto Hop = reinterpret_cast<std::uint64_t>(Thunk);
        std::memcpy(Target + 2, &Hop, sizeof(Hop)); Target[10] = 0xFF; Target[11] = 0xE0;
        std::memcpy(Thunk, Code.data(), Code.size());
        std::array<std::uint8_t, 12> Patched{};
        std::memcpy(Patched.data(), Target, Patched.size());
        std::array<std::uint8_t, 12> Expected{};
        std::memcpy(Expected.data(), MovRax.data(), MovRax.size());
        std::memcpy(Expected.data() + 2, &Hop, sizeof(Hop));
        Expected[10] = 0xFF; Expected[11] = 0xE0;
        if (Patched != Expected) throw std::runtime_error(PEVM_TEXT("VM bridge patch verification failed"));
        DWORD Ignored = 0;
        HideProtect(Target, 12, PAGE_EXECUTE_READ, &Ignored);
        ThunkUsed += Code.size();
        FlushInstructionCache(GetCurrentProcess(), Target, 12);
        FlushInstructionCache(GetCurrentProcess(), Thunk, Code.size());
    }

    // Drops the thunk page to execute/read after every bridge is installed.
    // VirtualProtect granularity is one page, so per-thunk protection would
    // freeze the whole page and break later thunk writes in the same page.
    void SealBridges() {
        if (!ThunkBase || ThunkUsed == 0) return;
        DWORD Ignored = 0;
        HideProtect(ThunkBase, ThunkUsed, PAGE_EXECUTE_READ, &Ignored);
        FlushInstructionCache(GetCurrentProcess(), ThunkBase, ThunkUsed);
    }

    [[noreturn]] void RunEntryPoint() {
        const auto Entry = reinterpret_cast<void(*)()>(Base + EntryPointRva);
        Entry();
        ExitProcess(0);
    }

    // Anti-dump: after relocation/import/TLS processing nothing needs the PE
    // headers of the mapped payload anymore, so they are wiped to break
    // memory dumps that rebuild the image from its headers.
    void WipeHeaders() {
        const auto Size = NtHeaders->OptionalHeader.SizeOfHeaders;
        DWORD OldProtection = 0;
        if (HideProtect(Base, Size, PAGE_READWRITE, &OldProtection)) {
            SecureZeroMemory(Base, Size);
            HideProtect(Base, Size, PAGE_READONLY, &OldProtection);
            FlushInstructionCache(GetCurrentProcess(), Base, Size);
        }
    }

    // Access for the code-page vault (sealing runs outside the class).
    std::uint8_t* ImageBase() const { return Base; }
    const IMAGE_NT_HEADERS64* NtHeadersView() const { return NtHeaders; }

private:
    std::uint8_t* Base{};
    const IMAGE_NT_HEADERS64* NtHeaders{};
    std::uint32_t EntryPointRva{};
    PRUNTIME_FUNCTION FunctionTable{};
    std::uint8_t* ThunkBase{};
    std::size_t ThunkUsed{};
    static constexpr std::size_t ThunkPageBytes = 64 * 1024;

    const IMAGE_DATA_DIRECTORY& Directory(std::size_t Index) const {
        return NtHeaders->OptionalHeader.DataDirectory[Index];
    }

    void ApplyRelocations() {
        const auto Delta = reinterpret_cast<std::intptr_t>(Base) -
                           static_cast<std::intptr_t>(NtHeaders->OptionalHeader.ImageBase);
        if (Delta == 0) return;
        const auto& Data = Directory(IMAGE_DIRECTORY_ENTRY_BASERELOC);
        if (Data.VirtualAddress == 0 || Data.Size == 0) throw std::runtime_error(PEVM_TEXT("payload cannot be relocated"));
        std::size_t Consumed = 0;
        while (Consumed < Data.Size) {
            const auto Block = reinterpret_cast<IMAGE_BASE_RELOCATION*>(Base + Data.VirtualAddress + Consumed);
            if (Block->SizeOfBlock < sizeof(*Block) || Block->SizeOfBlock > Data.Size - Consumed) {
                throw std::runtime_error(PEVM_TEXT("relocation block invalid"));
            }
            const auto Count = (Block->SizeOfBlock - sizeof(*Block)) / sizeof(std::uint16_t);
            const auto Entries = reinterpret_cast<std::uint16_t*>(Block + 1);
            for (std::size_t I = 0; I < Count; ++I) {
                const auto Type = Entries[I] >> 12;
                const auto Offset = Entries[I] & 0x0fff;
                if (Type == IMAGE_REL_BASED_DIR64) {
                    auto Target = reinterpret_cast<std::uint64_t*>(Base + Block->VirtualAddress + Offset);
                    *Target += static_cast<std::uint64_t>(Delta);
                } else if (Type != IMAGE_REL_BASED_ABSOLUTE) {
                    throw std::runtime_error(PEVM_TEXT("unsupported relocation type"));
                }
            }
            Consumed += Block->SizeOfBlock;
        }
    }

    void ResolveImports() {
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

    void RunTlsCallbacks() {
        const auto& Data = Directory(IMAGE_DIRECTORY_ENTRY_TLS);
        if (Data.VirtualAddress == 0 || Data.Size < sizeof(IMAGE_TLS_DIRECTORY64)) return;
        const auto Tls = reinterpret_cast<IMAGE_TLS_DIRECTORY64*>(Base + Data.VirtualAddress);
        if (Tls->AddressOfCallBacks == 0) return;
        auto Callbacks = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(Tls->AddressOfCallBacks);
        for (; *Callbacks; ++Callbacks) (*Callbacks)(Base, DLL_PROCESS_ATTACH, nullptr);
    }
};

// VMP-style license gate: the key arrives via the PEVM_LICENSE environment
// variable or a .license file next to the wrapper. Anything missing, forged,
// locked to another machine or expired fails closed with one message.
void VerifyLicense(std::span<const std::uint8_t, 32> Secret) {
    std::string Key;
    wchar_t EnvBuffer[4096]{};
    if (GetEnvironmentVariableW(L"PEVM_LICENSE", EnvBuffer, 4096) != 0) {
        const int Length = WideCharToMultiByte(CP_ACP, 0, EnvBuffer, -1, nullptr, 0, nullptr, nullptr);
        if (Length > 1) {
            Key.resize(static_cast<std::size_t>(Length - 1));
            WideCharToMultiByte(CP_ACP, 0, EnvBuffer, -1, Key.data(), Length, nullptr, nullptr);
        }
    }
    if (Key.empty()) {
        std::ifstream LicenseFile(SelfPath().wstring() + L".license", std::ios::binary);
        if (LicenseFile) {
            std::ostringstream Buffer;
            Buffer << LicenseFile.rdbuf();
            Key = Buffer.str();
        }
    }
    auto Failure = [&]([[maybe_unused]] const char* Reason) {
        throw std::runtime_error(PEVM_TEXT("license check failed"));
    };
    const auto Trimmed = Key.find("PEVML1.");
    if (Trimmed == std::string::npos) Failure("missing");
    Key = Key.substr(Trimmed);

    std::vector<std::uint8_t> Raw;
    try {
        Raw = pevm::crypto::Base64Decode(Key.substr(std::char_traits<char>::length(KLicensePrefix)));
    } catch (const std::exception&) {
        Failure("malformed");
    }
    if (Raw.size() != sizeof(LicensePayload)) Failure("malformed");
    LicensePayload Payload{};
    std::memcpy(&Payload, Raw.data(), sizeof(Payload));

    FILETIME Now{};
    GetSystemTimeAsFileTime(&Now);
    const auto NowFileTime = (static_cast<std::uint64_t>(Now.dwHighDateTime) << 32) | Now.dwLowDateTime;
    const auto Reason = pevm::license::VerifyPayload(Payload, Secret,
                                                     pevm::license::MachineId(), NowFileTime);
    if (!Reason.empty()) Failure(Reason.c_str());
}

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
    if (Metadata.LicenseRequired != 0) VerifyLicense(Metadata.LicenseSecret);
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
    Payload.Prepare();
    if (Metadata.VmDataRawSize != 0) {
        LoadVmp3(std::span(Image).subspan(Metadata.VmDataRawOffset, Metadata.VmDataRawSize),
                 Password, Metadata.HandlerProfile);
        for (std::size_t I = 0; I < GVirtualizedPrograms.size(); ++I) {
            Payload.InstallVmBridge(GVirtualizedPrograms[I].Program.EntryAddress, I);
        }
        Payload.SealBridges();
    }
    // Code pages must be sealed while the build secret is still alive and
    // before the headers are wiped (section discovery needs the section
    // table); the wipe order below is load-bearing.
    TextVault::Instance.Seal(Payload.ImageBase(), Payload.NtHeadersView(), Password);
    Payload.WipeHeaders();
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
