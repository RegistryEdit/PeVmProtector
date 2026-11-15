#include "AnalysisTools.h"

#include <cstddef>
#include <cstdint>

namespace PeVm::Stub {
namespace {

// Keep the release rule table encoded, but compare every decoded character.
// Hash-only identities could incorrectly classify an unrelated colliding name.
struct EncodedText {
    std::uint8_t Bytes[64]{};
    std::uint8_t Length{};
};

constexpr std::uint8_t TextKey(std::size_t Index) noexcept {
    return static_cast<std::uint8_t>(0x80U | ((Index * 29U + 0x27U) & 0x7FU));
}

template <std::size_t N>
consteval EncodedText Encode(const wchar_t (&Text)[N]) {
    static_assert(N > 1 && N <= 65);
    EncodedText Result{};
    Result.Length = static_cast<std::uint8_t>(N - 1);
    for (std::size_t I = 0; I < N - 1; ++I) {
        if (Text[I] <= 0 || Text[I] > 0x7F) throw "non-ASCII identity rule";
        Result.Bytes[I] = static_cast<std::uint8_t>(Text[I]) ^ TextKey(I);
    }
    return Result;
}

constexpr wchar_t FoldAscii(wchar_t Character) noexcept {
    return Character >= L'A' && Character <= L'Z'
        ? static_cast<wchar_t>(Character + (L'a' - L'A')) : Character;
}

bool StartsWith(std::wstring_view Text, const EncodedText& Rule) noexcept {
    if (Text.size() < Rule.Length) return false;
    for (std::size_t I = 0; I < Rule.Length; ++I) {
        const auto Character = static_cast<wchar_t>(Rule.Bytes[I] ^ TextKey(I));
        if (FoldAscii(Text[I]) != FoldAscii(Character)) return false;
    }
    return true;
}

bool Equals(std::wstring_view Text, const EncodedText& Rule) noexcept {
    return Text.size() == Rule.Length && StartsWith(Text, Rule);
}

constexpr EncodedText Executables[]{
    Encode(L"x64dbg.exe"), Encode(L"x32dbg.exe"), Encode(L"ollydbg.exe"),
    Encode(L"ida.exe"), Encode(L"ida64.exe"), Encode(L"ida32.exe"),
    Encode(L"idag.exe"), Encode(L"idag64.exe"), Encode(L"idat.exe"), Encode(L"idat64.exe"),
    Encode(L"windbg.exe"), Encode(L"windbgx.exe"), Encode(L"cdb.exe"), Encode(L"ntsd.exe"),
    Encode(L"dnspy.exe"), Encode(L"dnspy-x86.exe"), Encode(L"dnspy-x64.exe"),
    Encode(L"dnspyx86.exe"), Encode(L"dnspyx64.exe"),
    Encode(L"cheatengine.exe"), Encode(L"cheatengine-i386.exe"),
    Encode(L"cheatengine-x86_64.exe"), Encode(L"cheatengine-x86_64-sse4-avx2.exe"),
    Encode(L"reclass.exe"), Encode(L"reclass.net.exe"), Encode(L"reclass64.exe"),
    Encode(L"frida.exe"), Encode(L"frida-trace.exe"),
    Encode(L"frida-inject.exe"), Encode(L"frida-server.exe")
};

constexpr EncodedText StrongClasses[]{
    Encode(L"OLLYDBG"), Encode(L"x64dbgClass"),
    Encode(L"x32dbgClass"), Encode(L"WinDbgFrameClass")
};

constexpr EncodedText Brands[]{
    Encode(L"IDA Pro"), Encode(L"IDA Freeware"), Encode(L"IDA Free"), Encode(L"IDA"),
    Encode(L"x64dbg"), Encode(L"x32dbg"), Encode(L"dnSpy"), Encode(L"Cheat Engine"),
    Encode(L"ReClass.NET"), Encode(L"ReClass"), Encode(L"Ghidra")
};

constexpr auto QtPrefix = Encode(L"Qt");
constexpr auto QtWindowPrefix = Encode(L"QWindow");
constexpr auto FormsPrefix = Encode(L"WindowsForms10.");
constexpr auto SwingClass = Encode(L"SunAwtFrame");
constexpr auto DelphiClass = Encode(L"TMainForm");

bool Digit(wchar_t Character) noexcept {
    return Character >= L'0' && Character <= L'9';
}

bool IdentifierTail(std::wstring_view Text, bool AllowDot) noexcept {
    for (const auto Character : Text) {
        const auto Folded = FoldAscii(Character);
        if (!Digit(Character) && !(Folded >= L'a' && Folded <= L'z') &&
            Character != L'_' && !(AllowDot && Character == L'.')) return false;
    }
    return true;
}

bool GenericClass(std::wstring_view Class) noexcept {
    if (Equals(Class, SwingClass) || Equals(Class, DelphiClass)) return true;
    if (StartsWith(Class, FormsPrefix)) {
        const auto Tail = Class.substr(FormsPrefix.Length);
        return !Tail.empty() && IdentifierTail(Tail, true);
    }
    if (!StartsWith(Class, QtPrefix)) return false;
    auto Tail = Class.substr(QtPrefix.Length);
    std::size_t Digits = 0;
    while (Digits < Tail.size() && Digit(Tail[Digits])) ++Digits;
    if (Digits == 0) return false;
    Tail.remove_prefix(Digits);
    return StartsWith(Tail, QtWindowPrefix) &&
        IdentifierTail(Tail.substr(QtWindowPrefix.Length), false);
}

bool DescriptionSuffix(std::wstring_view Tail) noexcept {
    return (!Tail.empty() && Tail.front() == L':') ||
        (Tail.size() >= 3 && Tail.substr(0, 3) == L" - ");
}

// Plain prose after a brand is not an identity. Accept exact names, dotted
// numeric versions (optionally v-prefixed), and explicit title separators.
bool BrandTitle(std::wstring_view Title, bool AllowDescription) noexcept {
    for (const auto& Brand : Brands) {
        if (!StartsWith(Title, Brand)) continue;
        auto Tail = Title.substr(Brand.Length);
        if (Tail.empty()) return true;
        if (AllowDescription && DescriptionSuffix(Tail)) return true;
        if (Tail.front() != L' ') continue;
        Tail.remove_prefix(1);
        if (!Tail.empty() && FoldAscii(Tail.front()) == L'v') Tail.remove_prefix(1);
        if (Tail.empty() || !Digit(Tail.front())) continue;
        std::size_t Position = 0;
        while (Position < Tail.size() && Digit(Tail[Position])) ++Position;
        while (Position < Tail.size() && Tail[Position] == L'.') {
            ++Position;
            if (Position == Tail.size() || !Digit(Tail[Position])) break;
            while (Position < Tail.size() && Digit(Tail[Position])) ++Position;
        }
        // A trailing or repeated dot is a malformed version, not a brand hit.
        if (Position != 0 && Tail[Position - 1] == L'.') continue;
        Tail.remove_prefix(Position);
        if (Tail.empty() || (AllowDescription && DescriptionSuffix(Tail))) return true;
    }
    return false;
}

bool AnalysisTitle(std::wstring_view Title) noexcept {
    if (Title.find(L'\0') != std::wstring_view::npos) return false;
    if (BrandTitle(Title, true)) return true;
    const auto Separator = Title.rfind(L" - ");
    return Separator != std::wstring_view::npos && Separator != 0 &&
        BrandTitle(Title.substr(Separator + 3), false);
}

template <std::size_t N>
std::size_t BoundedLength(const wchar_t (&Text)[N]) noexcept {
    std::size_t Length = 0;
    while (Length < N && Text[Length] != L'\0') ++Length;
    return Length;
}

constexpr std::size_t EnumerationLimit = 65536;

struct LastErrorScope {
    DWORD Saved{GetLastError()};
    ~LastErrorScope() noexcept { SetLastError(Saved); }
};

struct WindowScan {
    const AnalysisToolApis& Apis;
    DWORD ExcludedPid;
    AnalysisToolResult Result{AnalysisToolStatus::Clear};
    std::size_t Windows{};
};

BOOL StopUnavailable(WindowScan& Scan) noexcept {
    Scan.Result = {};
    return FALSE;
}

BOOL CALLBACK InspectWindow(HWND Window, LPARAM Parameter) noexcept {
    auto& Scan = *reinterpret_cast<WindowScan*>(Parameter);
    if (Scan.Windows++ >= EnumerationLimit) return StopUnavailable(Scan);

    DWORD Pid{};
    SetLastError(ERROR_SUCCESS);
    const auto Thread = Scan.Apis.WindowProcess(Window, &Pid);
    // Window destruction during enumeration is routine. Excluding our own
    // process also avoids synchronously sending WM_GETTEXT into our threads.
    if (Thread == 0) {
        const auto Error = GetLastError();
        return Error == ERROR_SUCCESS || Error == ERROR_INVALID_WINDOW_HANDLE
            ? TRUE : StopUnavailable(Scan);
    }
    if (Pid == 0) return StopUnavailable(Scan);
    if (Pid == Scan.ExcludedPid) return TRUE;

    wchar_t ClassBuffer[512]{};
    SetLastError(ERROR_SUCCESS);
    const auto ClassCount = Scan.Apis.ClassName(Window, ClassBuffer, 512);
    const auto ClassError = GetLastError();
    if (ClassCount <= 0) {
        return ClassError == ERROR_INVALID_WINDOW_HANDLE ? TRUE : StopUnavailable(Scan);
    }
    if (ClassCount >= 511 || BoundedLength(ClassBuffer) != static_cast<std::size_t>(ClassCount))
        return StopUnavailable(Scan);

    const std::wstring_view Class{ClassBuffer, static_cast<std::size_t>(ClassCount)};
    auto Evidence = AnalysisToolEvidence::None;
    for (const auto& Rule : StrongClasses) {
        if (Equals(Class, Rule)) { Evidence = AnalysisToolEvidence::WindowClass; break; }
    }
    if (Evidence == AnalysisToolEvidence::None) {
        // Reading unrelated application titles cannot add useful evidence.
        if (!GenericClass(Class)) return TRUE;
        wchar_t TitleBuffer[2048]{};
        SetLastError(ERROR_SUCCESS);
        const auto TitleCount = Scan.Apis.WindowText(Window, TitleBuffer, 2048);
        const auto TitleError = GetLastError();
        if (TitleCount < 0 || (TitleCount == 0 && TitleError != ERROR_SUCCESS)) {
            return TitleError == ERROR_INVALID_WINDOW_HANDLE ? TRUE : StopUnavailable(Scan);
        }
        if (TitleCount >= 2047 || BoundedLength(TitleBuffer) != static_cast<std::size_t>(TitleCount))
            return StopUnavailable(Scan);
        if (AnalysisTitle({TitleBuffer, static_cast<std::size_t>(TitleCount)}))
            Evidence = AnalysisToolEvidence::WindowIdentity;
    }
    if (Evidence == AnalysisToolEvidence::None) return TRUE;

    // Do not use a detected identity after its HWND vanished or changed owner.
    DWORD VerifiedPid{};
    SetLastError(ERROR_SUCCESS);
    const auto VerifiedThread = Scan.Apis.WindowProcess(Window, &VerifiedPid);
    if (VerifiedThread == 0) {
        const auto Error = GetLastError();
        return Error == ERROR_SUCCESS || Error == ERROR_INVALID_WINDOW_HANDLE
            ? TRUE : StopUnavailable(Scan);
    }
    if (VerifiedPid == 0) return StopUnavailable(Scan);
    if (VerifiedThread != Thread || VerifiedPid != Pid ||
        VerifiedPid == Scan.ExcludedPid) return TRUE;
    Scan.Result = {AnalysisToolStatus::Detected, Evidence, Pid};
    return FALSE;
}

AnalysisToolResult CloseSnapshot(const AnalysisToolApis& Apis, HANDLE Snapshot,
                                AnalysisToolResult Result) noexcept {
    return Apis.Close(Snapshot) ? Result : AnalysisToolResult{};
}

} // namespace

bool IsAnalysisExecutable(std::wstring_view Name) noexcept {
    if (Name.find(L'\0') != std::wstring_view::npos) return false;
    const auto Slash = Name.find_last_of(L"/\\");
    if (Slash != std::wstring_view::npos) Name.remove_prefix(Slash + 1);
    for (const auto& Rule : Executables) if (Equals(Name, Rule)) return true;
    return false;
}

AnalysisToolEvidence ClassifyAnalysisWindow(std::wstring_view Class, std::wstring_view Title) noexcept {
    for (const auto& Rule : StrongClasses)
        if (Equals(Class, Rule)) return AnalysisToolEvidence::WindowClass;
    return GenericClass(Class) && AnalysisTitle(Title)
        ? AnalysisToolEvidence::WindowIdentity : AnalysisToolEvidence::None;
}

AnalysisToolResult ProbeAnalysisTools(const AnalysisToolApis& Apis, DWORD ExcludedPid) noexcept {
    // Periodic probes run beside caller code; incidental WinAPI errors must
    // never replace the calling thread's pending application error.
    const LastErrorScope PreserveCallerError;
    if (!Apis.Snapshot || !Apis.First || !Apis.Next || !Apis.Close ||
        !Apis.Enum || !Apis.ClassName || !Apis.WindowText || !Apis.WindowProcess) return {};

    const auto Snapshot = Apis.Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Snapshot == nullptr || Snapshot == INVALID_HANDLE_VALUE) return {};

    PROCESSENTRY32W Entry{};
    Entry.dwSize = sizeof(Entry);
    SetLastError(ERROR_SUCCESS);
    auto Available = Apis.First(Snapshot, &Entry);
    auto Error = GetLastError();
    std::size_t Processes = 0;
    while (Available) {
        if (Processes++ >= EnumerationLimit) return CloseSnapshot(Apis, Snapshot, {});
        const auto Length = BoundedLength(Entry.szExeFile);
        if (Length == sizeof(Entry.szExeFile) / sizeof(Entry.szExeFile[0]))
            return CloseSnapshot(Apis, Snapshot, {});
        if (Entry.th32ProcessID != ExcludedPid && Entry.th32ProcessID != 0 &&
            IsAnalysisExecutable({Entry.szExeFile, Length})) {
            return CloseSnapshot(Apis, Snapshot,
                {AnalysisToolStatus::Detected, AnalysisToolEvidence::ProcessName, Entry.th32ProcessID});
        }
        Entry = {};
        Entry.dwSize = sizeof(Entry);
        SetLastError(ERROR_SUCCESS);
        Available = Apis.Next(Snapshot, &Entry);
        Error = GetLastError();
    }
    const auto ProcessResult = CloseSnapshot(Apis, Snapshot,
        Error == ERROR_NO_MORE_FILES ? AnalysisToolResult{AnalysisToolStatus::Clear} : AnalysisToolResult{});
    if (ProcessResult.Status != AnalysisToolStatus::Clear) return ProcessResult;

    WindowScan Scan{Apis, ExcludedPid};
    SetLastError(ERROR_SUCCESS);
    const auto Completed = Apis.Enum(InspectWindow, reinterpret_cast<LPARAM>(&Scan));
    if (Scan.Result.Status == AnalysisToolStatus::Detected) return Scan.Result;
    if (!Completed || Scan.Result.Status != AnalysisToolStatus::Clear) return {};
    return Scan.Result;
}

} // namespace PeVm::Stub
