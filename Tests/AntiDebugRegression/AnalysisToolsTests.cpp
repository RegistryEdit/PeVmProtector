#include "../../Src/Apps/Stub/AnalysisTools.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {
using PeVm::Stub::AnalysisToolApis;
using PeVm::Stub::AnalysisToolEvidence;
using PeVm::Stub::AnalysisToolResult;
using PeVm::Stub::AnalysisToolStatus;
using PeVm::Stub::ClassifyAnalysisWindow;
using PeVm::Stub::IsAnalysisExecutable;
using PeVm::Stub::ProbeAnalysisTools;

unsigned Checks{};
void Require(bool Condition, const char* Message) {
    ++Checks;
    if (!Condition) throw std::runtime_error(Message);
}
void Expect(const AnalysisToolResult& Result, AnalysisToolStatus Status,
            AnalysisToolEvidence Evidence, DWORD ProcessId, const char* Message) {
    Require(Result.Status == Status && Result.Evidence == Evidence && Result.ProcessId == ProcessId, Message);
}

AnalysisToolResult ProbePreservingLastError(const AnalysisToolApis& Apis, DWORD ExcludedPid,
                                         DWORD CallerError = 0x6A17B3E1U) {
    SetLastError(CallerError);
    const auto Result = ProbeAnalysisTools(Apis, ExcludedPid);
    const auto ReturnedError = GetLastError();
    Require(ReturnedError == CallerError, "probe preserves the caller's LastError on every return path");
    return Result;
}

void TestExecutableNames() {
    const std::wstring_view Positive[]{
        L"x64dbg.exe", L"x32dbg.exe", L"ollydbg.exe", L"ida.exe", L"ida64.exe", L"ida32.exe",
        L"idag.exe", L"idag64.exe", L"idat.exe", L"idat64.exe", L"windbg.exe", L"windbgx.exe",
        L"cdb.exe", L"ntsd.exe", L"dnspy.exe", L"dnspy-x86.exe", L"dnspy-x64.exe",
        L"dnspyx86.exe", L"dnspyx64.exe", L"cheatengine.exe", L"cheatengine-i386.exe",
        L"cheatengine-x86_64.exe", L"cheatengine-x86_64-sse4-avx2.exe", L"reclass.exe",
        L"reclass.net.exe", L"reclass64.exe", L"frida.exe", L"frida-trace.exe",
        L"frida-inject.exe", L"frida-server.exe"};
    for (const auto Name : Positive) {
        Require(IsAnalysisExecutable(Name), "known executable basename matched exactly");
        std::wstring Mixed(Name);
        for (std::size_t I = 0; I < Mixed.size(); I += 2)
            if (Mixed[I] >= L'a' && Mixed[I] <= L'z') Mixed[I] -= L'a' - L'A';
        Require(IsAnalysisExecutable(Mixed), "executable basename matching ignores ASCII case");
        Require(!IsAnalysisExecutable(std::wstring(Name) + L".bak"), "backup suffix does not match executable");
        Require(!IsAnalysisExecutable(L"notes-" + std::wstring(Name)), "embedded executable name does not match");
    }
    const std::wstring_view Negative[]{
        L"", L"ida", L"x64dbg", L"ida-backup.exe", L"ida64_backup.exe", L"myx64dbgtool.exe",
        L"notes-x64dbg.txt", L"x64dbg.exe.old", L"x64dbg.executable", L"x64dbg.exe ",
        L" x64dbg.exe", L"chrome.exe", L"msedge.exe", L"firefox.exe", L"iexplore.exe",
        L"Code.exe", L"Code - Insiders.exe", L"Codex.exe", L"python.exe", L"pythonw.exe",
        L"python3.exe", L"java.exe", L"javaw.exe", L"node.exe", L"powershell.exe", L"pwsh.exe",
        L"notepad.exe", L"explorer.exe", L"devenv.exe", L"QtDesigner.exe", L"ida-report.exe"};
    for (const auto Name : Negative) Require(!IsAnalysisExecutable(Name), "ordinary executable is not a tool-name hit");
    const std::wstring EmbeddedNull = std::wstring(L"x64dbg.exe") + wchar_t{} + L".bak";
    Require(!IsAnalysisExecutable(EmbeddedNull), "embedded null cannot hide a basename suffix");
}

void TestWindowIdentities() {
    for (const auto Class : {L"OLLYDBG", L"x64dbgClass", L"x32dbgClass", L"WinDbgFrameClass"}) {
        Require(ClassifyAnalysisWindow(Class, L"") == AnalysisToolEvidence::WindowClass,
            "strong debugger class needs no title");
    }
    struct Identity { const wchar_t* Class; const wchar_t* Title; };
    const Identity Positive[]{
        {L"Qt5QWindowIcon", L"IDA"}, {L"Qt6QWindowIcon", L"IDA Pro - program.exe"},
        {L"Qt5152QWindowIcon", L"program.exe - IDA Pro"},
        {L"Qt5152QWindowIcon", L"program.exe - x64dbg"},
        {L"Qt5QWindowIcon", L"x64dbg"}, {L"Qt5QWindowIcon", L"x64dbg: program.exe"},
        {L"Qt5QWindowIcon", L"IDA Freeware"}, {L"Qt5QWindowIcon", L"IDA Free 9.0"},
        {L"WindowsForms10.Window.8.app.0.141b42a_r9_ad1", L"dnSpy"},
        {L"WindowsForms10.Window.8.app.0.141b42a_r9_ad1", L"program.dll - dnSpy"},
        {L"SunAwtFrame", L"Ghidra: project"}, {L"SunAwtFrame", L"Ghidra - CodeBrowser"},
        {L"TMainForm", L"Cheat Engine 7.5"}, {L"TMainForm", L"ReClass.NET"}};
    for (const auto& Item : Positive)
        Require(ClassifyAnalysisWindow(Item.Class, Item.Title) == AnalysisToolEvidence::WindowIdentity,
            "generic framework class requires an anchored tool identity");
    const Identity Negative[]{
        {L"Chrome_WidgetWin_1", L"IDA Pro"}, {L"Chrome_WidgetWin_1", L"program.exe - x64dbg"},
        {L"MozillaWindowClass", L"IDA Pro - tutorial"}, {L"ApplicationFrameWindow", L"x64dbg"},
        {L"Qt5QWindowIcon", L"notes about IDA"}, {L"Qt5152QWindowIcon", L"Using IDA in an article"},
        {L"Qt5QWindowIcon", L"x64dbg documentation"}, {L"Qt5QWindowIcon", L"IDA documentation"},
        {L"Qt5QWindowIcon", L""}, {L"Qt5QWindowIcon", L"normal application"},
        {L"Qt5QWindowIcon", L"IDAPro"}, {L"Qt5QWindowIcon", L"myx64dbg"},
        {L"QtDocumentation", L"IDA Pro"}, {L"WindowsForms10.Window.8.app.0.141b42a_r9_ad1", L"notes about dnSpy"},
        {L"SunAwtFrame", L"Java application"}, {L"SunAwtFrame", L"Ghidra documentation"},
        {L"TMainForm", L"Cheat Engine documentation"}, {L"ConsoleWindowClass", L"Ghidra"},
        {L"", L"IDA Pro"}, {L"STATIC", L"x64dbg"}};
    for (const auto& Item : Negative)
        Require(ClassifyAnalysisWindow(Item.Class, Item.Title) == AnalysisToolEvidence::None,
            "browser titles and incidental brand mentions do not identify a tool");
}

struct ProcessEntry { DWORD Pid; std::wstring Name; bool Terminated{true}; };
struct WindowEntry {
    DWORD Pid{4001};
    std::wstring Class{L"STATIC"}, Title;
    DWORD ClassError{}, TextError{};
    DWORD PidError{}, VerifiedPidError{};
    unsigned PidReads{};
    bool VanishOnVerify{}, ChangeOwnerOnVerify{}, BadPid{}, BadVerifiedPid{};
    bool UnterminatedClass{}, UnterminatedTitle{};
    DWORD ReplacementPid{4002}, ReplacementThread{102};
    DWORD PidSuccessError{}, VerifiedPidSuccessError{};
};
struct Fixture {
    std::vector<ProcessEntry> Processes;
    std::vector<WindowEntry> Windows;
    HANDLE SnapshotValue{reinterpret_cast<HANDLE>(std::uintptr_t{0x13579})};
    DWORD FirstError{}, NextError{}, EnumError{}, CloseError{};
    std::size_t ProcessIndex{};
    unsigned Snapshots{}, Firsts{}, Nexts{}, Closes{}, Enums{}, Classes{}, Titles{}, Pids{};
    bool SnapshotArguments{true}, EntrySize{true}, ClosedCorrectHandle{true};
};
Fixture* Active{};
class FixtureScope {
public:
    explicit FixtureScope(Fixture& Data) { Active = &Data; }
    ~FixtureScope() { Active = nullptr; }
    FixtureScope(const FixtureScope&) = delete;
    FixtureScope& operator=(const FixtureScope&) = delete;
};

HANDLE WINAPI Snapshot(DWORD Flags, DWORD Pid) {
    ++Active->Snapshots;
    Active->SnapshotArguments &= Flags == TH32CS_SNAPPROCESS && Pid == 0;
    if (Active->SnapshotValue == INVALID_HANDLE_VALUE || Active->SnapshotValue == nullptr)
        SetLastError(ERROR_ACCESS_DENIED);
    return Active->SnapshotValue;
}
BOOL FillProcess(LPPROCESSENTRY32W Entry) {
    Active->EntrySize &= Entry && Entry->dwSize == sizeof(PROCESSENTRY32W);
    if (!Entry || Active->ProcessIndex >= Active->Processes.size()) return FALSE;
    const auto& Process = Active->Processes[Active->ProcessIndex];
    Entry->th32ProcessID = Process.Pid;
    std::fill(std::begin(Entry->szExeFile), std::end(Entry->szExeFile), Process.Terminated ? wchar_t{} : L'A');
    const auto Limit = std::size(Entry->szExeFile) - (Process.Terminated ? 1 : 0);
    std::copy_n(Process.Name.begin(), (std::min)(Process.Name.size(), Limit), Entry->szExeFile);
    return TRUE;
}
BOOL WINAPI First(HANDLE Handle, LPPROCESSENTRY32W Entry) {
    ++Active->Firsts;
    Active->ClosedCorrectHandle &= Handle == Active->SnapshotValue;
    Active->ProcessIndex = 0;
    if (Active->FirstError) { SetLastError(Active->FirstError); return FALSE; }
    if (Active->Processes.empty()) { SetLastError(ERROR_NO_MORE_FILES); return FALSE; }
    return FillProcess(Entry);
}
BOOL WINAPI Next(HANDLE Handle, LPPROCESSENTRY32W Entry) {
    ++Active->Nexts;
    Active->ClosedCorrectHandle &= Handle == Active->SnapshotValue;
    if (Active->NextError) { SetLastError(Active->NextError); return FALSE; }
    if (++Active->ProcessIndex == Active->Processes.size()) { SetLastError(ERROR_NO_MORE_FILES); return FALSE; }
    return FillProcess(Entry);
}
BOOL WINAPI Close(HANDLE Handle) {
    ++Active->Closes;
    Active->ClosedCorrectHandle &= Handle == Active->SnapshotValue;
    if (Active->CloseError) { SetLastError(Active->CloseError); return FALSE; }
    return TRUE;
}
WindowEntry* FakeWindow(HWND Window) {
    const auto Number = reinterpret_cast<std::uintptr_t>(Window);
    if (Number < 0x2000 || Number - 0x2000 >= Active->Windows.size()) return nullptr;
    return &Active->Windows[Number - 0x2000];
}
BOOL WINAPI Enum(WNDENUMPROC Callback, LPARAM Param) {
    ++Active->Enums;
    if (Active->EnumError) { SetLastError(Active->EnumError); return FALSE; }
    for (std::size_t I = 0; I < Active->Windows.size(); ++I) {
        if (!Callback(reinterpret_cast<HWND>(std::uintptr_t{0x2000} + I), Param)) {
            SetLastError(ERROR_CANCELLED); // Early detection is not an EnumWindows failure.
            return FALSE;
        }
    }
    return TRUE;
}
int CopyWindowText(std::wstring_view Text, LPWSTR Buffer, int Size) {
    if (!Buffer || Size <= 0) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    const auto Bytes = (std::min)(Text.size(), static_cast<std::size_t>(Size - 1));
    std::copy_n(Text.begin(), Bytes, Buffer);
    Buffer[Bytes] = 0;
    return static_cast<int>(Bytes);
}
int WINAPI ClassName(HWND Window, LPWSTR Buffer, int Size) {
    ++Active->Classes;
    const auto Item = FakeWindow(Window);
    if (!Item) { SetLastError(ERROR_INVALID_WINDOW_HANDLE); return 0; }
    if (Item->ClassError) { SetLastError(Item->ClassError); return 0; }
    if (Item->UnterminatedClass) {
        std::fill_n(Buffer, Size, L'A');
        std::copy_n(Item->Class.begin(), (std::min)(Item->Class.size(), static_cast<std::size_t>(Size)), Buffer);
        return static_cast<int>(Item->Class.size());
    }
    return CopyWindowText(Item->Class, Buffer, Size);
}
int WINAPI WindowText(HWND Window, LPWSTR Buffer, int Size) {
    ++Active->Titles;
    const auto Item = FakeWindow(Window);
    if (!Item) { SetLastError(ERROR_INVALID_WINDOW_HANDLE); return 0; }
    if (Item->TextError) { SetLastError(Item->TextError); return 0; }
    if (Item->UnterminatedTitle) {
        std::fill_n(Buffer, Size, L'A');
        std::copy_n(Item->Title.begin(), (std::min)(Item->Title.size(), static_cast<std::size_t>(Size)), Buffer);
        return static_cast<int>(Item->Title.size());
    }
    return CopyWindowText(Item->Title, Buffer, Size);
}
DWORD WINAPI WindowProcess(HWND Window, LPDWORD Pid) {
    ++Active->Pids;
    const auto Item = FakeWindow(Window);
    if (Item) {
        const bool Verify = ++Item->PidReads > 1;
        const auto Error = Verify ? Item->VerifiedPidError : Item->PidError;
        if (Error) { *Pid = 0; SetLastError(Error); return 0; }
        if (Verify && Item->VanishOnVerify) { *Pid = 0; return 0; }
        const auto SuccessError = Verify ? Item->VerifiedPidSuccessError : Item->PidSuccessError;
        if (SuccessError) SetLastError(SuccessError);
        if ((Verify && Item->BadVerifiedPid) || (!Verify && Item->BadPid)) { *Pid = 0; return 101; }
        if (Verify && Item->ChangeOwnerOnVerify) {
            *Pid = Item->ReplacementPid;
            return Item->ReplacementThread;
        }
    }
    *Pid = Item ? Item->Pid : 0;
    return Item && Item->Pid ? 101 : 0;
}
const AnalysisToolApis FakeApis{Snapshot, First, Next, Close, Enum, ClassName, WindowText, WindowProcess};
const AnalysisToolApis NativeApis{CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, CloseHandle,
    EnumWindows, GetClassNameW, GetWindowTextW, GetWindowThreadProcessId};

void RequireLifetime(const Fixture& Data, unsigned Closes, const char* Message) {
    Require(Data.Closes == Closes && Data.ClosedCorrectHandle && Data.SnapshotArguments && Data.EntrySize, Message);
}

void TestInjectedProcessProbe() {
    {
        Fixture Data;
        FixtureScope Scope(Data);
        Expect(ProbePreservingLastError(FakeApis, 3001), AnalysisToolStatus::Clear, AnalysisToolEvidence::None, 0,
            "empty snapshot with ERROR_NO_MORE_FILES is clear");
        Require(Data.Firsts == 1 && Data.Nexts == 0 && Data.Enums == 1, "empty process list still performs one window scan");
        RequireLifetime(Data, 1, "empty snapshot is closed exactly once");
    }
    {
        Fixture Data;
        Data.Processes = {{3001, L"IDA64.EXE"}, {3002, L"python.exe"}, {3003, L"x64dbg.exe.bak"}};
        FixtureScope Scope(Data);
        Expect(ProbePreservingLastError(FakeApis, 3001), AnalysisToolStatus::Clear, AnalysisToolEvidence::None, 0,
            "own PID and ordinary or backup process names are excluded");
        Require(Data.Nexts == 3 && Data.Enums == 1, "clean processes are fully enumerated");
        RequireLifetime(Data, 1, "clean snapshot is closed exactly once");
    }
    {
        Fixture Data;
        Data.Processes = {{3001, L"python.exe"}, {3002, L"x64DBG.EXE"}, {3003, L"java.exe"}};
        FixtureScope Scope(Data);
        Expect(ProbePreservingLastError(FakeApis, 3001), AnalysisToolStatus::Detected, AnalysisToolEvidence::ProcessName, 3002,
            "exact foreign executable hit reports its PID and evidence");
        Require(Data.Nexts == 1 && Data.Enums == 0, "process hit ends probe without an unnecessary window scan");
        RequireLifetime(Data, 1, "detected snapshot is closed before return");
    }
    for (const auto Bad : {INVALID_HANDLE_VALUE, static_cast<HANDLE>(nullptr)}) {
        Fixture Data;
        Data.SnapshotValue = Bad;
        FixtureScope Scope(Data);
        Expect(ProbePreservingLastError(FakeApis, 3001), AnalysisToolStatus::Unavailable, AnalysisToolEvidence::None, 0,
            "invalid snapshot is unavailable rather than clear");
        Require(Data.Firsts == 0 && Data.Nexts == 0 && Data.Enums == 0, "invalid snapshot is never enumerated");
        RequireLifetime(Data, 0, "invalid snapshot is never closed as a valid handle");
    }
    for (const auto Error : {ERROR_ACCESS_DENIED, ERROR_PARTIAL_COPY, ERROR_INVALID_HANDLE}) {
        Fixture Data;
        Data.FirstError = Error;
        FixtureScope Scope(Data);
        Expect(ProbePreservingLastError(FakeApis, 3001), AnalysisToolStatus::Unavailable, AnalysisToolEvidence::None, 0,
            "first-entry API error differs from normal empty enumeration");
        RequireLifetime(Data, 1, "first-entry failure still releases snapshot");
    }
    for (const auto Error : {ERROR_ACCESS_DENIED, ERROR_PARTIAL_COPY, ERROR_INVALID_HANDLE}) {
        Fixture Data;
        Data.Processes = {{3001, L"java.exe"}};
        Data.NextError = Error;
        FixtureScope Scope(Data);
        Expect(ProbePreservingLastError(FakeApis, 3001), AnalysisToolStatus::Unavailable, AnalysisToolEvidence::None, 0,
            "next-entry API error differs from normal end of enumeration");
        RequireLifetime(Data, 1, "next-entry failure still releases snapshot");
    }
    for (unsigned Missing = 0; Missing < 8; ++Missing) {
        auto Apis = FakeApis;
        switch (Missing) {
        case 0: Apis.Snapshot = nullptr; break;
        case 1: Apis.First = nullptr; break;
        case 2: Apis.Next = nullptr; break;
        case 3: Apis.Close = nullptr; break;
        case 4: Apis.Enum = nullptr; break;
        case 5: Apis.ClassName = nullptr; break;
        case 6: Apis.WindowText = nullptr; break;
        case 7: Apis.WindowProcess = nullptr; break;
        }
        Fixture Data;
        FixtureScope Scope(Data);
        Expect(ProbePreservingLastError(Apis, 3001), AnalysisToolStatus::Unavailable, AnalysisToolEvidence::None, 0,
            "any unresolved required API makes probe unavailable");
        Require(Data.Snapshots == 0 && Data.Closes == 0 && Data.Enums == 0, "missing APIs are rejected before acquiring resources");
    }
    for (const bool ProcessHit : {false, true}) {
        Fixture Data;
        if (ProcessHit) Data.Processes = {{4001, L"ida64.exe"}};
        Data.CloseError = ERROR_ACCESS_DENIED;
        FixtureScope Scope(Data);
        Expect(ProbePreservingLastError(FakeApis, 3001), AnalysisToolStatus::Unavailable, AnalysisToolEvidence::None, 0,
            "snapshot close failure cannot return clear or detected evidence");
        Require(Data.Enums == 0, "failed snapshot close stops before window scan");
        RequireLifetime(Data, 1, "close failure attempts snapshot release exactly once");
    }
    {
        Fixture Data;
        Data.Processes = {{4001, L"ida64.exe", false}};
        FixtureScope Scope(Data);
        Expect(ProbePreservingLastError(FakeApis, 3001), AnalysisToolStatus::Unavailable, AnalysisToolEvidence::None, 0,
            "unterminated process executable name is unavailable");
        RequireLifetime(Data, 1, "malformed process name still releases snapshot");
    }
}

void TestInjectedWindowProbe() {
    {
        Fixture Data;
        WindowEntry Window{4001, L"STATIC", L"ordinary application"};
        Window.PidSuccessError = ERROR_ACCESS_DENIED;
        Data.Windows.push_back(Window);
        FixtureScope Scope(Data);
        Expect(ProbePreservingLastError(FakeApis, 3001), AnalysisToolStatus::Clear, AnalysisToolEvidence::None, 0,
            "successful initial window PID lookup ignores a residual nonzero LastError");
        Require(Data.Pids == 1 && Data.Classes == 1 && Data.Titles == 0,
            "successful PID lookup with residual error still inspects an ordinary window");
        RequireLifetime(Data, 1, "residual PID error retains snapshot lifetime discipline");
    }
    for (unsigned Stage = 0; Stage < 3; ++Stage) {
        Fixture Data;
        WindowEntry Window{4001, L"OLLYDBG", L""};
        if (Stage != 1) Window.PidSuccessError = ERROR_ACCESS_DENIED;
        if (Stage != 0) Window.VerifiedPidSuccessError = ERROR_INVALID_WINDOW_HANDLE;
        Data.Windows.push_back(Window);
        FixtureScope Scope(Data);
        Expect(ProbePreservingLastError(FakeApis, 3001), AnalysisToolStatus::Detected,
            AnalysisToolEvidence::WindowClass, 4001,
            "successful initial or verified PID lookup ignores a residual nonzero LastError");
        Require(Data.Pids == 2, "residual PID errors still reach window ownership verification");
        RequireLifetime(Data, 1, "detected window with residual PID errors releases snapshot");
    }
    {
        Fixture Data;
        Data.Windows = {{4001, L"OLLYDBG", L""}};
        FixtureScope Scope(Data);
        Expect(ProbePreservingLastError(FakeApis, 3001), AnalysisToolStatus::Detected, AnalysisToolEvidence::WindowClass, 4001,
            "strong class hit survives normal callback-stopped enumeration");
        Require(Data.Enums == 1, "strong-class detection calls EnumWindows once");
        RequireLifetime(Data, 1, "window class detection releases process snapshot");
    }
    {
        Fixture Data;
        Data.Windows = {{4001, L"Chrome_WidgetWin_1", L"IDA Pro"},
            {4002, L"Qt5152QWindowIcon", L"program.exe - x64dbg"}};
        FixtureScope Scope(Data);
        Expect(ProbePreservingLastError(FakeApis, 3001), AnalysisToolStatus::Detected, AnalysisToolEvidence::WindowIdentity, 4002,
            "browser title is skipped before anchored Qt tool identity");
        RequireLifetime(Data, 1, "window identity detection releases snapshot");
    }
    {
        Fixture Data;
        Data.Windows = {{3001, L"x64dbgClass", L"x64dbg"}, {0, L"OLLYDBG", L""}};
        FixtureScope Scope(Data);
        Expect(ProbePreservingLastError(FakeApis, 3001), AnalysisToolStatus::Clear, AnalysisToolEvidence::None, 0,
            "excluded PID and vanished window do not produce a hit");
        Require(Data.Classes == 0 && Data.Titles == 0, "excluded or vanished windows are not read");
        RequireLifetime(Data, 1, "excluded windows still release snapshot");
    }
    {
        Fixture Data;
        Data.Windows = {{4001, L"Qt5QWindowIcon", L""}, {4002, L"Chrome_WidgetWin_1", L"program.exe - IDA Pro"}};
        FixtureScope Scope(Data);
        Expect(ProbePreservingLastError(FakeApis, 3001), AnalysisToolStatus::Clear, AnalysisToolEvidence::None, 0,
            "empty valid title and browser brand title remain clear");
    }
    {
        Fixture Data;
        Data.EnumError = ERROR_ACCESS_DENIED;
        FixtureScope Scope(Data);
        Expect(ProbePreservingLastError(FakeApis, 3001), AnalysisToolStatus::Unavailable, AnalysisToolEvidence::None, 0,
            "EnumWindows failure is unavailable instead of a clean scan");
        RequireLifetime(Data, 1, "EnumWindows failure releases snapshot");
    }
    for (const bool TitleFailure : {false, true}) {
        Fixture Data;
        WindowEntry Window{4001, L"Qt5QWindowIcon", L"IDA Pro"};
        if (TitleFailure) Window.TextError = ERROR_ACCESS_DENIED;
        else Window.ClassError = ERROR_ACCESS_DENIED;
        Data.Windows.push_back(Window);
        FixtureScope Scope(Data);
        Expect(ProbePreservingLastError(FakeApis, 3001), AnalysisToolStatus::Unavailable, AnalysisToolEvidence::None, 0,
            "explicit class or title API error makes scan unavailable");
        RequireLifetime(Data, 1, "window read error releases snapshot");
    }
    for (const bool TitleFailure : {false, true}) {
        Fixture Data;
        WindowEntry Window{4001, L"Qt5QWindowIcon", L"IDA Pro"};
        if (TitleFailure) Window.TextError = ERROR_INVALID_WINDOW_HANDLE;
        else Window.ClassError = ERROR_INVALID_WINDOW_HANDLE;
        Data.Windows.push_back(Window);
        FixtureScope Scope(Data);
        Expect(ProbePreservingLastError(FakeApis, 3001), AnalysisToolStatus::Clear, AnalysisToolEvidence::None, 0,
            "window disappearance during a read is benign");
        RequireLifetime(Data, 1, "vanished window releases snapshot");
    }
    for (const bool VerifyFailure : {false, true}) {
        Fixture Data;
        WindowEntry Window{4001, L"OLLYDBG", L""};
        if (VerifyFailure) Window.VerifiedPidError = ERROR_ACCESS_DENIED;
        else Window.PidError = ERROR_ACCESS_DENIED;
        Data.Windows.push_back(Window);
        FixtureScope Scope(Data);
        Expect(ProbePreservingLastError(FakeApis, 3001), AnalysisToolStatus::Unavailable, AnalysisToolEvidence::None, 0,
            "explicit initial or verified window PID API error is unavailable");
        Require(Data.Pids == (VerifyFailure ? 2U : 1U), "PID failure occurs at the requested validation stage");
        RequireLifetime(Data, 1, "PID API failure retains snapshot lifetime discipline");
    }
    for (const bool VerifyFailure : {false, true}) {
        Fixture Data;
        WindowEntry Window{4001, L"OLLYDBG", L""};
        if (VerifyFailure) Window.VerifiedPidError = ERROR_INVALID_WINDOW_HANDLE;
        else Window.PidError = ERROR_INVALID_WINDOW_HANDLE;
        Data.Windows.push_back(Window);
        FixtureScope Scope(Data);
        Expect(ProbePreservingLastError(FakeApis, 3001), AnalysisToolStatus::Clear, AnalysisToolEvidence::None, 0,
            "initial or verified HWND disappearance remains benign");
        RequireLifetime(Data, 1, "vanished PID lookup still releases snapshot");
    }
    {
        Fixture Data;
        WindowEntry Window{4001, L"OLLYDBG", L""};
        Window.VanishOnVerify = true;
        Data.Windows.push_back(Window);
        FixtureScope Scope(Data);
        Expect(ProbePreservingLastError(FakeApis, 3001), AnalysisToolStatus::Clear, AnalysisToolEvidence::None, 0,
            "verified PID lookup returning zero without error is a vanished window");
    }
    for (const bool Verified : {false, true}) {
        Fixture Data;
        WindowEntry Window{4001, L"OLLYDBG", L""};
        if (Verified) Window.BadVerifiedPid = true;
        else Window.BadPid = true;
        Data.Windows.push_back(Window);
        FixtureScope Scope(Data);
        Expect(ProbePreservingLastError(FakeApis, 3001), AnalysisToolStatus::Unavailable, AnalysisToolEvidence::None, 0,
            "nonzero window thread with zero PID is malformed rather than vanished");
    }
    for (const DWORD Replacement : {DWORD{4002}, DWORD{3001}, DWORD{4001}}) {
        Fixture Data;
        WindowEntry Window{4001, L"OLLYDBG", L""};
        Window.ChangeOwnerOnVerify = true;
        Window.ReplacementPid = Replacement;
        Data.Windows.push_back(Window);
        FixtureScope Scope(Data);
        Expect(ProbePreservingLastError(FakeApis, 3001), AnalysisToolStatus::Clear, AnalysisToolEvidence::None, 0,
            "changed window owner, excluded PID, or changed thread invalidates stale identity");
    }
    for (const bool Title : {false, true}) {
        Fixture Data;
        WindowEntry Window{4001, L"Qt5QWindowIcon", L"IDA Pro"};
        if (Title) Window.Title = L"IDA Pro - " + std::wstring(3000, L'A');
        else Window.Class = L"Qt5QWindow" + std::wstring(600, L'A');
        Data.Windows.push_back(Window);
        FixtureScope Scope(Data);
        Expect(ProbePreservingLastError(FakeApis, 3001), AnalysisToolStatus::Unavailable, AnalysisToolEvidence::None, 0,
            "truncated class or title must not provide partial identity evidence");
    }
    for (const bool Title : {false, true}) {
        Fixture Data;
        WindowEntry Window{4001, Title ? L"Qt5QWindowIcon" : L"OLLYDBG", L"IDA Pro"};
        if (Title) Window.UnterminatedTitle = true;
        else Window.UnterminatedClass = true;
        Data.Windows.push_back(Window);
        FixtureScope Scope(Data);
        Expect(ProbePreservingLastError(FakeApis, 3001), AnalysisToolStatus::Unavailable, AnalysisToolEvidence::None, 0,
            "reported class or title count requires an actual string terminator");
    }
    for (unsigned I = 0; I < 32; ++I) {
        Fixture Data;
        Data.Processes = {{3001, L"Code.exe"}};
        Data.EnumError = ERROR_ACCESS_DENIED;
        FixtureScope Scope(Data);
        Expect(ProbePreservingLastError(FakeApis, 3001), AnalysisToolStatus::Unavailable, AnalysisToolEvidence::None, 0,
            "repeated enum failure remains fail closed");
        RequireLifetime(Data, 1, "repeated failed probe releases every snapshot");
    }
}

void TestEnumerationBudgets() {
    constexpr std::size_t Limit = 65536;
    for (const std::size_t Count : {Limit, Limit + 1}) {
        Fixture Data;
        Data.Processes.assign(Count, ProcessEntry{3001, L"python.exe"});
        FixtureScope Scope(Data);
        const auto Status = Count == Limit ? AnalysisToolStatus::Clear : AnalysisToolStatus::Unavailable;
        Expect(ProbePreservingLastError(FakeApis, 3001), Status, AnalysisToolEvidence::None, 0,
            "process enumeration allows its exact budget and rejects overflow");
        Require(Data.Nexts == Limit, "process enumeration stops at the configured budget");
        RequireLifetime(Data, 1, "process budget exhaustion closes snapshot");
    }
    for (const std::size_t Count : {Limit, Limit + 1}) {
        Fixture Data;
        Data.Windows.assign(Count, WindowEntry{0, L"STATIC", L""});
        FixtureScope Scope(Data);
        const auto Status = Count == Limit ? AnalysisToolStatus::Clear : AnalysisToolStatus::Unavailable;
        Expect(ProbePreservingLastError(FakeApis, 3001), Status, AnalysisToolEvidence::None, 0,
            "window enumeration allows its exact budget and rejects overflow");
        Require(Data.Pids == Limit && Data.Enums == 1, "window enumeration stops before an over-budget PID read");
        RequireLifetime(Data, 1, "window budget exhaustion retains snapshot lifetime discipline");
    }
}

class OwnedWindow final {
public:
    OwnedWindow(const wchar_t* Class, const wchar_t* Title) : Class(Class), Instance(GetModuleHandleW(nullptr)) {
        WNDCLASSEXW WindowClass{sizeof(WindowClass)};
        WindowClass.lpfnWndProc = DefWindowProcW;
        WindowClass.hInstance = Instance;
        WindowClass.lpszClassName = Class;
        Atom = RegisterClassExW(&WindowClass);
        if (!Atom) throw std::runtime_error("cannot register analysis-tool test window class");
        Window = CreateWindowExW(0, Class, Title, WS_OVERLAPPEDWINDOW, 0, 0, 160, 80,
            nullptr, nullptr, Instance, nullptr);
        if (!Window) {
            UnregisterClassW(Class, Instance);
            Atom = 0;
            throw std::runtime_error("cannot create analysis-tool test window");
        }
    }
    ~OwnedWindow() {
        if (Window) DestroyWindow(Window);
        if (Atom) UnregisterClassW(Class, Instance);
    }
    OwnedWindow(const OwnedWindow&) = delete;
    OwnedWindow& operator=(const OwnedWindow&) = delete;
    HWND Handle() const { return Window; }

private:
    const wchar_t* Class;
    HINSTANCE Instance{};
    ATOM Atom{};
    HWND Window{};
};

HWND OwnedTarget{};
unsigned RealEnumerations{};
struct EnumRequest { WNDENUMPROC Callback; LPARAM Parameter; };
BOOL CALLBACK OwnedCallback(HWND Window, LPARAM Parameter) {
    const auto& Request = *reinterpret_cast<const EnumRequest*>(Parameter);
    // Other windows are left untouched, and their titles/classes are not read.
    return Window == OwnedTarget ? Request.Callback(Window, Request.Parameter) : TRUE;
}
BOOL WINAPI EnumerateOwned(WNDENUMPROC Callback, LPARAM Parameter) {
    ++RealEnumerations;
    EnumRequest Request{Callback, Parameter};
    return EnumWindows(OwnedCallback, reinterpret_cast<LPARAM>(&Request));
}

void TestRealWindowsAndHandles() {
    struct Case { const wchar_t* Class; const wchar_t* Title; AnalysisToolEvidence Evidence; };
    const Case Cases[]{
        {L"OLLYDBG", L"", AnalysisToolEvidence::WindowClass},
        {L"Qt5152QWindowIcon", L"fixture.exe - IDA Pro", AnalysisToolEvidence::WindowIdentity},
        {L"Qt5152QWindowIcon", L"fixture.exe - x64dbg", AnalysisToolEvidence::WindowIdentity},
        {L"Qt5152QWindowIcon", L"Article mentioning IDA Pro", AnalysisToolEvidence::None},
        {L"Chrome_WidgetWin_1", L"IDA Pro", AnalysisToolEvidence::None},
        {L"WindowsForms10.Window.8.app.0.141b42a_r9_ad1", L"fixture.dll - dnSpy", AnalysisToolEvidence::WindowIdentity},
        {L"SunAwtFrame", L"Ghidra: fixture project", AnalysisToolEvidence::WindowIdentity}};
    for (const auto& Item : Cases) {
        OwnedWindow Window(Item.Class, Item.Title);
        OwnedTarget = Window.Handle();
        Fixture Data;
        FixtureScope Scope(Data);
        auto Apis = FakeApis;
        Apis.Enum = EnumerateOwned;
        Apis.ClassName = GetClassNameW;
        Apis.WindowText = GetWindowTextW;
        Apis.WindowProcess = GetWindowThreadProcessId;
        RealEnumerations = 0;
        const auto Status = Item.Evidence == AnalysisToolEvidence::None ? AnalysisToolStatus::Clear : AnalysisToolStatus::Detected;
        const auto Pid = Item.Evidence == AnalysisToolEvidence::None ? 0 : GetCurrentProcessId();
        Expect(ProbePreservingLastError(Apis, 0), Status, Item.Evidence, Pid,
            "production probe identifies real owned Windows class and title");
        Require(RealEnumerations == 1, "real EnumWindows is invoked exactly once per probe");
        RequireLifetime(Data, 1, "real window probe closes its injected process snapshot");
        Expect(ProbePreservingLastError(Apis, GetCurrentProcessId()), AnalysisToolStatus::Clear, AnalysisToolEvidence::None, 0,
            "real current-process window is excluded by production PID policy");
        OwnedTarget = nullptr;
    }

    DWORD Before{}, After{};
    Require(GetProcessHandleCount(GetCurrentProcess(), &Before) != FALSE, "read handle count before native analysis probes");
    for (unsigned I = 0; I < 16; ++I) {
        const auto CallerError = I % 2 == 0 ? DWORD{ERROR_SUCCESS} : DWORD{0x6A17B3E1U};
        const auto Result = ProbePreservingLastError(NativeApis, GetCurrentProcessId(), CallerError);
        // An operator's actual analysis tool may legitimately already be open.
        // Detection is accepted here; deterministic evidence is tested above.
        Require(Result.Status == AnalysisToolStatus::Clear || Result.Status == AnalysisToolStatus::Detected,
            "fully native probe completes without unavailable state");
    }
    Require(GetProcessHandleCount(GetCurrentProcess(), &After) != FALSE, "read handle count after native analysis probes");
    Require(After == Before, "native process and window probes do not leak snapshot handles");
}
}

unsigned AnalysisToolsTests() {
    Checks = 0;
    TestExecutableNames();
    TestWindowIdentities();
    TestInjectedProcessProbe();
    TestInjectedWindowProbe();
    TestEnumerationBudgets();
    TestRealWindowsAndHandles();
    return Checks;
}
