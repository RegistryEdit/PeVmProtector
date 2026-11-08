#include "../../Src/Apps/Stub/AntiDebug.h"

#include <cstdio>
#include <cstdlib>
#include <string>

using PeVm::Stub::HardwareBreakpointStatus;
using PeVm::Stub::ThreadContextApis;

namespace {

const ThreadContextApis NativeApis{
    DuplicateHandle, CreateThread, SuspendThread, GetThreadContext,
    ResumeThread, WaitForSingleObject, CloseHandle};
int Checks = 0;
int EnvironmentReads = 0;
volatile LONG Resumes = 0;

void Require(bool Condition, const char* Message) {
    ++Checks;
    if (!Condition) {
        std::fprintf(stderr, "FAIL: %s (Win32=%lu)\n", Message, GetLastError());
        // A test may own a suspended thread: end the process instead of
        // unwinding past a stack request still referenced by that thread.
        ExitProcess(1);
    }
}

DWORD WINAPI ReadEnvironment(LPCWSTR Name, LPWSTR Buffer, DWORD Size) {
    ++EnvironmentReads;
    return GetEnvironmentVariableW(Name, Buffer, Size);
}

void TestDevelopmentPolicy() {
    constexpr auto Name = L"PEVM_ALLOW_DEBUGGER";
    const auto Size = GetEnvironmentVariableW(Name, nullptr, 0);
    std::wstring Previous(Size, L'\0');
    if (Size != 0) GetEnvironmentVariableW(Name, Previous.data(), Size);
    const wchar_t* Values[]{nullptr, L"", L"0", L"1", L"true", L"01", L"11", L"1 ", L" 1"};
    for (const auto Value : Values) {
        Require(SetEnvironmentVariableW(Name, Value) != FALSE, "set environment fixture");
        EnvironmentReads = 0;
        const auto Allowed = PeVm::Stub::DevelopmentDebuggerAllowed(ReadEnvironment, Name);
#if defined(PEVM_DEVELOPMENT_DEBUGGER)
        const bool Expected = Value && std::wstring(Value) == L"1";
        Require(Allowed == Expected, "Debug bypass requires exactly 1");
        Require(EnvironmentReads == 1, "Debug reads the policy once");
#else
        Require(!Allowed, "Release has no debugger bypass");
        Require(EnvironmentReads == 0, "Release must never query the bypass environment variable");
#endif
    }
    Require(!PeVm::Stub::DevelopmentDebuggerAllowed(nullptr, Name), "missing environment API denies bypass");
    Require(SetEnvironmentVariableW(Name, Size != 0 ? Previous.c_str() : nullptr) != FALSE,
            "restore environment fixture");
}

__declspec(noinline) void UnusedBreakpointTarget() {
    // Its address is a valid execution breakpoint site, never executed by
    // a test thread. Detection must inspect DR7, not wait for an exception.
    InterlockedIncrement(&Resumes);
}

struct ProbeRequest {
    const ThreadContextApis* Apis;
    HardwareBreakpointStatus Status = HardwareBreakpointStatus::Unavailable;
};

DWORD WINAPI ProbeThread(void* Parameter) {
    auto& Request = *static_cast<ProbeRequest*>(Parameter);
    Request.Status = PeVm::Stub::ProbeHardwareBreakpoints(*Request.Apis);
    return 0;
}

void TestRealRegisters(DWORD64 Enables, bool StaleAddresses) {
    ProbeRequest Request{&NativeApis};
    const auto Target = CreateThread(nullptr, 0, ProbeThread, &Request, CREATE_SUSPENDED, nullptr);
    Require(Target != nullptr, "create suspended register fixture");
    CONTEXT Context{};
    Context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    Require(GetThreadContext(Target, &Context) != FALSE, "read stopped fixture context");
    const auto Address = reinterpret_cast<DWORD64>(&UnusedBreakpointTarget);
    Context.Dr0 = (StaleAddresses || (Enables & 0x03)) ? Address : 0;
    Context.Dr1 = (StaleAddresses || (Enables & 0x0C)) ? Address : 0;
    Context.Dr2 = (StaleAddresses || (Enables & 0x30)) ? Address : 0;
    Context.Dr3 = (StaleAddresses || (Enables & 0xC0)) ? Address : 0;
    Context.Dr6 = 0;
    Context.Dr7 = Enables;
    Require(SetThreadContext(Target, &Context) != FALSE, "set actual hardware breakpoint registers");
    CONTEXT ReadBack{};
    ReadBack.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    Require(GetThreadContext(Target, &ReadBack) != FALSE, "verify actual hardware registers");
    Require((ReadBack.Dr7 & 0xFFU) == Enables, "OS retained breakpoint enable bits");
    // Windows may normalize disabled address registers to zero. A separate
    // injected snapshot below verifies stale nonzero addresses explicitly.
    Require(ResumeThread(Target) == 1, "resume register fixture exactly once");
    Require(WaitForSingleObject(Target, 10000) == WAIT_OBJECT_0, "probe completed without a suspended-thread hang");
    const auto Expected = Enables != 0 ? HardwareBreakpointStatus::Detected : HardwareBreakpointStatus::Clear;
    Require(Request.Status == Expected, "production probe reports actual DR7 state");
    Require(CloseHandle(Target) != FALSE, "close register fixture");
    // The fixture thread has exited, releasing its debug registers. The
    // controlling thread must remain clean (debug registers are per-thread).
    Require(PeVm::Stub::ProbeHardwareBreakpoints(NativeApis) == HardwareBreakpointStatus::Clear,
            "fixture leaves controlling thread clean");
}

BOOL WINAPI FailDuplicate(HANDLE, HANDLE, HANDLE, LPHANDLE, DWORD, BOOL, DWORD) { return FALSE; }
HANDLE WINAPI FailCreate(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD) {
    return nullptr;
}
DWORD WINAPI FailSuspend(HANDLE) { return static_cast<DWORD>(-1); }
BOOL WINAPI FailGet(HANDLE, LPCONTEXT) { return FALSE; }
BOOL WINAPI GetWithStaleAddresses(HANDLE Thread, LPCONTEXT Context) {
    if (!GetThreadContext(Thread, Context)) return FALSE;
    Context->Dr0 = Context->Dr1 = Context->Dr2 = Context->Dr3 = 0x12340000;
    Context->Dr7 &= ~static_cast<DWORD64>(0xFF);
    return TRUE;
}
DWORD WINAPI CountResume(HANDLE Thread) {
    InterlockedIncrement(&Resumes);
    return ResumeThread(Thread);
}

void TestFailuresAndLifetime() {
    auto Apis = NativeApis;
    Apis.Get = GetWithStaleAddresses;
    Require(PeVm::Stub::ProbeHardwareBreakpoints(Apis) == HardwareBreakpointStatus::Clear,
            "disabled nonzero addresses in a captured snapshot do not count as breakpoints");
    Apis.Get = nullptr;
    Require(PeVm::Stub::ProbeHardwareBreakpoints(Apis) == HardwareBreakpointStatus::Unavailable,
            "unresolved API is not a clean context");
    Apis = NativeApis;
    Apis.Duplicate = FailDuplicate;
    Require(PeVm::Stub::ProbeHardwareBreakpoints(Apis) == HardwareBreakpointStatus::Unavailable,
            "duplicate failure is unavailable");
    Apis = NativeApis;
    Apis.Create = FailCreate;
    Require(PeVm::Stub::ProbeHardwareBreakpoints(Apis) == HardwareBreakpointStatus::Unavailable,
            "worker creation failure is unavailable");
    Apis = NativeApis;
    Apis.Resume = CountResume;
    Apis.Suspend = FailSuspend;
    Resumes = 0;
    Require(PeVm::Stub::ProbeHardwareBreakpoints(Apis) == HardwareBreakpointStatus::Unavailable,
            "suspend failure is unavailable");
    Require(Resumes == 0, "failed suspend must not decrement someone else's suspend count");
    Apis.Suspend = SuspendThread;
    Apis.Get = FailGet;
    Require(PeVm::Stub::ProbeHardwareBreakpoints(Apis) == HardwareBreakpointStatus::Unavailable,
            "context failure is unavailable");
    Require(Resumes == 1, "failed context read still resumes caller exactly once");

    DWORD Before = 0, After = 0;
    Require(GetProcessHandleCount(GetCurrentProcess(), &Before) != FALSE, "read initial handle count");
    for (int I = 0; I != 64; ++I) {
        Require(PeVm::Stub::ProbeHardwareBreakpoints(NativeApis) == HardwareBreakpointStatus::Clear,
                "repeated real context capture");
        Require(PeVm::Stub::ProbeHardwareBreakpoints(Apis) == HardwareBreakpointStatus::Unavailable,
                "repeated failed context capture recovers");
        auto CreateFailure = NativeApis;
        CreateFailure.Create = FailCreate;
        Require(PeVm::Stub::ProbeHardwareBreakpoints(CreateFailure) == HardwareBreakpointStatus::Unavailable,
                "repeated create failure closes duplicate");
    }
    Require(GetProcessHandleCount(GetCurrentProcess(), &After) != FALSE, "read final handle count");
    Require(After == Before, "success and failure paths do not leak handles");
}

} // namespace

int main() {
    TestDevelopmentPolicy();
    TestRealRegisters(0, false);
    TestRealRegisters(0, true);
    for (unsigned Slot = 0; Slot != 4; ++Slot) TestRealRegisters(1ULL << (Slot * 2), false);
    TestRealRegisters(0x55, false);
    TestFailuresAndLifetime();
    std::printf("Anti-debug regression: %d checks passed (real DR0-DR3/DR7, policy, recovery, handles).\n", Checks);
    return 0;
}
