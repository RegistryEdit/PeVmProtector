#include "AntiDebug.h"

#include <intrin.h>

namespace PeVm::Stub {

bool DevelopmentDebuggerAllowed(ReadEnvironmentFn Read, const wchar_t* Name) noexcept {
#if defined(PEVM_DEVELOPMENT_DEBUGGER)
    wchar_t Value[2]{};
    return Read != nullptr && Read(Name, Value, 2) == 1 && Value[0] == L'1';
#else
    (void)Read;
    (void)Name;
    return false;
#endif
}

namespace {

struct ContextRequest {
    const ThreadContextApis* Apis;
    HANDLE Target;
    HardwareBreakpointStatus Status = HardwareBreakpointStatus::Unavailable;
};

DWORD WINAPI ReadStoppedThread(void* Parameter) {
    auto& Request = *static_cast<ContextRequest*>(Parameter);
    const auto& Apis = *Request.Apis;
    CONTEXT Context{};
    Context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (Apis.Suspend(Request.Target) == static_cast<DWORD>(-1)) return 0;

    BOOL Read = FALSE;
    // No allocation, export resolution, logging or locks while the caller
    // is suspended. Always undo exactly our own suspend, including failures.
    __try {
        Read = Apis.Get(Request.Target, &Context);
    } __finally {
        if (Apis.Resume(Request.Target) == static_cast<DWORD>(-1)) {
            // A suspended owner cannot recover. Never leave it hung or let
            // the request/handle lifetime end while the worker still runs.
            __fastfail(FAST_FAIL_FATAL_APP_EXIT);
        }
    }
    if (Read) {
        // DR7 L0/G0 ... L3/G3 enable the four slots. Stale DR0-DR3 addresses
        // with every slot disabled are not active breakpoints.
        Request.Status = (Context.Dr7 & 0xFFU) != 0
            ? HardwareBreakpointStatus::Detected : HardwareBreakpointStatus::Clear;
    }
    return 0;
}

} // namespace

HardwareBreakpointStatus ProbeHardwareBreakpoints(const ThreadContextApis& Apis) noexcept {
    if (!Apis.Duplicate || !Apis.Create || !Apis.Suspend || !Apis.Get ||
        !Apis.Resume || !Apis.Wait || !Apis.Close) {
        return HardwareBreakpointStatus::Unavailable;
    }

    HANDLE Target = nullptr;
    if (!Apis.Duplicate(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(),
                        &Target, THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT, FALSE, 0)) {
        return HardwareBreakpointStatus::Unavailable;
    }
    ContextRequest Request{&Apis, Target};
    const auto Worker = Apis.Create(nullptr, 0, ReadStoppedThread, &Request, 0, nullptr);
    if (Worker == nullptr) {
        Apis.Close(Target);
        return HardwareBreakpointStatus::Unavailable;
    }

    // Join before releasing the stack request or target handle. A wait
    // failure/timeout cannot safely return while the worker may still use it.
    if (Apis.Wait(Worker, 10000) != WAIT_OBJECT_0) __fastfail(FAST_FAIL_FATAL_APP_EXIT);
    Apis.Close(Worker);
    Apis.Close(Target);
    return Request.Status;
}

} // namespace PeVm::Stub
