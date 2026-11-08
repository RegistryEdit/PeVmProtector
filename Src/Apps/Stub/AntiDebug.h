#pragma once

#include <windows.h>

namespace PeVm::Stub {

using ReadEnvironmentFn = DWORD(WINAPI*)(LPCWSTR, LPWSTR, DWORD);

// Release always returns false without reading the environment. The caller
// also compiles out name decoding/API resolution in that configuration.
bool DevelopmentDebuggerAllowed(ReadEnvironmentFn Read, const wchar_t* Name) noexcept;

enum class HardwareBreakpointStatus { Unavailable, Clear, Detected };

// Resolve every API before starting the worker: the suspended caller may
// hold CRT/loader locks, so the worker must not resolve exports or allocate.
struct ThreadContextApis {
    decltype(&::DuplicateHandle) Duplicate;
    decltype(&::CreateThread) Create;
    decltype(&::SuspendThread) Suspend;
    decltype(&::GetThreadContext) Get;
    decltype(&::ResumeThread) Resume;
    decltype(&::WaitForSingleObject) Wait;
    decltype(&::CloseHandle) Close;
};

// Call from normal startup code, never DllMain/TLS callbacks. Samples only
// the calling thread; no periodic scan of application threads is performed.
HardwareBreakpointStatus ProbeHardwareBreakpoints(const ThreadContextApis& Apis) noexcept;

} // namespace PeVm::Stub
