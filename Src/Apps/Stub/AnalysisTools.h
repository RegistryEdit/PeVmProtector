#pragma once

#include <windows.h>
#include <tlhelp32.h>
#include <string_view>

namespace PeVm::Stub {

enum class AnalysisToolStatus { Unavailable, Clear, Detected };
enum class AnalysisToolEvidence { None, ProcessName, WindowClass, WindowIdentity };

struct AnalysisToolResult {
    AnalysisToolStatus Status{AnalysisToolStatus::Unavailable};
    AnalysisToolEvidence Evidence{AnalysisToolEvidence::None};
    DWORD ProcessId{};
};

// Resolve APIs in normal caller context. The probe neither loads modules nor
// inspects arbitrary process data, logs names/titles, or terminates processes.
struct AnalysisToolApis {
    decltype(&::CreateToolhelp32Snapshot) Snapshot{};
    decltype(&::Process32FirstW) First{};
    decltype(&::Process32NextW) Next{};
    decltype(&::CloseHandle) Close{};
    decltype(&::EnumWindows) Enum{};
    decltype(&::GetClassNameW) ClassName{};
    decltype(&::GetWindowTextW) WindowText{};
    decltype(&::GetWindowThreadProcessId) WindowProcess{};
};

bool IsAnalysisExecutable(std::wstring_view Name) noexcept;
AnalysisToolEvidence ClassifyAnalysisWindow(std::wstring_view Class, std::wstring_view Title) noexcept;
AnalysisToolResult ProbeAnalysisTools(const AnalysisToolApis& Apis, DWORD ExcludedPid) noexcept;

} // namespace PeVm::Stub
