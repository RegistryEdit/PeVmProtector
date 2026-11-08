#include "LicenseRuntime.h"
#include <windows.h>
#include <vector>

namespace pevm::activation {
namespace {
std::string EnvironmentLicense() {
    SetLastError(ERROR_SUCCESS);
    const auto Needed = GetEnvironmentVariableW(L"PEVM_LICENSE", nullptr, 0);
    if (!Needed) {
        if (GetLastError() == ERROR_ENVVAR_NOT_FOUND) return {};
        throw std::runtime_error("license environment value is empty or unreadable");
    }
    if (Needed > license::KMaximumTextBytes + 1) throw std::runtime_error("license environment value too long");
    std::vector<wchar_t> Buffer(Needed);
    const auto Length = GetEnvironmentVariableW(L"PEVM_LICENSE", Buffer.data(), Needed);
    if (!Length || Length >= Needed) throw std::runtime_error("license environment value changed while reading");
    std::string Text;
    for (DWORD I = 0; I < Length; ++I) {
        if (Buffer[I] > 127) throw std::runtime_error("license must be ASCII");
        Text.push_back(static_cast<char>(Buffer[I]));
    }
    return Text;
}
} // namespace

bool TryResolveLicense(const LicensePolicy& Policy, const std::filesystem::path& Wrapper,
                       const std::filesystem::path& Directory, std::string& Reason) {
    Reason.clear();
    try {
        const auto Text = EnvironmentLicense();
        if (!Text.empty() && TryVerifyLicense(Policy, Text, Reason)) return true;
    } catch (const std::exception& Error) { Reason = Error.what(); }
    try {
        const auto Path = std::filesystem::path(Wrapper.wstring() + L".license");
        if (std::filesystem::exists(Path) && TryVerifyLicense(Policy, license::ReadTextFile(Path), Reason)) return true;
    } catch (const std::exception& Error) { Reason = Error.what(); }
    if (!Directory.empty()) {
        try {
            std::string CacheReason;
            if (!ReadLicenseCache(Policy, Wrapper, Directory, CacheReason).empty()) { Reason.clear(); return true; }
            if (CacheReason != "no saved license") Reason = CacheReason;
        } catch (const std::exception& Error) { Reason = Error.what(); }
    }
    if (Reason.empty()) Reason = "license required";
    return false;
}

void EnsureLicense(const LicensePolicy& Policy, const std::filesystem::path& Wrapper, bool AllowDialog) {
    license::ValidatePolicy(Policy);
    std::filesystem::path Directory;
    try { Directory = CacheDirectory(); }
    catch (const std::exception&) { /* A missing profile cannot block valid manual authorization. */ }
    std::string Reason;
    if (TryResolveLicense(Policy, Wrapper, Directory, Reason)) return;
    if (!AllowDialog) throw std::runtime_error("license check failed: " + Reason);
    const auto Text = PromptForLicense(Policy, Wrapper, Reason);
    // Recheck at the launch boundary, including time elapsed while the dialog was open.
    if (!TryVerifyLicense(Policy, Text, Reason)) throw std::runtime_error("license check failed: " + Reason);
    try {
        if (Directory.empty()) throw std::runtime_error("no cache directory");
        WriteLicenseCache(Policy, Wrapper, Directory, Text);
    } catch (const std::exception&) {
        MessageBoxW(nullptr, UseChineseLicenseUi()
            ? L"卡密验证成功，但无法保存到当前用户的缓存。程序将继续启动；下次运行可能需要重新输入卡密。"
            : L"License verified, but it could not be saved for this Windows user. The program will start; you may need to enter the license again next time.",
            UseChineseLicenseUi() ? L"无法记住卡密" : L"License could not be remembered", MB_OK | MB_ICONWARNING);
    }
    // The cache warning is interactive too; a license may expire while it is open.
    if (!TryVerifyLicense(Policy, Text, Reason)) throw std::runtime_error("license check failed: " + Reason);
}
} // namespace pevm::activation
