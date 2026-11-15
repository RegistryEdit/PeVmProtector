#include "LicenseRuntime.h"
#include "LicenseClock.h"
#include <windows.h>
#include <dpapi.h>
#include <atomic>
#include <algorithm>
#include <cstring>
#include <mutex>
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
                       const std::filesystem::path& Directory, std::string& Reason, std::string* VerifiedText) {
    Reason.clear();
    if (VerifiedText) VerifiedText->clear();
    const auto Accept = [&](const std::string& Text) {
        if (!TryVerifyLicense(Policy, Text, Reason)) return false;
        if (VerifiedText) *VerifiedText = license::FormatLicense(license::ParseLicense(Text));
        return true;
    };
    try {
        const auto Text = EnvironmentLicense();
        if (!Text.empty() && Accept(Text)) return true;
    } catch (const std::exception& Error) { Reason = Error.what(); }
    try {
        const auto Path = std::filesystem::path(Wrapper.wstring() + L".license");
        if (std::filesystem::exists(Path) && Accept(license::ReadTextFile(Path))) return true;
    } catch (const std::exception& Error) { Reason = Error.what(); }
    if (!Directory.empty()) {
        try {
            std::string CacheReason;
            const auto Text = ReadLicenseCache(Policy, Wrapper, Directory, CacheReason);
            if (!Text.empty() && Accept(Text)) { Reason.clear(); return true; }
            if (CacheReason != "no saved license") Reason = CacheReason;
        } catch (const std::exception& Error) { Reason = Error.what(); }
    }
    if (Reason.empty()) Reason = "license required";
    return false;
}

std::string EnsureLicense(const LicensePolicy& Policy, const std::filesystem::path& Wrapper, bool AllowDialog) {
    license::ValidatePolicy(Policy);
    std::filesystem::path Directory;
    try { Directory = CacheDirectory(); }
    catch (const std::exception&) { /* A missing profile cannot block valid manual authorization. */ }
    std::string Reason;
    std::string VerifiedText;
    if (TryResolveLicense(Policy, Wrapper, Directory, Reason, &VerifiedText)) return VerifiedText;
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
    return Text;
}

namespace {
struct Session {
    std::mutex Mutex;
    LicensePolicy Policy{};
    std::vector<std::uint8_t> Sealed;
    std::atomic<bool> Active{};
    std::atomic<bool> Initialized{};
    std::atomic<std::uint64_t> NextCheck{};
    std::uint64_t StartUtc{}, StartTicks{};
    bool Failed{};
};
// The watchdog outlives CRT teardown; keep its encrypted state alive until exit.
Session& GSession = *new Session;
struct SensitiveBytes {
    std::vector<std::uint8_t> Data;
    ~SensitiveBytes() { if (!Data.empty()) SecureZeroMemory(Data.data(), Data.size()); }
};
}
std::uint64_t MonotonicLicenseTime(std::uint64_t NowUtc, std::uint64_t StartUtc,
                                  std::uint64_t NowTicks, std::uint64_t StartTicks) {
    if (NowUtc == 0 || NowUtc > license::KMaximumTimestamp || StartUtc == 0 ||
        NowTicks < StartTicks || StartUtc > license::KMaximumTimestamp ||
        NowTicks - StartTicks > (license::KMaximumTimestamp - StartUtc) / 10000)
        throw std::runtime_error("invalid license session clock");
    const auto Expected = StartUtc + (NowTicks - StartTicks) * 10000;
    if (NowUtc < Expected && Expected - NowUtc > license::KClockSkewTicks)
        throw std::runtime_error("system clock rolled back during license session");
    return std::max(NowUtc, Expected);
}
bool LicenseCheckDue(std::uint64_t NowTicks, std::uint64_t LastTicks, std::uint64_t NextCheck) {
    if (NowTicks < LastTicks || LastTicks > UINT64_MAX - 30000 ||
        (NextCheck != 0 && NextCheck != LastTicks + 30000))
        throw std::runtime_error("invalid license check schedule");
    return NowTicks >= NextCheck;
}
void InitializeLicenseSession(const LicensePolicy& Policy, std::string_view VerifiedText) {
    std::string Reason;
    if (!TryVerifyLicense(Policy, VerifiedText, Reason)) throw std::runtime_error("license session rejected: " + Reason);
    auto Payload = license::ParseLicense(VerifiedText);
    struct Erase { license::LicensePayload& Payload; ~Erase() { SecureZeroMemory(&Payload, sizeof(Payload)); } } Eraser{Payload};
    SensitiveBytes Plain;
    Plain.Data.resize((sizeof(Payload) + 15) & ~std::size_t(15));
    std::memcpy(Plain.Data.data(), &Payload, sizeof(Payload));
    if (!CryptProtectMemory(Plain.Data.data(), static_cast<DWORD>(Plain.Data.size()), CRYPTPROTECTMEMORY_SAME_PROCESS))
        throw std::runtime_error("cannot protect license session memory");
    const std::lock_guard Lock(GSession.Mutex);
    if (GSession.Initialized.load(std::memory_order_acquire))
        throw std::runtime_error("license session already initialized");
    GSession.Policy = Policy;
    GSession.Sealed = std::move(Plain.Data);
    GSession.StartUtc = license::CurrentFileTime();
    GSession.StartTicks = GetTickCount64();
    GSession.NextCheck.store(0, std::memory_order_relaxed);
    GSession.Active.store(true, std::memory_order_release);
    GSession.Initialized.store(true, std::memory_order_release);
}
bool HasLicenseSession() {
    return GSession.Initialized.load(std::memory_order_acquire) || GSession.Active.load(std::memory_order_acquire);
}
void RevalidateLicenseSession(bool Force) {
    if (!HasLicenseSession()) return;
    const std::lock_guard Lock(GSession.Mutex);
    try {
        const auto Ticks = GetTickCount64();
        const auto Next = GSession.NextCheck.load(std::memory_order_relaxed);
        if (!GSession.Initialized.load(std::memory_order_acquire) || !GSession.Active.load(std::memory_order_acquire) ||
            GSession.Failed || GSession.Sealed.size() != ((sizeof(license::LicensePayload) + 15) & ~std::size_t(15)))
            throw std::runtime_error("invalid license session state");
        const auto Due = LicenseCheckDue(Ticks, GSession.StartTicks, Next);
        if (!Force && !Due) return;
        SensitiveBytes Plain{GSession.Sealed};
        if (!CryptUnprotectMemory(Plain.Data.data(), static_cast<DWORD>(Plain.Data.size()), CRYPTPROTECTMEMORY_SAME_PROCESS))
            throw std::runtime_error("cannot unlock license session memory");
        license::LicensePayload Payload;
        std::memcpy(&Payload, Plain.Data.data(), sizeof(Payload));
        struct Erase { license::LicensePayload& Payload; ~Erase() { SecureZeroMemory(&Payload, sizeof(Payload)); } } Eraser{Payload};
        const auto Machine = license::MachineId();
        const auto Now = MonotonicLicenseTime(license::CurrentFileTime(), GSession.StartUtc, Ticks, GSession.StartTicks);
        LicenseClockTransaction Clock(GSession.Policy, Machine, LicenseClockDirectory(), Now);
        const auto Reason = license::VerifyPayload(Payload, GSession.Policy, Machine, Clock.EffectiveTime());
        if (!Reason.empty()) throw std::runtime_error("license session check failed: " + Reason);
        Clock.Commit();
        // Every successful check becomes the next monotonic anchor, including forward
        // clock corrections. Reverting to the original startup time cannot extend expiry.
        GSession.StartUtc = Clock.EffectiveTime();
        GSession.StartTicks = Ticks;
        GSession.NextCheck.store(Ticks + 30000, std::memory_order_relaxed);
    } catch (...) {
        GSession.Failed = true; // A failed check remains fatal even if its caller catches it.
        throw;
    }
}
} // namespace pevm::activation
