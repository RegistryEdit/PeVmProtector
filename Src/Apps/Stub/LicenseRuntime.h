#pragma once
#include "PeVmLicense.h"
#include <filesystem>
#include <stdexcept>
#include <string>

namespace pevm::activation {
class Cancelled final : public std::runtime_error {
public:
    Cancelled() : std::runtime_error("license input cancelled") {}
};

// Empty reason means valid. Every source, including the cache, is reverified.
bool TryVerifyLicense(const LicensePolicy& Policy, std::string_view Text, std::string& Reason,
                      bool* InvalidLicense = nullptr);
std::filesystem::path CacheDirectory();
std::filesystem::path CachePath(const LicensePolicy& Policy, const std::filesystem::path& Wrapper,
                                const std::filesystem::path& Directory);
std::string ReadLicenseCache(const LicensePolicy& Policy, const std::filesystem::path& Wrapper,
                             const std::filesystem::path& Directory, std::string& Reason);
void WriteLicenseCache(const LicensePolicy& Policy, const std::filesystem::path& Wrapper,
                       const std::filesystem::path& Directory, std::string_view Text);
// Tries each source independently. An invalid source never counts as authorization.
bool TryResolveLicense(const LicensePolicy& Policy, const std::filesystem::path& Wrapper,
                       const std::filesystem::path& Directory, std::string& Reason, std::string* VerifiedText = nullptr);
bool UseChineseLicenseUi();

// The native prompt returns only fully verified text; cancellation throws Cancelled.
std::string PromptForLicense(const LicensePolicy& Policy, const std::filesystem::path& Wrapper,
                              const std::string& InitialReason);
std::string EnsureLicense(const LicensePolicy& Policy, const std::filesystem::path& Wrapper, bool AllowDialog);
void InitializeLicenseSession(const LicensePolicy& Policy, std::string_view VerifiedText);
void RevalidateLicenseSession(bool Force = false);
bool HasLicenseSession();
std::uint64_t MonotonicLicenseTime(std::uint64_t NowUtc, std::uint64_t StartUtc,
                                  std::uint64_t NowTicks, std::uint64_t StartTicks);
bool LicenseCheckDue(std::uint64_t NowTicks, std::uint64_t LastTicks, std::uint64_t NextCheck);
} // namespace pevm::activation
