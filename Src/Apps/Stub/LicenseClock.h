#pragma once

#include "PeVmLicense.h"
#include <filesystem>
#include <memory>

namespace pevm::activation {
std::filesystem::path LicenseClockDirectory();
std::filesystem::path LicenseClockPath(const LicensePolicy& Policy, const license::Digest& Machine,
                                       const std::filesystem::path& Directory);

// Holds a cross-process lock while the caller verifies authorization. Construction
// checks the persistent clock but never advances it. Commit only after the signed
// payload is accepted at EffectiveTime(); failed/expired cards must not update it.
class LicenseClockTransaction final {
public:
    LicenseClockTransaction(const LicensePolicy& Policy, const license::Digest& Machine,
                            const std::filesystem::path& Directory, std::uint64_t NowUtc);
    ~LicenseClockTransaction();
    LicenseClockTransaction(const LicenseClockTransaction&) = delete;
    LicenseClockTransaction& operator=(const LicenseClockTransaction&) = delete;
    LicenseClockTransaction(LicenseClockTransaction&&) = delete;
    LicenseClockTransaction& operator=(LicenseClockTransaction&&) = delete;

    std::uint64_t EffectiveTime() const noexcept;
    void Commit();

private:
    struct State;
    std::unique_ptr<State> Data;
};
} // namespace pevm::activation
