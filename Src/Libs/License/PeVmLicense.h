#pragma once

// Prototype licensing in the spirit of VMProtect's serial system: the
// protected wrapper embeds a 32-byte HMAC secret and requires a license key
// that is machine-locked with optional expiry; the loader verifies it before
// running the payload. Prototype strength: the secret is symmetric and
// embedded in the loader, so this raises the bar rather than providing
// unforgeable licensing.

#include <windows.h>

#include <array>
#include <cstdint>
#include <span>
#include <string>

#include "PeVmCrypto.h"
#include "WrapperFormat.h"

namespace pevm::license {

// System-drive volume serial; stable enough to lock a license to a machine
// without shipping hardware probes.
inline std::uint32_t MachineId() {
    wchar_t WindowsDirectory[MAX_PATH + 1] = L"C:\\Windows";
    UINT Length = GetWindowsDirectoryW(WindowsDirectory, MAX_PATH);
    if (Length == 0 || Length > MAX_PATH - 2) return 0;
    // The returned path starts with the system drive root, e.g. "C:\Windows";
    // its first three characters are the root "C:\".
    std::wstring Root(WindowsDirectory, 3);
    DWORD Serial = 0;
    if (!GetVolumeInformationW(Root.c_str(), nullptr, 0, &Serial, nullptr, nullptr, nullptr, 0)) {
        return 0;
    }
    return Serial;
}

inline LicensePayload MakePayload(std::uint32_t Machine, std::uint32_t Days,
                                  std::uint64_t IssuedFileTime,
                                  std::span<const std::uint8_t, KLicenseSecretBytes> Secret) {
    LicensePayload Payload{Machine, Days, IssuedFileTime, {}};
    crypto::HmacSha256 Mac(Secret);
    Mac.Update(std::span(reinterpret_cast<const std::uint8_t*>(&Payload.MachineId), 16));
    auto Tag = Mac.Finish();
    std::copy_n(Tag.begin(), sizeof(Payload.Tag), Payload.Tag);
    return Payload;
}

// Full verification: tag, machine lock and expiry. Returns an empty string on
// success, otherwise a short reason.
inline std::string VerifyPayload(const LicensePayload& Payload,
                                 std::span<const std::uint8_t, KLicenseSecretBytes> Secret,
                                 std::uint32_t CurrentMachine, std::uint64_t NowFileTime) {
    LicensePayload Expected{Payload.MachineId, Payload.Days, Payload.IssuedFileTime, {}};
    crypto::HmacSha256 Mac(Secret);
    Mac.Update(std::span(reinterpret_cast<const std::uint8_t*>(&Expected.MachineId), 16));
    auto Tag = Mac.Finish();
    if (!crypto::ConstantEqual(std::span(Tag).first(sizeof(Payload.Tag)),
                               std::span(Payload.Tag, sizeof(Payload.Tag)))) {
        return "license signature invalid";
    }
    if (Payload.MachineId != CurrentMachine) return "license is locked to another machine";
    if (Payload.Days != 0) {
        const auto Expiry = Payload.IssuedFileTime +
                            static_cast<std::uint64_t>(Payload.Days) * 864000000000ULL;
        if (NowFileTime >= Expiry) return "license expired";
    }
    return {};
}

inline std::string FormatLicense(const LicensePayload& Payload) {
    return KLicensePrefix + crypto::Base64Encode(
        std::span(reinterpret_cast<const std::uint8_t*>(&Payload), sizeof(Payload)));
}

} // namespace pevm::license
