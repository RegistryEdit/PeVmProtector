#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include "WrapperFormat.h"
#include "PeVmLicenseFormat.h"

namespace pevm::license {
using Digest = std::array<std::uint8_t, 32>;
using PublicKey = std::array<std::uint8_t, 72>;
inline constexpr std::size_t KMaximumTextBytes = 4096;
inline constexpr std::uint32_t KMaximumDays = 36500;
inline constexpr std::uint64_t KTicksPerDay = 864000000000ULL;
inline constexpr std::uint64_t KClockSkewTicks = 3000000000ULL;
inline constexpr std::uint64_t KMaximumTimestamp = 0x7fffffffffffffffULL;

// Fixed little-endian fields; CNG's 64-byte signature is r||s, big-endian.
#pragma pack(push, 1)
struct LicensePayload {
    std::uint32_t Version{KPayloadVersion};
    std::array<std::uint8_t, 16> LicenseId{};
    Digest KeyId{};
    Digest ProductId{};
    Digest Machine{};
    std::uint64_t IssuedFileTime{};
    std::uint64_t ExpiresFileTime{}; // zero means perpetual
    Digest UnlockKey{}; // v3: issuer-derived product secret, covered by the signature
    std::array<std::uint8_t, 64> Signature{};
};
#pragma pack(pop)
static_assert(sizeof(LicensePayload) == 228);
static_assert(offsetof(LicensePayload, UnlockKey) == 132);
static_assert(offsetof(LicensePayload, Signature) == 164);

std::uint64_t CurrentFileTime();
Digest MachineId();
Digest ParseMachineId(std::string_view Text);
Digest ProductId(std::string_view Text);
std::uint32_t ParseDays(std::string_view Text);

// DPAPI protects private files for the issuing Windows user; outputs never overwrite.
void GenerateKeyFiles(const std::filesystem::path& PrivatePath, const std::filesystem::path& PublicPath);
void ExportPublicKeyFile(const std::filesystem::path& PrivatePath, const std::filesystem::path& PublicPath);
PublicKey ReadPublicKey(const std::filesystem::path& Path);
LicensePolicy MakePolicy(const std::filesystem::path& PublicPath, std::string_view Product);
void ValidatePolicy(const LicensePolicy& Policy);
LicensePayload IssueLicense(const std::filesystem::path& PrivatePath, std::string_view Product,
                            const Digest& Machine, std::uint32_t Days, std::uint64_t IssuedFileTime,
                            bool Legacy = false);
// The signing key stays on the issuing machine. The build credential is DPAPI
// sealed for the build user, product/key bound and independently issuer signed.
void ExportBuildKeyFile(const std::filesystem::path& PrivatePath, const std::filesystem::path& Output,
                        std::string_view Product);
Digest ReadBuildKey(const std::filesystem::path& Path, const LicensePolicy& Policy);
// Authenticates the entire embedded image and footer; the key is absent from EXE.
std::vector<std::uint8_t> SealLicensedSecret(const Digest& UnlockKey, std::span<const std::uint8_t> Image,
                                          WrapperFooter& Footer, std::string_view Secret);
std::string OpenLicensedSecret(const Digest& UnlockKey, std::span<const std::uint8_t> Image,
                              const WrapperFooter& Footer, std::span<const std::uint8_t> Sealed);
std::string FormatLicense(const LicensePayload& Payload);
LicensePayload ParseLicense(std::string_view Text);
// Empty means valid; throws on platform/key failures. Reject either kind of failure.
std::string VerifyPayload(const LicensePayload& Payload, const LicensePolicy& Policy,
                           const Digest& CurrentMachine, std::uint64_t NowFileTime);
std::string ReadTextFile(const std::filesystem::path& Path);
void WriteNewTextFile(const std::filesystem::path& Path, std::string_view Text);
std::string ReadRuntimeLicense(const std::filesystem::path& WrapperPath);
} // namespace pevm::license
