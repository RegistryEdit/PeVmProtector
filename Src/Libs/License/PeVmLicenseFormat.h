#pragma once

#include <cstdint>

namespace pevm::license {
// Stable public names: PEVM-<purpose>.<canonical Base64>.
// Wire-format revisions belong inside the payload, not in product/file names.
inline constexpr char KLicensePrefix[] = "PEVM-LICENSE.";
inline constexpr char KPublicKeyPrefix[] = "PEVM-PUBLIC.";
inline constexpr char KPrivateKeyPrefix[] = "PEVM-PRIVATE.";
inline constexpr std::uint32_t KPayloadVersion = 2;
} // namespace pevm::license
