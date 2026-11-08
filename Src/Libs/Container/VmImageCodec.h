#pragma once

#include "PeVmCrypto.h"
#include "VmProtect.h"

#include <span>
#include <string_view>
#include <vector>

namespace pevm {

struct DecodedVmFunction {
    vmprotect::LiftedProgram Program;
    std::uint64_t Seed{};
};

// Internal wire revision only; the public feature name remains VM protection.
inline constexpr std::uint32_t KVmImageVersion = 6;
inline constexpr std::size_t KVmImageTagSize = 32;

crypto::Bytes EncodeVmImage(std::span<const vmprotect::LiftedProgram> Programs,
                           std::uint64_t Seed, std::string_view BuildSecret,
                           std::span<const std::uint8_t> HandlerProfile, bool Decoys,
                           std::vector<vmprotect::CompilationStats>* Statistics = nullptr);

// Authenticates the entire image before allocating/decrypting its instruction
// table. Rejects noncanonical tables, reserved fields and trailing bytes.
std::vector<DecodedVmFunction> DecodeVmImage(std::span<const std::uint8_t> Data,
                                           std::string_view BuildSecret,
                                           std::span<const std::uint8_t> HandlerProfile);

} // namespace pevm
