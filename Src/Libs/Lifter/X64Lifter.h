#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "VmProtect.h"
#include "PeImage.h"

namespace x64lift {

struct LiftResult {
    vmprotect::LiftedProgram Program;
    std::string Json;
    std::size_t BasicBlockCount{};
};

struct MultiLiftResult {
    std::vector<LiftResult> Functions;
    std::string Json;
};

// One virtualization candidate discovered from .pdata / the export table.
struct FunctionCandidate {
    std::uint32_t Rva{};
    std::uint32_t Size{};
    std::string Name;   // export name when the function is exported
};

// Enumerates every function entry in a PE32+ image: RUNTIME_FUNCTION records
// from the exception directory provide the candidates, export names annotate
// them. MinimumBytes filters tiny thunks.
std::vector<FunctionCandidate> ScanFunctions(const std::filesystem::path& Input,
                                             std::size_t MinimumBytes = 16);
std::vector<FunctionCandidate> ScanFunctions(const pevm::pe::ImageView& Image,
                                             std::size_t MinimumBytes = 16);

// Per-function failures when lifting a candidate list; the successes still
// lift and serialize normally.
struct MultiLiftAttempt {
    MultiLiftResult Lifted;
    std::vector<std::pair<std::uint32_t, std::string>> Failures;
};

// Lifts every RVA, keeping the ones that succeed and recording why the rest
// were rejected (fail closed per function instead of the whole batch).
MultiLiftAttempt LiftPeFunctionsTolerant(const std::filesystem::path& Input,
                                         const std::vector<std::uint32_t>& FunctionRvas);
MultiLiftAttempt LiftPeFunctionsTolerant(const pevm::pe::ImageView& Image,
                                         const std::vector<std::uint32_t>& FunctionRvas);

// VMP-style mutation pass over a lifted program: algebraic rewrites whose
// result is provably identical and junk instructions written to scratch
// registers no lifted program reads. Seeded, so one seed reproduces one
// mutation layout.
void MutateProgram(vmprotect::LiftedProgram& Program, std::uint64_t Seed);

LiftResult LiftPeFunction(const std::filesystem::path& Input, std::uint32_t FunctionRva,
                          std::size_t MaximumBytes = 4096);
LiftResult LiftPeFunction(const pevm::pe::ImageView& Image, std::uint32_t FunctionRva,
                          std::size_t MaximumBytes = 4096);
// Lifts a bare machine-code blob (no PE container); FunctionRva only names
// the entry boundary. Used by `lift-raw` for direct ISA decode testing.
LiftResult LiftRawCode(const std::vector<std::uint8_t>& Code, std::uint32_t FunctionRva,
                       std::size_t MaximumBytes = 4096);
void WriteManifest(const std::filesystem::path& Output, const LiftResult& Result);
MultiLiftResult LiftPeFunctions(const std::filesystem::path& Input,
                                const std::vector<std::uint32_t>& FunctionRvas);
MultiLiftResult LiftPeFunctions(const pevm::pe::ImageView& Image,
                                const std::vector<std::uint32_t>& FunctionRvas);

// Serializes a lifted program into the authenticated VM image. The loader
// verifies HMAC-SHA256 over the header, entries, ciphertext and decoys before
// decrypting the XTEA-CTR instruction table. Key purposes are separated.
std::vector<std::uint8_t> SerializeVmp3(const LiftResult& Result, std::uint64_t Seed,
                                        std::string_view BuildSecret,
                                        std::span<const std::uint8_t> HandlerProfile,
                                        bool AntiDisassembly = false);
// Serializes several lifted programs into one authenticated VM image: a plain
// entry table (RVA, offset, count) precedes the concatenated encrypted
// instruction table, so the loader can install one bridge per function.
std::vector<std::uint8_t> SerializeVmp3Multi(const MultiLiftResult& Results, std::uint64_t Seed,
                                             std::string_view BuildSecret,
                                             std::span<const std::uint8_t> HandlerProfile,
                                             bool AntiDisassembly = false,
                                             std::vector<vmprotect::CompilationStats>* Statistics = nullptr);

} // namespace x64lift
