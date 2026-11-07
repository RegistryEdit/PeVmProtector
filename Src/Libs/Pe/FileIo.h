#pragma once

#include <cstdint>
#include <filesystem>
#include <span>
#include <vector>

namespace util {
std::vector<std::uint8_t> ReadFile(const std::filesystem::path& Path);
// Exclusive sibling staging file + flushed write + replacement rename.
// A failed commit never deletes the previous output.
void WriteFileAtomic(const std::filesystem::path& Path, std::span<const std::uint8_t> Data);
}
