#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace pevm::pe {

struct ImageInfo {
    std::uint16_t Machine{};
    std::uint16_t Sections{};
    std::uint32_t EntryRva{};
    bool Pe64{};
    std::uint16_t Subsystem{};
};

struct Section {
    std::string Name;
    std::uint32_t VirtualAddress{}, VirtualSize{}, RawOffset{}, RawSize{}, Characteristics{};
    bool Executable() const { return (Characteristics & 0x20000000U) != 0; }
};

struct DataDirectory {
    std::uint32_t Address{}, Size{};
};

// Validated view of an on-disk PE, not of a mapped image. The caller owns the
// bytes and must keep them alive and unchanged for the lifetime of this view.
// Metadata is decoded by value; no unaligned Windows structure casts.
class ImageView {
public:
    explicit ImageView(std::span<const std::uint8_t> File);
    const ImageInfo& Info() const { return Header; }
    const std::vector<Section>& Sections() const { return SectionTable; }
    std::size_t NtOffset() const { return Nt; }
    std::uint16_t OptionalHeaderSize() const { return OptionalSize; }
    std::uint32_t SizeOfHeaders() const { return HeaderSize; }
    std::uint32_t SizeOfImage() const { return ImageSize; }
    std::uint32_t SectionAlignment() const { return VirtualAlignment; }
    std::uint32_t FileAlignment() const { return RawAlignment; }
    std::uint32_t SizeOfInitializedData() const { return InitializedDataSize; }
    std::span<const std::uint8_t> FileBytes() const { return File; }
    DataDirectory Directory(std::size_t Index) const;
    // Certificate directory (index 4) uses a file offset, not an RVA.
    std::span<const std::uint8_t> DirectoryBytes(std::size_t Index) const;
    const Section* SectionAt(std::uint32_t Rva) const;
    std::span<const std::uint8_t> FileTailAtRva(std::uint32_t Rva) const;
    std::span<const std::uint8_t> FileBytesAtRva(std::uint32_t Rva, std::size_t Size) const;
    std::span<const std::uint8_t> CodeAtRva(std::uint32_t Rva, std::size_t MaximumBytes) const;
    std::string StringAtRva(std::uint32_t Rva) const;
    void RequireX64() const;

private:
    std::span<const std::uint8_t> File;
    ImageInfo Header;
    std::size_t Nt{};
    std::uint16_t OptionalSize{};
    std::uint32_t HeaderSize{}, ImageSize{};
    std::uint32_t VirtualAlignment{}, RawAlignment{}, InitializedDataSize{};
    std::vector<Section> SectionTable;
    std::array<DataDirectory, 16> Directories{};
};

} // namespace pevm::pe
