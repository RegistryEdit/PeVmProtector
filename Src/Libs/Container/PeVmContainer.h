#pragma once

// Container format (v5) and the key-derivation VM: packing, unpacking and
// integrity verification of .pvm containers, shared by the CLI and the loader.

#include <array>
#include <bit>
#include <cstring>
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <stdexcept>
#include <type_traits>
#include <vector>

#include "PeVmCrypto.h"
#include "PeImage.h"
#include "FileIo.h"

using Bytes = pevm::crypto::Bytes;
namespace crypto = pevm::crypto;

namespace util {

template <typename T>
constexpr T Bswap(T Value) {
    static_assert(std::is_integral_v<T>);
    using U = std::make_unsigned_t<T>;
    U X = static_cast<U>(Value), Y = 0;
    for (std::size_t I = 0; I < sizeof(T); ++I) Y = static_cast<U>((Y << 8) | ((X >> (I * 8)) & 0xff));
    return static_cast<T>(Y);
}

template <typename T>
T LoadLe(std::span<const std::uint8_t> Data, std::size_t Offset) {
    static_assert(std::is_integral_v<T>);
    if (Offset > Data.size() || sizeof(T) > Data.size() - Offset) {
        throw std::runtime_error("truncated input");
    }
    T Value{};
    std::memcpy(&Value, Data.data() + Offset, sizeof(T));
    if constexpr (std::endian::native == std::endian::big) {
        Value = Bswap(Value);
    }
    return Value;
}

template <typename T>
void AppendLe(Bytes& Out, T Value) {
    static_assert(std::is_integral_v<T>);
    if constexpr (std::endian::native == std::endian::big) {
        Value = Bswap(Value);
    }
    const auto* P = reinterpret_cast<const std::uint8_t*>(&Value);
    Out.insert(Out.end(), P, P + sizeof(T));
}

std::string Hex(std::span<const std::uint8_t> Data);
Bytes FromHex(std::string_view Text);

} // namespace util

// Key-VM opcodes: the container derives its content key by running this
// bytecode (random opcode mapping per container) over the scrypt output.
enum class Op : std::uint8_t {
    MovI=0x01, Load64=0x02, Xor=0x03, Add=0x04, Mul=0x05,
    Rol=0x06, Store64=0x07, Out64=0x08, XorI=0x09, AddI=0x0A, Halt=0xFF
};

constexpr std::size_t KOpcodeCount = 11;
using OpcodeMap = std::array<std::uint8_t, KOpcodeCount>;

constexpr OpcodeMap KIdentityMap = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0xFF
};

Op DecodeOp(std::uint8_t Encoded, const OpcodeMap& Map);
Bytes KeyProgram(const OpcodeMap& Map = KIdentityMap);

// Password KDF parameters stored in the container header. The single
// supported KDF is scrypt (RFC 7914); Id guards against stranger headers.
struct KdfParams {
    std::uint8_t Id{};
    std::uint8_t LogN{};
    std::uint8_t R{};
    std::uint8_t P{};
};

// 2^14 * 128 * 8 = 16 MiB working set, ~150ms per derivation in Release.
constexpr KdfParams KDefaultKdf{1, 14, 8, 1};

std::array<std::uint32_t, 4> DeriveKey(std::string_view Password, std::span<const std::uint8_t, 8> Nonce,
                                       std::span<const std::uint8_t> Program,
                                       const OpcodeMap& Map, const KdfParams& Params);

using PeInfo = pevm::pe::ImageInfo;

// IMAGE_SUBSYSTEM values the tool talks about by name.
constexpr std::uint16_t KSubsystemNative = 1;
constexpr std::uint16_t KSubsystemGui = 2;
constexpr std::uint16_t KSubsystemConsole = 3;

const char* SubsystemName(std::uint16_t Subsystem);
PeInfo ParsePe(std::span<const std::uint8_t> Data);

#pragma pack(push,1)
struct ContainerHeader {
    char Magic[8];
    std::uint16_t Version;
    std::uint16_t HeaderSize;
    std::uint16_t Machine;
    std::uint16_t SectionCount;
    std::uint16_t Subsystem;
    std::uint8_t Compression;   // 0 = stored, 1 = LZSS
    std::uint8_t Reserved;
    std::uint32_t EntryRva;
    std::uint64_t OriginalSize;   // uncompressed payload size
    std::uint32_t ProgramSize;
    std::uint32_t PayloadSize;    // stored (possibly compressed) size
    std::uint8_t Nonce[8];
    std::uint8_t OpcodeMap[KOpcodeCount];
    std::uint8_t PasswordCheck[16];
    std::uint8_t PlainSha256[32];
    // KDF id and scrypt parameters (N stored as log2).
    std::uint8_t KdfId;
    std::uint8_t KdfLogN;
    std::uint8_t KdfR;
    std::uint8_t KdfP;
};
#pragma pack(pop)

constexpr std::uint8_t KCompressionNone = 0;
constexpr std::uint8_t KCompressionLzss = 1;

ContainerHeader ParseContainer(std::span<const std::uint8_t> File);

namespace pevm::build { class Log; }
// In-memory build stage: no file I/O or completion event. Callers can reuse
// the same immutable input snapshot for inspection, lifting and packing.
Bytes PackContainer(std::span<const std::uint8_t> Plain, std::string_view Password,
                    bool Compress = false, pevm::build::Log* Progress = nullptr);
void CmdPack(const std::filesystem::path& Input, const std::filesystem::path& Output,
             std::string_view Password, bool Compress = false, pevm::build::Log* Progress = nullptr);
void CmdUnpack(const std::filesystem::path& Input, const std::filesystem::path& Output,
               std::string_view Password);
std::vector<std::uint8_t> UnpackContainer(std::span<const std::uint8_t> Container,
                                          std::string_view Password);
