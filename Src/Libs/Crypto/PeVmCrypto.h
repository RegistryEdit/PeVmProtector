#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

// Shared primitives for the container format, the stub loader and the .vmp3
// codec: SHA-256/HMAC/PBKDF2, scrypt (RFC 7914) for password derivation and
// XTEA-CTR for payload encryption.
namespace pevm::crypto {

using Bytes = std::vector<std::uint8_t>;
using Sha256Digest = std::array<std::uint8_t, 32>;
using XteaKey = std::array<std::uint32_t, 4>;

class Sha256 {
public:
    void Update(std::span<const std::uint8_t> Input);
    Sha256Digest Finish();

    static Sha256Digest Digest(std::span<const std::uint8_t> Input);

private:
    void Compress(const std::uint8_t* InputBlock);

    std::array<std::uint32_t, 8> State = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                                          0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    std::array<std::uint8_t, 64> Block{};
    std::size_t Used{};
    std::uint64_t Total{};
};

class HmacSha256 {
public:
    explicit HmacSha256(std::span<const std::uint8_t> Key);
    void Update(std::span<const std::uint8_t> Input) { Hash.Update(Input); }
    Sha256Digest Finish();

private:
    Sha256 Hash;
    std::array<std::uint8_t, 64> Opad{};
};

Bytes Pbkdf2(std::span<const std::uint8_t> Password, std::span<const std::uint8_t> Salt,
             std::uint64_t Iterations, std::size_t DerivedLength);

// RFC 7914 scrypt. N must be a power of two > 1; the working set is
// 128 * R * N bytes.
Bytes Scrypt(std::span<const std::uint8_t> Password, std::span<const std::uint8_t> Salt,
             std::uint32_t N, std::uint32_t R, std::uint32_t P, std::size_t DerivedLength);

std::array<std::uint8_t, 8> XteaBlock(std::uint64_t Counter, const XteaKey& Key);
void XteaCtr(Bytes& Data, const XteaKey& Key, std::uint64_t Nonce);

// LZSS with a 4 KiB window: 3..18 byte matches as 2-byte (offset,len) tokens,
// literals inline. LzssDecompress verifies the exact expected size.
Bytes LzssCompress(std::span<const std::uint8_t> Input);
Bytes LzssDecompress(std::span<const std::uint8_t> Input, std::size_t ExpectedSize);

bool ConstantEqual(std::span<const std::uint8_t> A, std::span<const std::uint8_t> B);
std::string Hex(std::span<const std::uint8_t> Data);

std::string Base64Encode(std::span<const std::uint8_t> Data);
std::vector<std::uint8_t> Base64Decode(std::string_view Text);

} // namespace pevm::crypto
