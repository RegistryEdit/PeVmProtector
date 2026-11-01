#pragma once

#include <array>
#include <cstdint>
#include <span>

#pragma pack(push, 1)
struct WrapperFooter {
    std::array<char, 8> Magic;
    std::uint32_t Version;
    std::uint64_t PayloadSize;
    std::uint64_t PayloadOffset;
    std::uint64_t StubSize;
    std::uint64_t MetadataOffset;
    std::uint32_t MetadataSize;
    std::uint32_t SecretSize;
    std::array<std::uint8_t, 16> Salt;
    std::uint64_t SecretTag;
};

struct VmpMetadata {
    std::array<char, 8> Magic;
    std::uint32_t Version;
    std::uint64_t BuildId;
    std::uint32_t RuntimeRawOffset;
    std::uint32_t RuntimeRawSize;
    std::uint64_t RuntimeTag;
    std::uint32_t PayloadRawOffset;
    std::uint32_t PayloadRawSize;
    std::uint64_t PayloadTag;
    std::uint32_t VmDataRawOffset;
    std::uint32_t VmDataRawSize;
    std::uint64_t VmDataTag;
    std::array<std::uint8_t, 32> HandlerProfile;
    // v3: customer watermark, XOR-obfuscated UTF-8, NUL-padded.
    std::array<std::uint8_t, 64> Watermark;
    // v4: licensing. When LicenseRequired is nonzero the loader verifies a
    // license before running the payload (machine-locked, optional expiry).
    std::uint32_t LicenseRequired;
    std::array<std::uint8_t, 32> LicenseSecret;
};

struct Vmp3Header {
    std::array<char, 8> Magic;
    std::uint32_t Version;
    std::uint32_t FunctionCount;
    std::uint64_t Seed;
    std::uint32_t DecoySize;
    std::uint32_t Reserved;
};

// One .vmp3 v3 entry per virtualized function. InstructionOffset indexes the
// concatenated (still encrypted) instruction table in instruction units.
struct Vmp3Entry {
    std::uint32_t FunctionRva;
    std::uint32_t InstructionOffset;
    std::uint32_t InstructionCount;
    std::uint32_t Reserved;
};

struct Vmp3Instruction {
    std::uint8_t Op;
    std::uint8_t Dst;
    std::uint8_t Src;
    std::uint8_t Reserved;
    std::uint64_t Immediate;
    std::uint32_t Address;
    std::uint32_t Target;
};
#pragma pack(pop)

inline constexpr std::array<char, 8> KWrapperMagic = {'P','E','V','M','R','U','N','2'};
inline constexpr std::array<char, 8> KVmpMetadataMagic = {'V','M','P','M','E','T','A','2'};
inline constexpr std::array<char, 8> KVmp3Magic = {'P','E','V','M','V','M','3','\0'};

inline constexpr char KLicensePrefix[] = "PEVML1.";
inline constexpr std::size_t KLicenseSecretBytes = 32;

// Binary license payload wrapped inside a "PEVML1.<base64>" text key. The
// tag is HMAC-SHA256(secret, machineId/days/issued) truncated to 8 bytes.
#pragma pack(push, 1)
struct LicensePayload {
    std::uint32_t MachineId;
    std::uint32_t Days;              // validity days from issue; 0 = unlimited
    std::uint64_t IssuedFileTime;
    std::uint8_t Tag[8];
};
#pragma pack(pop)

inline std::uint64_t WrapperMix64(std::uint64_t Value) {
    Value += 0x9E3779B97F4A7C15ULL;
    Value = (Value ^ (Value >> 30)) * 0xBF58476D1CE4E5B9ULL;
    Value = (Value ^ (Value >> 27)) * 0x94D049BB133111EBULL;
    return Value ^ (Value >> 31);
}

// Per-build handler profile: a deterministic pseudo-random byte string keyed
// on the BuildId. It lives in .vmp2 and is mixed into the .vmp3 key material,
// so a loader that skips metadata validation cannot decrypt the VM program.
inline std::array<std::uint8_t, 32> MakeHandlerProfile(std::uint64_t BuildId) {
    auto State = BuildId ^ 0xD1B54A32D192ED03ULL;
    std::array<std::uint8_t, 32> Profile{};
    for (auto& Value : Profile) {
        State = WrapperMix64(State);
        Value = static_cast<std::uint8_t>(State >> 32);
    }
    return Profile;
}

inline std::uint64_t WrapperFingerprint(std::span<const std::uint8_t> Stub,
                                        std::span<const std::uint8_t> Payload,
                                        const std::array<std::uint8_t, 16>& Salt) {
    std::uint64_t Hash = 0xCBF29CE484222325ULL;
    auto Add = [&](std::uint8_t Value) { Hash = (Hash ^ Value) * 0x100000001B3ULL; };
    for (const auto Value : Stub) Add(Value);
    for (const auto Value : Payload) Add(Value);
    for (const auto Value : Salt) Add(Value);
    return WrapperMix64(Hash);
}

inline std::uint8_t WrapperSecretByte(std::uint64_t Fingerprint, std::size_t Index) {
    const auto Block = WrapperMix64(Fingerprint ^
        (static_cast<std::uint64_t>(Index >> 3) * 0xD6E8FEB86659FD93ULL));
    return static_cast<std::uint8_t>(Block >> ((Index & 7U) * 8));
}

inline std::uint64_t WrapperSecretTag(std::span<const std::uint8_t> Secret,
                                      std::uint64_t Fingerprint) {
    std::uint64_t Hash = Fingerprint ^ 0xA0761D6478BD642FULL;
    for (const auto Value : Secret) Hash = WrapperMix64(Hash ^ Value);
    return Hash;
}

inline std::uint64_t VmpRegionTag(std::span<const std::uint8_t> Region,
                                  std::uint64_t BuildId, std::uint64_t Domain) {
    std::uint64_t Hash = WrapperMix64(BuildId ^ Domain ^ Region.size());
    for (std::size_t I = 0; I < Region.size(); ++I) {
        Hash = WrapperMix64(Hash ^ Region[I] ^ (static_cast<std::uint64_t>(I) << (I & 7U)));
    }
    return Hash;
}
