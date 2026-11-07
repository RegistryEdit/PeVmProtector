#include "PeVmLicense.h"
#include "PeVmCrypto.h"
#include <windows.h>
#include <bcrypt.h>
#include <dpapi.h>
#include <algorithm>
#include <charconv>
#include <cstddef>
#include <cstring>
#include <fstream>
#include <stdexcept>
#include <vector>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")

namespace pevm::license {
namespace {
constexpr NTSTATUS KInvalidSignature = static_cast<NTSTATUS>(0xC000A000UL);

void Check(NTSTATUS Status, const char* Message) {
    if (Status < 0) throw std::runtime_error(Message);
}
struct Algorithm {
    BCRYPT_ALG_HANDLE Handle{};
    Algorithm() {
        Check(BCryptOpenAlgorithmProvider(&Handle, BCRYPT_ECDSA_P256_ALGORITHM,
                                          MS_PRIMITIVE_PROVIDER, 0), "cannot open ECDSA provider");
    }
    ~Algorithm() { if (Handle) BCryptCloseAlgorithmProvider(Handle, 0); }
    Algorithm(const Algorithm&) = delete;
    Algorithm& operator=(const Algorithm&) = delete;
};
struct Key {
    BCRYPT_KEY_HANDLE Handle{};
    Key() = default;
    ~Key() { if (Handle) BCryptDestroyKey(Handle); }
    Key(const Key&) = delete;
    Key& operator=(const Key&) = delete;
};
struct LocalBlob {
    DATA_BLOB Blob{};
    ~LocalBlob() {
        if (Blob.pbData) { SecureZeroMemory(Blob.pbData, Blob.cbData); LocalFree(Blob.pbData); }
    }
};
struct SecretBytes {
    std::vector<std::uint8_t> Data;
    ~SecretBytes() { if (!Data.empty()) SecureZeroMemory(Data.data(), Data.size()); }
};
bool Nonzero(std::span<const std::uint8_t> Data) {
    return std::any_of(Data.begin(), Data.end(), [](auto B) { return B != 0; });
}
std::span<const std::uint8_t> Bytes(std::string_view Text) {
    return {reinterpret_cast<const std::uint8_t*>(Text.data()), Text.size()};
}
std::string_view Trim(std::string_view Text) {
    const auto Begin = Text.find_first_not_of(" \t\r\n");
    if (Begin == std::string_view::npos) return {};
    return Text.substr(Begin, Text.find_last_not_of(" \t\r\n") - Begin + 1);
}
std::vector<std::uint8_t> Decode(std::string_view Text, std::string_view Prefix) {
    if (Text.size() > KMaximumTextBytes) throw std::runtime_error("license/key text too long");
    Text = Trim(Text);
    if (!Text.starts_with(Prefix)) {
        throw std::runtime_error("unsupported license/key format; reissue legacy licenses using signing keys");
    }
    const auto Encoded = Text.substr(Prefix.size());
    if (Encoded.empty() || Encoded.size() % 4 != 0) throw std::runtime_error("invalid license/key encoding");
    auto Decoded = crypto::Base64Decode(Encoded);
    // Strict roundtrip rejects misplaced padding, whitespace and trailing junk.
    if (crypto::Base64Encode(Decoded) != Encoded) throw std::runtime_error("noncanonical license/key encoding");
    return Decoded;
}
void ImportPublic(const Algorithm& Provider, Key& Result, const PublicKey& Public) {
    BCRYPT_ECCKEY_BLOB Header{};
    std::memcpy(&Header, Public.data(), sizeof(Header));
    if (Header.dwMagic != BCRYPT_ECDSA_PUBLIC_P256_MAGIC || Header.cbKey != 32) {
        throw std::runtime_error("invalid ECDSA P-256 public key");
    }
    Check(BCryptImportKeyPair(Provider.Handle, nullptr, BCRYPT_ECCPUBLIC_BLOB, &Result.Handle,
                              const_cast<PUCHAR>(Public.data()), static_cast<ULONG>(Public.size()), 0),
          "invalid ECDSA public key point");
}
PublicKey ExportPublic(const Key& SigningKey) {
    PublicKey Public{};
    ULONG Written{};
    Check(BCryptExportKey(SigningKey.Handle, nullptr, BCRYPT_ECCPUBLIC_BLOB, Public.data(),
                          static_cast<ULONG>(Public.size()), &Written, 0), "cannot export public key");
    if (Written != Public.size()) throw std::runtime_error("unexpected public key size");
    return Public;
}
void ImportPrivate(const Algorithm& Provider, Key& Result, const std::filesystem::path& Path) {
    auto Protected = Decode(ReadTextFile(Path), KPrivateKeyPrefix);
    DATA_BLOB Input{static_cast<DWORD>(Protected.size()), Protected.data()};
    LocalBlob Plain;
    if (!CryptUnprotectData(&Input, nullptr, nullptr, nullptr, nullptr,
                            CRYPTPROTECT_UI_FORBIDDEN, &Plain.Blob)) {
        throw std::runtime_error("cannot unlock signing key: use the issuing Windows account and machine");
    }
    BCRYPT_ECCKEY_BLOB Header{};
    if (Plain.Blob.cbData != sizeof(Header) + 96) throw std::runtime_error("invalid private key size");
    std::memcpy(&Header, Plain.Blob.pbData, sizeof(Header));
    if (Header.dwMagic != BCRYPT_ECDSA_PRIVATE_P256_MAGIC || Header.cbKey != 32) {
        throw std::runtime_error("invalid ECDSA private key");
    }
    Check(BCryptImportKeyPair(Provider.Handle, nullptr, BCRYPT_ECCPRIVATE_BLOB, &Result.Handle,
                              Plain.Blob.pbData, Plain.Blob.cbData, 0), "cannot import signing key");
}
Digest SignatureHash(const LicensePayload& Payload) {
    crypto::Sha256 Hash;
    // Protocol domain bytes are stable even when public names change.
    Hash.Update(Bytes("PeVmProtector-License-v2"));
    Hash.Update({reinterpret_cast<const std::uint8_t*>(&Payload), offsetof(LicensePayload, Signature)});
    return Hash.Finish();
}
} // namespace

std::uint64_t CurrentFileTime() {
    FILETIME Now{};
    GetSystemTimeAsFileTime(&Now);
    return (static_cast<std::uint64_t>(Now.dwHighDateTime) << 32) | Now.dwLowDateTime;
}
Digest MachineId() {
    wchar_t Guid[256]{};
    DWORD Size = sizeof(Guid);
    if (RegGetValueW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid",
                     RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY, nullptr, Guid, &Size) != ERROR_SUCCESS ||
        Size < 2 * sizeof(wchar_t) || Size > sizeof(Guid)) throw std::runtime_error("cannot read machine identity");
    Guid[255] = 0;
    std::wstring Normalized(Guid);
    for (auto& C : Normalized) if (C >= L'A' && C <= L'Z') C += L'a' - L'A';
    wchar_t WindowsDirectory[MAX_PATH + 1]{};
    const auto Length = GetWindowsDirectoryW(WindowsDirectory, MAX_PATH);
    if (Length < 3 || Length >= MAX_PATH) throw std::runtime_error("cannot locate system volume");
    const std::wstring Root(WindowsDirectory, 3);
    DWORD Serial{};
    if (!GetVolumeInformationW(Root.c_str(), nullptr, 0, &Serial, nullptr, nullptr, nullptr, 0) || Serial == 0) {
        throw std::runtime_error("cannot read system volume identity");
    }
    crypto::Sha256 Hash;
    Hash.Update(Bytes("PEVM-MACHINE-v2"));
    Hash.Update({reinterpret_cast<const std::uint8_t*>(Normalized.data()), Normalized.size() * sizeof(wchar_t)});
    Hash.Update({reinterpret_cast<const std::uint8_t*>(&Serial), sizeof(Serial)});
    return Hash.Finish();
}
Digest ParseMachineId(std::string_view Text) {
    if (Text.size() != 64) throw std::runtime_error("machine id must be exactly 64 hex characters");
    const auto Nibble = [](char C) -> unsigned {
        if (C >= '0' && C <= '9') return C - '0';
        if (C >= 'a' && C <= 'f') return C - 'a' + 10;
        if (C >= 'A' && C <= 'F') return C - 'A' + 10;
        throw std::runtime_error("machine id contains non-hex characters");
    };
    Digest Result{};
    for (std::size_t I = 0; I < Result.size(); ++I) {
        Result[I] = static_cast<std::uint8_t>((Nibble(Text[I * 2]) << 4) | Nibble(Text[I * 2 + 1]));
    }
    if (!Nonzero(Result)) throw std::runtime_error("machine id cannot be zero");
    return Result;
}
Digest ProductId(std::string_view Text) {
    if (Text.empty() || Text.size() > 64) throw std::runtime_error("product id requires 1..64 ASCII letters/digits/._-");
    for (const auto C : Text) {
        if (!((C >= 'A' && C <= 'Z') || (C >= 'a' && C <= 'z') || (C >= '0' && C <= '9') ||
              C == '.' || C == '_' || C == '-')) throw std::runtime_error("invalid product id character");
    }
    crypto::Sha256 Hash;
    Hash.Update(Bytes("PEVM-PRODUCT-v2"));
    Hash.Update(Bytes(Text));
    return Hash.Finish();
}
std::uint32_t ParseDays(std::string_view Text) {
    if (Text.empty()) throw std::runtime_error("license days cannot be empty");
    std::uint32_t Value{};
    const auto [End, Error] = std::from_chars(Text.data(), Text.data() + Text.size(), Value);
    if (Error != std::errc{} || End != Text.data() + Text.size() || Value > KMaximumDays) {
        throw std::runtime_error("license days must be a decimal integer in 0..36500 (0 = perpetual)");
    }
    return Value;
}
std::string ReadTextFile(const std::filesystem::path& Path) {
    std::ifstream File(Path, std::ios::binary);
    if (!File) throw std::runtime_error("cannot open license/key file");
    std::array<char, KMaximumTextBytes + 1> Buffer{};
    File.read(Buffer.data(), Buffer.size());
    const auto Count = static_cast<std::size_t>(File.gcount());
    if (File.bad() || Count > KMaximumTextBytes) throw std::runtime_error("license/key file too large or unreadable");
    return {Buffer.data(), Count};
}
void WriteNewTextFile(const std::filesystem::path& Path, std::string_view Text) {
    const auto Handle = CreateFileW(Path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                                    FILE_ATTRIBUTE_NORMAL, nullptr);
    if (Handle == INVALID_HANDLE_VALUE) throw std::runtime_error("cannot create output file (must not already exist)");
    DWORD Written{};
    const bool Ok = Text.size() <= MAXDWORD &&
        WriteFile(Handle, Text.data(), static_cast<DWORD>(Text.size()), &Written, nullptr) &&
        Written == Text.size() && FlushFileBuffers(Handle);
    CloseHandle(Handle);
    if (!Ok) { DeleteFileW(Path.c_str()); throw std::runtime_error("cannot write license/key file"); }
}
void GenerateKeyFiles(const std::filesystem::path& PrivatePath, const std::filesystem::path& PublicPath) {
    if (_wcsicmp(std::filesystem::absolute(PrivatePath).lexically_normal().c_str(),
                 std::filesystem::absolute(PublicPath).lexically_normal().c_str()) == 0 ||
        std::filesystem::exists(PrivatePath) || std::filesystem::exists(PublicPath)) {
        throw std::runtime_error("key paths must be distinct and must not exist");
    }
    Algorithm Provider;
    Key SigningKey;
    Check(BCryptGenerateKeyPair(Provider.Handle, &SigningKey.Handle, 256, 0), "cannot generate signing key");
    Check(BCryptFinalizeKeyPair(SigningKey.Handle, 0), "cannot finalize signing key");
    const auto Public = ExportPublic(SigningKey);
    SecretBytes Private;
    Private.Data.resize(104);
    ULONG Written{};
    Check(BCryptExportKey(SigningKey.Handle, nullptr, BCRYPT_ECCPRIVATE_BLOB, Private.Data.data(),
                          static_cast<ULONG>(Private.Data.size()), &Written, 0), "cannot export private key");
    if (Written != Private.Data.size()) throw std::runtime_error("unexpected private key size");
    DATA_BLOB Input{Written, Private.Data.data()};
    LocalBlob Protected;
    if (!CryptProtectData(&Input, L"PeVmProtector signing key", nullptr, nullptr, nullptr,
                          CRYPTPROTECT_UI_FORBIDDEN, &Protected.Blob)) {
        throw std::runtime_error("cannot protect signing key with Windows DPAPI");
    }
    WriteNewTextFile(PrivatePath, KPrivateKeyPrefix + crypto::Base64Encode({Protected.Blob.pbData, Protected.Blob.cbData}) + "\n");
    // Preserve the private file on failure; license-export-public can recover its public half.
    WriteNewTextFile(PublicPath, KPublicKeyPrefix + crypto::Base64Encode(Public) + "\n");
}
void ExportPublicKeyFile(const std::filesystem::path& PrivatePath, const std::filesystem::path& PublicPath) {
    Algorithm Provider;
    Key SigningKey;
    ImportPrivate(Provider, SigningKey, PrivatePath);
    WriteNewTextFile(PublicPath, KPublicKeyPrefix + crypto::Base64Encode(ExportPublic(SigningKey)) + "\n");
}
PublicKey ReadPublicKey(const std::filesystem::path& Path) {
    const auto Raw = Decode(ReadTextFile(Path), KPublicKeyPrefix);
    if (Raw.size() != PublicKey{}.size()) throw std::runtime_error("invalid public key file length");
    PublicKey Public{};
    std::copy(Raw.begin(), Raw.end(), Public.begin());
    Algorithm Provider;
    Key VerificationKey;
    ImportPublic(Provider, VerificationKey, Public);
    return Public;
}
LicensePolicy MakePolicy(const std::filesystem::path& PublicPath, std::string_view Product) {
    LicensePolicy Policy{};
    Policy.Required = 1;
    Policy.PublicKey = ReadPublicKey(PublicPath);
    Policy.ProductId = ProductId(Product);
    return Policy;
}
void ValidatePolicy(const LicensePolicy& Policy) {
    if (Policy.Required > 1) throw std::runtime_error("invalid license policy");
    if (Policy.Required == 0) {
        if (Nonzero(Policy.PublicKey) || Nonzero(Policy.ProductId)) throw std::runtime_error("disabled license policy has key data");
        return;
    }
    if (!Nonzero(Policy.ProductId)) throw std::runtime_error("license product binding missing");
    Algorithm Provider;
    Key VerificationKey;
    ImportPublic(Provider, VerificationKey, Policy.PublicKey);
}
LicensePayload IssueLicense(const std::filesystem::path& PrivatePath, std::string_view Product,
                            const Digest& Machine, std::uint32_t Days, std::uint64_t IssuedFileTime) {
    if (!Nonzero(Machine)) throw std::runtime_error("machine id cannot be zero");
    if (Days > KMaximumDays || IssuedFileTime == 0 || IssuedFileTime > KMaximumTimestamp ||
        Days > (KMaximumTimestamp - IssuedFileTime) / KTicksPerDay) {
        throw std::runtime_error("invalid license time or expiry overflow");
    }
    LicensePayload Payload{};
    Payload.ProductId = ProductId(Product);
    Payload.Machine = Machine;
    Payload.IssuedFileTime = IssuedFileTime;
    Payload.ExpiresFileTime = Days == 0 ? 0 : IssuedFileTime + Days * KTicksPerDay;
    Check(BCryptGenRandom(nullptr, Payload.LicenseId.data(), static_cast<ULONG>(Payload.LicenseId.size()),
                          BCRYPT_USE_SYSTEM_PREFERRED_RNG), "cannot generate license id");
    Algorithm Provider;
    Key SigningKey;
    ImportPrivate(Provider, SigningKey, PrivatePath);
    Payload.KeyId = crypto::Sha256::Digest(ExportPublic(SigningKey));
    auto Hash = SignatureHash(Payload);
    ULONG Written{};
    Check(BCryptSignHash(SigningKey.Handle, nullptr, Hash.data(), static_cast<ULONG>(Hash.size()),
                         Payload.Signature.data(), static_cast<ULONG>(Payload.Signature.size()), &Written, 0),
          "cannot sign license");
    if (Written != Payload.Signature.size()) throw std::runtime_error("unexpected license signature size");
    return Payload;
}
std::string FormatLicense(const LicensePayload& Payload) {
    return KLicensePrefix + crypto::Base64Encode({reinterpret_cast<const std::uint8_t*>(&Payload), sizeof(Payload)});
}
LicensePayload ParseLicense(std::string_view Text) {
    const auto Raw = Decode(Text, KLicensePrefix);
    if (Raw.size() != sizeof(LicensePayload)) throw std::runtime_error("invalid license length");
    LicensePayload Payload{};
    std::memcpy(&Payload, Raw.data(), sizeof(Payload));
    if (Payload.Version != KPayloadVersion) throw std::runtime_error("unsupported license version");
    return Payload;
}
std::string VerifyPayload(const LicensePayload& Payload, const LicensePolicy& Policy,
                           const Digest& CurrentMachine, std::uint64_t NowFileTime) {
    if (Policy.Required != 1) return "license policy is not enabled";
    ValidatePolicy(Policy);
    if (Payload.Version != KPayloadVersion) return "unsupported license version";
    if (!crypto::ConstantEqual(Payload.KeyId, crypto::Sha256::Digest(Policy.PublicKey))) return "license signing key mismatch";
    Algorithm Provider;
    Key VerificationKey;
    ImportPublic(Provider, VerificationKey, Policy.PublicKey);
    auto Hash = SignatureHash(Payload);
    const auto Status = BCryptVerifySignature(VerificationKey.Handle, nullptr, Hash.data(), static_cast<ULONG>(Hash.size()),
        const_cast<PUCHAR>(Payload.Signature.data()), static_cast<ULONG>(Payload.Signature.size()), 0);
    if (Status == KInvalidSignature) return "license signature invalid";
    Check(Status, "license signature verification failed");
    if (!Nonzero(Payload.LicenseId)) return "license id is missing";
    if (!crypto::ConstantEqual(Payload.ProductId, Policy.ProductId)) return "license product mismatch";
    if (!Nonzero(CurrentMachine) || !crypto::ConstantEqual(Payload.Machine, CurrentMachine)) return "license machine mismatch";
    if (NowFileTime == 0 || NowFileTime > KMaximumTimestamp || Payload.IssuedFileTime == 0 ||
        Payload.IssuedFileTime > KMaximumTimestamp || Payload.ExpiresFileTime > KMaximumTimestamp ||
        (Payload.ExpiresFileTime != 0 && Payload.ExpiresFileTime <= Payload.IssuedFileTime)) return "invalid license time";
    if (NowFileTime < Payload.IssuedFileTime && Payload.IssuedFileTime - NowFileTime > KClockSkewTicks) {
        return "license issued in the future or system clock rolled back";
    }
    if (Payload.ExpiresFileTime != 0 && NowFileTime >= Payload.ExpiresFileTime) return "license expired";
    return {};
}
std::string ReadRuntimeLicense(const std::filesystem::path& WrapperPath) {
    SetLastError(ERROR_SUCCESS);
    const auto Needed = GetEnvironmentVariableW(L"PEVM_LICENSE", nullptr, 0);
    if (Needed == 0) {
        if (GetLastError() != ERROR_ENVVAR_NOT_FOUND) throw std::runtime_error("license environment value is empty or unreadable");
        return ReadTextFile(WrapperPath.wstring() + L".license");
    }
    if (Needed > KMaximumTextBytes + 1) throw std::runtime_error("license environment value too long");
    std::vector<wchar_t> Buffer(Needed);
    const auto Length = GetEnvironmentVariableW(L"PEVM_LICENSE", Buffer.data(), Needed);
    if (Length == 0 || Length >= Needed) throw std::runtime_error("license environment value changed while reading");
    std::string Text;
    Text.reserve(Length);
    for (DWORD I = 0; I < Length; ++I) {
        if (Buffer[I] > 127) throw std::runtime_error("license must be ASCII");
        Text.push_back(static_cast<char>(Buffer[I]));
    }
    return Text;
}
} // namespace pevm::license
