#include "PeVmLicense.h"
#include "PeVmCrypto.h"
#include <windows.h>
#include <bcrypt.h>
#include <algorithm>
#include <limits>
#include <stdexcept>

#pragma comment(lib, "bcrypt.lib")

namespace pevm::license {
namespace {
constexpr std::size_t KTagBytes = 16;
struct Cipher {
    BCRYPT_ALG_HANDLE Algorithm{};
    BCRYPT_KEY_HANDLE Key{};
    std::vector<std::uint8_t> Object;
    explicit Cipher(const Digest& Secret) {
        try {
            if (BCryptOpenAlgorithmProvider(&Algorithm, BCRYPT_AES_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0) < 0 ||
                BCryptSetProperty(Algorithm, BCRYPT_CHAINING_MODE,
                    reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)), sizeof(BCRYPT_CHAIN_MODE_GCM), 0) < 0)
                throw std::runtime_error("cannot initialize AES-GCM");
            DWORD Size{}, Written{};
            if (BCryptGetProperty(Algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&Size), sizeof(Size), &Written, 0) < 0)
                throw std::runtime_error("cannot query AES key size");
            Object.resize(Size);
            if (BCryptGenerateSymmetricKey(Algorithm, &Key, Object.data(), Size,
                    const_cast<PUCHAR>(Secret.data()), static_cast<ULONG>(Secret.size()), 0) < 0)
                throw std::runtime_error("cannot create AES key");
        } catch (...) { Release(); throw; }
    }
    void Release() {
        if (Key) { BCryptDestroyKey(Key); Key = nullptr; }
        if (Algorithm) { BCryptCloseAlgorithmProvider(Algorithm, 0); Algorithm = nullptr; }
        if (!Object.empty()) SecureZeroMemory(Object.data(), Object.size());
    }
    ~Cipher() { Release(); }
    Cipher(const Cipher&) = delete;
};
Digest AssociatedData(std::span<const std::uint8_t> Image, const WrapperFooter& Footer) {
    crypto::Sha256 Hash;
    constexpr std::string_view Domain = "PeVmProtector-LicensedWrapper-v1";
    Hash.Update({reinterpret_cast<const std::uint8_t*>(Domain.data()), Domain.size()});
    Hash.Update(Image);
    Hash.Update({reinterpret_cast<const std::uint8_t*>(&Footer), sizeof(Footer)});
    return Hash.Finish();
}
struct DerivedKey {
    Digest Value;
    DerivedKey(const Digest& Unlock, const WrapperFooter& Footer) {
        if (std::none_of(Unlock.begin(), Unlock.end(), [](auto B) { return B != 0; }))
            throw std::runtime_error("missing license payload unlock key");
        crypto::HmacSha256 Hash(Unlock);
        constexpr std::string_view Domain = "PeVmProtector-LicensedSecret-v1";
        Hash.Update({reinterpret_cast<const std::uint8_t*>(Domain.data()), Domain.size()});
        Hash.Update(Footer.Salt);
        Value = Hash.Finish();
    }
    ~DerivedKey() { SecureZeroMemory(Value.data(), Value.size()); }
};
void CheckFooter(std::span<const std::uint8_t> Image, const WrapperFooter& Footer, std::size_t Size) {
    if (Footer.Magic != KWrapperMagic || Footer.Version != 3 || Footer.SecretTag != 0 ||
        Footer.StubSize != Image.size() || Footer.SecretSize != Size || Size < KTagBytes || Size > KMaximumTextBytes + KTagBytes)
        throw std::runtime_error("invalid licensed secret envelope");
}
} // namespace

std::vector<std::uint8_t> SealLicensedSecret(const Digest& UnlockKey, std::span<const std::uint8_t> Image,
                                          WrapperFooter& Footer, std::string_view Secret) {
    if (Secret.size() > KMaximumTextBytes) throw std::runtime_error("licensed build password exceeds 4096 bytes");
    Footer.Version = 3;
    Footer.SecretTag = 0;
    Footer.SecretSize = static_cast<std::uint32_t>(Secret.size() + KTagBytes);
    if (BCryptGenRandom(nullptr, Footer.Salt.data(), static_cast<ULONG>(Footer.Salt.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
        throw std::runtime_error("cannot generate licensed wrapper nonce");
    CheckFooter(Image, Footer, Footer.SecretSize);
    auto Aad = AssociatedData(Image, Footer);
    DerivedKey Derived(UnlockKey, Footer);
    Cipher Aes(Derived.Value);
    std::vector<std::uint8_t> Output(Footer.SecretSize);
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO Info;
    BCRYPT_INIT_AUTH_MODE_INFO(Info);
    Info.pbNonce = Footer.Salt.data(); Info.cbNonce = 12;
    Info.pbAuthData = Aad.data(); Info.cbAuthData = static_cast<ULONG>(Aad.size());
    Info.pbTag = Output.data() + Secret.size(); Info.cbTag = KTagBytes;
    ULONG Written{};
    if (BCryptEncrypt(Aes.Key, reinterpret_cast<PUCHAR>(const_cast<char*>(Secret.data())), static_cast<ULONG>(Secret.size()),
        &Info, nullptr, 0, Output.data(), static_cast<ULONG>(Secret.size()), &Written, 0) < 0 || Written != Secret.size())
        throw std::runtime_error("cannot seal licensed build password");
    return Output;
}
std::string OpenLicensedSecret(const Digest& UnlockKey, std::span<const std::uint8_t> Image,
                              const WrapperFooter& Footer, std::span<const std::uint8_t> Sealed) {
    CheckFooter(Image, Footer, Sealed.size());
    auto Aad = AssociatedData(Image, Footer);
    DerivedKey Derived(UnlockKey, Footer);
    Cipher Aes(Derived.Value);
    const auto Size = Sealed.size() - KTagBytes;
    std::string Plain(Size, '\0');
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO Info;
    BCRYPT_INIT_AUTH_MODE_INFO(Info);
    Info.pbNonce = const_cast<PUCHAR>(Footer.Salt.data()); Info.cbNonce = 12;
    Info.pbAuthData = Aad.data(); Info.cbAuthData = static_cast<ULONG>(Aad.size());
    Info.pbTag = const_cast<PUCHAR>(Sealed.data() + Size); Info.cbTag = KTagBytes;
    ULONG Written{};
    if (BCryptDecrypt(Aes.Key, const_cast<PUCHAR>(Sealed.data()), static_cast<ULONG>(Size),
        &Info, nullptr, 0, reinterpret_cast<PUCHAR>(Plain.data()), static_cast<ULONG>(Size), &Written, 0) < 0 || Written != Size) {
        SecureZeroMemory(Plain.data(), Plain.size());
        throw std::runtime_error("licensed wrapper authentication failed");
    }
    return Plain;
}
} // namespace pevm::license
