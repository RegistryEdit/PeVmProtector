#include "LicenseRuntime.h"
#include "PeVmCrypto.h"
#include "FileIo.h"
#include <windows.h>
#include <shlobj.h>
#include <dpapi.h>
#include <algorithm>
#include <fstream>
#include <vector>

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "crypt32.lib")

namespace pevm::activation {
namespace {
constexpr std::size_t KMaximumCacheBytes = 16384;
struct LocalBlob {
    DATA_BLOB Value{};
    ~LocalBlob() {
        if (Value.pbData) { SecureZeroMemory(Value.pbData, Value.cbData); LocalFree(Value.pbData); }
    }
};

license::Digest CacheIdentity(const LicensePolicy& Policy, const std::filesystem::path& Wrapper) {
    // Lexical absolute paths remain stable while the wrapper is being replaced.
    auto Path = std::filesystem::absolute(Wrapper).lexically_normal().wstring();
    std::replace(Path.begin(), Path.end(), L'/', L'\\');
    const auto Length = LCMapStringEx(LOCALE_NAME_INVARIANT, LCMAP_LOWERCASE, Path.data(),
        static_cast<int>(Path.size()), nullptr, 0, nullptr, nullptr, 0);
    if (Length <= 0) throw std::runtime_error("cannot normalize license cache identity");
    std::wstring Lower(static_cast<std::size_t>(Length), L'\0');
    if (!LCMapStringEx(LOCALE_NAME_INVARIANT, LCMAP_LOWERCASE, Path.data(), static_cast<int>(Path.size()),
        Lower.data(), Length, nullptr, nullptr, 0)) throw std::runtime_error("cannot normalize license cache identity");
    crypto::Sha256 Hash;
    constexpr std::string_view Domain = "PeVmProtector-LicenseCache-v1";
    Hash.Update({reinterpret_cast<const std::uint8_t*>(Domain.data()), Domain.size()});
    Hash.Update(crypto::Sha256::Digest(Policy.PublicKey));
    Hash.Update(Policy.ProductId);
    Hash.Update({reinterpret_cast<const std::uint8_t*>(Lower.data()), Lower.size() * sizeof(wchar_t)});
    return Hash.Finish();
}

std::string Decrypt(std::span<const std::uint8_t> Data, license::Digest& Identity) {
    DATA_BLOB Input{static_cast<DWORD>(Data.size()), const_cast<BYTE*>(Data.data())};
    DATA_BLOB Entropy{static_cast<DWORD>(Identity.size()), Identity.data()};
    LocalBlob Plain;
    if (!CryptUnprotectData(&Input, nullptr, &Entropy, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &Plain.Value))
        throw std::runtime_error("cannot unlock saved license");
    if (!Plain.Value.cbData || Plain.Value.cbData > license::KMaximumTextBytes)
        throw std::runtime_error("invalid saved license size");
    return {reinterpret_cast<const char*>(Plain.Value.pbData), Plain.Value.cbData};
}
} // namespace

bool TryVerifyLicense(const LicensePolicy& Policy, std::string_view Text, std::string& Reason) {
    try {
        const auto Payload = license::ParseLicense(Text);
        Reason = license::VerifyPayload(Payload, Policy, license::MachineId(), license::CurrentFileTime());
        return Reason.empty();
    } catch (const std::exception& Error) {
        Reason = Error.what();
        return false;
    }
}

std::filesystem::path CacheDirectory() {
    PWSTR Raw{};
    const auto Status = SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_DEFAULT, nullptr, &Raw);
    struct KnownFolder { PWSTR Path; ~KnownFolder() { CoTaskMemFree(Path); } } Owner{Raw};
    if (FAILED(Status) || !Raw) throw std::runtime_error("cannot locate per-user license cache");
    return std::filesystem::path(Raw) / L"PeVmProtector" / L"LicenseCache";
}

std::filesystem::path CachePath(const LicensePolicy& Policy, const std::filesystem::path& Wrapper,
                                const std::filesystem::path& Directory) {
    return Directory / (crypto::Hex(CacheIdentity(Policy, Wrapper)) + ".bin");
}

std::string ReadLicenseCache(const LicensePolicy& Policy, const std::filesystem::path& Wrapper,
                             const std::filesystem::path& Directory, std::string& Reason) {
    const auto Path = CachePath(Policy, Wrapper, Directory);
    const auto Attributes = GetFileAttributesW(Path.c_str());
    if (Attributes == INVALID_FILE_ATTRIBUTES) { Reason = "no saved license"; return {}; }
    // Never follow or remove directories/reparse points supplied as cache entries.
    if (Attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) {
        Reason = "invalid saved license file"; return {};
    }
    try {
        std::ifstream File(Path, std::ios::binary);
        std::vector<std::uint8_t> Data(KMaximumCacheBytes + 1);
        if (!File) throw std::runtime_error("cannot read saved license");
        File.read(reinterpret_cast<char*>(Data.data()), static_cast<std::streamsize>(Data.size()));
        const auto Size = File.gcount();
        if (File.bad() || Size <= 0 || Size > static_cast<std::streamsize>(KMaximumCacheBytes))
            throw std::runtime_error("invalid saved license size");
        Data.resize(static_cast<std::size_t>(Size));
        auto Identity = CacheIdentity(Policy, Wrapper);
        auto Text = Decrypt(Data, Identity);
        if (!TryVerifyLicense(Policy, Text, Reason)) throw std::runtime_error(Reason);
        return Text;
    } catch (const std::exception& Error) {
        Reason = Error.what();
        // A stale cache is disposable; a failed cleanup must not authorize startup.
        DeleteFileW(Path.c_str());
        return {};
    }
}

void WriteLicenseCache(const LicensePolicy& Policy, const std::filesystem::path& Wrapper,
                       const std::filesystem::path& Directory, std::string_view Text) {
    std::string Reason;
    if (!TryVerifyLicense(Policy, Text, Reason)) throw std::runtime_error(Reason);
    const auto Canonical = license::FormatLicense(license::ParseLicense(Text));
    auto Identity = CacheIdentity(Policy, Wrapper);
    DATA_BLOB Input{static_cast<DWORD>(Canonical.size()), reinterpret_cast<BYTE*>(const_cast<char*>(Canonical.data()))};
    DATA_BLOB Entropy{static_cast<DWORD>(Identity.size()), Identity.data()};
    LocalBlob Protected;
    if (!CryptProtectData(&Input, L"PeVmProtector saved license", &Entropy, nullptr, nullptr,
                           CRYPTPROTECT_UI_FORBIDDEN, &Protected.Value))
        throw std::runtime_error("cannot protect saved license");
    const std::span<const std::uint8_t> Bytes(Protected.Value.pbData, Protected.Value.cbData);
    if (Bytes.size() > KMaximumCacheBytes || Decrypt(Bytes, Identity) != Canonical)
        throw std::runtime_error("saved license roundtrip failed");
    std::filesystem::create_directories(Directory);
    util::WriteFileAtomic(CachePath(Policy, Wrapper, Directory), Bytes);
}
} // namespace pevm::activation
