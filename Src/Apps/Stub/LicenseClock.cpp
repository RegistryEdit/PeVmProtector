#include "LicenseClock.h"
#include "PeVmCrypto.h"
#include "FileIo.h"
#include <windows.h>
#include <shlobj.h>
#include <dpapi.h>
#include <algorithm>
#include <array>
#include <cstring>
#include <optional>
#include <stdexcept>
#include <vector>

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "crypt32.lib")

namespace pevm::activation {
namespace {
constexpr DWORD KMaximumClockBytes = 4096;
constexpr std::array<char, 8> KClockMagic{'P', 'V', 'M', 'C', 'L', 'K', '0', '1'};
struct ClockRecord {
    std::array<char, 8> Magic{KClockMagic};
    std::uint32_t Version{1};
    std::uint32_t Reserved{};
    license::Digest Identity{};
    std::uint64_t HighUtc{};
};
static_assert(sizeof(ClockRecord) == 56);
static_assert(offsetof(ClockRecord, HighUtc) == 48);

struct Handle {
    HANDLE Value{INVALID_HANDLE_VALUE};
    ~Handle() { if (Value != INVALID_HANDLE_VALUE) CloseHandle(Value); }
    Handle() = default;
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
};
struct LocalBlob {
    DATA_BLOB Value{};
    ~LocalBlob() {
        if (Value.pbData) { SecureZeroMemory(Value.pbData, Value.cbData); LocalFree(Value.pbData); }
    }
};
bool ValidTimestamp(std::uint64_t Time) {
    return Time != 0 && Time <= license::KMaximumTimestamp;
}
license::Digest ClockIdentity(const LicensePolicy& Policy, const license::Digest& Machine) {
    license::ValidatePolicy(Policy);
    if (Policy.Required == 0 || std::all_of(Machine.begin(), Machine.end(), [](auto B) { return B == 0; }))
        throw std::runtime_error("invalid license clock identity");
    constexpr std::string_view Domain = "PeVmProtector-LicenseClock-v1";
    crypto::Sha256 Hash;
    Hash.Update({reinterpret_cast<const std::uint8_t*>(Domain.data()), Domain.size()});
    Hash.Update(crypto::Sha256::Digest(Policy.PublicKey));
    Hash.Update(Policy.ProductId);
    Hash.Update(Machine);
    return Hash.Finish();
}
void CheckRegularFile(HANDLE File) {
    BY_HANDLE_FILE_INFORMATION Information{};
    if (GetFileType(File) != FILE_TYPE_DISK || !GetFileInformationByHandle(File, &Information) ||
        (Information.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0 ||
        Information.nNumberOfLinks != 1)
        throw std::runtime_error("invalid license clock file");
}
std::optional<std::uint64_t> ReadClock(const std::filesystem::path& Path, license::Digest& Identity) {
    Handle File;
    File.Value = CreateFileW(Path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                             FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (File.Value == INVALID_HANDLE_VALUE) {
        if (GetLastError() == ERROR_FILE_NOT_FOUND) return std::nullopt;
        throw std::runtime_error("cannot read persistent license clock");
    }
    CheckRegularFile(File.Value);
    LARGE_INTEGER Size{};
    if (!GetFileSizeEx(File.Value, &Size) || Size.QuadPart <= 0 || Size.QuadPart > KMaximumClockBytes)
        throw std::runtime_error("invalid persistent license clock size");
    std::vector<std::uint8_t> Bytes(static_cast<std::size_t>(Size.QuadPart));
    DWORD Read{};
    if (!ReadFile(File.Value, Bytes.data(), static_cast<DWORD>(Bytes.size()), &Read, nullptr) || Read != Bytes.size())
        throw std::runtime_error("cannot read persistent license clock");
    DATA_BLOB Input{static_cast<DWORD>(Bytes.size()), Bytes.data()};
    DATA_BLOB Entropy{static_cast<DWORD>(Identity.size()), Identity.data()};
    LocalBlob Plain;
    if (!CryptUnprotectData(&Input, nullptr, &Entropy, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &Plain.Value))
        throw std::runtime_error("cannot authenticate persistent license clock");
    if (Plain.Value.cbData != sizeof(ClockRecord))
        throw std::runtime_error("invalid persistent license clock record");
    ClockRecord Record;
    std::memcpy(&Record, Plain.Value.pbData, sizeof(Record));
    if (Record.Magic != KClockMagic || Record.Version != 1 || Record.Reserved != 0 ||
        !crypto::ConstantEqual(Record.Identity, Identity) || !ValidTimestamp(Record.HighUtc))
        throw std::runtime_error("invalid persistent license clock record");
    return Record.HighUtc;
}
} // namespace

struct LicenseClockTransaction::State {
    std::filesystem::path Path;
    license::Digest Identity{};
    std::optional<std::uint64_t> Observed;
    std::uint64_t Effective{};
    bool Committed{};
    Handle Directory;
    Handle Lock;
};

std::filesystem::path LicenseClockDirectory() {
    PWSTR Raw{};
    const auto Status = SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_DEFAULT, nullptr, &Raw);
    struct KnownFolder { PWSTR Path; ~KnownFolder() { CoTaskMemFree(Path); } } Owner{Raw};
    if (FAILED(Status) || !Raw) throw std::runtime_error("cannot locate persistent license clock directory");
    return std::filesystem::path(Raw) / L"PeVmProtector" / L"LicenseClock";
}
std::filesystem::path LicenseClockPath(const LicensePolicy& Policy, const license::Digest& Machine,
                                       const std::filesystem::path& Directory) {
    if (Directory.empty()) throw std::runtime_error("no persistent license clock directory");
    return Directory / (crypto::Hex(ClockIdentity(Policy, Machine)) + ".bin");
}

LicenseClockTransaction::LicenseClockTransaction(const LicensePolicy& Policy, const license::Digest& Machine,
                                                const std::filesystem::path& Directory, std::uint64_t NowUtc)
    : Data(std::make_unique<State>()) {
    if (!ValidTimestamp(NowUtc)) throw std::runtime_error("invalid license clock time");
    if (Directory.empty()) throw std::runtime_error("no persistent license clock directory");
    Data->Identity = ClockIdentity(Policy, Machine);
    const auto Absolute = std::filesystem::absolute(Directory).lexically_normal();
    std::filesystem::create_directories(Absolute);
    // Pin the directory against replacement for this transaction, and inspect the
    // actual opened object rather than a separate pathname attribute query.
    Data->Directory.Value = CreateFileW(Absolute.c_str(), FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    FILE_ATTRIBUTE_TAG_INFO DirectoryInfo{};
    if (Data->Directory.Value == INVALID_HANDLE_VALUE ||
        !GetFileInformationByHandleEx(Data->Directory.Value, FileAttributeTagInfo, &DirectoryInfo, sizeof(DirectoryInfo)) ||
        (DirectoryInfo.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
        (DirectoryInfo.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
        throw std::runtime_error("invalid persistent license clock directory");
    Data->Path = Absolute / (crypto::Hex(Data->Identity) + ".bin");
    auto LockPath = Data->Path;
    LockPath += L".lock";
    for (unsigned Attempt = 0; Attempt < 100; ++Attempt) {
        Data->Lock.Value = CreateFileW(LockPath.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_ALWAYS,
                                      FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (Data->Lock.Value != INVALID_HANDLE_VALUE) break;
        const auto Error = GetLastError();
        if (Error != ERROR_SHARING_VIOLATION && Error != ERROR_LOCK_VIOLATION)
            throw std::runtime_error("cannot lock persistent license clock");
        Sleep(20);
    }
    if (Data->Lock.Value == INVALID_HANDLE_VALUE) throw std::runtime_error("persistent license clock is busy");
    CheckRegularFile(Data->Lock.Value);
    Data->Observed = ReadClock(Data->Path, Data->Identity);
    if (Data->Observed && NowUtc < *Data->Observed && *Data->Observed - NowUtc > license::KClockSkewTicks)
        throw std::runtime_error("system clock rolled back since previous licensed run");
    Data->Effective = std::max(NowUtc, Data->Observed.value_or(NowUtc));
}
LicenseClockTransaction::~LicenseClockTransaction() = default;
std::uint64_t LicenseClockTransaction::EffectiveTime() const noexcept { return Data->Effective; }
void LicenseClockTransaction::Commit() {
    if (Data->Committed) throw std::runtime_error("license clock transaction already committed");
    // Cooperating processes hold the same lock; any unexpected change is rejected
    // rather than silently replacing a damaged/newer record during verification.
    if (ReadClock(Data->Path, Data->Identity) != Data->Observed)
        throw std::runtime_error("persistent license clock changed while validating");
    if (!Data->Observed || Data->Effective > *Data->Observed) {
        ClockRecord Record;
        Record.Identity = Data->Identity;
        Record.HighUtc = Data->Effective;
        DATA_BLOB Input{static_cast<DWORD>(sizeof(Record)), reinterpret_cast<BYTE*>(&Record)};
        DATA_BLOB Entropy{static_cast<DWORD>(Data->Identity.size()), Data->Identity.data()};
        LocalBlob Protected;
        if (!CryptProtectData(&Input, L"PeVmProtector license clock", &Entropy, nullptr, nullptr,
                               CRYPTPROTECT_UI_FORBIDDEN, &Protected.Value) ||
            Protected.Value.cbData == 0 || Protected.Value.cbData > KMaximumClockBytes)
            throw std::runtime_error("cannot protect persistent license clock");
        util::WriteFileAtomic(Data->Path, {Protected.Value.pbData, Protected.Value.cbData});
    }
    Data->Committed = true;
}
} // namespace pevm::activation
