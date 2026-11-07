#include "FileIo.h"

#include <algorithm>
#include <atomic>
#include <fstream>
#include <limits>
#include <stdexcept>
#include <system_error>
#include <windows.h>

namespace util {
std::vector<std::uint8_t> ReadFile(const std::filesystem::path& Path) {
    std::ifstream File(Path, std::ios::binary | std::ios::ate);
    if (!File) throw std::runtime_error("cannot open input: " + Path.string());
    const auto End = File.tellg();
    if (End < 0) throw std::runtime_error("cannot determine input size");
    const auto Size = static_cast<std::uint64_t>(End);
    if (Size > std::numeric_limits<std::size_t>::max() ||
        Size > static_cast<std::uint64_t>(std::numeric_limits<std::streamsize>::max()))
        throw std::runtime_error("input too large");
    std::vector<std::uint8_t> Data(static_cast<std::size_t>(Size));
    File.seekg(0);
    if (!Data.empty() && !File.read(reinterpret_cast<char*>(Data.data()), static_cast<std::streamsize>(Data.size())))
        throw std::runtime_error("cannot read input");
    return Data;
}

namespace {
[[noreturn]] void IoError(const char* Operation) {
    throw std::system_error(static_cast<int>(GetLastError()), std::system_category(), Operation);
}
struct StagedFile {
    std::filesystem::path Path;
    HANDLE Handle = INVALID_HANDLE_VALUE;
    bool Owned = false;
    ~StagedFile() {
        if (Handle != INVALID_HANDLE_VALUE) CloseHandle(Handle);
        if (Owned) DeleteFileW(Path.c_str());
    }
};
}

void WriteFileAtomic(const std::filesystem::path& Path, std::span<const std::uint8_t> Data) {
    static std::atomic<std::uint64_t> Sequence{};
    StagedFile Stage;
    for (unsigned Attempt = 0; Attempt < 128; ++Attempt) {
        Stage.Path = Path;
        Stage.Path += L".pevm-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
                      std::to_wstring(Sequence.fetch_add(1, std::memory_order_relaxed)) + L".tmp";
        Stage.Handle = CreateFileW(Stage.Path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (Stage.Handle != INVALID_HANDLE_VALUE) { Stage.Owned = true; break; }
        if (GetLastError() != ERROR_FILE_EXISTS && GetLastError() != ERROR_ALREADY_EXISTS) IoError("cannot create output");
    }
    if (!Stage.Owned) throw std::runtime_error("cannot create unique output staging file");
    for (std::size_t At = 0; At < Data.size();) {
        const auto Count = static_cast<DWORD>(std::min<std::size_t>(Data.size() - At, 1024 * 1024));
        DWORD Written{};
        if (!WriteFile(Stage.Handle, Data.data() + At, Count, &Written, nullptr)) IoError("cannot write output");
        if (Written == 0) throw std::runtime_error("output write made no progress");
        At += Written;
    }
    if (!FlushFileBuffers(Stage.Handle)) IoError("cannot flush output");
    if (!CloseHandle(Stage.Handle)) IoError("cannot close output");
    Stage.Handle = INVALID_HANDLE_VALUE;
    if (!MoveFileExW(Stage.Path.c_str(), Path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        IoError("cannot commit output");
    Stage.Owned = false;
}
} // namespace util
