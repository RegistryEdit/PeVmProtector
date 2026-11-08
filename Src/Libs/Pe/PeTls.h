#pragma once

#include "PeImage.h"
#include <algorithm>
#include <cstring>
#include <optional>
#include <stdexcept>
#include <windows.h>

namespace pevm::pe {
struct TlsLayout {
    IMAGE_TLS_DIRECTORY64 Directory{};
    std::uint32_t TemplateRva{}, IndexRva{}, CallbacksRva{};
    std::uint32_t TemplateBytes{}, TotalBytes{};
};

// Validate VAs before the mapper relocates them or calls any TLS code.
inline std::optional<TlsLayout> ReadTlsLayout(const ImageView& Image) {
    const auto Data = Image.Directory(IMAGE_DIRECTORY_ENTRY_TLS);
    if (!Data.Address && !Data.Size) return std::nullopt;
    Image.RequireX64();
    if (Data.Size < sizeof(IMAGE_TLS_DIRECTORY64)) throw std::runtime_error("TLS directory truncated");
    TlsLayout Result;
    std::memcpy(&Result.Directory, Image.FileBytesAtRva(Data.Address, sizeof(Result.Directory)).data(),
                sizeof(Result.Directory));
    std::uint64_t ImageBase{};
    std::memcpy(&ImageBase, Image.FileBytes().data() + Image.NtOffset() + 24 + 24, sizeof(ImageBase));
    const auto Rva = [&](std::uint64_t Va, std::size_t Bytes) {
        if (Va < ImageBase || Va - ImageBase > Image.SizeOfImage() ||
            Bytes > Image.SizeOfImage() - (Va - ImageBase))
            throw std::runtime_error("TLS address outside image");
        return static_cast<std::uint32_t>(Va - ImageBase);
    };
    const auto& Tls = Result.Directory;
    if (Tls.EndAddressOfRawData < Tls.StartAddressOfRawData)
        throw std::runtime_error("TLS template range invalid");
    const auto RawBytes = Tls.EndAddressOfRawData - Tls.StartAddressOfRawData;
    const auto Total = RawBytes + Tls.SizeOfZeroFill;
    if (RawBytes > Image.SizeOfImage() || Total < RawBytes || Total > 16 * 1024 * 1024)
        throw std::runtime_error("TLS template too large");
    Result.TemplateBytes = static_cast<std::uint32_t>(RawBytes);
    Result.TotalBytes = static_cast<std::uint32_t>(Total);
    if (RawBytes) {
        Result.TemplateRva = Rva(Tls.StartAddressOfRawData, Result.TemplateBytes);
        (void)Image.FileBytesAtRva(Result.TemplateRva, Result.TemplateBytes);
    }
    Result.IndexRva = Rva(Tls.AddressOfIndex, sizeof(DWORD));
    const auto* IndexSection = Image.SectionAt(Result.IndexRva);
    if (!IndexSection || !(IndexSection->Characteristics & IMAGE_SCN_MEM_WRITE))
        throw std::runtime_error("TLS index is not writable");
    if (Tls.AddressOfCallBacks) {
        Result.CallbacksRva = Rva(Tls.AddressOfCallBacks, sizeof(std::uint64_t));
        bool Terminated = false;
        for (std::size_t I = 0; I < 1024; ++I) {
            std::uint64_t Callback{};
            const auto At = static_cast<std::uint64_t>(Result.CallbacksRva) + I * sizeof(Callback);
            if (At > UINT32_MAX) throw std::runtime_error("TLS callbacks outside image");
            std::memcpy(&Callback, Image.FileBytesAtRva(static_cast<std::uint32_t>(At), sizeof(Callback)).data(), sizeof(Callback));
            if (!Callback) { Terminated = true; break; }
            const auto* Code = Image.SectionAt(Rva(Callback, 1));
            if (!Code || !Code->Executable()) throw std::runtime_error("TLS callback is not executable");
        }
        if (!Terminated) throw std::runtime_error("TLS callbacks not terminated");
    }
    return Result;
}

// Windows allocates the wrapper's static TLS slot for every thread. Enlarge
// that slot with zero fill; the runtime copies the encrypted payload's real
// template into it and forwards notifications. No payload data is exposed here.
inline void ConfigureWrapperTls(std::vector<std::uint8_t>& Stub, const ImageView& Payload) {
    const auto PayloadTls = ReadTlsLayout(Payload);
    const ImageView Wrapper(Stub);
    const auto PayloadNt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(Payload.FileBytes().data() + Payload.NtOffset());
    auto* WrapperNt = reinterpret_cast<IMAGE_NT_HEADERS64*>(Stub.data() + Wrapper.NtOffset());
    WrapperNt->OptionalHeader.SizeOfStackReserve = std::max(WrapperNt->OptionalHeader.SizeOfStackReserve,
                                                          PayloadNt->OptionalHeader.SizeOfStackReserve);
    WrapperNt->OptionalHeader.SizeOfStackCommit = std::max(WrapperNt->OptionalHeader.SizeOfStackCommit,
                                                         PayloadNt->OptionalHeader.SizeOfStackCommit);
    if (!PayloadTls) return;
    const auto WrapperTls = ReadTlsLayout(Wrapper);
    if (!WrapperTls || !WrapperTls->CallbacksRva)
        throw std::runtime_error("stub has no static TLS carrier; rebuild PeVmStub");
    // The stock stub only carries the CRT's eight-byte TLS guard (including
    // its 0x80 initializer). User TLS in a custom stub needs a separate slot.
    if (WrapperTls->TemplateBytes > 8 || WrapperTls->Directory.SizeOfZeroFill)
        throw std::runtime_error("custom stub TLS data cannot share the payload TLS slot");
    auto Tls = WrapperTls->Directory;
    const auto Total = std::max(WrapperTls->TotalBytes, PayloadTls->TotalBytes);
    Tls.SizeOfZeroFill = Total - WrapperTls->TemplateBytes;
    Tls.Characteristics = std::max(Tls.Characteristics & IMAGE_SCN_ALIGN_MASK,
                                  PayloadTls->Directory.Characteristics & IMAGE_SCN_ALIGN_MASK);
    const auto DirectoryBytes = Wrapper.FileBytesAtRva(Wrapper.Directory(IMAGE_DIRECTORY_ENTRY_TLS).Address, sizeof(Tls));
    std::memcpy(Stub.data() + (DirectoryBytes.data() - Stub.data()), &Tls, sizeof(Tls));
}
} // namespace pevm::pe
