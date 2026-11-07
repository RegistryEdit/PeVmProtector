#pragma once

#include "PeVmContainer.h"
#include <chrono>
#include <exception>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace pevm::build {
inline std::string Number(std::uint64_t Value) { return std::to_string(Value); }
inline std::string Hex(std::uint64_t Value) {
    std::ostringstream Out;
    Out << "0x" << std::hex << Value;
    return Out.str();
}
inline std::string Size(std::uint64_t Value) {
    std::ostringstream Out;
    Out << Value << " bytes";
    if (Value >= 1024) Out << " (" << std::fixed << std::setprecision(2)
                           << static_cast<double>(Value) / (Value >= 1048576 ? 1048576.0 : 1024.0)
                           << (Value >= 1048576 ? " MiB)" : " KiB)");
    return Out.str();
}
inline std::string Ratio(std::uint64_t Part, std::uint64_t Whole) {
    if (Whole == 0) return "n/a";
    std::ostringstream Out;
    Out << std::fixed << std::setprecision(2) << 100.0 * static_cast<double>(Part) / static_cast<double>(Whole) << '%';
    return Out.str();
}
inline std::string SafeText(std::string_view Text) {
    std::string Result(Text);
    for (auto& C : Result) if (static_cast<unsigned char>(C) < 32 || C == 127) C = '?';
    return Result;
}

// One flushed timeline per user command, shared by nested packing stages.
class Log {
    using Clock = std::chrono::steady_clock;
    Clock::time_point Started = Clock::now(), StageStarted = Started;
    std::string Stage;
    std::size_t StageNumber{};
    int Exceptions = std::uncaught_exceptions();
    bool Complete{};
    static std::string Elapsed(Clock::time_point From) {
        std::ostringstream Out;
        Out << std::fixed << std::setprecision(2)
            << std::chrono::duration<double, std::milli>(Clock::now() - From).count() << " ms";
        return Out.str();
    }
public:
    Log(std::string_view Operation, const std::filesystem::path& Input, const std::filesystem::path& Output) {
        std::cout << "[build] " << Operation << '\n';
        Detail("input", std::filesystem::absolute(Input).lexically_normal().string());
        Detail("output", std::filesystem::absolute(Output).lexically_normal().string());
    }
    Log(const Log&) = delete;
    Log& operator=(const Log&) = delete;
    ~Log() noexcept {
        if (!Complete && std::uncaught_exceptions() > Exceptions) {
            try {
                std::cout << "[failed] " << (Stage.empty() ? "setup" : Stage)
                          << " | elapsed: " << Elapsed(Started) << '\n' << std::flush;
            } catch (...) {}
        }
    }
    void Detail(std::string_view Label, std::string_view Value) const {
        std::cout << "  " << Label << ": " << SafeText(Value) << '\n' << std::flush;
    }
    void Step(std::string_view Name) {
        if (!Stage.empty()) Detail("stage elapsed", Elapsed(StageStarted));
        Stage = Name;
        StageStarted = Clock::now();
        std::cout << "[stage " << ++StageNumber << "] " << Name << '\n' << std::flush;
    }
    PeInfo InputInfo(std::span<const std::uint8_t> Bytes) {
        const pevm::pe::ImageView Image(Bytes);
        const auto Pe = Image.Info();
        Detail("input size", Size(Bytes.size()));
        const auto Machine = Pe.Machine == 0x8664 ? "x64" : Pe.Machine == 0x14c ? "x86" : Pe.Machine == 0xaa64 ? "ARM64" : "other";
        Detail("PE", std::string(Pe.Pe64 ? "PE32+" : "PE32") + ", architecture=" + Machine +
               ", machine=" + Hex(Pe.Machine) + ", subsystem=" + SubsystemName(Pe.Subsystem));
        Detail("entry RVA", Hex(Pe.EntryRva));
        Detail("section count", Number(Pe.Sections));
        for (std::size_t I = 0; I < Image.Sections().size(); ++I) {
            const auto& Section = Image.Sections()[I];
            const auto Flags = Section.Characteristics;
            const std::string Access{(Flags & 0x40000000U) ? 'R' : '-', (Flags & 0x80000000U) ? 'W' : '-', (Flags & 0x20000000U) ? 'X' : '-'};
            Detail("section[" + Number(I) + "]", Section.Name + " | RVA=" + Hex(Section.VirtualAddress) +
                   " | virtual=" + Size(Section.VirtualSize) + " | file offset=" + Hex(Section.RawOffset) +
                   " | raw=" + Size(Section.RawSize) + " | " + Access);
        }
        return Pe;
    }
    void Finish(std::span<const std::uint8_t> Output, std::uint64_t InputSize) {
        Detail("stage elapsed", Elapsed(StageStarted));
        Detail("output size", Size(Output.size()));
        Detail("output/input", Ratio(Output.size(), InputSize));
        Detail("output SHA-256", crypto::Hex(crypto::Sha256::Digest(Output)));
        Detail("total elapsed", Elapsed(Started));
        Complete = true;
        std::cout << "[complete] output committed\n" << std::flush;
    }
};
} // namespace pevm::build
