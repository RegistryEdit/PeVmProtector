#pragma once
#include "PeVmLicense.h"
#include "PeVmCrypto.h"
#include <windows.h>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>

namespace licensecli {
struct Options {
    bool Required{};
    std::string PublicPath;
    std::string Product;
    bool Parse(std::string_view Arg) {
        if (Arg == "--license") {
            if (Required) throw std::runtime_error("duplicate --license");
            Required = true;
        } else if (Arg.starts_with("--license-public-key=")) {
            if (!PublicPath.empty() || Arg.size() == 21) throw std::runtime_error("invalid/duplicate public key option");
            PublicPath = Arg.substr(21);
        } else if (Arg.starts_with("--license-product=")) {
            if (!Product.empty() || Arg.size() == 18) throw std::runtime_error("invalid/duplicate product option");
            Product = Arg.substr(18);
        } else if (Arg.starts_with("--license-secret")) {
            throw std::runtime_error("--license-secret was removed; use --license-public-key and reissue signed licenses");
        } else return false;
        return true;
    }
    LicensePolicy Resolve() const {
        if (!Required) {
            if (!PublicPath.empty() || !Product.empty()) throw std::runtime_error("license options require --license");
            return {};
        }
        if (PublicPath.empty() || Product.empty()) throw std::runtime_error("--license requires --license-public-key=<file> and --license-product=<id>");
        return pevm::license::MakePolicy(PublicPath, Product);
    }
};

inline std::string Expiry(std::uint64_t Time) {
    if (Time == 0) return "perpetual";
    FILETIME FileTime{static_cast<DWORD>(Time), static_cast<DWORD>(Time >> 32)};
    SYSTEMTIME Utc{};
    if (!FileTimeToSystemTime(&FileTime, &Utc)) throw std::runtime_error("invalid expiry timestamp");
    std::ostringstream Out;
    Out << std::setfill('0') << std::setw(4) << Utc.wYear << '-'
        << std::setw(2) << Utc.wMonth << '-' << std::setw(2) << Utc.wDay << 'T'
        << std::setw(2) << Utc.wHour << ':' << std::setw(2) << Utc.wMinute << ':'
        << std::setw(2) << Utc.wSecond << 'Z';
    return Out.str();
}
inline void MakeLicense(int Argc, char** Argv) {
    std::uint32_t Days = 30;
    bool DaysSet = false, MachineSet = false;
    pevm::license::Digest Machine{};
    std::string Product, Output;
    for (int I = 3; I < Argc; ++I) {
        const std::string_view Arg = Argv[I];
        if (Arg.starts_with("--machine=")) {
            if (MachineSet) throw std::runtime_error("duplicate --machine");
            Machine = pevm::license::ParseMachineId(Arg.substr(10));
            MachineSet = true;
        } else if (Arg.starts_with("--product=")) {
            if (!Product.empty() || Arg.size() == 10) throw std::runtime_error("invalid/duplicate --product");
            Product = Arg.substr(10);
        } else if (Arg.starts_with("--output=")) {
            if (!Output.empty() || Arg.size() == 9) throw std::runtime_error("invalid/duplicate --output");
            Output = Arg.substr(9);
        } else {
            if (DaysSet || Arg.starts_with("--")) throw std::runtime_error("unknown/duplicate license-issue option");
            Days = pevm::license::ParseDays(Arg);
            DaysSet = true;
        }
    }
    if (!MachineSet || Product.empty()) throw std::runtime_error("license-issue requires --machine=<64hex> and --product=<id>");
    const auto Payload = pevm::license::IssueLicense(Argv[2], Product, Machine, Days, pevm::license::CurrentFileTime());
    const auto Text = pevm::license::FormatLicense(Payload);
    if (Output.empty()) std::cout << Text << "\n";
    else {
        pevm::license::WriteNewTextFile(Output, Text + "\n");
        std::cout << "license file: " << Output << "\n";
    }
    std::cout << "license id: " << pevm::crypto::Hex(Payload.LicenseId) << "\n"
              << "product: " << Product << "\nexpires: " << Expiry(Payload.ExpiresFileTime) << "\n";
}
inline void VerifyLicense(int Argc, char** Argv) {
    std::string Product;
    pevm::license::Digest Machine{};
    bool MachineSet = false;
    for (int I = 4; I < Argc; ++I) {
        const std::string_view Arg = Argv[I];
        if (Arg.starts_with("--product=")) {
            if (!Product.empty() || Arg.size() == 10) throw std::runtime_error("invalid/duplicate --product");
            Product = Arg.substr(10);
        } else if (Arg.starts_with("--machine=")) {
            if (MachineSet) throw std::runtime_error("duplicate --machine");
            Machine = pevm::license::ParseMachineId(Arg.substr(10));
            MachineSet = true;
        } else throw std::runtime_error("unknown license-verify option");
    }
    if (Product.empty()) throw std::runtime_error("license-verify requires --product=<id>");
    if (!MachineSet) Machine = pevm::license::MachineId();
    const auto Policy = pevm::license::MakePolicy(Argv[2], Product);
    const auto Payload = pevm::license::ParseLicense(pevm::license::ReadTextFile(Argv[3]));
    const auto Reason = pevm::license::VerifyPayload(Payload, Policy, Machine, pevm::license::CurrentFileTime());
    if (!Reason.empty()) throw std::runtime_error(Reason);
    std::cout << "license valid\nlicense id: " << pevm::crypto::Hex(Payload.LicenseId)
              << "\nexpires: " << Expiry(Payload.ExpiresFileTime) << "\n";
}
} // namespace licensecli
