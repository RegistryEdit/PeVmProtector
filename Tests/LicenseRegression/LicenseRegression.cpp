#include "PeVmLicense.h"
#include "PeVmCrypto.h"
#include <windows.h>
#include <algorithm>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
using namespace pevm::license;
namespace fs = std::filesystem;
std::size_t Checks{};
void Require(bool Condition, const char* Message) {
    ++Checks;
    if (!Condition) throw std::runtime_error(Message);
}
template<class F> void Reject(F&& Action) {
    ++Checks;
    try { Action(); }
    catch (const std::exception&) { return; }
    throw std::runtime_error("invalid input unexpectedly accepted");
}
struct EnvironmentGuard {
    std::vector<wchar_t> Original;
    bool Present{};
    EnvironmentGuard() {
        SetLastError(ERROR_SUCCESS);
        const auto Size = GetEnvironmentVariableW(L"PEVM_LICENSE", nullptr, 0);
        Present = Size != 0 || GetLastError() != ERROR_ENVVAR_NOT_FOUND;
        Original.resize(Size ? Size : 1);
        if (Size) GetEnvironmentVariableW(L"PEVM_LICENSE", Original.data(), Size);
    }
    ~EnvironmentGuard() { SetEnvironmentVariableW(L"PEVM_LICENSE", Present ? Original.data() : nullptr); }
};
void TestInputs() {
    Require(ParseDays("0") == 0 && ParseDays("30") == 30 && ParseDays("36500") == 36500, "days bounds");
    for (const auto Text : {"", "-1", "+1", "30x", "1.5", " 1", "1 ", "36501", "4294967296"}) {
        Reject([&] { ParseDays(Text); });
    }
    Reject([] { ParseDays(std::string_view{}); });
    for (const auto Text : {"", "has space", "with/slash", "with=equals", "产品"}) {
        Reject([&] { ProductId(Text); });
    }
    Require(ProductId("Product") != ProductId("product"), "product must be case sensitive");
    ProductId(std::string(64, 'a'));
    Reject([] { ProductId(std::string(65, 'a')); });
    Reject([] { ParseMachineId("12345678"); });
    Reject([] { ParseMachineId(std::string(64, '0')); });
    Reject([] { ParseMachineId(std::string(64, 'g')); });
    Require(ParseMachineId(std::string(64, 'A')) == ParseMachineId(std::string(64, 'a')), "hex casing");
    Require(ParseMachineId(pevm::crypto::Hex(MachineId())) == MachineId(), "machine id roundtrip/stability");
}
void TestLicense(const fs::path& Work) {
    const auto Private = Work / "issuer.private";
    const auto Public = Work / "issuer.pub";
    const auto OtherPrivate = Work / "other.private";
    const auto OtherPublic = Work / "other.pub";
    GenerateKeyFiles(Private, Public);
    GenerateKeyFiles(OtherPrivate, OtherPublic);
    const auto PrivateText = ReadTextFile(Private);
    Require(PrivateText.starts_with("PEVM-PRIVATE."), "private file format");
    const auto ProtectedText = std::string_view(PrivateText).substr(sizeof(KPrivateKeyPrefix) - 1);
    const auto Protected = pevm::crypto::Base64Decode(ProtectedText.substr(0, ProtectedText.size() - 1));
    Require(Protected.size() > 104, "private file must contain DPAPI envelope");
    const auto PublicBefore = ReadTextFile(Public);
    Require(PublicBefore.starts_with("PEVM-PUBLIC."), "public file format");
    WriteNewTextFile(Work / "legacy.pub", "PEVMPUB2." + PublicBefore.substr(sizeof(KPublicKeyPrefix) - 1));
    Reject([&] { ReadPublicKey(Work / "legacy.pub"); });
    WriteNewTextFile(Work / "legacy.private", "PEVMPRIV2." + PrivateText.substr(sizeof(KPrivateKeyPrefix) - 1));
    Reject([&] { ExportPublicKeyFile(Work / "legacy.private", Work / "legacy-export.pub"); });
    Reject([&] { GenerateKeyFiles(Private, Public); });
    Reject([&] { GenerateKeyFiles(Work / "unused.private", Public); });
    Require(!fs::exists(Work / "unused.private"), "keygen must preflight existing public path");
    Reject([&] { GenerateKeyFiles(Work / "same", Work / "same"); });
    Require(ReadTextFile(Private) == PrivateText && ReadTextFile(Public) == PublicBefore, "keygen overwrote key");
    ExportPublicKeyFile(Private, Work / "recovered.pub");
    Require(ReadPublicKey(Work / "recovered.pub") == ReadPublicKey(Public), "public key recovery");
    Reject([&] { ExportPublicKeyFile(Private, Public); });
    // A failed public write preserves a recoverable private key.
    Reject([&] { GenerateKeyFiles(Work / "partial.private", Work / "missing-dir" / "partial.pub"); });
    ExportPublicKeyFile(Work / "partial.private", Work / "partial.pub");
    ReadPublicKey(Work / "partial.pub");

    const auto Policy = MakePolicy(Public, "regression.product");
    const auto Machine = MachineId();
    const auto Now = CurrentFileTime();
    const auto Payload = IssueLicense(Private, "regression.product", Machine, 30, Now);
    const auto Token = FormatLicense(Payload);
    Require(Token.starts_with("PEVM-LICENSE."), "license text format");
    const auto EncodedPayload = Token.substr(sizeof(KLicensePrefix) - 1);
    const auto Roundtrip = ParseLicense(" \t" + Token + "\r\n");
    Require(FormatLicense(Roundtrip) == Token, "license serialization roundtrip");
    Require(VerifyPayload(Roundtrip, Policy, Machine, Now).empty(), "fresh signed license");
    Require(VerifyPayload(Payload, Policy, Machine, Payload.ExpiresFileTime - 1).empty(), "before expiry");
    Require(VerifyPayload(Payload, Policy, Machine, Payload.ExpiresFileTime) == "license expired", "exact expiry");
    Require(VerifyPayload(Payload, Policy, Machine, Now - KClockSkewTicks).empty(), "clock skew boundary");
    Require(!VerifyPayload(Payload, Policy, Machine, Now - KClockSkewTicks - 1).empty(), "future issuance");
    Require(!VerifyPayload(Payload, Policy, Machine, 0).empty(), "zero verifier clock");
    Require(!VerifyPayload(Payload, Policy, Machine, KMaximumTimestamp + 1).empty(), "overflow verifier clock");
    const auto Perpetual = IssueLicense(Private, "regression.product", Machine, 0, Now);
    Require(Perpetual.ExpiresFileTime == 0 && VerifyPayload(Perpetual, Policy, Machine, KMaximumTimestamp).empty(), "perpetual license");
    const auto Second = IssueLicense(Private, "regression.product", Machine, 30, Now);
    Require(Payload.LicenseId != Second.LicenseId, "random license ids");
    auto OtherMachine = Machine;
    OtherMachine[0] ^= 1;
    Require(!VerifyPayload(Payload, Policy, OtherMachine, Now).empty(), "wrong device");
    Require(!VerifyPayload(Payload, Policy, Digest{}, Now).empty(), "zero device");
    Require(!VerifyPayload(Payload, MakePolicy(Public, "different-product"), Machine, Now).empty(), "wrong product");
    Require(!VerifyPayload(Payload, MakePolicy(OtherPublic, "regression.product"), Machine, Now).empty(), "wrong signing key");
    for (std::size_t I = 0; I < sizeof(Payload); ++I) {
        for (unsigned Bit = 0; Bit < 8; ++Bit) {
            auto Altered = Payload;
            reinterpret_cast<unsigned char*>(&Altered)[I] ^= static_cast<unsigned char>(1U << Bit);
            Require(!VerifyPayload(Altered, Policy, Machine, Now).empty(), "payload/signature bit tampering");
        }
    }
    for (const auto Days : {KMaximumDays + 1, 0xffffffffU}) {
        Reject([&] { IssueLicense(Private, "regression.product", Machine, Days, Now); });
    }
    Reject([&] { IssueLicense(Private, "regression.product", Machine, 1, KMaximumTimestamp); });
    Reject([&] { IssueLicense(Private, "regression.product", Machine, 0, 0); });
    Reject([&] { IssueLicense(Private, "regression.product", Machine, 0, KMaximumTimestamp + 1); });
    Reject([&] { IssueLicense(Private, "regression.product", {}, 30, Now); });
    ValidatePolicy({});
    Require(!VerifyPayload(Payload, {}, Machine, Now).empty(), "disabled verifier policy");
    auto InvalidPolicy = Policy;
    InvalidPolicy.Required = 0;
    Reject([&] { ValidatePolicy(InvalidPolicy); });
    InvalidPolicy.Required = 2;
    Reject([&] { ValidatePolicy(InvalidPolicy); });
    InvalidPolicy = Policy;
    InvalidPolicy.PublicKey.fill(0);
    Reject([&] { ValidatePolicy(InvalidPolicy); });
    InvalidPolicy = Policy;
    InvalidPolicy.ProductId.fill(0);
    Reject([&] { ValidatePolicy(InvalidPolicy); });

    for (const auto& Bad : {std::string{}, "PEVML1." + EncodedPayload, "PEVML2." + EncodedPayload, "prefix" + Token,
                            Token + "junk", Token + "=", Token.substr(0, Token.size() - 1),
                            std::string(KLicensePrefix) + "\n" + EncodedPayload,
                            Token + std::string(1, '\0'), std::string(4097, ' '), "pevm-license." + EncodedPayload,
                            std::string(KPublicKeyPrefix) + EncodedPayload, std::string(KPrivateKeyPrefix) + EncodedPayload}) {
        Reject([&] { ParseLicense(Bad); });
    }
    auto Noncanonical = Token;
    constexpr std::string_view Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    Noncanonical[Noncanonical.size() - 3] = Alphabet[Alphabet.find(Noncanonical[Noncanonical.size() - 3]) + 1];
    Reject([&] { ParseLicense(Noncanonical); });
    WriteNewTextFile(Work / "bad.private", "PEVM-PRIVATE.AAAA\n");
    Reject([&] { IssueLicense(Work / "bad.private", "regression.product", Machine, 30, Now); });
    Reject([&] { IssueLicense(Public, "regression.product", Machine, 30, Now); });
    Reject([&] { ReadPublicKey(Private); });
    WriteNewTextFile(Work / "bad.pub", "PEVM-PUBLIC.AAAA\n");
    Reject([&] { ReadPublicKey(Work / "bad.pub"); });
    auto BadPoint = Policy.PublicKey;
    std::fill(BadPoint.begin() + 8, BadPoint.end(), std::uint8_t{0xff});
    WriteNewTextFile(Work / "bad-point.pub", "PEVM-PUBLIC." + pevm::crypto::Base64Encode(BadPoint));
    Reject([&] { ReadPublicKey(Work / "bad-point.pub"); });

    const auto Wrapper = Work / "application.exe";
    WriteNewTextFile(Wrapper.wstring() + L".license", Token + "\n");
    Reject([&] { WriteNewTextFile(Wrapper.wstring() + L".license", "replacement"); });
    WriteNewTextFile(Work / "oversized", std::string(4097, 'A'));
    Reject([&] { ReadTextFile(Work / "oversized"); });
    WriteNewTextFile(Work / "boundary", std::string(4096, 'A'));
    Require(ReadTextFile(Work / "boundary").size() == 4096, "file size boundary");
    EnvironmentGuard Guard;
    const auto Set = [](const wchar_t* Value) {
        Require(SetEnvironmentVariableW(L"PEVM_LICENSE", Value) != 0, "set test environment");
    };
    Set(nullptr);
    Require(FormatLicense(ParseLicense(ReadRuntimeLicense(Wrapper))) == Token, "sidecar source");
    Reject([&] { ReadRuntimeLicense(Work / "no-sidecar.exe"); });
    const std::wstring WideToken(Token.begin(), Token.end());
    Set(WideToken.c_str());
    Require(ReadRuntimeLicense(Work / "no-sidecar.exe") == Token, "environment source");
    Set(L"invalid");
    Reject([&] { ParseLicense(ReadRuntimeLicense(Wrapper)); });
    Set(L"");
    Reject([&] { ReadRuntimeLicense(Wrapper); });
    Set(std::wstring(4097, L'A').c_str());
    Reject([&] { ReadRuntimeLicense(Wrapper); });
    Set(L"non-ascii-卡密");
    Reject([&] { ReadRuntimeLicense(Wrapper); });
}
} // namespace

int main(int Argc, char** Argv) {
    try {
        const fs::path Base = Argc > 1 ? Argv[1] : "TestArtifacts";
        const auto Work = Base / ("license-regression-" + std::to_string(CurrentFileTime()) + "-" + std::to_string(GetCurrentProcessId()));
        fs::create_directories(Work);
        TestInputs();
        TestLicense(Work);
        std::cout << "License regression: " << Checks << " checks passed\n";
        return 0;
    } catch (const std::exception& Error) {
        std::cerr << "License regression FAILED after " << Checks << " checks: " << Error.what() << '\n';
        return 1;
    }
}
