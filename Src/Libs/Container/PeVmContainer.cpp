#include "PeVmContainer.h"
#include "BuildLog.h"

#include <algorithm>
#include <bit>
#include <chrono>
#include <cstring>
#include <fstream>
#include <iostream>
#include <limits>
#include <optional>
#include <stdexcept>

namespace fs = std::filesystem;
namespace crypto = pevm::crypto;

namespace util {

std::string Hex(std::span<const std::uint8_t> Data) {
    return crypto::Hex(Data);
}

Bytes FromHex(std::string_view Text) {
    auto Nibble = [](char C) -> unsigned {
        if (C >= '0' && C <= '9') return static_cast<unsigned>(C - '0');
        if (C >= 'a' && C <= 'f') return static_cast<unsigned>(C - 'a' + 10);
        if (C >= 'A' && C <= 'F') return static_cast<unsigned>(C - 'A' + 10);
        throw std::runtime_error("invalid hex input");
    };
    std::size_t Start = 0;
    if (Text.size() >= 2 && Text[0] == '0' && (Text[1] == 'x' || Text[1] == 'X')) Start = 2;
    if ((Text.size() - Start) % 2 != 0) throw std::runtime_error("invalid hex input");
    Bytes Out;
    Out.reserve((Text.size() - Start) / 2);
    for (std::size_t I = Start; I < Text.size(); I += 2) {
        Out.push_back(static_cast<std::uint8_t>((Nibble(Text[I]) << 4) | Nibble(Text[I + 1])));
    }
    return Out;
}

} // namespace util

namespace {

constexpr std::array<Op, KOpcodeCount> KLogicalOps = {
    Op::MovI, Op::Load64, Op::Xor, Op::Add, Op::Mul, Op::Rol,
    Op::Store64, Op::Out64, Op::XorI, Op::AddI, Op::Halt
};

std::size_t OpIndex(Op Operation) {
    for (std::size_t I = 0; I < KLogicalOps.size(); ++I) if (KLogicalOps[I] == Operation) return I;
    throw std::runtime_error("unknown logical opcode");
}

} // namespace

Op DecodeOp(std::uint8_t Encoded, const OpcodeMap& Map) {
    for (std::size_t I = 0; I < Map.size(); ++I) if (Map[I] == Encoded) return KLogicalOps[I];
    throw std::runtime_error("VM illegal encoded opcode");
}

class Vm {
public:
    Bytes Run(std::span<const std::uint8_t> Code, std::span<const std::uint8_t> Input,
              const OpcodeMap& Map = KIdentityMap) {
        Regs.fill(0);
        Scratch.fill(0);
        Bytes Output;
        std::size_t Pc = 0;
        std::size_t Fuel = 4096;
        auto Byte = [&]() -> std::uint8_t {
            if (Pc >= Code.size()) throw std::runtime_error("VM bytecode truncated");
            return Code[Pc++];
        };
        auto Reg = [&]() -> std::uint8_t {
            const auto R = Byte();
            if (R >= Regs.size()) throw std::runtime_error("VM invalid register");
            return R;
        };
        auto Imm64 = [&]() -> std::uint64_t {
            if (Pc > Code.size() || 8 > Code.size() - Pc) throw std::runtime_error("VM immediate truncated");
            const auto V = util::LoadLe<std::uint64_t>(Code, Pc);
            Pc += 8;
            return V;
        };

        while (Fuel-- != 0) {
            switch (DecodeOp(Byte(), Map)) {
            case Op::MovI: { const auto D=Reg(); Regs[D]=Imm64(); break; }
            case Op::Load64: {
                const auto D=Reg(); const auto Off=Byte();
                if (Off > Input.size() || 8 > Input.size()-Off) throw std::runtime_error("VM input OOB");
                Regs[D]=util::LoadLe<std::uint64_t>(Input, Off); break;
            }
            case Op::Xor: { const auto D=Reg(), S=Reg(); Regs[D]^=Regs[S]; break; }
            case Op::Add: { const auto D=Reg(), S=Reg(); Regs[D]+=Regs[S]; break; }
            case Op::Mul: { const auto D=Reg(), S=Reg(); Regs[D]*=Regs[S]; break; }
            case Op::Rol: { const auto D=Reg(), N=Byte(); Regs[D]=std::rotl(Regs[D], N & 63); break; }
            case Op::Store64: {
                const auto S=Reg(); const auto Off=Byte();
                if (Off > Scratch.size() || 8 > Scratch.size()-Off) throw std::runtime_error("VM scratch OOB");
                auto V=Regs[S];
                if constexpr (std::endian::native == std::endian::big) V=util::Bswap(V);
                std::memcpy(Scratch.data()+Off, &V, 8); break;
            }
            case Op::Out64: {
                auto V=Regs[Reg()];
                if constexpr (std::endian::native == std::endian::big) V=util::Bswap(V);
                const auto* P=reinterpret_cast<const std::uint8_t*>(&V);
                Output.insert(Output.end(), P, P+8); break;
            }
            case Op::XorI: { const auto D=Reg(); Regs[D]^=Imm64(); break; }
            case Op::AddI: { const auto D=Reg(); Regs[D]+=Imm64(); break; }
            case Op::Halt: return Output;
            default: throw std::runtime_error("VM illegal opcode");
            }
        }
        throw std::runtime_error("VM fuel exhausted");
    }

private:
    std::array<std::uint64_t, 8> Regs{};
    std::array<std::uint8_t, 256> Scratch{};
};

Bytes KeyProgram(const OpcodeMap& Map) {
    Bytes C;
    auto EmitOp=[&](Op X){ C.push_back(Map[OpIndex(X)]); };
    auto R=[&](std::uint8_t X){ C.push_back(X); };
    auto U8=[&](std::uint8_t X){ C.push_back(X); };
    auto U64=[&](std::uint64_t X){ util::AppendLe(C,X); };
    EmitOp(Op::Load64); R(0); U8(0);
    EmitOp(Op::Load64); R(1); U8(8);
    EmitOp(Op::Load64); R(2); U8(16);
    EmitOp(Op::Load64); R(3); U8(24);
    EmitOp(Op::Xor); R(0); R(2);
    EmitOp(Op::Add); R(1); R(3);
    EmitOp(Op::Rol); R(0); U8(17);
    EmitOp(Op::Rol); R(1); U8(29);
    EmitOp(Op::XorI); R(0); U64(0xA0761D6478BD642FULL);
    EmitOp(Op::AddI); R(1); U64(0xE7037ED1A0B428DBULL);
    EmitOp(Op::MovI); R(4); U64(0x9E3779B185EBCA87ULL);
    EmitOp(Op::Mul); R(0); R(4);
    EmitOp(Op::Xor); R(1); R(0);
    EmitOp(Op::Out64); R(0);
    EmitOp(Op::Out64); R(1);
    EmitOp(Op::Halt);
    return C;
}

namespace {

constexpr std::uint16_t KContainerVersion = 5;
constexpr std::array<char,8> KMagic={'P','E','V','M','P','K','1','\0'};

std::array<std::uint8_t, 32> PasswordSeed(std::string_view Password, std::span<const std::uint8_t, 8> Nonce,
                                          const KdfParams& Params) {
    if (Params.Id != 1) throw std::runtime_error("unsupported container KDF");
    if (Params.LogN < 10 || Params.LogN > 20 || Params.R < 1 || Params.R > 8 || Params.P < 1 || Params.P > 4) {
        throw std::runtime_error("container KDF parameters out of range");
    }
    const auto PasswordBytes = std::span(reinterpret_cast<const std::uint8_t*>(Password.data()), Password.size());
    static constexpr std::array<std::uint8_t, 15> Domain = {'P','E','V','M','-','K','D','F','-','S','C','R','Y','P','T'};
    Bytes Salt(Nonce.begin(), Nonce.end());
    Salt.insert(Salt.end(), Domain.begin(), Domain.end());
    const auto Seed = crypto::Scrypt(PasswordBytes, Salt, std::uint32_t{1} << Params.LogN,
                                     Params.R, Params.P, 32);
    std::array<std::uint8_t, 32> Out{};
    std::copy_n(Seed.begin(), Out.size(), Out.begin());
    return Out;
}

std::array<std::uint8_t,8> MakeNonce(std::span<const std::uint8_t> Plain) {
    const auto Hash=crypto::Sha256::Digest(Plain);
    std::array<std::uint8_t,8> Nonce{};
    std::copy_n(Hash.begin()+8,8,Nonce.begin());
    const auto Ticks=static_cast<std::uint64_t>(std::chrono::high_resolution_clock::now().time_since_epoch().count());
    for(std::size_t I=0;I<8;++I) Nonce[I]^=static_cast<std::uint8_t>(Ticks>>(I*8));
    return Nonce;
}

OpcodeMap MakeOpcodeMap(std::span<const std::uint8_t, 8> Nonce,
                        std::span<const std::uint8_t, 32> PlainHash) {
    OpcodeMap Map = {0x13,0x27,0x39,0x4D,0x52,0x68,0x7B,0x8E,0xA4,0xC1,0xF3};
    std::uint64_t State = util::LoadLe<std::uint64_t>(Nonce, 0) ^
                          util::LoadLe<std::uint64_t>(PlainHash, 0) ^ 0xD1B54A32D192ED03ULL;
    auto Next = [&]() {
        State ^= State >> 12; State ^= State << 25; State ^= State >> 27;
        return State * 0x2545F4914F6CDD1DULL;
    };
    for (std::size_t I = Map.size() - 1; I > 0; --I) {
        const auto J = static_cast<std::size_t>(Next() % (I + 1));
        std::swap(Map[I], Map[J]);
    }
    return Map;
}

std::array<std::uint8_t,16> PasswordCheck(std::string_view Password, std::span<const std::uint8_t,8> Nonce) {
    crypto::Sha256 H;
    static constexpr std::array<std::uint8_t,9> Domain={'P','E','V','M','-','P','W','-','1'};
    H.Update(Domain);
    H.Update(std::span(reinterpret_cast<const std::uint8_t*>(Password.data()),Password.size()));
    H.Update(Nonce);
    const auto Full=H.Finish();
    std::array<std::uint8_t,16> Out{};
    std::copy_n(Full.begin(),16,Out.begin());
    return Out;
}

} // namespace

std::array<std::uint32_t, 4> DeriveKey(std::string_view Password, std::span<const std::uint8_t, 8> Nonce,
                                       std::span<const std::uint8_t> Program,
                                       const OpcodeMap& Map, const KdfParams& Params) {
    const auto Seed = PasswordSeed(Password, Nonce, Params);
    Vm VmInstance;
    const auto Raw = VmInstance.Run(Program, Seed, Map);
    if (Raw.size() != 16) throw std::runtime_error("key VM returned wrong size");
    std::array<std::uint32_t,4> Key{};
    for (std::size_t I=0;I<4;++I) Key[I]=util::LoadLe<std::uint32_t>(Raw,I*4);
    return Key;
}

const char* SubsystemName(std::uint16_t Subsystem) {
    switch (Subsystem) {
    case KSubsystemNative: return "native";
    case KSubsystemGui: return "gui";
    case KSubsystemConsole: return "console";
    default: return "other";
    }
}

PeInfo ParsePe(std::span<const std::uint8_t> Data) {
    return pevm::pe::ImageView(Data).Info();
}

ContainerHeader ParseContainer(std::span<const std::uint8_t> File) {
    if(File.size()<sizeof(ContainerHeader)) throw std::runtime_error("container truncated");
    ContainerHeader H{};
    std::memcpy(&H,File.data(),sizeof(H));
    if(!std::equal(KMagic.begin(),KMagic.end(),H.Magic)) throw std::runtime_error("bad container magic");
    if(H.Version!=KContainerVersion || H.HeaderSize!=sizeof(ContainerHeader)) {
        throw std::runtime_error("unsupported container version");
    }
    for (std::size_t I=0;I<KOpcodeCount;++I) {
        for (std::size_t J=I+1;J<KOpcodeCount;++J) {
            if (H.OpcodeMap[I]==H.OpcodeMap[J]) throw std::runtime_error("duplicate opcode mapping");
        }
    }
    const std::uint64_t Expected=static_cast<std::uint64_t>(H.HeaderSize)+H.ProgramSize+H.PayloadSize;
    if(Expected!=File.size()) throw std::runtime_error("container size mismatch");
    if(H.Compression!=KCompressionNone && H.Compression!=KCompressionLzss) throw std::runtime_error("unsupported container compression");
    if(H.Compression==KCompressionNone && H.OriginalSize!=H.PayloadSize) throw std::runtime_error("container size mismatch");
    return H;
}

Bytes PackContainer(std::span<const std::uint8_t> Plain, std::string_view Password,
                    bool Compress, pevm::build::Log* Progress) {
    if (Password.size() < 8) throw std::runtime_error("password must be at least 8 characters");
    const auto Pe = ParsePe(Plain);
    if(Plain.size()>std::numeric_limits<std::uint32_t>::max()) throw std::runtime_error("PE larger than 4 GiB is unsupported");
    if (Progress) Progress->Step("Hash input and prepare key program");
    const auto Nonce=MakeNonce(Plain);
    const auto PlainHash=crypto::Sha256::Digest(Plain);
    const auto Map=MakeOpcodeMap(Nonce,PlainHash);
    const auto Program=KeyProgram(Map);
    if (Progress) Progress->Detail("plain SHA-256", util::Hex(PlainHash));
    if (Progress) Progress->Detail("key VM bytecode", pevm::build::Size(Program.size()));
    if (Progress) Progress->Step("Derive payload encryption key");
    if (Progress) Progress->Detail("KDF", "scrypt N=" + std::to_string(std::uint32_t{1} << KDefaultKdf.LogN) +
               " r=" + std::to_string(KDefaultKdf.R) + " p=" + std::to_string(KDefaultKdf.P));
    if (Progress) Progress->Detail("cipher", "XTEA-CTR, 128-bit key");
    const auto Key=DeriveKey(Password,Nonce,Program,Map,KDefaultKdf);
    const auto Check=PasswordCheck(Password,Nonce);

    // Compression is applied before encryption; incompressible inputs stay
    // stored so the container never grows.
    std::uint8_t Compression = KCompressionNone;
    if (Progress) Progress->Step("Prepare payload storage");
    if (Progress) Progress->Detail("compression requested", Compress ? "LZSS" : "off");
    Bytes Stored(Plain.begin(), Plain.end());
    if (Compress) {
        auto Packed = crypto::LzssCompress(Plain);
        if (Packed.size() < Plain.size()) {
            Compression = KCompressionLzss;
            Stored = std::move(Packed);
        }
    }
    if(Stored.size()>std::numeric_limits<std::uint32_t>::max()) throw std::runtime_error("PE larger than 4 GiB is unsupported");
    if (Progress) Progress->Detail("compression result", Compression == KCompressionLzss ? "lzss" :
               Compress ? "stored (compression did not reduce size)" : "stored (compression disabled)");
    if (Progress) Progress->Detail("stored payload", pevm::build::Size(Stored.size()));
    if (Progress) Progress->Detail("stored/original", pevm::build::Ratio(Stored.size(), Plain.size()));
    if (Progress) Progress->Detail("compression saved", pevm::build::Size(Plain.size() - Stored.size()));

    if (Progress) Progress->Step("Encrypt payload and assemble container");
    ContainerHeader H{};
    std::copy(KMagic.begin(),KMagic.end(),H.Magic);
    H.Version=KContainerVersion; H.HeaderSize=sizeof(H); H.Machine=Pe.Machine; H.SectionCount=Pe.Sections;
    H.Subsystem=Pe.Subsystem; H.Compression=Compression;
    H.EntryRva=Pe.EntryRva; H.OriginalSize=Plain.size(); H.ProgramSize=static_cast<std::uint32_t>(Program.size());
    H.PayloadSize=static_cast<std::uint32_t>(Stored.size());
    H.KdfId=KDefaultKdf.Id; H.KdfLogN=KDefaultKdf.LogN; H.KdfR=KDefaultKdf.R; H.KdfP=KDefaultKdf.P;
    std::copy(Nonce.begin(),Nonce.end(),H.Nonce);
    std::copy(Map.begin(),Map.end(),H.OpcodeMap);
    std::copy(Check.begin(),Check.end(),H.PasswordCheck);
    std::copy(PlainHash.begin(),PlainHash.end(),H.PlainSha256);
    crypto::XteaCtr(Stored,Key,util::LoadLe<std::uint64_t>(Nonce,0));

    Bytes Container(sizeof(H));
    std::memcpy(Container.data(),&H,sizeof(H));
    Container.insert(Container.end(),Program.begin(),Program.end());
    Container.insert(Container.end(),Stored.begin(),Stored.end());
    if (Progress) Progress->Detail("container header", pevm::build::Size(sizeof(H)));
    if (Progress) Progress->Detail("encrypted payload", pevm::build::Size(Stored.size()));
    if (Progress) Progress->Detail("container size", pevm::build::Size(Container.size()));
    return Container;
}

void CmdPack(const fs::path& Input, const fs::path& Output, std::string_view Password,
             bool Compress, pevm::build::Log* Progress) {
    std::optional<pevm::build::Log> OwnLog;
    if (!Progress) { OwnLog.emplace("pack", Input, Output); Progress = &*OwnLog; }
    auto& Log = *Progress;
    Log.Step("Read PE payload");
    const auto Plain = util::ReadFile(Input);
    if (OwnLog) Log.InputInfo(Plain);
    const auto Container = PackContainer(Plain, Password, Compress, Progress);
    Log.Step("Write container");
    util::WriteFileAtomic(Output, Container);
    if (OwnLog) Log.Finish(Container, Plain.size());
}

void CmdUnpack(const fs::path& Input, const fs::path& Output, std::string_view Password) {
    const auto Container=util::ReadFile(Input);
    const auto Plain = UnpackContainer(Container, Password);
    util::WriteFileAtomic(Output,Plain);
    const auto Hash=crypto::Sha256::Digest(Plain);
    std::cout<<"unpacked: "<<Input<<" -> "<<Output<<"\nSHA-256: "<<util::Hex(Hash)<<"\n";
}

std::vector<std::uint8_t> UnpackContainer(std::span<const std::uint8_t> Container, std::string_view Password) {
    const auto H=ParseContainer(Container);
    std::array<std::uint8_t,8> Nonce{}; std::copy_n(H.Nonce,8,Nonce.begin());
    const auto Check=PasswordCheck(Password,Nonce);
    if(!crypto::ConstantEqual(Check,std::span(H.PasswordCheck,16))) throw std::runtime_error("wrong password");
    const auto Program=std::span(Container).subspan(H.HeaderSize,H.ProgramSize);
    OpcodeMap Map{}; std::copy_n(H.OpcodeMap,KOpcodeCount,Map.begin());
    Bytes Plain(Container.begin()+H.HeaderSize+H.ProgramSize,Container.end());
    const auto Key=DeriveKey(Password,Nonce,Program,Map,
                             KdfParams{H.KdfId,H.KdfLogN,H.KdfR,H.KdfP});
    crypto::XteaCtr(Plain,Key,util::LoadLe<std::uint64_t>(Nonce,0));
    if (H.Compression == KCompressionLzss) {
        Plain = crypto::LzssDecompress(Plain, H.OriginalSize);
    }
    const auto Hash=crypto::Sha256::Digest(Plain);
    if(!crypto::ConstantEqual(Hash,std::span(H.PlainSha256,32))) throw std::runtime_error("integrity check failed");
    const auto Pe=ParsePe(Plain);
    if(Pe.Machine!=H.Machine || Pe.EntryRva!=H.EntryRva || Pe.Subsystem!=H.Subsystem || Pe.Sections!=H.SectionCount) throw std::runtime_error("metadata check failed");
    return Plain;
}
