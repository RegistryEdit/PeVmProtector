#include "PeVmCrypto.h"

#include <algorithm>
#include <bit>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace pevm::crypto {
namespace {

constexpr std::uint32_t Bswap32(std::uint32_t Value) {
    return ((Value & 0x000000ffU) << 24) | ((Value & 0x0000ff00U) << 8) |
           ((Value & 0x00ff0000U) >> 8) | ((Value & 0xff000000U) >> 24);
}

constexpr std::array<std::uint32_t, 64> KSha256K = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

} // namespace

void Sha256::Update(std::span<const std::uint8_t> Input) {
    Total += Input.size();
    for (const auto Byte : Input) {
        Block[Used++] = Byte;
        if (Used == Block.size()) {
            Compress(Block.data());
            Used = 0;
        }
    }
}

Sha256Digest Sha256::Finish() {
    const std::uint64_t Bits = Total * 8;
    Block[Used++] = 0x80;
    if (Used > 56) {
        std::fill(Block.begin() + static_cast<std::ptrdiff_t>(Used), Block.end(), std::uint8_t{0});
        Compress(Block.data());
        Used = 0;
    }
    std::fill(Block.begin() + static_cast<std::ptrdiff_t>(Used), Block.begin() + 56, std::uint8_t{0});
    for (int I = 0; I < 8; ++I) Block[63 - I] = static_cast<std::uint8_t>(Bits >> (I * 8));
    Compress(Block.data());

    Sha256Digest Out{};
    for (std::size_t I = 0; I < State.size(); ++I) {
        Out[I * 4] = static_cast<std::uint8_t>(State[I] >> 24);
        Out[I * 4 + 1] = static_cast<std::uint8_t>(State[I] >> 16);
        Out[I * 4 + 2] = static_cast<std::uint8_t>(State[I] >> 8);
        Out[I * 4 + 3] = static_cast<std::uint8_t>(State[I]);
    }
    return Out;
}

Sha256Digest Sha256::Digest(std::span<const std::uint8_t> Input) {
    Sha256 Hash;
    Hash.Update(Input);
    return Hash.Finish();
}

void Sha256::Compress(const std::uint8_t* InputBlock) {
    std::array<std::uint32_t, 64> W{};
    for (std::size_t I = 0; I < 16; ++I) {
        W[I] = (static_cast<std::uint32_t>(InputBlock[I * 4]) << 24) |
               (static_cast<std::uint32_t>(InputBlock[I * 4 + 1]) << 16) |
               (static_cast<std::uint32_t>(InputBlock[I * 4 + 2]) << 8) |
               InputBlock[I * 4 + 3];
    }
    for (std::size_t I = 16; I < 64; ++I) {
        const auto S0 = std::rotr(W[I - 15], 7) ^ std::rotr(W[I - 15], 18) ^ (W[I - 15] >> 3);
        const auto S1 = std::rotr(W[I - 2], 17) ^ std::rotr(W[I - 2], 19) ^ (W[I - 2] >> 10);
        W[I] = W[I - 16] + S0 + W[I - 7] + S1;
    }
    auto [A,B,C,D,E,F,G,H] = State;
    for (std::size_t I = 0; I < 64; ++I) {
        const auto S1 = std::rotr(E, 6) ^ std::rotr(E, 11) ^ std::rotr(E, 25);
        const auto Ch = (E & F) ^ (~E & G);
        const auto T1 = H + S1 + Ch + KSha256K[I] + W[I];
        const auto S0 = std::rotr(A, 2) ^ std::rotr(A, 13) ^ std::rotr(A, 22);
        const auto Maj = (A & B) ^ (A & C) ^ (B & C);
        const auto T2 = S0 + Maj;
        H=G; G=F; F=E; E=D+T1; D=C; C=B; B=A; A=T1+T2;
    }
    State[0]+=A; State[1]+=B; State[2]+=C; State[3]+=D;
    State[4]+=E; State[5]+=F; State[6]+=G; State[7]+=H;
}

HmacSha256::HmacSha256(std::span<const std::uint8_t> Key) {
    std::array<std::uint8_t, 64> Pad{};
    if (Key.size() > Pad.size()) {
        auto Compressed = Sha256::Digest(Key);
        std::copy_n(Compressed.begin(), Compressed.size(), Pad.begin());
    } else {
        std::copy(Key.begin(), Key.end(), Pad.begin());
    }
    for (std::size_t I = 0; I < Pad.size(); ++I) {
        Opad[I] = static_cast<std::uint8_t>(Pad[I] ^ 0x5c);
        Pad[I] = static_cast<std::uint8_t>(Pad[I] ^ 0x36);
    }
    Hash.Update(Pad);
}

Sha256Digest HmacSha256::Finish() {
    auto Inner = Hash.Finish();
    Sha256 Outer;
    Outer.Update(Opad);
    Outer.Update(Inner);
    return Outer.Finish();
}

Bytes Pbkdf2(std::span<const std::uint8_t> Password, std::span<const std::uint8_t> Salt,
             std::uint64_t Iterations, std::size_t DerivedLength) {
    if (Iterations == 0) throw std::runtime_error("PBKDF2 requires at least one iteration");
    Bytes Output;
    const std::uint32_t BlockCount = static_cast<std::uint32_t>(
        (DerivedLength + 31) / 32);
    for (std::uint32_t Block = 1; Block <= BlockCount; ++Block) {
        std::array<std::uint8_t, 4> Index = {
            static_cast<std::uint8_t>(Block >> 24), static_cast<std::uint8_t>(Block >> 16),
            static_cast<std::uint8_t>(Block >> 8), static_cast<std::uint8_t>(Block)};
        HmacSha256 Mac(Password);
        Mac.Update(Salt);
        Mac.Update(Index);
        auto U = Mac.Finish();
        std::array<std::uint8_t, 32> T = U;
        for (std::uint64_t I = 1; I < Iterations; ++I) {
            HmacSha256 Round(Password);
            Round.Update(U);
            U = Round.Finish();
            for (std::size_t J = 0; J < T.size(); ++J) T[J] ^= U[J];
        }
        const auto Take = std::min<std::size_t>(32, DerivedLength - Output.size());
        Output.insert(Output.end(), T.begin(), T.begin() + static_cast<std::ptrdiff_t>(Take));
    }
    return Output;
}

namespace {

void Salsa20_8(std::span<std::uint8_t, 64> Block) {
    std::uint32_t X[16];
    std::uint32_t Original[16];
    std::memcpy(Original, Block.data(), 64);
    std::memcpy(X, Block.data(), 64);
    if constexpr (std::endian::native == std::endian::big) {
        for (auto& W : X) W = Bswap32(W);
        for (auto& W : Original) W = Bswap32(W);
    }
    const auto Quarter = [](std::uint32_t& A, std::uint32_t& B, std::uint32_t& C, std::uint32_t& D) {
        B ^= std::rotl(A + D, 7);
        C ^= std::rotl(B + A, 9);
        D ^= std::rotl(C + B, 13);
        A ^= std::rotl(D + C, 18);
    };
    // Salsa20/8 = 8 rounds = 4 double rounds (column round then row round).
    for (unsigned Round = 0; Round < 4; ++Round) {
        Quarter(X[0], X[4], X[8], X[12]);
        Quarter(X[5], X[9], X[13], X[1]);
        Quarter(X[10], X[14], X[2], X[6]);
        Quarter(X[15], X[3], X[7], X[11]);
        Quarter(X[0], X[1], X[2], X[3]);
        Quarter(X[5], X[6], X[7], X[4]);
        Quarter(X[10], X[11], X[8], X[9]);
        Quarter(X[15], X[12], X[13], X[14]);
    }
    for (unsigned I = 0; I < 16; ++I) X[I] += Original[I];
    if constexpr (std::endian::native == std::endian::big) {
        for (auto& W : X) W = Bswap32(W);
    }
    std::memcpy(Block.data(), X, 64);
}

// BlockMix over 128*R byte blocks: input is 2R 64-byte Salsa blocks and the
// output interleaves the even and odd halves.
void BlockMix(std::span<const std::uint8_t> Input, std::span<std::uint8_t> Output, std::uint32_t R) {
    std::array<std::uint8_t, 64> X{};
    std::memcpy(X.data(), Input.data() + static_cast<std::size_t>(2 * R - 1) * 64, 64);
    Bytes Y(static_cast<std::size_t>(2 * R) * 64);
    for (std::uint32_t I = 0; I < 2 * R; ++I) {
        for (std::size_t J = 0; J < 64; ++J) {
            X[J] ^= Input[static_cast<std::size_t>(I) * 64 + J];
        }
        Salsa20_8(X);
        std::memcpy(Y.data() + static_cast<std::size_t>(I) * 64, X.data(), 64);
    }
    for (std::uint32_t I = 0; I < R; ++I) {
        std::memcpy(Output.data() + static_cast<std::size_t>(I) * 64,
                    Y.data() + static_cast<std::size_t>(2 * I) * 64, 64);
        std::memcpy(Output.data() + (static_cast<std::size_t>(R) + I) * 64,
                    Y.data() + static_cast<std::size_t>(2 * I + 1) * 64, 64);
    }
}

void Romix(std::span<std::uint8_t> Block, std::uint32_t N, std::uint32_t R) {
    const std::size_t BlockBytes = static_cast<std::size_t>(128) * R;
    Bytes Scratch(BlockBytes);
    Bytes Table(static_cast<std::size_t>(N) * BlockBytes);
    for (std::uint32_t I = 0; I < N; ++I) {
        std::memcpy(Table.data() + static_cast<std::size_t>(I) * BlockBytes, Block.data(), BlockBytes);
        BlockMix(Block, Scratch, R);
        std::memcpy(Block.data(), Scratch.data(), BlockBytes);
    }
    for (std::uint32_t I = 0; I < N; ++I) {
        const auto* Last = Block.data() + (static_cast<std::size_t>(2 * R - 1) * 64);
        const std::uint64_t J = static_cast<std::uint64_t>(Last[0]) |
                               (static_cast<std::uint64_t>(Last[1]) << 8) |
                               (static_cast<std::uint64_t>(Last[2]) << 16) |
                               (static_cast<std::uint64_t>(Last[3]) << 24) |
                               (static_cast<std::uint64_t>(Last[4]) << 32) |
                               (static_cast<std::uint64_t>(Last[5]) << 40) |
                               (static_cast<std::uint64_t>(Last[6]) << 48) |
                               (static_cast<std::uint64_t>(Last[7]) << 56);
        const auto Slot = static_cast<std::size_t>(J & (N - 1)) * BlockBytes;
        for (std::size_t K = 0; K < BlockBytes; ++K) Block[K] ^= Table[Slot + K];
        BlockMix(Block, Scratch, R);
        std::memcpy(Block.data(), Scratch.data(), BlockBytes);
    }
}

} // namespace

Bytes Scrypt(std::span<const std::uint8_t> Password, std::span<const std::uint8_t> Salt,
             std::uint32_t N, std::uint32_t R, std::uint32_t P, std::size_t DerivedLength) {
    if (N < 2 || (N & (N - 1)) != 0) throw std::runtime_error("scrypt N must be a power of two");
    if (R == 0 || P == 0) throw std::runtime_error("scrypt R and P must be nonzero");
    if (static_cast<std::uint64_t>(N) * R > (std::uint64_t{1} << 30)) {
        throw std::runtime_error("scrypt parameters exceed the memory budget");
    }
    const std::size_t BlockBytes = static_cast<std::size_t>(128) * R;
    auto B = Pbkdf2(Password, Salt, 1, static_cast<std::size_t>(P) * BlockBytes);
    for (std::uint32_t I = 0; I < P; ++I) {
        Romix(std::span(B).subspan(static_cast<std::size_t>(I) * BlockBytes, BlockBytes), N, R);
    }
    return Pbkdf2(Password, B, 1, DerivedLength);
}

std::array<std::uint8_t, 8> XteaBlock(std::uint64_t Counter, const XteaKey& Key) {
    std::uint32_t V0=static_cast<std::uint32_t>(Counter), V1=static_cast<std::uint32_t>(Counter>>32), Sum=0;
    constexpr std::uint32_t Delta=0x9E3779B9;
    for (unsigned I=0;I<32;++I) {
        V0 += (((V1<<4)^(V1>>5))+V1) ^ (Sum+Key[Sum&3]);
        Sum += Delta;
        V1 += (((V0<<4)^(V0>>5))+V0) ^ (Sum+Key[(Sum>>11)&3]);
    }
    std::array<std::uint8_t,8> Out{};
    std::uint64_t Joined=static_cast<std::uint64_t>(V0)|(static_cast<std::uint64_t>(V1)<<32);
    if constexpr (std::endian::native == std::endian::big) {
        const auto Lo = Bswap32(static_cast<std::uint32_t>(Joined));
        const auto Hi = Bswap32(static_cast<std::uint32_t>(Joined >> 32));
        Joined = (static_cast<std::uint64_t>(Lo) << 32) | Hi;
    }
    std::memcpy(Out.data(),&Joined,8);
    return Out;
}

void XteaCtr(Bytes& Data, const XteaKey& Key, std::uint64_t Nonce) {
    for (std::size_t Off=0, Block=0; Off<Data.size(); Off+=8,++Block) {
        const auto Stream=XteaBlock(Nonce+Block,Key);
        const auto N=std::min<std::size_t>(8,Data.size()-Off);
        for(std::size_t I=0;I<N;++I) Data[Off+I]^=Stream[I];
    }
}

bool ConstantEqual(std::span<const std::uint8_t> A, std::span<const std::uint8_t> B) {
    if (A.size() != B.size()) return false;
    std::uint8_t Diff = 0;
    for (std::size_t I = 0; I < A.size(); ++I) Diff |= static_cast<std::uint8_t>(A[I] ^ B[I]);
    return Diff == 0;
}

// LZSS: window 4096 bytes, match length 3..18, one flag byte per eight
// symbols. A match token is two bytes: byte0 = (offset-1) & 0xFF, byte1 =
// (len-3) | (((offset-1) >> 8) << 4). Corrupt input fails closed.
namespace {

std::size_t LzssKey(std::span<const std::uint8_t> Input, std::size_t Pos) {
    return (Input[Pos] | (Input[Pos + 1] << 8) | (Input[Pos + 2] << 16)) & 0xFFFFU;
}

} // namespace

Bytes LzssCompress(std::span<const std::uint8_t> Input) {
    Bytes Out;
    Out.reserve(Input.size() + Input.size() / 8 + 16);
    constexpr std::size_t Window = 4096;
    constexpr std::size_t MinMatch = 3;
    constexpr std::size_t MaxMatch = 18;
    // Heap-allocated: 64K buckets would blow the default thread stack.
    std::vector<std::vector<std::uint32_t>> Table(65536);
    std::size_t Pos = 0;
    while (Pos < Input.size()) {
        const auto FlagPosition = Out.size();
        Out.push_back(0);
        unsigned Mask = 0;
        for (unsigned Bit = 0; Bit < 8 && Pos < Input.size(); ++Bit) {
            std::size_t BestLength = 0, BestDistance = 0;
            if (Pos + MinMatch <= Input.size()) {
                auto& Chain = Table[LzssKey(Input, Pos)];
                unsigned Examined = 0;
                for (auto It = Chain.rbegin(); It != Chain.rend() && BestLength < MaxMatch && Examined < 64; ++It, ++Examined) {
                    const auto Candidate = *It;
                    if (Pos - static_cast<std::size_t>(Candidate) > Window) continue;
                    const auto Limit = std::min(MaxMatch, Input.size() - Pos);
                    std::size_t Length = 0;
                    while (Length < Limit && Input[Candidate + Length] == Input[Pos + Length]) ++Length;
                    if (Length >= MinMatch && Length > BestLength) {
                        BestLength = Length;
                        BestDistance = Pos - static_cast<std::size_t>(Candidate);
                    }
                }
            }
            if (BestLength >= MinMatch) {
                if (BestDistance > Pos) {
                    throw std::runtime_error("LZSS encode invariant broken: match before position");
                }
                const auto Offset = BestDistance - 1;
                Out.push_back(static_cast<std::uint8_t>(Offset & 0xFFU));
                Out.push_back(static_cast<std::uint8_t>(((Offset >> 8) & 0x0FU) << 4 | (BestLength - MinMatch)));
                Mask |= 1U << Bit;
                for (std::size_t K = 0; K < BestLength && Pos + K + MinMatch <= Input.size(); ++K) {
                    Table[LzssKey(Input, Pos + K)].push_back(static_cast<std::uint32_t>(Pos + K));
                }
                Pos += BestLength;
            } else {
                Out.push_back(Input[Pos]);
                if (Pos + MinMatch <= Input.size()) Table[LzssKey(Input, Pos)].push_back(static_cast<std::uint32_t>(Pos));
                ++Pos;
            }
        }
        Out[FlagPosition] = static_cast<std::uint8_t>(Mask);
    }
    return Out;
}

Bytes LzssDecompress(std::span<const std::uint8_t> Input, std::size_t ExpectedSize) {
    Bytes Out;
    Out.reserve(ExpectedSize);
    std::size_t Pos = 0;
    while (Out.size() < ExpectedSize) {
        if (Pos >= Input.size()) throw std::runtime_error("compressed stream truncated");
        const auto Mask = Input[Pos++];
        for (unsigned Bit = 0; Bit < 8 && Out.size() < ExpectedSize; ++Bit) {
            if (Pos >= Input.size()) throw std::runtime_error("compressed stream truncated");
            if ((Mask & (1U << Bit)) != 0) {
                if (Pos + 2 > Input.size()) throw std::runtime_error("compressed stream truncated");
                const auto Low = Input[Pos++];
                const auto High = Input[Pos++];
                const auto Offset = static_cast<std::size_t>(Low | ((High & 0xF0U) >> 4 << 8)) + 1;
                const auto Length = static_cast<std::size_t>(High & 0x0FU) + 3;
                if (Offset > Out.size()) {
                    std::ostringstream Diagnostics;
                    Diagnostics << "compressed stream corrupt (offset " << Offset
                                << " > produced " << Out.size() << ", length " << Length
                                << ", at input " << Pos - 2 << ")";
                    throw std::runtime_error(Diagnostics.str());
                }
                for (std::size_t K = 0; K < Length; ++K) Out.push_back(Out[Out.size() - Offset]);
            } else {
                Out.push_back(Input[Pos++]);
            }
        }
    }
    if (Out.size() != ExpectedSize) throw std::runtime_error("decompressed size mismatch");
    return Out;
}

std::string Hex(std::span<const std::uint8_t> Data) {
    std::ostringstream Out;
    Out << std::hex << std::setfill('0');
    for (auto B : Data) Out << std::setw(2) << static_cast<unsigned>(B);
    return Out.str();
}

std::string Base64Encode(std::span<const std::uint8_t> Data) {
    static constexpr std::array<char, 64> Alphabet = {
        'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P',
        'Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f',
        'g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v',
        'w','x','y','z','0','1','2','3','4','5','6','7','8','9','+','/'};
    std::string Out;
    Out.reserve((Data.size() + 2) / 3 * 4);
    std::size_t I = 0;
    while (I + 3 <= Data.size()) {
        const auto Group = (Data[I] << 16) | (Data[I + 1] << 8) | Data[I + 2];
        Out.push_back(Alphabet[(Group >> 18) & 63]);
        Out.push_back(Alphabet[(Group >> 12) & 63]);
        Out.push_back(Alphabet[(Group >> 6) & 63]);
        Out.push_back(Alphabet[Group & 63]);
        I += 3;
    }
    const auto Remainder = Data.size() - I;
    if (Remainder == 1) {
        const auto Group = Data[I] << 16;
        Out.push_back(Alphabet[(Group >> 18) & 63]);
        Out.push_back(Alphabet[(Group >> 12) & 63]);
        Out.push_back('=');
        Out.push_back('=');
    } else if (Remainder == 2) {
        const auto Group = (Data[I] << 16) | (Data[I + 1] << 8);
        Out.push_back(Alphabet[(Group >> 18) & 63]);
        Out.push_back(Alphabet[(Group >> 12) & 63]);
        Out.push_back(Alphabet[(Group >> 6) & 63]);
        Out.push_back('=');
    }
    return Out;
}

std::vector<std::uint8_t> Base64Decode(std::string_view Text) {
    auto ValueOf = [](char C) -> unsigned {
        if (C >= 'A' && C <= 'Z') return static_cast<unsigned>(C - 'A');
        if (C >= 'a' && C <= 'z') return static_cast<unsigned>(C - 'a' + 26);
        if (C >= '0' && C <= '9') return static_cast<unsigned>(C - '0' + 52);
        if (C == '+') return 62;
        if (C == '/') return 63;
        throw std::runtime_error("invalid base64 input");
    };
    std::vector<std::uint8_t> Out;
    unsigned Accumulator = 0;
    unsigned Bits = 0;
    for (const char C : Text) {
        if (C == '=' || C == '\r' || C == '\n') continue;
        Accumulator = (Accumulator << 6) | ValueOf(C);
        Bits += 6;
        if (Bits >= 8) {
            Bits -= 8;
            Out.push_back(static_cast<std::uint8_t>(Accumulator >> Bits));
        }
    }
    return Out;
}

} // namespace pevm::crypto
