#include "VmImageCodec.h"
#include "WrapperFormat.h"

#include <cstring>
#include <stdexcept>
#include <unordered_set>

namespace pevm {
namespace {
using namespace crypto;

std::span<const std::uint8_t> BytesOf(std::string_view Value) {
    return {reinterpret_cast<const std::uint8_t*>(Value.data()), Value.size()};
}

void Wipe(void* Data, std::size_t Size) noexcept {
    auto* Byte = static_cast<volatile std::uint8_t*>(Data);
    while (Size-- != 0) *Byte++ = 0;
}

struct WipedTable {
    Bytes Data;
    ~WipedTable() { Wipe(Data.data(), Data.size()); }
};

struct ImageKeys {
    Sha256Digest Encryption{};
    Sha256Digest Authentication{};
    Sha256Digest FunctionSeeds{};
    ~ImageKeys() { Wipe(this, sizeof(*this)); }
};

Sha256Digest Derive(std::string_view Secret, std::string_view Purpose,
                    std::uint64_t Seed, std::span<const std::uint8_t> Profile) {
    HmacSha256 Hash(BytesOf(Secret));
    Hash.Update(BytesOf(Purpose));
    std::array<std::uint8_t, 12> Context{};
    for (unsigned I = 0; I < 4; ++I) Context[I] = static_cast<std::uint8_t>(KVmImageVersion >> (8 * I));
    for (unsigned I = 0; I < 8; ++I) Context[4 + I] = static_cast<std::uint8_t>(Seed >> (8 * I));
    Hash.Update(Context);
    Hash.Update(Profile);
    return Hash.Finish();
}

ImageKeys MakeKeys(std::string_view Secret, std::uint64_t Seed,
                   std::span<const std::uint8_t> Profile) {
    if (Secret.empty() || Profile.size() != 32) throw std::runtime_error("VM image key context invalid");
    return {Derive(Secret, "PEVM-VM-ENCRYPTION", Seed, Profile),
            Derive(Secret, "PEVM-VM-AUTHENTICATION", Seed, Profile),
            Derive(Secret, "PEVM-VM-FUNCTION-SEEDS", Seed, Profile)};
}

Sha256Digest ImageTag(std::span<const std::uint8_t> Image, const ImageKeys& Keys) {
    HmacSha256 Hash(Keys.Authentication);
    Hash.Update(BytesOf("PEVM-VM-IMAGE"));
    Hash.Update(Image);
    return Hash.Finish();
}

void CryptTable(Bytes& Table, const ImageKeys& Keys, std::uint64_t Seed) {
    XteaKey Key{};
    for (std::size_t I = 0; I < Key.size(); ++I) {
        for (unsigned B = 0; B < 4; ++B) Key[I] |= static_cast<std::uint32_t>(Keys.Encryption[I * 4 + B]) << (B * 8);
    }
    XteaCtr(Table, Key, Seed);
    Wipe(Key.data(), sizeof(Key));
}

std::uint64_t FunctionSeed(const ImageKeys& Keys, std::uint32_t Rva) {
    HmacSha256 Hash(Keys.FunctionSeeds);
    std::array<std::uint8_t, 4> Encoded{};
    for (unsigned I = 0; I < 4; ++I) Encoded[I] = static_cast<std::uint8_t>(Rva >> (8 * I));
    Hash.Update(Encoded);
    auto Digest = Hash.Finish();
    std::uint64_t Seed = 0;
    for (unsigned I = 0; I < 8; ++I) Seed |= static_cast<std::uint64_t>(Digest[I]) << (8 * I);
    Wipe(Digest.data(), Digest.size());
    return Seed;
}

template <typename T> T Read(std::span<const std::uint8_t> Data, std::size_t Offset) {
    if (Offset > Data.size() || sizeof(T) > Data.size() - Offset) throw std::runtime_error("VM image truncated");
    T Value{};
    std::memcpy(&Value, Data.data() + Offset, sizeof(Value));
    return Value;
}
} // namespace

crypto::Bytes EncodeVmImage(std::span<const vmprotect::LiftedProgram> Programs,
                           std::uint64_t Seed, std::string_view BuildSecret,
                           std::span<const std::uint8_t> HandlerProfile, bool Decoys,
                           std::vector<vmprotect::CompilationStats>* Statistics) {
    if (Programs.empty() || Programs.size() > UINT32_MAX) throw std::runtime_error("VM image function count invalid");
    const auto Keys = MakeKeys(BuildSecret, Seed, HandlerProfile);
    std::size_t Count = 0;
    std::vector<vmprotect::CompilationStats> CompiledStats;
    if (Statistics) CompiledStats.reserve(Programs.size());
    std::unordered_set<std::uint32_t> Entries;
    for (const auto& Program : Programs) {
        if (Program.Instructions.empty() || Program.Instructions.size() > UINT32_MAX - Count) {
            throw std::runtime_error("VM image instruction count invalid");
        }
        if (!Entries.insert(Program.EntryAddress).second) throw std::runtime_error("VM image duplicate function entry");
        // Use the same validator/assembler that the loader will use.
        const auto Compiled = vmprotect::CompileLiftedProgram(Program, FunctionSeed(Keys, Program.EntryAddress));
        if (Statistics) CompiledStats.push_back(vmprotect::GetCompilationStats(Compiled));
        Count += Program.Instructions.size();
    }
    const std::uint32_t DecoySize = Decoys ? 128U : 0U;
    const Vmp3Header Header{KVmp3Magic, KVmImageVersion, static_cast<std::uint32_t>(Programs.size()), Seed, DecoySize, 0};
    const auto EntryBytes = Programs.size() * sizeof(Vmp3Entry);
    WipedTable Table{Bytes(Count * sizeof(Vmp3Instruction))};
    Bytes Data(sizeof(Header) + EntryBytes + Table.Data.size() + DecoySize + KVmImageTagSize);
    std::memcpy(Data.data(), &Header, sizeof(Header));
    std::size_t Cursor = 0;
    for (std::size_t F = 0; F < Programs.size(); ++F) {
        const auto& Program = Programs[F];
        const Vmp3Entry Entry{Program.EntryAddress, static_cast<std::uint32_t>(Cursor),
                             static_cast<std::uint32_t>(Program.Instructions.size()), Program.ResumeAddress};
        std::memcpy(Data.data() + sizeof(Header) + F * sizeof(Entry), &Entry, sizeof(Entry));
        for (const auto& Instruction : Program.Instructions) {
            const Vmp3Instruction Record{static_cast<std::uint8_t>(Instruction.Op), Instruction.Dst,
                Instruction.Src, Instruction.Width, Instruction.Immediate, Instruction.Address, Instruction.Target};
            std::memcpy(Table.Data.data() + Cursor++ * sizeof(Record), &Record, sizeof(Record));
        }
    }
    CryptTable(Table.Data, Keys, Seed);
    std::memcpy(Data.data() + sizeof(Header) + EntryBytes, Table.Data.data(), Table.Data.size());
    auto State = Seed ^ 0xA5F1523D9E3779B9ULL;
    auto* DecoyData = Data.data() + Data.size() - KVmImageTagSize - DecoySize;
    for (std::uint32_t I = 0; I < DecoySize; ++I) {
        State = WrapperMix64(State + I);
        static constexpr std::array<std::uint8_t, 4> Patterns = {0x90, 0xCC, 0x0F, 0x0B};
        DecoyData[I] = (I + 1 < DecoySize && (I % 11U) == 0) ? 0x0F : Patterns[State & 3U];
        if (DecoyData[I] == 0x0F && I + 1 < DecoySize && (I % 11U) == 0) DecoyData[++I] = 0x0B;
    }
    const auto Tag = ImageTag(std::span(Data).first(Data.size() - KVmImageTagSize), Keys);
    std::memcpy(Data.data() + Data.size() - Tag.size(), Tag.data(), Tag.size());
    if (Statistics) *Statistics = std::move(CompiledStats);
    return Data;
}

std::vector<DecodedVmFunction> DecodeVmImage(std::span<const std::uint8_t> Data,
                                           std::string_view BuildSecret,
                                           std::span<const std::uint8_t> HandlerProfile) {
    if (Data.size() < sizeof(Vmp3Header) + KVmImageTagSize) throw std::runtime_error("VM image truncated");
    const auto Header = Read<Vmp3Header>(Data, 0);
    if (Header.Magic != KVmp3Magic || Header.Version != KVmImageVersion) {
        throw std::runtime_error("VM image unsupported format; rebuild the wrapper");
    }
    const auto Keys = MakeKeys(BuildSecret, Header.Seed, HandlerProfile);
    const auto Body = Data.first(Data.size() - KVmImageTagSize);
    const auto Tag = ImageTag(Body, Keys);
    if (!ConstantEqual(Tag, Data.last(KVmImageTagSize))) throw std::runtime_error("VM image authentication failed");
    if (Header.Reserved != 0 || (Header.DecoySize != 0 && Header.DecoySize != 128) ||
        Header.FunctionCount == 0 || Header.FunctionCount > (Body.size() - sizeof(Header)) / sizeof(Vmp3Entry)) {
        throw std::runtime_error("VM image header invalid");
    }
    const auto EntryBytes = static_cast<std::size_t>(Header.FunctionCount) * sizeof(Vmp3Entry);
    const auto TableOffset = sizeof(Header) + EntryBytes;
    if (Header.DecoySize > Body.size() - TableOffset) throw std::runtime_error("VM image decoy range invalid");
    const auto TableSize = Body.size() - TableOffset - Header.DecoySize;
    if (TableSize == 0 || TableSize % sizeof(Vmp3Instruction) != 0 || TableSize / sizeof(Vmp3Instruction) > UINT32_MAX) {
        throw std::runtime_error("VM image instruction table invalid");
    }
    const auto TotalInstructions = TableSize / sizeof(Vmp3Instruction);
    std::unordered_set<std::uint32_t> Seen;
    std::size_t Cursor = 0;
    for (std::size_t F = 0; F < Header.FunctionCount; ++F) {
        const auto Entry = Read<Vmp3Entry>(Body, sizeof(Header) + F * sizeof(Vmp3Entry));
        if ((Entry.ResumeRva && (Entry.ResumeRva<Entry.FunctionRva || Entry.ResumeRva-Entry.FunctionRva<5 ||
                                Entry.ResumeRva-Entry.FunctionRva>128 || Entry.ResumeRva>=0x80000000U)) ||
            Entry.InstructionCount == 0 || Entry.InstructionOffset != Cursor ||
            Entry.InstructionCount > TotalInstructions - Cursor || !Seen.insert(Entry.FunctionRva).second) {
            throw std::runtime_error("VM image entry table invalid");
        }
        Cursor += Entry.InstructionCount;
    }
    if (Cursor != TotalInstructions) throw std::runtime_error("VM image unclaimed instruction bytes");
    WipedTable Table{Bytes(Body.begin() + TableOffset, Body.begin() + TableOffset + TableSize)};
    CryptTable(Table.Data, Keys, Header.Seed);
    std::vector<DecodedVmFunction> Functions;
    Functions.reserve(Header.FunctionCount);
    for (std::size_t F = 0; F < Header.FunctionCount; ++F) {
        const auto Entry = Read<Vmp3Entry>(Body, sizeof(Header) + F * sizeof(Vmp3Entry));
        DecodedVmFunction Function{};
        Function.Program.EntryAddress = Entry.FunctionRva;
        Function.Program.ResumeAddress = Entry.ResumeRva;
        Function.Seed = FunctionSeed(Keys, Entry.FunctionRva);
        Function.Program.Instructions.reserve(Entry.InstructionCount);
        for (std::size_t I = 0; I < Entry.InstructionCount; ++I) {
            const auto Record = Read<Vmp3Instruction>(Table.Data, (Entry.InstructionOffset + I) * sizeof(Vmp3Instruction));
            if (!vmprotect::ValidOperandWidth(Record.Width) || Record.Op >= static_cast<std::uint8_t>(vmprotect::LiftedOp::Count)) {
                throw std::runtime_error("VM image instruction invalid");
            }
            Function.Program.Instructions.push_back({static_cast<vmprotect::LiftedOp>(Record.Op),
                Record.Dst, Record.Src, Record.Immediate, Record.Address, Record.Target, Record.Width});
        }
        Functions.push_back(std::move(Function));
    }
    return Functions;
}
} // namespace pevm
