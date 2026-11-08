#include "VmProtect.h"
#include "VmSimd.h"

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <limits>
#include <span>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>
#include <intrin.h>
#include <windows.h>
#include "WindowsResources.h"

namespace vmprotect {
extern "C" void PeVmCallNative(VmBridgeContext* Context);
namespace {

using Bytes = std::vector<std::uint8_t>;

enum class Op : std::uint8_t {
    MovI, Mov, Add, AddI, Sub, SubI, Adc, Sbb, Mul, MulI, Xor, And, Or, AndI, Neg, Not, Bswap, Test,
    ShlI, ShrI, ShlR, ShrR, SarI, SarR, RolI, RorI, RolR, RorR,
    Cmp, Jmp, Jz, Jnz,
    Ja, Jae, Jb, Jbe, Js, Jns, Jl, Jge, Jle, Jg, Jo, Jno, Jp, Jnp,
    Push, Pop, Call, Ret, Load64, Load64D, Store64, Store64D, Nop, Halt,
    Trap, Sized, Count
};

constexpr std::size_t KOpCount = static_cast<std::size_t>(Op::Count);
using OpMap = std::array<std::uint8_t, KOpCount>;
using RegisterMap = std::array<std::uint8_t, 16>;

// The register file holds the 16 x64 registers plus 8 physical scratch
// registers (indices 16..23). Scratch registers back synthetic lifter IR
// (address computation, read-modify-write memory ops); they are never
// permuted and never part of the native bridge.
constexpr std::size_t KRegisterCount = 24;
constexpr std::uint8_t KScratchBase = 16;

// Each op with multiple handler implementations owns one variant slot. The
// mapping is centralized so enum reordering cannot silently reshuffle which
// variant executes.
constexpr std::size_t KVariantSlots = 10;
constexpr std::uint8_t KNoVariant = 0xFF;

std::uint8_t VariantSlot(Op Operation) {
    switch (Operation) {
    case Op::Add: return 0; case Op::AddI: return 1;
    case Op::Sub: return 2; case Op::SubI: return 3;
    case Op::Xor: return 4; case Op::Mul: return 5;
    case Op::And: return 6; case Op::Or: return 7;
    case Op::Cmp: return 8; case Op::Test: return 9;
    default: return KNoVariant;
    }
}

// x86-style flag set. Pf is set for even parity of the low result byte.
struct Flags {
    bool Zf{}; bool Cf{}; bool Sf{}; bool Of{}; bool Pf{};
};

bool EvenParity(std::uint64_t Value) {
    return (std::popcount(static_cast<std::uint8_t>(Value)) & 1U) == 0U;
}

void SetAddFlags(Flags& F, std::uint64_t Dst, std::uint64_t Src, std::uint64_t Result) {
    F.Zf = Result == 0;
    F.Sf = (Result >> 63) != 0;
    F.Cf = Result < Dst;
    F.Of = (((Dst ^ Result) & (Src ^ Result)) >> 63) != 0;
    F.Pf = EvenParity(Result);
}

void SetSubFlags(Flags& F, std::uint64_t Dst, std::uint64_t Src, std::uint64_t Result) {
    F.Zf = Result == 0;
    F.Sf = (Result >> 63) != 0;
    F.Cf = Dst < Src;
    F.Of = (((Dst ^ Src) & (Dst ^ Result)) >> 63) != 0;
    F.Pf = EvenParity(Result);
}

void SetLogicFlags(Flags& F, std::uint64_t Result) {
    F.Zf = Result == 0;
    F.Sf = (Result >> 63) != 0;
    F.Cf = false;
    F.Of = false;
    F.Pf = EvenParity(Result);
}

std::uint64_t NextRandom(std::uint64_t& State) {
    State ^= State >> 12;
    State ^= State << 25;
    State ^= State >> 27;
    return State * 0x2545F4914F6CDD1DULL;
}

OpMap MakeMap(std::uint64_t Seed) {
    std::array<std::uint8_t, 251> Pool{};
    for (std::size_t I = 0; I < Pool.size(); ++I) Pool[I] = static_cast<std::uint8_t>(I + 1);
    for (std::size_t I = Pool.size() - 1; I > 0; --I) {
        std::swap(Pool[I], Pool[NextRandom(Seed) % (I + 1)]);
    }
    OpMap Map{};
    std::copy_n(Pool.begin(), Map.size(), Map.begin());
    return Map;
}

RegisterMap MakeRegisterMap(std::uint64_t Seed) {
    RegisterMap Map = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    for (std::size_t I = Map.size() - 1; I > 0; --I) {
        std::swap(Map[I], Map[NextRandom(Seed) % (I + 1)]);
    }
    return Map;
}

Op Decode(std::uint8_t Encoded, const OpMap& Map) {
    for (std::size_t I = 0; I < Map.size(); ++I) {
        if (Map[I] == Encoded) return static_cast<Op>(I);
    }
    throw std::runtime_error("VM2 illegal opcode");
}

const char* Name(Op Operation) {
    static constexpr std::array<const char*, KOpCount> Names = {
        "MOVI","MOV","ADD","ADDI","SUB","SUBI","ADC","SBB","MUL","MULI","XOR","AND","OR","ANDI","NEG","NOT","BSWAP","TEST",
        "SHLI","SHRI","SHLR","SHRR","SARI","SARR","ROLI","RORI","ROLR","RORR",
        "CMP","JMP","JZ","JNZ",
        "JA","JAE","JB","JBE","JS","JNS","JL","JGE","JLE","JG","JO","JNO","JP","JNP",
        "PUSH","POP","CALL","RET","LOAD64","LOAD64D","STORE64","STORE64D","NOP","HALT","TRAP","SIZED"
    };
    return Names[static_cast<std::size_t>(Operation)];
}

void AppendU32(Bytes& Out, std::uint32_t Value) {
    for (unsigned I = 0; I < 4; ++I) Out.push_back(static_cast<std::uint8_t>(Value >> (I * 8)));
}

void AppendU64(Bytes& Out, std::uint64_t Value) {
    for (unsigned I = 0; I < 8; ++I) Out.push_back(static_cast<std::uint8_t>(Value >> (I * 8)));
}

std::uint64_t Mix64(std::uint64_t Value);

std::uint32_t BranchMask(std::uint64_t Key, std::size_t OperandOffset) {
    return static_cast<std::uint32_t>(Mix64(Key ^ (static_cast<std::uint64_t>(OperandOffset) * 0x9E3779B185EBCA87ULL)));
}

class Assembler {
public:
    Assembler(OpMap OpcodeMap, RegisterMap Registers, std::uint64_t Seed, std::uint64_t BranchKey)
        : OpcodeMap(std::move(OpcodeMap)), Registers(std::move(Registers)),
          RandomState(Seed), BranchKey(BranchKey) {}

    void Label(std::string Value) {
        if (!Labels.emplace(std::move(Value), Code.size()).second) throw std::runtime_error("duplicate VM label");
    }

    void Rr(Op Operation, std::uint8_t Dst, std::uint8_t Src) { Opcode(Operation); Reg(Dst); Reg(Src); }
    void Ri(Op Operation, std::uint8_t Dst, std::uint64_t Imm) { Opcode(Operation); Reg(Dst); AppendU64(Code, Imm); }
    void RrI(Op Operation, std::uint8_t Dst, std::uint8_t Src, std::uint64_t Imm) {
        Opcode(Operation); Reg(Dst); Reg(Src); AppendU64(Code, Imm);
    }
    void R(Op Operation, std::uint8_t Value) { Opcode(Operation); Reg(Value); }
    void None(Op Operation) { Opcode(Operation); }
    void Sized(const LiftedInstruction& I) {
        Opcode(Op::Sized);
        Code.push_back(static_cast<std::uint8_t>(I.Op));
        Code.push_back(I.Width);
        Reg(I.Dst); Reg(I.Src); AppendU64(Code, I.Immediate);
    }

    void Junk() {
        const auto Count = static_cast<unsigned>((NextRandom(RandomState) % 3) + 1);
        for (unsigned I = 0; I < Count; ++I) None(Op::Nop);
    }

    void Jump(Op Operation, std::string LabelName) {
        Opcode(Operation);
        Fixups.push_back({Code.size(), std::move(LabelName)});
        AppendU32(Code, 0);
    }

    Bytes Finish() {
        if (Code.size() > UINT32_MAX) throw std::runtime_error("VM program too large");
        for (const auto& [Offset, Target] : Fixups) {
            const auto It = Labels.find(Target);
            if (It == Labels.end()) throw std::runtime_error("undefined VM label: " + Target);
            if (It->second > std::numeric_limits<std::uint32_t>::max()) throw std::runtime_error("VM program too large");
            const auto Address = static_cast<std::uint32_t>(It->second) ^ BranchMask(BranchKey, Offset);
            for (unsigned I = 0; I < 4; ++I) Code[Offset + I] = static_cast<std::uint8_t>(Address >> (I * 8));
        }
        return Code;
    }

    const std::vector<std::uint32_t>& GetInstructionOffsets() const { return InstructionOffsets; }

private:
    OpMap OpcodeMap;
    RegisterMap Registers;
    Bytes Code;
    std::unordered_map<std::string, std::size_t> Labels;
    std::vector<std::pair<std::size_t, std::string>> Fixups;
    std::vector<std::uint32_t> InstructionOffsets;

    std::uint64_t RandomState;
    std::uint64_t BranchKey;

    void Opcode(Op Operation) {
        if (Code.size() >= UINT32_MAX) throw std::runtime_error("VM program too large");
        InstructionOffsets.push_back(static_cast<std::uint32_t>(Code.size()));
        Code.push_back(OpcodeMap[static_cast<std::size_t>(Operation)]);
    }
    void Reg(std::uint8_t Value) {
        if (Value < Registers.size()) Code.push_back(Registers[Value]);
        else if (Value < KRegisterCount) Code.push_back(Value);
        else throw std::runtime_error("VM assembler invalid register");
    }
};

std::uint64_t Mix64(std::uint64_t Value) {
    Value += 0x9E3779B97F4A7C15ULL;
    Value = (Value ^ (Value >> 30)) * 0xBF58476D1CE4E5B9ULL;
    Value = (Value ^ (Value >> 27)) * 0x94D049BB133111EBULL;
    return Value ^ (Value >> 31);
}

std::uint64_t InstructionDecodeState(std::uint64_t Key, std::uint32_t Start, std::uint32_t End) {
    return Mix64(Key ^ (static_cast<std::uint64_t>(Start) << 32) ^ End ^ 0xD6E8FEB86659FD93ULL);
}

// Bytecode obfuscation, not a cryptographic cipher. Each record starts from
// its own address-bound state; plaintext feedback makes subsequent operand
// bytes depend on the opcode/operand prefix without keeping a decoded copy.
void AdvanceDecodeState(std::uint64_t& State, std::uint8_t Plain) {
    State = Mix64(State ^ (static_cast<std::uint64_t>(Plain) + 0x9E3779B97F4A7C15ULL));
}

void EncryptInstruction(Bytes& Data, std::uint64_t Key, std::uint32_t Start, std::uint32_t End) {
    auto State = InstructionDecodeState(Key, Start, End);
    for (std::uint32_t I = Start; I < End; ++I) {
        const auto Plain = Data[I];
        Data[I] ^= static_cast<std::uint8_t>(State);
        AdvanceDecodeState(State, Plain);
    }
}

struct Program {
    OpMap Map{};
    RegisterMap Registers{};
    std::array<std::uint8_t, KVariantSlots> HandlerVariants{};
    Bytes EncryptedCode;
    std::vector<std::uint32_t> InstructionOffsets;
    std::vector<std::uint64_t> InstructionTags;
    std::uint64_t Key{};
    std::uint64_t Tag{};
};

// The cached execution image contains encrypted operands, maps and boundaries
// in one read-only allocation. Validate once before publication; instruction
// authentication and branch CFI still run on every executed instruction.
struct FrozenProgram {
    OpMap Map{};
    RegisterMap Registers{};
    std::array<std::uint8_t, KVariantSlots> HandlerVariants{};
    std::span<const std::uint8_t> EncryptedCode;
    std::span<const std::uint32_t> InstructionOffsets;
    std::span<const std::uint64_t> InstructionTags;
    std::uint64_t Key{}, Tag{};
    std::array<Op, 256> Decoder{};
};

// Runtime checksums are inexpensive corruption checks; the serialized image
// uses HMAC-SHA256. Include the dispatch metadata as well as the code bytes.
template<class P> std::uint64_t IntegrityTag(const P& Program) {
    std::uint64_t Hash = 0xCBF29CE484222325ULL ^ Program.Key;
    auto Byte = [&](std::uint8_t Value) { Hash = (Hash ^ Value) * 0x100000001B3ULL; };
    auto Word = [&](std::uint64_t Value) {
        for (unsigned I = 0; I < 8; ++I) Byte(static_cast<std::uint8_t>(Value >> (8 * I)));
    };
    Word(Program.EncryptedCode.size());
    Word(Program.InstructionOffsets.size());
    Word(Program.InstructionTags.size());
    for (const auto Value : Program.EncryptedCode) Byte(Value);
    for (const auto Value : Program.Map) Byte(Value);
    for (const auto Value : Program.Registers) Byte(Value);
    for (const auto Value : Program.HandlerVariants) Byte(Value);
    for (const auto Value : Program.InstructionOffsets) Word(Value);
    for (const auto Value : Program.InstructionTags) Word(Value);
    return Mix64(Hash);
}

template<class P> void ValidateProgramLayout(const P& Program) {
    if (Program.EncryptedCode.empty() || Program.EncryptedCode.size() > UINT32_MAX ||
        Program.InstructionOffsets.empty() || Program.InstructionOffsets.front() != 0 ||
        Program.InstructionOffsets.size() != Program.InstructionTags.size()) {
        throw std::runtime_error("VM program layout invalid");
    }
    std::uint32_t Previous = 0;
    for (std::size_t I = 0; I < Program.InstructionOffsets.size(); ++I) {
        const auto Offset = Program.InstructionOffsets[I];
        if (Offset >= Program.EncryptedCode.size() || (I != 0 && Offset <= Previous)) {
            throw std::runtime_error("VM instruction boundaries invalid");
        }
        Previous = Offset;
    }
    std::array<bool, 256> Opcodes{};
    for (const auto Code : Program.Map) {
        if (Opcodes[Code]) throw std::runtime_error("VM opcode map invalid");
        Opcodes[Code] = true;
    }
    std::array<bool, 16> Registers{};
    for (const auto Register : Program.Registers) {
        if (Register >= Registers.size() || Registers[Register]) throw std::runtime_error("VM register map invalid");
        Registers[Register] = true;
    }
    for (const auto Variant : Program.HandlerVariants) {
        if (Variant > 3) throw std::runtime_error("VM handler variant invalid");
    }
}

std::size_t EncodedInstructionSize(Op Operation) {
    switch (Operation) {
    case Op::Sized: return 13;
    case Op::MovI: case Op::AddI: case Op::SubI: case Op::MulI: case Op::AndI:
    case Op::ShlI: case Op::ShrI: case Op::SarI: case Op::RolI: case Op::RorI:
        return 10;
    case Op::Load64D: case Op::Store64D: return 11;
    case Op::Jmp: case Op::Jz: case Op::Jnz: case Op::Ja: case Op::Jae:
    case Op::Jb: case Op::Jbe: case Op::Js: case Op::Jns: case Op::Jl:
    case Op::Jge: case Op::Jle: case Op::Jg: case Op::Jo: case Op::Jno:
    case Op::Jp: case Op::Jnp: case Op::Call: return 5;
    case Op::Neg: case Op::Not: case Op::Bswap: case Op::Push: case Op::Pop: return 2;
    case Op::Ret: case Op::Nop: case Op::Halt: case Op::Trap: return 1;
    default: return 3;
    }
}

std::uint64_t InstructionTag(std::span<const std::uint8_t> Data, std::uint32_t Offset,
                             std::uint32_t End, std::uint64_t Key) {
    std::uint64_t Hash = Mix64(Key ^ Offset ^ (static_cast<std::uint64_t>(End) << 32));
    for (std::uint32_t I = Offset; I < End; ++I) Hash = Mix64(Hash ^ Data[I] ^ I);
    return Hash;
}

void SealProgram(Program& Program, Assembler& A) {
    Program.EncryptedCode = A.Finish();
    Program.InstructionOffsets = A.GetInstructionOffsets();
    Program.InstructionTags.reserve(Program.InstructionOffsets.size());
    for (std::size_t I = 0; I < Program.InstructionOffsets.size(); ++I) {
        const auto End = I + 1 < Program.InstructionOffsets.size()
            ? Program.InstructionOffsets[I + 1]
            : static_cast<std::uint32_t>(Program.EncryptedCode.size());
        EncryptInstruction(Program.EncryptedCode, Program.Key, Program.InstructionOffsets[I], End);
        Program.InstructionTags.push_back(InstructionTag(Program.EncryptedCode,
                                                          Program.InstructionOffsets[I], End, Program.Key));
    }
    Program.Tag = IntegrityTag(Program);
}

Program CompileFactorial(std::uint64_t Seed) {
    Program Result;
    Result.Map = MakeMap(Seed ^ 0x9E3779B185EBCA87ULL);
    Result.Registers = MakeRegisterMap(Seed ^ 0xD1B54A32D192ED03ULL);
    auto VariantSeed = Seed ^ 0x94D049BB133111EBULL;
    for (auto& Variant : Result.HandlerVariants) Variant = static_cast<std::uint8_t>(NextRandom(VariantSeed) & 3U);
    Result.Key = NextRandom(Seed);
    Assembler A(Result.Map, Result.Registers, Seed ^ 0xA0761D6478BD642FULL, Result.Key);

    // Calling convention: r0=input/result. The protected function uses a real
    // VM loop, flags and conditional control flow.
    A.Ri(Op::MovI, 1, 1);       // result = 1
    A.Junk();
    A.Ri(Op::MovI, 2, 0);       // zero constant
    A.Label("loop");
    A.Rr(Op::Cmp, 0, 2);        // input == 0?
    A.Jump(Op::Jz, "done");
    A.Rr(Op::Mul, 1, 0);        // result *= input
    A.Junk();
    if ((Seed & 1U) == 0) A.Ri(Op::SubI, 0, 1);                 // --input
    else A.Ri(Op::AddI, 0, std::numeric_limits<std::uint64_t>::max());
    A.Jump(Op::Jmp, "loop");
    A.Label("done");
    A.Rr(Op::Mov, 0, 1);
    A.None(Op::Halt);

    SealProgram(Result, A);
    return Result;
}

Program CompileCallMemory(std::uint64_t Seed) {
    Program Result;
    Result.Map = MakeMap(Seed ^ 0x243F6A8885A308D3ULL);
    Result.Registers = MakeRegisterMap(Seed ^ 0x13198A2E03707344ULL);
    auto VariantSeed = Seed ^ 0xA4093822299F31D0ULL;
    for (auto& Variant : Result.HandlerVariants) Variant = static_cast<std::uint8_t>(NextRandom(VariantSeed) & 3U);
    Result.Key = NextRandom(Seed);
    Assembler A(Result.Map, Result.Registers, Seed ^ 0x082EFA98EC4E6C89ULL, Result.Key);

    A.Ri(Op::MovI, 1, 32);       // virtual memory offset
    A.R(Op::Push, 0);            // marshal argument through VM data stack
    A.Jump(Op::Call, "transform");
    A.Rr(Op::Store64, 0, 1);     // result -> VM memory
    A.Ri(Op::MovI, 0, 0);
    A.Rr(Op::Load64, 0, 1);      // VM memory -> result
    A.None(Op::Halt);
    A.Label("transform");
    A.R(Op::Pop, 2);
    A.Ri(Op::AddI, 2, 7);
    A.Ri(Op::MovI, 3, 3);
    A.Rr(Op::Mul, 2, 3);
    A.Ri(Op::MovI, 4, 0x55);
    A.Rr(Op::Xor, 2, 4);
    A.Rr(Op::Mov, 0, 2);
    A.None(Op::Ret);

    SealProgram(Result, A);
    return Result;
}

// Covers the x86-style flag set and the extended conditional jump family.
Program CompileBranchDemo(std::uint64_t Seed) {
    Program Result;
    Result.Map = MakeMap(Seed ^ 0x6C62272E07BB0142ULL);
    Result.Registers = MakeRegisterMap(Seed ^ 0x62EB8D5E6B2C6C05ULL);
    auto VariantSeed = Seed ^ 0x27D4EB2F165667C5ULL;
    for (auto& Variant : Result.HandlerVariants) Variant = static_cast<std::uint8_t>(NextRandom(VariantSeed) & 3U);
    Result.Key = NextRandom(Seed);
    Assembler A(Result.Map, Result.Registers, Seed ^ 0x9E3779B185EBCA87ULL, Result.Key);

    // Each condition group re-establishes flags with its own Cmp/Test/Add:
    // the AddI rewards between groups would otherwise clobber them.
    A.Ri(Op::MovI, 1, 0);                            // result accumulator
    A.Ri(Op::MovI, 2, 100);
    A.Rr(Op::Cmp, 0, 2);
    A.Jump(Op::Jae, "skip1");                        // x <  100 (unsigned)
    A.Ri(Op::AddI, 1, 1);
    A.Label("skip1");
    A.Rr(Op::Cmp, 0, 2);
    A.Jump(Op::Jnz, "skip2");                        // x == 100
    A.Ri(Op::AddI, 1, 2);
    A.Label("skip2");
    A.Rr(Op::Cmp, 0, 2);
    A.Jump(Op::Jbe, "skip3");                        // x >  100 (unsigned)
    A.Ri(Op::AddI, 1, 4);
    A.Label("skip3");
    A.Ri(Op::MovI, 3, 0xFFFFFFFFFFFFFFFDULL);        // -3
    A.Rr(Op::Cmp, 0, 3);
    A.Jump(Op::Jge, "skip4");                        // x <  -3 (signed)
    A.Ri(Op::AddI, 1, 8);
    A.Label("skip4");
    A.Ri(Op::MovI, 3, 0);
    A.Rr(Op::Cmp, 0, 3);
    A.Jump(Op::Js, "skip5");                         // x >= 0 (signed)
    A.Ri(Op::AddI, 1, 16);
    A.Label("skip5");
    A.Ri(Op::MovI, 4, 0xFF);
    A.Rr(Op::Test, 0, 4);
    A.Jump(Op::Jp, "parity_even");                   // Pf set = even parity
    A.Ri(Op::AddI, 1, 64);
    A.Jump(Op::Jmp, "parity_done");
    A.Label("parity_even");
    A.Ri(Op::AddI, 1, 32);
    A.Label("parity_done");
    A.Ri(Op::MovI, 5, 0x7FFFFFFFFFFFFFFFULL);
    A.Rr(Op::And, 5, 0);                             // nonneg(x)
    A.Ri(Op::MovI, 6, 0x7FFFFFFFFFFFFFFFULL);
    A.Rr(Op::Add, 5, 6);                             // signed overflow iff x != 0
    A.Jump(Op::Jno, "no_overflow");
    A.Ri(Op::AddI, 1, 128);
    A.Jump(Op::Jmp, "overflow_done");
    A.Label("no_overflow");
    A.Ri(Op::AddI, 1, 256);
    A.Label("overflow_done");
    A.Ri(Op::MovI, 3, 5);
    A.Rr(Op::Cmp, 0, 3);
    A.Jump(Op::Jg, "gt5");                           // x >  5 (signed)
    A.Ri(Op::AddI, 1, 1024);
    A.Jump(Op::Jmp, "cmp5_done");
    A.Label("gt5");
    A.Ri(Op::AddI, 1, 512);
    A.Label("cmp5_done");
    // Second pass covering the inverses: Jb/Ja/Jns/Jl/Jnp/Jo.
    A.Rr(Op::Cmp, 0, 2);
    A.Jump(Op::Jb, "add_b");
    A.Jump(Op::Jmp, "b_done");
    A.Label("add_b");
    A.Ri(Op::AddI, 1, 2048);
    A.Label("b_done");
    A.Rr(Op::Cmp, 0, 2);
    A.Jump(Op::Ja, "add_a");
    A.Jump(Op::Jmp, "a_done");
    A.Label("add_a");
    A.Ri(Op::AddI, 1, 4096);
    A.Label("a_done");
    A.Ri(Op::MovI, 3, 0);
    A.Rr(Op::Cmp, 0, 3);
    A.Jump(Op::Jns, "add_ns");
    A.Jump(Op::Jmp, "ns_done");
    A.Label("add_ns");
    A.Ri(Op::AddI, 1, 8192);
    A.Label("ns_done");
    A.Ri(Op::MovI, 3, 0xFFFFFFFFFFFFFFFDULL);
    A.Rr(Op::Cmp, 0, 3);
    A.Jump(Op::Jl, "add_l");
    A.Jump(Op::Jmp, "l_done");
    A.Label("add_l");
    A.Ri(Op::AddI, 1, 16384);
    A.Label("l_done");
    A.Rr(Op::Test, 0, 4);
    A.Jump(Op::Jnp, "add_np");
    A.Jump(Op::Jmp, "np_done");
    A.Label("add_np");
    A.Ri(Op::AddI, 1, 32768);
    A.Label("np_done");
    A.Ri(Op::MovI, 5, 0x7FFFFFFFFFFFFFFFULL);
    A.Rr(Op::And, 5, 0);
    A.Ri(Op::MovI, 6, 0x7FFFFFFFFFFFFFFFULL);
    A.Rr(Op::Add, 5, 6);
    A.Jump(Op::Jo, "add_o");
    A.Jump(Op::Jmp, "o_done");
    A.Label("add_o");
    A.Ri(Op::AddI, 1, 65536);
    A.Label("o_done");
    A.Rr(Op::Mov, 0, 1);
    A.None(Op::Halt);

    SealProgram(Result, A);
    return Result;
}

// Covers the extended ALU (MulI/And/Or/Test/shift-by-register), base+disp
// virtual memory addressing and the data stack used as a spill area.
Program CompileArithMemDemo(std::uint64_t Seed) {
    Program Result;
    Result.Map = MakeMap(Seed ^ 0x85EBCA77C2B2AE63ULL);
    Result.Registers = MakeRegisterMap(Seed ^ 0x165667B19E3779F9ULL);
    auto VariantSeed = Seed ^ 0x7F4A7C15D1B54A32ULL;
    for (auto& Variant : Result.HandlerVariants) Variant = static_cast<std::uint8_t>(NextRandom(VariantSeed) & 3U);
    Result.Key = NextRandom(Seed);
    Assembler A(Result.Map, Result.Registers, Seed ^ 0x27D4EB2F165667C5ULL, Result.Key);

    A.Rr(Op::Mov, 1, 0);
    A.Ri(Op::MovI, 2, 0xF0);
    A.Rr(Op::Or, 1, 2);                    // a = x | 0xF0
    A.Ri(Op::MovI, 2, 0xFF);
    A.Rr(Op::And, 1, 2);                   // a &= 0xFF
    A.Ri(Op::MulI, 1, 3);                  // a *= 3
    A.Rr(Op::Mov, 3, 1);
    A.Ri(Op::ShrI, 3, 2);                  // b = a >> 2
    A.Rr(Op::Mov, 4, 0);
    A.Ri(Op::SarI, 4, 3);                  // c = sar(x, 3)
    A.Rr(Op::Mov, 5, 0);
    A.Ri(Op::ShrI, 5, 1);
    A.Ri(Op::MovI, 6, 7);
    A.Rr(Op::And, 5, 6);                   // s = (x >> 1) & 7
    A.Rr(Op::Mov, 7, 0);
    A.Ri(Op::AddI, 7, 3);
    A.Rr(Op::ShlR, 7, 5);                  // e = (x + 3) << s
    A.Rr(Op::Mov, 8, 0);
    A.Ri(Op::MulI, 8, 5);
    A.Rr(Op::SarR, 8, 5);                  // f = sar(x * 5, s)
    A.Ri(Op::MovI, 9, 16);                 // memory base offset
    A.RrI(Op::Store64D, 9, 1, 0);          // mem[16] = a
    A.RrI(Op::Store64D, 9, 7, 8);          // mem[24] = e
    A.RrI(Op::Load64D, 10, 9, 0);          // r10 = a (roundtrip)
    A.RrI(Op::Load64D, 11, 9, 8);          // r11 = e (roundtrip)
    A.R(Op::Push, 10);
    A.R(Op::Push, 11);
    A.R(Op::Pop, 12);
    A.R(Op::Pop, 13);                      // stack shuffle, values preserved
    A.Jump(Op::Call, "helper");
    A.Rr(Op::Xor, 0, 12);
    A.Rr(Op::Xor, 0, 13);
    A.Rr(Op::Xor, 0, 3);
    A.Rr(Op::Xor, 0, 4);
    A.Rr(Op::Xor, 0, 8);
    A.None(Op::Halt);
    A.Label("helper");
    A.Rr(Op::Mov, 14, 0);
    A.Ri(Op::MulI, 14, 7);
    A.Ri(Op::AddI, 14, 1);
    A.Rr(Op::Mov, 0, 14);
    A.None(Op::Ret);

    SealProgram(Result, A);
    return Result;
}

class Machine {
public:
    std::uint64_t Run(const Program& Program, std::uint64_t Input, bool Trace,
                      const RunConfig& Config = {}) {
        std::array<std::uint64_t, 16> Logical{};
        Logical[0] = Input;
        RunRegisters(Program, Logical, Trace, Config);
        return Logical[0];
    }

    template<class P> void RunRegisters(const P& Program, std::array<std::uint64_t, 16>& Logical, bool Trace,
                      const RunConfig& Config = {}) {
        ValidateConfig(Config);
        if constexpr (!std::is_same_v<P, FrozenProgram>) {
            ValidateProgramLayout(Program);
            if (Program.Tag != IntegrityTag(Program)) {
                throw std::runtime_error("VM2 integrity violation");
            }
        }
        const auto& Code = Program.EncryptedCode;
        Regs.fill(0);
        Mapping = Program.Registers;
        Memory.assign(Config.NativeMemory ? 0 : Config.MemoryBytes, 0);
        Stack.clear();
        Calls.clear();
        for (std::size_t I = 0; I < Logical.size(); ++I) Regs[Program.Registers[I]] = Logical[I];
        Flags = {};
        if (Config.NativeContext) ReadNativeFlags(Config.NativeContext->Rflags);
        auto Finish = [&] {
            for (std::size_t I = 0; I < Logical.size(); ++I) Logical[I] = Regs[Program.Registers[I]];
            if (Config.NativeContext) Config.NativeContext->Rflags = NativeFlags(Config.NativeContext->Rflags);
        };
        auto Push = [&](std::uint64_t Value) {
            if (!Config.NativeMemory) { Stack.push_back(Value); return; }
            auto& Sp = Regs[Program.Registers[4]];
            if (Sp < Config.StackLower + 8 || Sp > Config.StackUpper) throw std::runtime_error("VM native stack overflow");
            Sp -= 8; std::memcpy(reinterpret_cast<void*>(Sp), &Value, 8);
        };
        auto Pop = [&]() -> std::uint64_t {
            if (!Config.NativeMemory) {
                if (Stack.empty()) throw std::runtime_error("VM2 stack underflow");
                const auto Value = Stack.back(); Stack.pop_back(); return Value;
            }
            auto& Sp = Regs[Program.Registers[4]];
            if (Sp < Config.StackLower || Sp > Config.StackUpper - 8) throw std::runtime_error("VM native stack underflow");
            std::uint64_t Value; std::memcpy(&Value, reinterpret_cast<void*>(Sp), 8); Sp += 8; return Value;
        };
        std::size_t Pc = 0;
        std::size_t Fuel = Config.Fuel;

        std::size_t SequentialIndex = 0;
        auto FindInstruction = [&](std::uint32_t Address) {
            if (SequentialIndex < Program.InstructionOffsets.size() &&
                Program.InstructionOffsets[SequentialIndex] == Address) return SequentialIndex;
            const auto It = std::lower_bound(Program.InstructionOffsets.begin(),
                                             Program.InstructionOffsets.end(), Address);
            if (It == Program.InstructionOffsets.end() || *It != Address) {
                throw std::runtime_error("VM2 CFI violation");
            }
            return static_cast<std::size_t>(It - Program.InstructionOffsets.begin());
        };

        std::size_t OperandEnd = 0;
        std::uint64_t DecodeState = 0;
        auto Byte = [&]() {
            if (Pc >= OperandEnd) throw std::runtime_error("VM2 truncated operand");
            const auto Plain = static_cast<std::uint8_t>(Code[Pc++] ^ static_cast<std::uint8_t>(DecodeState));
            AdvanceDecodeState(DecodeState, Plain);
            return Plain;
        };
        auto Reg = [&]() {
            const auto Value = Byte();
            if (Value >= Regs.size()) throw std::runtime_error("VM2 invalid register");
            return Value;
        };
        auto U32 = [&]() {
            if (Pc > Code.size() || 4 > Code.size() - Pc) throw std::runtime_error("VM2 truncated u32");
            std::uint32_t V = 0;
            for (unsigned I = 0; I < 4; ++I) V |= static_cast<std::uint32_t>(Byte()) << (I * 8);
            return V;
        };
        auto U64 = [&]() {
            if (Pc > Code.size() || 8 > Code.size() - Pc) throw std::runtime_error("VM2 truncated u64");
            std::uint64_t V = 0;
            for (unsigned I = 0; I < 8; ++I) V |= static_cast<std::uint64_t>(Byte()) << (I * 8);
            return V;
        };
        auto Target = [&](std::uint32_t Address) {
            (void)FindInstruction(Address);
            Pc = Address;
        };
        auto TakeBranch = [&](Op Operation) {
            switch (Operation) {
            case Op::Jz: return Flags.Zf;
            case Op::Jnz: return !Flags.Zf;
            case Op::Ja: return !Flags.Cf && !Flags.Zf;
            case Op::Jae: return !Flags.Cf;
            case Op::Jb: return Flags.Cf;
            case Op::Jbe: return Flags.Cf || Flags.Zf;
            case Op::Js: return Flags.Sf;
            case Op::Jns: return !Flags.Sf;
            case Op::Jl: return Flags.Sf != Flags.Of;
            case Op::Jge: return Flags.Sf == Flags.Of;
            case Op::Jle: return Flags.Zf || Flags.Sf != Flags.Of;
            case Op::Jg: return !Flags.Zf && Flags.Sf == Flags.Of;
            case Op::Jo: return Flags.Of;
            case Op::Jno: return !Flags.Of;
            case Op::Jp: return Flags.Pf;
            case Op::Jnp: return !Flags.Pf;
            default: throw std::runtime_error("VM2 internal: not a branch");
            }
        };
        // x86 shift semantics: count is masked to 6 bits, a zero count leaves
        // flags untouched, CF takes the last bit shifted out, OF is defined
        // only for 1-bit shifts.
        auto SetShiftFlags = [&](std::uint64_t Dst, unsigned Count, bool Arithmetic, std::uint64_t Result) {
            if (Count == 0) return;
            Flags.Zf = Result == 0;
            Flags.Sf = (Result >> 63) != 0;
            if (Arithmetic) {
                Flags.Cf = (static_cast<std::uint64_t>(static_cast<std::int64_t>(Dst) >> (Count - 1)) & 1U) != 0;
            } else {
                Flags.Cf = ((Dst >> (64 - Count)) & 1U) != 0;
            }
            Flags.Of = Count == 1 ? (Flags.Sf != Flags.Cf) : false;
            Flags.Pf = EvenParity(Result);
        };
        // x86 rotate semantics: ZF/SF/PF are untouched; CF takes the bit
        // rotated around (LSB for ROL, MSB for ROR) and OF is defined only
        // for 1-bit rotates.
        auto SetRotateFlags = [&](unsigned Count, bool Left, std::uint64_t Result) {
            if (Count == 0) return;
            Flags.Cf = Left ? (Result & 1U) != 0 : (Result >> 63) != 0;
            if (Count == 1) {
                Flags.Of = Left
                    ? (((Result >> 63) & 1U) != 0) != Flags.Cf
                    : (((Result >> 63) & 1U) != ((Result >> 62) & 1U));
            }
        };
        auto Bswap64 = [](std::uint64_t Value) {
            return ((Value & 0x00000000000000FFULL) << 56) | ((Value & 0x000000000000FF00ULL) << 40) |
                   ((Value & 0x0000000000FF0000ULL) << 24) | ((Value & 0x00000000FF000000ULL) << 8) |
                   ((Value & 0x000000FF00000000ULL) >> 8) | ((Value & 0x0000FF0000000000ULL) >> 24) |
                   ((Value & 0x00FF000000000000ULL) >> 40) | ((Value & 0xFF00000000000000ULL) >> 56);
        };

        while (Fuel-- != 0) {
            if (Config.StackLower && (Regs[Program.Registers[4]] < Config.StackLower ||
                Regs[Program.Registers[4]] > Config.StackUpper)) throw std::runtime_error("VM native stack range exceeded");
            const auto At = Pc;
            const auto InstructionIndex = FindInstruction(static_cast<std::uint32_t>(At));
            SequentialIndex = InstructionIndex + 1;
            const auto InstructionEnd = InstructionIndex + 1 < Program.InstructionOffsets.size()
                ? Program.InstructionOffsets[InstructionIndex + 1]
                : static_cast<std::uint32_t>(Code.size());
            if (Program.InstructionTags.size() != Program.InstructionOffsets.size() ||
                Program.InstructionTags[InstructionIndex] !=
                    InstructionTag(Code, static_cast<std::uint32_t>(At), InstructionEnd, Program.Key)) {
                throw std::runtime_error("VM2 instruction authentication failed");
            }
            OperandEnd = InstructionEnd;
            DecodeState = InstructionDecodeState(Program.Key, static_cast<std::uint32_t>(At), InstructionEnd);
            const auto InstructionVariant = static_cast<std::uint8_t>((DecodeState >> 32) & 3U);
            const auto Encoded = Byte();
            const auto Op = [&] {
                if constexpr (std::is_same_v<P, FrozenProgram>) return Program.Decoder[Encoded];
                else return Decode(Encoded, Program.Map);
            }();
            if (InstructionEnd - At != EncodedInstructionSize(Op)) {
                throw std::runtime_error("VM instruction size mismatch");
            }
            if (Trace) {
                std::cout << "vip=" << std::setw(4) << std::setfill('0') << std::hex << At
                          << " enc=" << std::setw(2) << static_cast<unsigned>(Encoded)
                          << " op=" << std::left << std::setw(8) << std::setfill(' ') << Name(Op)
                          << std::right << " r0=" << Regs[Program.Registers[0]]
                          << " r1=" << Regs[Program.Registers[1]]
                          << " zf=" << Flags.Zf << " cf=" << Flags.Cf
                          << " sf=" << Flags.Sf << " of=" << Flags.Of << std::dec << "\n";
            }
            switch (Op) {
            case Op::Sized: {
                const auto Kind = static_cast<LiftedOp>(Byte());
                const auto Width = Byte();
                const auto D = Reg(), S = Reg();
                const auto Imm = U64();
                ExecuteSized(Kind, Width, D, S, Imm, Config);
                break;
            }
            case Op::MovI: { const auto D=Reg(); Regs[D]=U64(); break; }
            case Op::Mov: { const auto D=Reg(),S=Reg(); Regs[D]=Regs[S]; break; }
            case Op::Add: {
                const auto D=Reg(),S=Reg(); const auto Dst=Regs[D],Src=Regs[S];
                switch ((Program.HandlerVariants[VariantSlot(Op::Add)] ^ InstructionVariant) & 3U) {
                case 1: Regs[D]=Dst-(~Src+1ULL); break;
                case 2: Regs[D]=(Dst|Src)+(Dst&Src); break;
                case 3: Regs[D]=2ULL*(Dst&Src)+(Dst^Src); break;
                default: Regs[D]=Dst+Src; break;
                }
                SetAddFlags(Flags,Dst,Src,Regs[D]); break; }
            case Op::AddI: {
                const auto D=Reg(); const auto V=U64(); const auto Dst=Regs[D];
                switch ((Program.HandlerVariants[VariantSlot(Op::AddI)] ^ InstructionVariant) & 3U) {
                case 1: Regs[D]=Dst-(~V+1ULL); break;
                case 2: Regs[D]=(Dst|V)+(Dst&V); break;
                case 3: Regs[D]=2ULL*(Dst&V)+(Dst^V); break;
                default: Regs[D]=Dst+V; break;
                }
                SetAddFlags(Flags,Dst,V,Regs[D]); break; }
            case Op::Sub: {
                const auto D=Reg(),S=Reg(); const auto Dst=Regs[D],Src=Regs[S];
                switch ((Program.HandlerVariants[VariantSlot(Op::Sub)] ^ InstructionVariant) & 3U) {
                case 1: Regs[D]=Dst+(~Src+1ULL); break;
                case 2: Regs[D]=(Dst^Src)-2ULL*(Src&~Dst); break;
                case 3: Regs[D]=(Dst+~Src)+1ULL; break;
                default: Regs[D]=Dst-Src; break;
                }
                SetSubFlags(Flags,Dst,Src,Regs[D]); break; }
            case Op::SubI: {
                const auto D=Reg(); const auto V=U64(); const auto Dst=Regs[D];
                switch ((Program.HandlerVariants[VariantSlot(Op::SubI)] ^ InstructionVariant) & 3U) {
                case 1: Regs[D]=Dst+(~V+1ULL); break;
                case 2: Regs[D]=(Dst^V)-2ULL*(V&~Dst); break;
                case 3: Regs[D]=(Dst+~V)+1ULL; break;
                default: Regs[D]=Dst-V; break;
                }
                SetSubFlags(Flags,Dst,V,Regs[D]); break; }
            case Op::Adc: {
                // x86 ADC: dst + src + carry-in; CF is the carry out of the
                // 65-bit sum, OF the signed overflow of that sum.
                const auto D=Reg(),S=Reg(); const auto Dst=Regs[D],Src=Regs[S];
                const bool CarryIn = Flags.Cf;
                const auto Result = Dst + Src + (CarryIn ? 1ULL : 0ULL);
                Regs[D]=Result;
                Flags.Zf = Result == 0;
                Flags.Sf = (Result >> 63) != 0;
                Flags.Pf = EvenParity(Result);
                Flags.Cf = (Result < Dst) || (CarryIn && Result == Dst);
                Flags.Of = ((~(Dst ^ Src) & (Dst ^ Result)) >> 63) != 0; break; }
            case Op::Sbb: {
                // x86 SBB: dst - src - borrow-in; CF is the borrow.
                const auto D=Reg(),S=Reg(); const auto Dst=Regs[D],Src=Regs[S];
                const bool BorrowIn = Flags.Cf;
                const auto Result = Dst - Src - (BorrowIn ? 1ULL : 0ULL);
                Regs[D]=Result;
                Flags.Zf = Result == 0;
                Flags.Sf = (Result >> 63) != 0;
                Flags.Pf = EvenParity(Result);
                Flags.Cf = (Dst < Src) || (BorrowIn && Dst == Src);
                Flags.Of = (((Dst ^ Src) & (Dst ^ Result)) >> 63) != 0; break; }
            case Op::Mul: { const auto D=Reg(),S=Reg(); Regs[D]*=Regs[S]; break; }
            case Op::MulI: { const auto D=Reg(); Regs[D]*=U64(); break; }
            case Op::Xor: {
                const auto D=Reg(),S=Reg(); const auto Dst=Regs[D],Src=Regs[S];
                switch ((Program.HandlerVariants[VariantSlot(Op::Xor)] ^ InstructionVariant) & 3U) {
                case 1: Regs[D]=(Dst|Src)&~(Dst&Src); break;
                case 2: Regs[D]=(Dst|Src)-(Dst&Src); break;
                case 3: Regs[D]=(Dst+Src)-2ULL*(Dst&Src); break;
                default: Regs[D]=Dst^Src; break;
                }
                SetLogicFlags(Flags,Regs[D]); break; }
            case Op::And: {
                const auto D=Reg(),S=Reg(); const auto Dst=Regs[D],Src=Regs[S];
                switch ((Program.HandlerVariants[VariantSlot(Op::And)] ^ InstructionVariant) & 3U) {
                case 1: Regs[D]=(Dst|Src)-(Dst^Src); break;
                case 2: Regs[D]=~(~Dst|~Src); break;
                case 3: Regs[D]=((Dst+Src)-(Dst^Src))>>1; break;
                default: Regs[D]=Dst&Src; break;
                }
                SetLogicFlags(Flags,Regs[D]); break; }
            case Op::Or: {
                const auto D=Reg(),S=Reg(); const auto Dst=Regs[D],Src=Regs[S];
                switch ((Program.HandlerVariants[VariantSlot(Op::Or)] ^ InstructionVariant) & 3U) {
                case 1: Regs[D]=(Dst&Src)+(Dst^Src); break;
                case 2: Regs[D]=~(~Dst&~Src); break;
                case 3: Regs[D]=((Dst+Src)+(Dst^Src))>>1; break;
                default: Regs[D]=Dst|Src; break;
                }
                SetLogicFlags(Flags,Regs[D]); break; }
            case Op::AndI: {
                const auto D=Reg(); const auto V=U64();
                Regs[D]&=V; SetLogicFlags(Flags,Regs[D]); break; }
            case Op::Neg: {
                // x86 NEG: all flags as `0 - operand`; CF set iff operand != 0.
                const auto D=Reg(); const auto Dst=Regs[D];
                Regs[D]=0ULL-Dst; SetSubFlags(Flags,0,Dst,Regs[D]); break; }
            case Op::Not: {
                // x86 NOT does not modify flags.
                const auto D=Reg(); Regs[D]=~Regs[D]; break; }
            case Op::Test: {
                const auto A=Reg(),B=Reg();
                SetLogicFlags(Flags,Regs[A]&Regs[B]); break; }
            case Op::ShlI: {
                const auto D=Reg(); const auto Count=static_cast<unsigned>(U64()&63);
                const auto Dst=Regs[D]; Regs[D]<<=Count;
                SetShiftFlags(Dst,Count,false,Regs[D]); break; }
            case Op::ShrI: {
                const auto D=Reg(); const auto Count=static_cast<unsigned>(U64()&63);
                const auto Dst=Regs[D]; Regs[D]>>=Count;
                SetShiftFlags(Dst,Count,false,Regs[D]); break; }
            case Op::ShlR: {
                const auto D=Reg(),S=Reg(); const auto Count=static_cast<unsigned>(Regs[S]&63);
                const auto Dst=Regs[D]; Regs[D]<<=Count;
                SetShiftFlags(Dst,Count,false,Regs[D]); break; }
            case Op::ShrR: {
                const auto D=Reg(),S=Reg(); const auto Count=static_cast<unsigned>(Regs[S]&63);
                const auto Dst=Regs[D]; Regs[D]>>=Count;
                SetShiftFlags(Dst,Count,false,Regs[D]); break; }
            case Op::SarI: {
                const auto D=Reg(); const auto Count=static_cast<unsigned>(U64()&63);
                const auto Dst=Regs[D];
                Regs[D]=static_cast<std::uint64_t>(static_cast<std::int64_t>(Dst)>>Count);
                SetShiftFlags(Dst,Count,true,Regs[D]); break; }
            case Op::SarR: {
                const auto D=Reg(),S=Reg(); const auto Count=static_cast<unsigned>(Regs[S]&63);
                const auto Dst=Regs[D];
                Regs[D]=static_cast<std::uint64_t>(static_cast<std::int64_t>(Dst)>>Count);
                SetShiftFlags(Dst,Count,true,Regs[D]); break; }
            case Op::RolI: {
                const auto D=Reg(); const auto Count=static_cast<unsigned>(U64()&63);
                const auto Dst=Regs[D];
                Regs[D]= Count==0 ? Dst : (Dst<<Count)|(Dst>>(64-Count));
                SetRotateFlags(Count,true,Regs[D]); break; }
            case Op::RorI: {
                const auto D=Reg(); const auto Count=static_cast<unsigned>(U64()&63);
                const auto Dst=Regs[D];
                Regs[D]= Count==0 ? Dst : (Dst>>Count)|(Dst<<(64-Count));
                SetRotateFlags(Count,false,Regs[D]); break; }
            case Op::RolR: {
                const auto D=Reg(),S=Reg(); const auto Count=static_cast<unsigned>(Regs[S]&63);
                const auto Dst=Regs[D];
                Regs[D]= Count==0 ? Dst : (Dst<<Count)|(Dst>>(64-Count));
                SetRotateFlags(Count,true,Regs[D]); break; }
            case Op::RorR: {
                const auto D=Reg(),S=Reg(); const auto Count=static_cast<unsigned>(Regs[S]&63);
                const auto Dst=Regs[D];
                Regs[D]= Count==0 ? Dst : (Dst>>Count)|(Dst<<(64-Count));
                SetRotateFlags(Count,false,Regs[D]); break; }
            case Op::Bswap: {
                const auto D=Reg(); Regs[D]=Bswap64(Regs[D]); break; }
            case Op::Cmp: {
                const auto A=Reg(),B=Reg();
                SetSubFlags(Flags,Regs[A],Regs[B],Regs[A]-Regs[B]); break; }
            case Op::Jmp: { const auto Operand=Pc; Target(U32() ^ BranchMask(Program.Key, Operand)); break; }
            case Op::Jz: case Op::Jnz: case Op::Ja: case Op::Jae: case Op::Jb: case Op::Jbe:
            case Op::Js: case Op::Jns: case Op::Jl: case Op::Jge: case Op::Jle: case Op::Jg:
            case Op::Jo: case Op::Jno: case Op::Jp: case Op::Jnp: {
                const auto Operand=Pc;
                const auto T=U32() ^ BranchMask(Program.Key, Operand);
                if (TakeBranch(Op)) Target(T); break; }
            case Op::Push: Push(Regs[Reg()]); break;
            case Op::Pop: { const auto D=Reg(); Regs[D]=Pop(); break; }
            case Op::Call: { const auto Operand=Pc; const auto T=U32() ^ BranchMask(Program.Key, Operand); Calls.push_back(Pc); if (Config.NativeMemory) Push(Pc); Target(T); break; }
            case Op::Ret: {
                // An empty VM2 call stack means the lifted function is
                // returning to its native caller: behave exactly like Halt.
                if (Calls.empty()) {
                    Finish();
                    return;
                }
                if (Config.NativeMemory) (void)Pop();
                Target(static_cast<std::uint32_t>(Calls.back())); Calls.pop_back(); break; }
            case Op::Load64: {
                const auto D=Reg(); const auto Off=Reg();
                if (Regs[Off]>Memory.size()-8) throw std::runtime_error("VM2 load OOB");
                std::memcpy(&Regs[D],Memory.data()+Regs[Off],8); break; }
            case Op::Load64D: {
                const auto D=Reg(); const auto B=Reg(); const auto Disp=U64();
                const auto Addr=Regs[B]+Disp;
                if (Memory.size()<8 || Addr>Memory.size()-8) throw std::runtime_error("VM2 load OOB");
                std::memcpy(&Regs[D],Memory.data()+Addr,8); break; }
            case Op::Store64: {
                const auto S=Reg(); const auto Off=Reg();
                if (Regs[Off]>Memory.size()-8) throw std::runtime_error("VM2 store OOB");
                std::memcpy(Memory.data()+Regs[Off],&Regs[S],8); break; }
            case Op::Store64D: {
                const auto B=Reg(); const auto S=Reg(); const auto Disp=U64();
                const auto Addr=Regs[B]+Disp;
                if (Memory.size()<8 || Addr>Memory.size()-8) throw std::runtime_error("VM2 store OOB");
                std::memcpy(Memory.data()+Addr,&Regs[S],8); break; }
            case Op::Nop: break;
            case Op::Trap: throw std::runtime_error("VM control flow falls past the lifted program");
            case Op::Halt:
                Finish();
                return;
            case Op::Count: throw std::runtime_error("VM2 invalid sentinel opcode");
            }
        }
        throw std::runtime_error("VM2 fuel exhausted");
    }

private:
    void ReadNativeFlags(std::uint64_t F) {
        Flags.Cf = F & 1; Flags.Pf = F & 4; Flags.Zf = F & 64; Flags.Sf = F & 128; Flags.Of = F & 2048;
    }
    std::uint64_t NativeFlags(std::uint64_t F) const {
        return (F & ~0x8c5ULL) | Flags.Cf | (std::uint64_t{Flags.Pf} << 2) |
               (std::uint64_t{Flags.Zf} << 6) | (std::uint64_t{Flags.Sf} << 7) | (std::uint64_t{Flags.Of} << 11);
    }
    void ExecuteSized(LiftedOp Op, std::uint8_t Width, std::uint8_t D,
                      std::uint8_t S, std::uint64_t Imm, const RunConfig& Config) {
        using O = LiftedOp;
        if (!ValidOperandWidth(Width)) throw std::runtime_error("VM invalid operand width");
        const unsigned Bits = Width & 0x7f;
        const auto Mask = Bits == 64 ? UINT64_MAX : (1ULL << Bits) - 1;
        const auto Sign = 1ULL << (Bits - 1);
        const auto Before = Flags;
        const auto A = Regs[D] & Mask, B = Regs[S] & Mask;
        auto R = A;
        bool Write = true;
        auto Zsp = [&] {
            R &= Mask;
            Flags.Zf = R == 0; Flags.Sf = (R & Sign) != 0; Flags.Pf = EvenParity(R);
        };
        auto Add = [&](std::uint64_t X, std::uint64_t Y, bool Carry) {
            const auto Sum = (X + Y) & Mask;
            R = (Sum + static_cast<unsigned>(Carry)) & Mask;
            Flags.Cf = Sum < X || (Carry && R == 0);
            Flags.Of = (~(X ^ Y) & (X ^ R) & Sign) != 0;
            Zsp();
        };
        auto Sub = [&](std::uint64_t X, std::uint64_t Y, bool Borrow) {
            R = (X - Y - static_cast<unsigned>(Borrow)) & Mask;
            Flags.Cf = X < Y || (Borrow && X == Y);
            Flags.Of = ((X ^ Y) & (X ^ R) & Sign) != 0;
            Zsp();
        };
        auto Signed = [](std::uint64_t Value, unsigned Size) {
            if (Size == 64) return static_cast<std::int64_t>(Value);
            const auto Top = 1ULL << (Size - 1);
            return static_cast<std::int64_t>(((Value & ((1ULL << Size) - 1)) ^ Top) - Top);
        };
        switch (Op) {
        case O::Simd: {
            if (!Config.NativeContext) throw std::runtime_error("VM SIMD context missing");
            auto& C=*Config.NativeContext;
            C.Rflags=NativeFlags(C.Rflags);
            ExecuteSimd(Imm,Bits,Regs[D],Regs[S],C,Memory,Config.NativeMemory);
            ReadNativeFlags(C.Rflags);
            return;
        }
        case O::NativeCall: {
            if (!Config.NativeMemory || !Config.NativeContext) throw std::runtime_error("VM native call requires an in-process bridge");
            auto& Context = *Config.NativeContext;
            for (std::size_t I = 0; I < 16; ++I) Context.Registers[I] = Regs[Mapping[I]];
            Context.Rflags = NativeFlags(Context.Rflags);
            Context.Mxcsr = _mm_getcsr();
            Context.CallTarget = Regs[D];
            Context.NativeArguments = Context.Registers[4] + (Imm ? 8 : 0);
            if (Context.NativeArguments < Config.StackLower || Context.NativeArguments > Config.StackUpper - 512)
                throw std::runtime_error("VM native call stack arguments exceed bridge range");
            PeVmCallNative(&Context);
            _mm_setcsr(Context.Mxcsr);
            for (std::size_t I = 0; I < 16; ++I) Regs[Mapping[I]] = Context.Registers[I];
            ReadNativeFlags(Context.Rflags);
            return;
        }
        case O::MovI: R = Imm; break;
        case O::Mov: R = B; break;
        case O::ImageAddress: R = Config.ImageBase + Imm; break;
        case O::ZeroExtend: case O::SignExtend:
            if (Imm != 8 && Imm != 16 && Imm != 32) throw std::runtime_error("VM invalid extension width");
            R = Op == O::SignExtend ? static_cast<std::uint64_t>(Signed(Regs[S], static_cast<unsigned>(Imm)))
                                  : Regs[S] & ((1ULL << Imm) - 1);
            break;
        case O::Add: Add(A, B, false); break;
        case O::AddI: Add(A, Imm & Mask, false); break;
        case O::Adc: Add(A, B, Before.Cf); break;
        case O::Sub: Sub(A, B, false); break;
        case O::SubI: Sub(A, Imm & Mask, false); break;
        case O::Sbb: Sub(A, B, Before.Cf); break;
        case O::Cmp: Sub(A, B, false); Write = false; break;
        case O::Inc: Add(A, 1, false); Flags.Cf = Before.Cf; break;
        case O::Dec: Sub(A, 1, false); Flags.Cf = Before.Cf; break;
        case O::Neg: Sub(0, A, false); break;
        case O::Not: R = ~A; break;
        case O::And: case O::AndI: case O::Or: case O::Xor: case O::Test:
            R = Op == O::Or ? A | B : Op == O::Xor ? A ^ B : A & (Op == O::AndI ? Imm : B);
            Flags.Cf = false; Flags.Of = false; Zsp();
            Write = Op != O::Test; break;
        case O::Mul: case O::MulI: {
            const auto X = Signed(A, Bits), Y = Signed(Op == O::MulI ? Imm : B, Bits);
            std::int64_t High;
            const auto Low = static_cast<std::uint64_t>(_mul128(X, Y, &High));
            R = Low & Mask;
            const auto Extended = Signed(R, Bits);
            Flags.Cf = Flags.Of = Low != static_cast<std::uint64_t>(Extended) || High != (Extended < 0 ? -1 : 0);
            break;
        }
        case O::Bswap:
            if (Bits != 32 && Bits != 64) throw std::runtime_error("VM invalid BSWAP width");
            R = 0;
            for (unsigned I = 0; I < Bits / 8; ++I) R = (R << 8) | ((A >> (I * 8)) & 255);
            break;
        case O::ShlI: case O::ShlR: case O::ShrI: case O::ShrR:
        case O::SarI: case O::SarR: case O::RolI: case O::RolR: case O::RorI: case O::RorR: {
            const bool RegisterCount = Op == O::ShlR || Op == O::ShrR || Op == O::SarR || Op == O::RolR || Op == O::RorR;
            const auto Count = static_cast<unsigned>((RegisterCount ? Regs[S] : Imm) & (Bits == 64 ? 63 : 31));
            if (Count == 0) break;
            const bool Left = Op == O::ShlI || Op == O::ShlR || Op == O::RolI || Op == O::RolR;
            const bool Rotate = Op == O::RolI || Op == O::RolR || Op == O::RorI || Op == O::RorR;
            const bool Arithmetic = Op == O::SarI || Op == O::SarR;
            if (Rotate) {
                const auto N = Count % Bits;
                R = N == 0 ? A : Left ? ((A << N) | (A >> (Bits - N))) & Mask
                                                    : ((A >> N) | (A << (Bits - N))) & Mask;
                Flags.Cf = Left ? (R & 1) != 0 : (R & Sign) != 0;
                if (Count == 1) Flags.Of = Left ? ((R & Sign) != 0) != Flags.Cf
                                              : ((R >> (Bits - 1)) ^ (R >> (Bits - 2))) & 1;
            } else {
                R = Arithmetic ? static_cast<std::uint64_t>(Signed(A, Bits) >> Count) & Mask
                  : Count >= Bits ? 0 : Left ? (A << Count) & Mask : A >> Count;
                if (Count <= Bits) Flags.Cf = ((A >> (Left ? Bits - Count : Count - 1)) & 1) != 0;
                else Flags.Cf = Arithmetic && (A & Sign) != 0;
                if (Count == 1) Flags.Of = Arithmetic ? false : Left ? ((R & Sign) != 0) != Flags.Cf : (A & Sign) != 0;
                Zsp();
            }
            break;
        }
        case O::LoadMem: case O::StoreMem: {
            const auto Address = (Op == O::LoadMem ? Regs[S] : Regs[D]) + Imm;
            const auto Bytes = Bits / 8;
            std::uint8_t* Pointer;
            if (Config.NativeMemory) Pointer = reinterpret_cast<std::uint8_t*>(Address);
            else {
                if (Memory.size() < Bytes || Address > Memory.size() - Bytes) throw std::runtime_error("VM2 memory OOB");
                Pointer = Memory.data() + Address;
            }
            if (Op == O::LoadMem) { R = 0; std::memcpy(&R, Pointer, Bytes); }
            else { std::memcpy(Pointer, &Regs[S], Bytes); Write = false; }
            break;
        }
        default: throw std::runtime_error("VM invalid sized opcode");
        }
        if (Write) Regs[D] = Bits >= 32 ? R & Mask : (Regs[D] & ~Mask) | (R & Mask);
        if (Width & KPreserveFlags) Flags = Before;
    }

    static void ValidateConfig(const RunConfig& Config) {
        if (Config.MemoryBytes < 8) throw std::runtime_error("VM2 memory too small");
        if (Config.MemoryBytes > (std::size_t{1} << 26)) throw std::runtime_error("VM2 memory configuration too large");
        if (Config.Fuel == 0) throw std::runtime_error("VM2 fuel configuration invalid");
    }

    std::array<std::uint64_t, KRegisterCount> Regs{};
    RegisterMap Mapping{};
    std::vector<std::uint8_t> Memory;
    std::vector<std::uint64_t> Stack;
    std::vector<std::size_t> Calls;
    Flags Flags;
};

std::uint64_t FactorialNative(std::uint64_t N) {
    std::uint64_t Result=1;
    while(N) Result*=N--;
    return Result;
}

std::uint64_t CallMemoryNative(std::uint64_t Input) {
    return ((Input + 7) * 3) ^ 0x55;
}

std::uint64_t BranchDemoNative(std::uint64_t X) {
    std::uint64_t R = 0;
    if (X < 100) R += 1;
    if (X == 100) R += 2;
    if (X > 100) R += 4;
    if (static_cast<std::int64_t>(X) < -3) R += 8;
    if (static_cast<std::int64_t>(X) >= 0) R += 16;
    if ((std::popcount(static_cast<std::uint8_t>(X)) % 2) == 0) R += 32; else R += 64;
    if ((X & 0x7FFFFFFFFFFFFFFFULL) != 0) R += 128; else R += 256;
    if (static_cast<std::int64_t>(X) > 5) R += 512; else R += 1024;
    if (X < 100) R += 2048;
    if (X > 100) R += 4096;
    if (static_cast<std::int64_t>(X) >= 0) R += 8192;
    if (static_cast<std::int64_t>(X) < -3) R += 16384;
    if ((std::popcount(static_cast<std::uint8_t>(X)) % 2) == 1) R += 32768;
    if ((X & 0x7FFFFFFFFFFFFFFFULL) != 0) R += 65536;
    return R;
}

std::uint64_t ArithMemDemoNative(std::uint64_t X) {
    const std::uint64_t A = ((X | 0xF0ULL) & 0xFFULL) * 3ULL;
    const std::uint64_t B = A >> 2;
    const std::uint64_t C = static_cast<std::uint64_t>(static_cast<std::int64_t>(X) >> 3);
    const std::uint64_t S = (X >> 1) & 7ULL;
    const std::uint64_t E = (X + 3ULL) << (S & 63);
    const std::uint64_t F = static_cast<std::uint64_t>(static_cast<std::int64_t>(X * 5ULL) >> (S & 63));
    const std::uint64_t Helper = X * 7ULL + 1ULL;
    return Helper ^ E ^ A ^ B ^ C ^ F;
}

// Covers the AndI/Neg/Not/Adc/Rol/Ror/Bswap handlers: NEG with full x86 CF
// semantics (CF=1 unless the operand is zero), flag-preserving NOT, immediate
// AND, the ADC carry chain read after NEG, x86 rotate flag semantics (only
// CF/OF move) and byte-order reversal.
std::uint64_t Bswap64Native(std::uint64_t Value) {
    return ((Value & 0x00000000000000FFULL) << 56) | ((Value & 0x000000000000FF00ULL) << 40) |
           ((Value & 0x0000000000FF0000ULL) << 24) | ((Value & 0x00000000FF000000ULL) << 8) |
           ((Value & 0x000000FF00000000ULL) >> 8) | ((Value & 0x0000FF0000000000ULL) >> 24) |
           ((Value & 0x00FF000000000000ULL) >> 40) | ((Value & 0xFF00000000000000ULL) >> 56);
}

std::uint64_t LogicDemoNative(std::uint64_t X) {
    const std::uint64_t Negated = 0ULL - X;
    const std::uint64_t Carry = X != 0 ? 1ULL : 0ULL;  // CF left by NEG
    const std::uint64_t Inverted = ~Negated;
    const std::uint64_t Rotated = std::rotl(X, 7) ^ std::rotr(X, 3);
    return (Inverted & 0xFFFFFFFFULL) ^ (Negated << 1) ^ Carry ^ Rotated ^ Bswap64Native(X);
}

Program CompileLogicDemo(std::uint64_t Seed) {
    Program Result;
    Result.Map = MakeMap(Seed ^ 0x9E3779B97F4A7C15ULL);
    Result.Registers = MakeRegisterMap(Seed ^ 0x2545F4914F6CDD1DULL);
    auto VariantSeed = Seed ^ 0x84222325CBF29CE4ULL;
    for (auto& Variant : Result.HandlerVariants) Variant = static_cast<std::uint8_t>(NextRandom(VariantSeed) & 3U);
    Result.Key = NextRandom(Seed);
    Assembler A(Result.Map, Result.Registers, Seed ^ 0x1B8735932BFE6A21ULL, Result.Key);

    A.Ri(Op::MovI, 3, 0);                    // r3 = 0 (carry accumulator)
    A.Rr(Op::Mov, 1, 0);                     // r1 = x
    A.R(Op::Neg, 1);                         // r1 = -x, CF = x != 0
    A.Rr(Op::Adc, 3, 3);                     // r3 = 0 + 0 + CF
    A.Rr(Op::Mov, 2, 1);                     // r2 = -x
    A.R(Op::Not, 2);                         // r2 = ~(-x)
    A.Ri(Op::AndI, 2, 0xFFFFFFFFULL);        // r2 &= mask
    A.Ri(Op::ShlI, 1, 1);                    // r1 = (-x) << 1
    A.Rr(Op::Xor, 2, 1);
    A.Rr(Op::Xor, 2, 3);                     // fold in the NEG carry
    A.Rr(Op::Mov, 4, 0);                     // r4 = x
    A.Ri(Op::RolI, 4, 7);                    // r4 = rotl(x, 7)
    A.Rr(Op::Mov, 5, 0);                     // r5 = x
    A.Ri(Op::RorI, 5, 3);                    // r5 = rotr(x, 3)
    A.Rr(Op::Xor, 4, 5);
    A.Rr(Op::Mov, 6, 0);                     // r6 = x
    A.R(Op::Bswap, 6);                       // r6 = bswap(x)
    A.Rr(Op::Xor, 2, 4);
    A.Rr(Op::Xor, 2, 6);
    A.Rr(Op::Mov, 0, 2);
    A.None(Op::Halt);

    SealProgram(Result, A);
    return Result;
}

// Loads from a base that lands far outside VM memory; used for the OOB test.
Program CompileOobDemo(std::uint64_t Seed) {
    Program Result;
    Result.Map = MakeMap(Seed ^ 0x2545F4914F6CDD1DULL);
    Result.Registers = MakeRegisterMap(Seed ^ 0x9E3779B97F4A7C15ULL);
    auto KeySeed = Seed ^ 0xD6E8FEB86659FD93ULL;
    Result.Key = NextRandom(KeySeed);
    Assembler A(Result.Map, Result.Registers, Seed, Result.Key);
    A.Ri(Op::MovI, 1, 0xFFFFFFFFFFFFFF00ULL);
    A.RrI(Op::Load64D, 0, 1, 0xFFULL);
    A.None(Op::Halt);
    SealProgram(Result, A);
    return Result;
}

// Endless jump; used for the fuel-limit test.
Program CompileSpinDemo(std::uint64_t Seed) {
    Program Result;
    Result.Map = MakeMap(Seed ^ 0x165667B19E3779F9ULL);
    Result.Registers = MakeRegisterMap(Seed ^ 0x85EBCA77C2B2AE63ULL);
    auto KeySeed = Seed ^ 0x6C62272E07BB0142ULL;
    Result.Key = NextRandom(KeySeed);
    Assembler A(Result.Map, Result.Registers, Seed, Result.Key);
    A.Label("spin");
    A.Jump(Op::Jmp, "spin");
    SealProgram(Result, A);
    return Result;
}

} // namespace

struct CompiledProgram::Storage {
    CompilationStats Stats;
    pevm::platform::VirtualAllocation Memory;
    const FrozenProgram* Bytecode{};

    Storage(const Program& Source, CompilationStats Metrics) : Stats(Metrics) {
        ValidateProgramLayout(Source);
        if (Source.Tag != IntegrityTag(Source)) throw std::runtime_error("VM2 integrity violation");
        const auto Align = [](std::size_t N) { return (N + 7) & ~std::size_t{7}; };
        const auto CodeOffset = Align(sizeof(FrozenProgram));
        const auto OffsetsOffset = Align(CodeOffset + Source.EncryptedCode.size());
        const auto TagsOffset = Align(OffsetsOffset + Source.InstructionOffsets.size() * 4);
        const auto Bytes = TagsOffset + Source.InstructionTags.size() * 8;
        auto* Base = static_cast<std::uint8_t*>(VirtualAlloc(nullptr, Bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        if (!Base) throw std::runtime_error("VM immutable image allocation failed");
        Memory.reset(Base);
        auto* View = new (Base) FrozenProgram;
        View->Map=Source.Map; View->Registers=Source.Registers; View->HandlerVariants=Source.HandlerVariants;
        View->Key=Source.Key; View->Tag=Source.Tag;
        std::memcpy(Base+CodeOffset,Source.EncryptedCode.data(),Source.EncryptedCode.size());
        std::memcpy(Base+OffsetsOffset,Source.InstructionOffsets.data(),Source.InstructionOffsets.size()*4);
        std::memcpy(Base+TagsOffset,Source.InstructionTags.data(),Source.InstructionTags.size()*8);
        View->EncryptedCode={Base+CodeOffset,Source.EncryptedCode.size()};
        View->InstructionOffsets={reinterpret_cast<const std::uint32_t*>(Base+OffsetsOffset),Source.InstructionOffsets.size()};
        View->InstructionTags={reinterpret_cast<const std::uint64_t*>(Base+TagsOffset),Source.InstructionTags.size()};
        View->Decoder.fill(Op::Count);
        for (std::size_t I=0; I<Source.Map.size(); ++I) View->Decoder[Source.Map[I]]=static_cast<Op>(I);
        DWORD Old;
        if (!VirtualProtect(Base,Bytes,PAGE_READONLY,&Old)) throw std::runtime_error("VM immutable image protection failed");
        Bytecode=View;
    }
};

namespace {
Program CompileLiftedBytecode(const LiftedProgram& Lifted, std::uint64_t Seed, CompilationStats& Stats) {
    if (Lifted.Instructions.empty()) throw std::runtime_error("VM bridge received an empty program");
    if(Lifted.ResumeAddress) {
        if(Lifted.ResumeAddress<Lifted.EntryAddress || Lifted.ResumeAddress-Lifted.EntryAddress<5 ||
           Lifted.ResumeAddress-Lifted.EntryAddress>128 || Lifted.Instructions.back().Op!=LiftedOp::Ret ||
           !std::all_of(Lifted.Instructions.begin(),Lifted.Instructions.end(),NativeFragmentInstruction))
            throw std::runtime_error("VM invalid native EH fragment");
    }

    Program Result;
    Result.Map = MakeMap(Seed ^ 0xB7E151628AED2A6BULL);
    Result.Registers = MakeRegisterMap(Seed ^ 0xC6EF372FE94F82BEULL);
    auto VariantSeed = Seed ^ 0x9E3779B97F4A7C15ULL;
    for (auto& Variant : Result.HandlerVariants) Variant = static_cast<std::uint8_t>(NextRandom(VariantSeed) & 3U);
    Result.Key = NextRandom(VariantSeed);
    Assembler A(Result.Map, Result.Registers, Seed ^ 0xD1B54A32D192ED03ULL, Result.Key);

    std::unordered_map<std::uint32_t, std::string> Labels;
    Labels.reserve(Lifted.Instructions.size());
    for (const auto& Instruction : Lifted.Instructions) {
        if (!Labels.emplace(Instruction.Address, "B_" + std::to_string(Instruction.Address)).second) {
            throw std::runtime_error("VM bridge duplicate lifted address");
        }
    }
    if (!Labels.contains(Lifted.EntryAddress)) throw std::runtime_error("VM bridge entry is not an instruction boundary");

    const auto Register = [](std::uint8_t Value) {
        if (Value >= KRegisterCount) throw std::runtime_error("VM bridge register outside VM2 register file");
        return Value;
    };
    const auto Target = [&](std::uint32_t Address) -> const std::string& {
        const auto It = Labels.find(Address);
        if (It == Labels.end()) throw std::runtime_error("VM bridge branch target is not a lifted boundary");
        return It->second;
    };
    const auto Branch = [&](LiftedOp Lifted, std::uint32_t Destination) {
        switch (Lifted) {
        case LiftedOp::Jmp: A.Jump(Op::Jmp, Target(Destination)); break;
        case LiftedOp::Jz: A.Jump(Op::Jz, Target(Destination)); break;
        case LiftedOp::Jnz: A.Jump(Op::Jnz, Target(Destination)); break;
        case LiftedOp::Ja: A.Jump(Op::Ja, Target(Destination)); break;
        case LiftedOp::Jae: A.Jump(Op::Jae, Target(Destination)); break;
        case LiftedOp::Jb: A.Jump(Op::Jb, Target(Destination)); break;
        case LiftedOp::Jbe: A.Jump(Op::Jbe, Target(Destination)); break;
        case LiftedOp::Js: A.Jump(Op::Js, Target(Destination)); break;
        case LiftedOp::Jns: A.Jump(Op::Jns, Target(Destination)); break;
        case LiftedOp::Jl: A.Jump(Op::Jl, Target(Destination)); break;
        case LiftedOp::Jge: A.Jump(Op::Jge, Target(Destination)); break;
        case LiftedOp::Jle: A.Jump(Op::Jle, Target(Destination)); break;
        case LiftedOp::Jg: A.Jump(Op::Jg, Target(Destination)); break;
        case LiftedOp::Jo: A.Jump(Op::Jo, Target(Destination)); break;
        case LiftedOp::Jno: A.Jump(Op::Jno, Target(Destination)); break;
        case LiftedOp::Jp: A.Jump(Op::Jp, Target(Destination)); break;
        case LiftedOp::Jnp: A.Jump(Op::Jnp, Target(Destination)); break;
        default: throw std::runtime_error("VM bridge internal: not a branch");
        }
    };

    // Preserve logical fallthrough independently of the physical block order.
    // Leaders include call continuations and targets in the middle of a run.
    const auto HasTarget = [](LiftedOp Op) {
        return (Op >= LiftedOp::Jmp && Op <= LiftedOp::Jnp) || Op == LiftedOp::Call;
    };
    const auto EndsBlock = [&](LiftedOp Op) {
        return HasTarget(Op) || Op == LiftedOp::Ret || Op == LiftedOp::Halt;
    };
    const auto HasFallthrough = [](LiftedOp Op) {
        return Op != LiftedOp::Jmp && Op != LiftedOp::Ret && Op != LiftedOp::Halt;
    };
    std::unordered_map<std::uint32_t, std::size_t> Indices;
    Indices.reserve(Lifted.Instructions.size());
    for (std::size_t I = 0; I < Lifted.Instructions.size(); ++I) Indices.emplace(Lifted.Instructions[I].Address, I);
    std::vector<bool> Leader(Lifted.Instructions.size(), false);
    Leader.front() = true;
    Leader[Indices.at(Lifted.EntryAddress)] = true;
    for (std::size_t I = 0; I < Lifted.Instructions.size(); ++I) {
        const auto& Instruction = Lifted.Instructions[I];
        if (Instruction.Op >= LiftedOp::Count) throw std::runtime_error("VM bridge invalid lifted opcode");
        if (HasTarget(Instruction.Op)) {
            (void)Target(Instruction.Target);
            Leader[Indices.at(Instruction.Target)] = true;
        }
        if (EndsBlock(Instruction.Op) && I + 1 < Leader.size()) Leader[I + 1] = true;
    }
    std::vector<std::size_t> Starts;
    for (std::size_t I = 0; I < Leader.size(); ++I) if (Leader[I]) Starts.push_back(I);
    Stats.BasicBlocks = Starts.size();
    std::vector<std::size_t> Order(Starts.size());
    for (std::size_t I = 0; I < Order.size(); ++I) Order[I] = I;
    auto LayoutState = Mix64(Seed ^ 0xA0761D6478BD642FULL);
    if (LayoutState == 0) LayoutState = 0xE7037ED1A0B428DBULL;
    for (std::size_t I = Order.size(); I > 1; --I) std::swap(Order[I - 1], Order[NextRandom(LayoutState) % I]);
    for (std::size_t I = 0; I < Order.size(); ++I) if (Order[I] != I) ++Stats.RelocatedBlocks;
    if (Lifted.Instructions[Starts[Order.front()]].Address != Lifted.EntryAddress) {
        A.Jump(Op::Jmp, Target(Lifted.EntryAddress));
        ++Stats.LinkInstructions;
    }
    for (std::size_t Physical = 0; Physical < Order.size(); ++Physical) {
        const auto Block = Order[Physical];
        const auto Start = Starts[Block];
        const auto End = Block + 1 < Starts.size() ? Starts[Block + 1] : Lifted.Instructions.size();
        for (std::size_t I = Start; I < End; ++I) {
            const auto& Instruction = Lifted.Instructions[I];
            A.Label(Labels.at(Instruction.Address));
            // Native address anchors bind to the following instruction; they
            // need no runtime dispatch of their own.
            if (Instruction.Op == LiftedOp::Nop) continue;
            if (!ValidOperandWidth(Instruction.Width)) throw std::runtime_error("VM invalid operand width");
            if (Instruction.Op <= LiftedOp::Cmp || Instruction.Op == LiftedOp::LoadMem ||
                Instruction.Op == LiftedOp::StoreMem || Instruction.Op >= LiftedOp::ZeroExtend) {
                A.Sized(Instruction);
                continue;
            }
            if (Instruction.Width != 64) throw std::runtime_error("VM invalid control operand width");
            switch (Instruction.Op) {
            case LiftedOp::MovI: A.Ri(Op::MovI, Register(Instruction.Dst), Instruction.Immediate); break;
            case LiftedOp::Mov: A.Rr(Op::Mov, Register(Instruction.Dst), Register(Instruction.Src)); break;
            case LiftedOp::Add: A.Rr(Op::Add, Register(Instruction.Dst), Register(Instruction.Src)); break;
            case LiftedOp::AddI: A.Ri(Op::AddI, Register(Instruction.Dst), Instruction.Immediate); break;
            case LiftedOp::Sub: A.Rr(Op::Sub, Register(Instruction.Dst), Register(Instruction.Src)); break;
            case LiftedOp::SubI: A.Ri(Op::SubI, Register(Instruction.Dst), Instruction.Immediate); break;
            case LiftedOp::Adc: A.Rr(Op::Adc, Register(Instruction.Dst), Register(Instruction.Src)); break;
            case LiftedOp::Sbb: A.Rr(Op::Sbb, Register(Instruction.Dst), Register(Instruction.Src)); break;
            case LiftedOp::Mul: A.Rr(Op::Mul, Register(Instruction.Dst), Register(Instruction.Src)); break;
            case LiftedOp::MulI: A.Ri(Op::MulI, Register(Instruction.Dst), Instruction.Immediate); break;
            case LiftedOp::Xor: A.Rr(Op::Xor, Register(Instruction.Dst), Register(Instruction.Src)); break;
            case LiftedOp::And: A.Rr(Op::And, Register(Instruction.Dst), Register(Instruction.Src)); break;
            case LiftedOp::AndI: A.Ri(Op::AndI, Register(Instruction.Dst), Instruction.Immediate); break;
            case LiftedOp::Neg: A.R(Op::Neg, Register(Instruction.Dst)); break;
            case LiftedOp::Not: A.R(Op::Not, Register(Instruction.Dst)); break;
            case LiftedOp::Or: A.Rr(Op::Or, Register(Instruction.Dst), Register(Instruction.Src)); break;
            case LiftedOp::Test: A.Rr(Op::Test, Register(Instruction.Dst), Register(Instruction.Src)); break;
            case LiftedOp::ShlI: A.Ri(Op::ShlI, Register(Instruction.Dst), Instruction.Immediate); break;
            case LiftedOp::ShrI: A.Ri(Op::ShrI, Register(Instruction.Dst), Instruction.Immediate); break;
            case LiftedOp::ShlR: A.Rr(Op::ShlR, Register(Instruction.Dst), Register(Instruction.Src)); break;
            case LiftedOp::ShrR: A.Rr(Op::ShrR, Register(Instruction.Dst), Register(Instruction.Src)); break;
            case LiftedOp::SarI: A.Ri(Op::SarI, Register(Instruction.Dst), Instruction.Immediate); break;
            case LiftedOp::SarR: A.Rr(Op::SarR, Register(Instruction.Dst), Register(Instruction.Src)); break;
            case LiftedOp::RolI: A.Ri(Op::RolI, Register(Instruction.Dst), Instruction.Immediate); break;
            case LiftedOp::RorI: A.Ri(Op::RorI, Register(Instruction.Dst), Instruction.Immediate); break;
            case LiftedOp::RolR: A.Rr(Op::RolR, Register(Instruction.Dst), Register(Instruction.Src)); break;
            case LiftedOp::RorR: A.Rr(Op::RorR, Register(Instruction.Dst), Register(Instruction.Src)); break;
            case LiftedOp::Bswap: A.R(Op::Bswap, Register(Instruction.Dst)); break;
            case LiftedOp::Cmp: A.Rr(Op::Cmp, Register(Instruction.Dst), Register(Instruction.Src)); break;
            case LiftedOp::Push: A.R(Op::Push, Register(Instruction.Dst)); break;
            case LiftedOp::Pop: A.R(Op::Pop, Register(Instruction.Dst)); break;
            case LiftedOp::LoadMem: A.RrI(Op::Load64D, Register(Instruction.Dst), Register(Instruction.Src), Instruction.Immediate); break;
            case LiftedOp::StoreMem: A.RrI(Op::Store64D, Register(Instruction.Dst), Register(Instruction.Src), Instruction.Immediate); break;
            case LiftedOp::Call: A.Jump(Op::Call, Target(Instruction.Target)); break;
            case LiftedOp::Ret: A.None(Op::Ret); break;
            case LiftedOp::Nop: A.None(Op::Nop); break;
            case LiftedOp::Halt: A.None(Op::Halt); break;
            default: Branch(Instruction.Op, Instruction.Target); break;
            }
        }
        const auto Last = Lifted.Instructions[End - 1].Op;
        if (HasFallthrough(Last)) {
            if (End == Lifted.Instructions.size()) {
                A.None(Op::Trap);
            } else if (Physical + 1 == Order.size() || Starts[Order[Physical + 1]] != End) {
                A.Jump(Op::Jmp, Target(Lifted.Instructions[End].Address));
                ++Stats.LinkInstructions;
            }
        }
    }
    SealProgram(Result, A);

    Stats.BytecodeInstructions = Result.InstructionOffsets.size();
    Stats.BytecodeBytes = Result.EncryptedCode.size();
    return Result;
}
} // namespace

CompiledProgram CompileLiftedProgram(const LiftedProgram& Lifted, std::uint64_t Seed) {
    CompilationStats Stats{};
    auto Result = CompileLiftedBytecode(Lifted, Seed, Stats);
    CompiledProgram Compiled;
    Compiled.Data = std::make_shared<CompiledProgram::Storage>(Result, Stats);
    return Compiled;
}

CompilationStats GetCompilationStats(const CompiledProgram& Compiled) {
    if (!Compiled.Data) throw std::runtime_error("VM bridge received an empty compiled program");
    return Compiled.Data->Stats;
}

void InvokeCompiledProgram(const CompiledProgram& Compiled, VmBridgeContext& Context,
                            bool Trace, const RunConfig& Config) {
    if (!Compiled.Data) throw std::runtime_error("VM bridge received an empty compiled program");
    Machine Vm;
    auto Execution=Config;
    if (!Execution.NativeContext) Execution.NativeContext=&Context;
    struct MxcsrScope {
        VmBridgeContext& Context;
        unsigned Saved=_mm_getcsr();
        explicit MxcsrScope(VmBridgeContext& C):Context(C) { _mm_setcsr(C.Mxcsr); }
        ~MxcsrScope() { Context.Mxcsr=_mm_getcsr(); _mm_setcsr(Saved); }
    } FloatingState(Context);
    Vm.RunRegisters(*Compiled.Data->Bytecode, Context.Registers, Trace, Execution);
}

void InvokeLiftedProgram(const LiftedProgram& Lifted, VmBridgeContext& Context,
                         std::uint64_t Seed, bool Trace, const RunConfig& Config) {
    InvokeCompiledProgram(CompileLiftedProgram(Lifted, Seed), Context, Trace, Config);
}

std::uint64_t RunDemo(std::uint64_t Input, std::uint64_t Seed, bool Trace) {
    if(Input>20) throw std::runtime_error("factorial demo accepts 0..20");
    const auto Program=CompileFactorial(Seed);
    Machine Vm;
    const auto Output=Vm.Run(Program,Input,Trace);
    std::cout<<"VM2 program: "<<Program.EncryptedCode.size()<<" encrypted bytes\n"
             <<"opcode fingerprint: ";
    for(const auto X:Program.Map) std::cout<<std::hex<<std::setw(2)<<std::setfill('0')<<static_cast<unsigned>(X);
    std::cout<<"\nregister map: ";
    for(const auto X:Program.Registers) std::cout<<static_cast<unsigned>(X);
    std::cout<<"\nhandler variants: ";
    for(const auto X:Program.HandlerVariants) std::cout<<static_cast<unsigned>(X);
    std::cout<<std::dec<<"\nintegrity tag: 0x"<<std::hex<<Program.Tag<<std::dec<<"\n";
    return Output;
}

std::uint64_t RunCallMemoryDemo(std::uint64_t Input, std::uint64_t Seed, bool Trace) {
    const auto Program = CompileCallMemory(Seed);
    Machine Vm;
    const auto Output = Vm.Run(Program, Input, Trace);
    std::cout << "VM2 call/memory program: " << Program.EncryptedCode.size() << " encrypted bytes\n"
              << "instruction boundaries: " << Program.InstructionOffsets.size() << "\n"
              << "integrity tag: 0x" << std::hex << Program.Tag << std::dec << "\n";
    return Output;
}

void SelfTest() {
    // A changed decoded prefix must affect subsequent ciphertext, and moving
    // an otherwise identical instruction must change its decoding context.
    for (const auto Key : {1ULL, 0x123456789abcdef0ULL, 0xffffffffffffffffULL}) {
        Bytes Plain(20, 0x5a), First = Plain, Changed = Plain;
        Changed[1] ^= 1;
        EncryptInstruction(First, Key, 0, 20);
        EncryptInstruction(Changed, Key, 0, 20);
        if (First[0] != Changed[0] || std::equal(First.begin() + 2, First.end(), Changed.begin() + 2)) {
            throw std::runtime_error("VM rolling operand feedback failed");
        }
        Bytes Relocated(28, 0x5a);
        EncryptInstruction(Relocated, Key, 8, 28);
        if (std::equal(First.begin(), First.end(), Relocated.begin() + 8)) {
            throw std::runtime_error("VM instruction decoding context is not address-bound");
        }
    }
    std::size_t BranchCases = 0, ArithMemCases = 0, LogicCases = 0;
    for(std::uint64_t Seed: {1ULL,2ULL,0x123456789abcdef0ULL}) {
        const auto Program=CompileFactorial(Seed);
        const auto CallProgram=CompileCallMemory(Seed);
        Machine Vm;
        for(std::uint64_t N=0;N<=20;++N) {
            const auto Actual=Vm.Run(Program,N,false);
            const auto Expected=FactorialNative(N);
            if(Actual!=Expected) throw std::runtime_error("VM2 differential test failed");
        }
        for(std::uint64_t N=0;N<=100;++N) {
            const auto Actual=Vm.Run(CallProgram,N,false);
            const auto Expected=CallMemoryNative(N);
            if(Actual!=Expected) throw std::runtime_error("VM2 call/memory differential test failed");
        }

        const auto BranchProgram=CompileBranchDemo(Seed);
        const auto ArithProgram=CompileArithMemDemo(Seed);
        const auto LogicProgram=CompileLogicDemo(Seed);
        for (std::uint64_t N = 0; N <= 255; ++N) {
            const auto Actual=Vm.Run(BranchProgram,N,false);
            const auto Expected=BranchDemoNative(N);
            if(Actual!=Expected) throw std::runtime_error("VM2 branch/flags differential test failed");
            ++BranchCases;
            const auto ArithActual=Vm.Run(ArithProgram,N,false);
            const auto ArithExpected=ArithMemDemoNative(N);
            if(ArithActual!=ArithExpected) throw std::runtime_error("VM2 arith/memory differential test failed");
            ++ArithMemCases;
            const auto LogicActual=Vm.Run(LogicProgram,N,false);
            const auto LogicExpected=LogicDemoNative(N);
            if(LogicActual!=LogicExpected) throw std::runtime_error("VM2 logic differential test failed");
            ++LogicCases;
        }
        for (std::uint64_t N : {99ULL,100ULL,101ULL,0x7FFFFFFFFFFFFFFFULL,
                                0x8000000000000000ULL,0xFFFFFFFFFFFFFFFDULL,
                                0xFFFFFFFFFFFFFFFEULL,0xFFFFFFFFFFFFFFFFULL}) {
            const auto Actual=Vm.Run(BranchProgram,N,false);
            const auto Expected=BranchDemoNative(N);
            if(Actual!=Expected) throw std::runtime_error("VM2 branch/flags differential test failed");
            ++BranchCases;
            const auto ArithActual=Vm.Run(ArithProgram,N,false);
            const auto ArithExpected=ArithMemDemoNative(N);
            if(ArithActual!=ArithExpected) throw std::runtime_error("VM2 arith/memory differential test failed");
            ++ArithMemCases;
            const auto LogicActual=Vm.Run(LogicProgram,N,false);
            const auto LogicExpected=LogicDemoNative(N);
            if(LogicActual!=LogicExpected) throw std::runtime_error("VM2 logic differential test failed");
            ++LogicCases;
        }

        // Handler variant identities must hold for every variant value, not
        // just the seeds' random picks: pin all slots to each value 0..3 and
        // re-run the factorial/call-memory differentials.
        for (std::uint64_t VariantValue = 0; VariantValue < 4; ++VariantValue) {
            auto VariantFactorial = Program;
            VariantFactorial.HandlerVariants.fill(static_cast<std::uint8_t>(VariantValue));
            auto VariantCall = CallProgram;
            VariantCall.HandlerVariants.fill(static_cast<std::uint8_t>(VariantValue));
            // The integrity tag covers the variants; pinning them changes it.
            VariantFactorial.Tag = IntegrityTag(VariantFactorial);
            VariantCall.Tag = IntegrityTag(VariantCall);
            for (std::uint64_t N = 0; N <= 20; ++N) {
                if (Vm.Run(VariantFactorial, N, false) != FactorialNative(N)) {
                    throw std::runtime_error("VM2 variant factorial differential failed");
                }
            }
            for (std::uint64_t N = 0; N <= 100; ++N) {
                if (Vm.Run(VariantCall, N, false) != CallMemoryNative(N)) {
                    throw std::runtime_error("VM2 variant call/memory differential failed");
                }
            }
        }

        auto Tampered = Program;
        Tampered.EncryptedCode[Tampered.EncryptedCode.size()/2] ^= 1;
        bool Rejected = false;
        try { (void)Vm.Run(Tampered, 5, false); }
        catch (const std::runtime_error&) { Rejected = true; }
        if (!Rejected) throw std::runtime_error("VM2 tamper test failed");

        auto InstructionTampered = CallProgram;
        InstructionTampered.EncryptedCode.back() ^= 1;
        InstructionTampered.Tag = IntegrityTag(InstructionTampered);
        Rejected = false;
        try { (void)Vm.Run(InstructionTampered, 5, false); }
        catch (const std::runtime_error&) { Rejected = true; }
        if (!Rejected) throw std::runtime_error("VM2 instruction tag test failed");

        auto ExpectLayoutRejection = [&](const auto& Change, const char* Reason, bool Retag) {
            auto Invalid = CallProgram;
            Change(Invalid);
            if (Retag) Invalid.Tag = IntegrityTag(Invalid);
            try { (void)Vm.Run(Invalid, 5, false); }
            catch (const std::runtime_error& Error) {
                if (std::string_view(Error.what()).find(Reason) != std::string_view::npos) return;
                throw std::runtime_error(std::string("VM unexpected layout rejection: ") + Error.what());
            }
            throw std::runtime_error("VM invalid layout accepted");
        };
        ExpectLayoutRejection([](auto& P) { P.InstructionOffsets.clear(); }, "layout", true);
        ExpectLayoutRejection([](auto& P) { P.InstructionTags.pop_back(); }, "layout", true);
        ExpectLayoutRejection([](auto& P) { P.InstructionOffsets.back() = UINT32_MAX; }, "boundaries", true);
        ExpectLayoutRejection([](auto& P) { P.InstructionOffsets[1] = 0; }, "boundaries", true);
        ExpectLayoutRejection([](auto& P) { P.Registers[0] = 255; }, "register map", true);
        ExpectLayoutRejection([](auto& P) { P.Registers[0] = P.Registers[1]; }, "register map", true);
        ExpectLayoutRejection([](auto& P) { P.Map[0] = P.Map[1]; }, "opcode map", true);
        ExpectLayoutRejection([](auto& P) { P.HandlerVariants[0] = 4; }, "variant", true);
        // Valid-shaped metadata changes must be bound to the outer checksum.
        ExpectLayoutRejection([](auto& P) { ++P.InstructionOffsets[1]; }, "integrity", false);
        ExpectLayoutRejection([](auto& P) { P.InstructionTags[0] ^= 1; }, "integrity", false);
        // Even with both checksums regenerated, an opcode cannot change the
        // authenticated record's operand width or terminate inside a record.
        ExpectLayoutRejection([](auto& P) {
            P.EncryptedCode[0] = P.Map[static_cast<std::size_t>(Op::Halt)] ^ static_cast<std::uint8_t>(InstructionDecodeState(P.Key, 0, P.InstructionOffsets[1]));
            P.InstructionTags[0] = InstructionTag(P.EncryptedCode, 0, P.InstructionOffsets[1], P.Key);
        }, "instruction size", true);

        // Out-of-bounds VM memory access must fail closed.
        {
            const auto OobProgram = CompileOobDemo(Seed);
            bool OobRejected = false;
            try { (void)Vm.Run(OobProgram, 0, false); }
            catch (const std::runtime_error&) { OobRejected = true; }
            if (!OobRejected) throw std::runtime_error("VM2 OOB memory test failed");
        }
        // Configurable fuel must cut off runaway programs.
        {
            const auto LoopProgram = CompileSpinDemo(Seed);
            bool FuelRejected = false;
            try { (void)Vm.Run(LoopProgram, 0, false, RunConfig{10, 4096}); }
            catch (const std::runtime_error&) { FuelRejected = true; }
            if (!FuelRejected) throw std::runtime_error("VM2 fuel limit test failed");
        }
    }
    std::cout<<"VM2 self-test: OK (63 factorial, 303 call/memory, "
             <<BranchCases<<" branch/flags, "<<ArithMemCases<<" arith/memory, "
             <<LogicCases<<" logic (AndI/Neg/Not/Adc/Rol/Ror/Bswap), "
             <<"variant sweep 0..3, 39 tamper/layout cases, 6 rolling decode checks, oob+fuel)\n";
}

} // namespace vmprotect
