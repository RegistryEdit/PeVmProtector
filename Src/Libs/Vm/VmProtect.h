#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace vmprotect {

// Register values use x64 encoding numbers RAX..R15. The native trampoline
// owns preservation of nonvolatile registers and stack setup.
enum class LiftedOp : std::uint8_t {
    MovI, Mov, Add, AddI, Sub, SubI, Adc, Sbb, Mul, MulI, Xor, And, Or, AndI, Neg, Not, Bswap, Test,
    ShlI, ShrI, ShlR, ShrR, SarI, SarR, RolI, RorI, RolR, RorR,
    Cmp, Jmp, Jz, Jnz,
    Ja, Jae, Jb, Jbe, Js, Jns, Jl, Jge, Jle, Jg, Jo, Jno, Jp, Jnp,
    Push, Pop, LoadMem, StoreMem, Call, Ret, Nop, Halt, Count
};

struct LiftedInstruction {
    LiftedOp Op{};
    std::uint8_t Dst{};
    std::uint8_t Src{};
    std::uint64_t Immediate{};
    std::uint32_t Address{};
    std::uint32_t Target{};
};

struct LiftedProgram {
    std::vector<LiftedInstruction> Instructions;
    std::uint32_t EntryAddress{};
};

// Native/VM call bridge.  Arguments are marshalled by register number and the
// virtualized function returns through RAX (Registers[0]).
struct VmBridgeContext {
    std::array<std::uint64_t, 16> Registers{};
};

// Runtime limits for a single VM execution. Defaults preserve the historical
// 100k-instruction fuel and 4 KiB flat memory.
struct RunConfig {
    std::size_t Fuel = 100000;
    std::size_t MemoryBytes = 4096;
};

void InvokeLiftedProgram(const LiftedProgram& Program, VmBridgeContext& Context,
                         std::uint64_t Seed, bool Trace,
                         const RunConfig& Config = {});

// Executes a virtualized factorial function. The implementation is translated
// into randomized, encrypted VM bytecode rather than compiled as native logic.
std::uint64_t RunDemo(std::uint64_t Input, std::uint64_t Seed, bool Trace);
std::uint64_t RunCallMemoryDemo(std::uint64_t Input, std::uint64_t Seed, bool Trace);
void SelfTest();

} // namespace vmprotect
