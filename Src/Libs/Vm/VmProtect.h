#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
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

// Non-secret build metrics; no bytecode, keys or address maps are exposed.
struct CompilationStats {
    std::size_t BasicBlocks{};
    std::size_t RelocatedBlocks{};
    std::size_t LinkInstructions{};
    std::size_t BytecodeInstructions{};
    std::size_t BytecodeBytes{};
};

// Immutable encrypted bytecode, reusable across calls and threads. Registers,
// flags, stacks and VM memory belong to each invocation, never to this handle.
class CompiledProgram {
public:
    CompiledProgram() = default;

private:
    struct Storage;
    std::shared_ptr<const Storage> Data;
    friend CompiledProgram CompileLiftedProgram(const LiftedProgram&, std::uint64_t);
    friend CompilationStats GetCompilationStats(const CompiledProgram&);
    friend void InvokeCompiledProgram(const CompiledProgram&, VmBridgeContext&, bool,
                                       const RunConfig&);
};

CompiledProgram CompileLiftedProgram(const LiftedProgram& Program, std::uint64_t Seed);
CompilationStats GetCompilationStats(const CompiledProgram& Program);
void InvokeCompiledProgram(const CompiledProgram& Program, VmBridgeContext& Context,
                            bool Trace, const RunConfig& Config = {});

// Convenience entry for one-shot callers; hot paths should compile once.
void InvokeLiftedProgram(const LiftedProgram& Program, VmBridgeContext& Context,
                         std::uint64_t Seed, bool Trace,
                         const RunConfig& Config = {});

// Executes a virtualized factorial function. The implementation is translated
// into randomized, encrypted VM bytecode rather than compiled as native logic.
std::uint64_t RunDemo(std::uint64_t Input, std::uint64_t Seed, bool Trace);
std::uint64_t RunCallMemoryDemo(std::uint64_t Input, std::uint64_t Seed, bool Trace);
void SelfTest();

} // namespace vmprotect
