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
    Push, Pop, LoadMem, StoreMem, Call, Ret, Nop, Halt,
    ZeroExtend, SignExtend, Inc, Dec, ImageAddress, NativeCall, Simd, Count
};

struct LiftedInstruction {
    LiftedOp Op{};
    std::uint8_t Dst{};
    std::uint8_t Src{};
    std::uint64_t Immediate{};
    std::uint32_t Address{};
    std::uint32_t Target{};
    // Operand width in bits. Bit 7 preserves flags for address arithmetic.
    std::uint8_t Width = 64;
};

inline constexpr std::uint8_t KPreserveFlags = 0x80;
inline constexpr bool ValidOperandWidth(std::uint8_t Width) {
    const auto Bits = Width & 0x7f;
    return Bits == 8 || Bits == 16 || Bits == 32 || Bits == 64;
}

struct LiftedProgram {
    std::vector<LiftedInstruction> Instructions;
    std::uint32_t EntryAddress{};
    // Nonzero for a straight-line fragment in an existing native EH frame.
    std::uint32_t ResumeAddress{};
};

// Native/VM call bridge.  Arguments are marshalled by register number and the
// virtualized function returns through RAX (Registers[0]).
struct alignas(16) VmBridgeContext {
    std::array<std::uint64_t, 16> Registers{};
    std::array<std::array<std::uint8_t,16>,16> Xmm{};
    std::uint64_t Rflags = 0x202;
    std::uint64_t CallTarget{};
    std::uint64_t NativeArguments{};
    std::uint32_t Mxcsr = 0x1f80;
};
static_assert(offsetof(VmBridgeContext, Xmm) == 128);
static_assert(offsetof(VmBridgeContext, Rflags) == 384);
static_assert(offsetof(VmBridgeContext, NativeArguments) == 400);
static_assert(offsetof(VmBridgeContext, Mxcsr) == 408);
static_assert(sizeof(VmBridgeContext) == 416);

// Runtime limits for a single VM execution. Defaults preserve the historical
// 100k-instruction fuel and 4 KiB flat memory.
struct RunConfig {
    std::size_t Fuel = 100000;
    std::size_t MemoryBytes = 4096;
    // Explicit opt-in for the in-process native bridge; CLI simulation keeps
    // using bounded, invocation-local flat memory.
    bool NativeMemory = false;
    std::uint64_t ImageBase = 0;
    VmBridgeContext* NativeContext = nullptr;
    std::uint64_t StackLower = 0;
    std::uint64_t StackUpper = 0;
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
