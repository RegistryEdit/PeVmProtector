#include <cstdint>
#include <cstdio>
#include <intrin.h>
#include <windows.h>

extern "C" __declspec(noinline) std::uint64_t LiftHelper(std::uint64_t Value) {
    return Value + 7;
}

extern "C" __declspec(dllexport, noinline) std::uint64_t LiftTarget(
    std::uint64_t First, std::uint64_t Second, std::uint64_t Third, std::uint64_t Fourth) {
    return First ^ Second ^ Third ^ Fourth;
}

extern "C" __declspec(dllexport, noinline) std::uint64_t LoopTarget(std::uint64_t Count) {
    std::uint64_t Result = 1;
    for (std::uint64_t I = 0; I < Count; ++I) Result = Result * 3 + 1;
    return Result;
}

extern "C" __declspec(dllexport, noinline) std::uint64_t BranchTarget(
    std::uint64_t A, std::uint64_t B) {
    if (A < B) return A * 2;                        // unsigned Jb
    if (static_cast<std::int64_t>(A) > static_cast<std::int64_t>(B)) return B + 7;  // signed Jg
    return A ^ B;
}

extern "C" __declspec(dllexport, noinline) std::uint64_t ShiftTarget(std::uint64_t V) {
    return ((V << 3) ^ (V >> 2)) + 1;
}

// The lifter treats base-register memory operands as offsets into flat VM
// memory, so the bridge passes a VM offset (not a native pointer) via --rcx.
extern "C" __declspec(dllexport, noinline) std::uint64_t MemTarget(std::uint64_t* Values) {
    return Values[0] + Values[1] + Values[2] + Values[3];
}

// Fifth argument arrives on the native stack and must survive virtualization.
extern "C" __declspec(dllexport, noinline) std::uint64_t StackTarget(
    std::uint64_t A, std::uint64_t B, std::uint64_t C, std::uint64_t D, std::uint64_t E) {
    return A + B + C + D + E;
}

// CPUID (0F A2) is not liftable and must fail closed.
extern "C" __declspec(dllexport, noinline) std::uint64_t CpuIdTarget() {
    std::int32_t Registers[4];
    __cpuid(Registers, 0);
    return static_cast<std::uint32_t>(Registers[0]);
}

// NEG/NOT coverage: sub-from-zero and bitwise complement.
extern "C" __declspec(dllexport, noinline) std::uint64_t NegNotTarget(std::uint64_t X) {
    return (0ULL - X) ^ ~X;
}

// MOVZX/MOVSXD coverage: narrow-type extension plus int32 -> int64 sext.
extern "C" __declspec(dllexport, noinline) std::uint64_t ExtendTarget(std::uint64_t X) {
    const auto Signed32 = static_cast<std::int64_t>(static_cast<std::int32_t>(X));
    const auto Low16 = static_cast<std::uint16_t>(X);
    return static_cast<std::uint64_t>(Signed32 * 5LL) + Low16 * 3ULL;
}

// SETcc coverage: bool results from comparisons materialize through setcc.
// The sink is a caller-provided VM-memory offset (like MemTarget): stack and
// globals are not liftable addressing modes.
extern "C" __declspec(dllexport, noinline) std::uint64_t SetccTarget(
    std::uint64_t A, std::uint64_t B, volatile std::uint64_t* Sink) {
    *Sink += (A < B);                                            // setb
    *Sink += (static_cast<std::int64_t>(A) < static_cast<std::int64_t>(B));  // setl
    *Sink += (A == B);                                           // sete
    return *Sink;
}

// Group1 memory forms (add/xor/and [mem], imm) via volatile RMW, plus TEST
// with an immediate. The lifter maps the pointer to a flat VM-memory offset,
// so the bridge passes a zeroed VM offset and the result is deterministic.
extern "C" __declspec(dllexport, noinline) std::uint64_t MemImmTarget(volatile std::uint64_t* Slot) {
    *Slot += 0x1234;
    *Slot ^= 0x55;
    *Slot &= ~3ULL;
    if ((*Slot & 0xF000ULL) != 0) return 0xAULL + *Slot;
    return *Slot;
}

static void PrintFixtureRva(const char* Name, const void* Function,
                            std::uint64_t Rcx, std::uint64_t Rdx, std::uint64_t R8,
                            std::uint64_t R9, std::uint64_t ExpectedRax) {
    const auto Base = reinterpret_cast<std::uint64_t>(GetModuleHandleW(nullptr));
    const auto Rva = reinterpret_cast<std::uint64_t>(Function) - Base;
    std::printf("PEVM-FIXTURE-RVA %s=0x%llX rcx=0x%llX rdx=0x%llX r8=0x%llX r9=0x%llX rax=0x%llX\n",
                Name, static_cast<unsigned long long>(Rva), static_cast<unsigned long long>(Rcx),
                static_cast<unsigned long long>(Rdx), static_cast<unsigned long long>(R8),
                static_cast<unsigned long long>(R9), static_cast<unsigned long long>(ExpectedRax));
}

int main() {
    const std::uint64_t Mem[4] = {0x1111, 0x2222, 0x3333, 0x4444};
    volatile std::uint64_t MemImmBuffer = 0;
    volatile std::uint64_t SetccBuffer = 0;
    volatile std::uint64_t SetccBuffer2 = 0;
    if (LiftTarget(0x11, 0x22, 0x44, 0x88) != 0xff) return 1;
    if (LoopTarget(7) != 3280) return 1;
    if (BranchTarget(3, 9) != 6) return 1;
    if (BranchTarget(0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFF0ULL) != 0xFFFFFFFFFFFFFFF7ULL) return 1;
    if (ShiftTarget(0xF0) != 0x7BD) return 1;
    if (MemTarget(const_cast<std::uint64_t*>(Mem)) != 0x1111 + 0x2222 + 0x3333 + 0x4444) return 1;
    if (StackTarget(1, 2, 3, 4, 5) != 15) return 1;
    if (NegNotTarget(0xF0) != 0x1F) { std::puts("FAIL NegNot"); return 1; }
    if (SetccTarget(3, 9, &SetccBuffer) != 2) { std::puts("FAIL Setcc"); return 1; }
    if (SetccTarget(5, 5, &SetccBuffer2) != 1) { std::puts("FAIL Setcc2"); return 1; }
    if (MemImmTarget(&MemImmBuffer) != 0x126A) { std::puts("FAIL MemImm"); return 1; }

    PrintFixtureRva("LiftTarget", reinterpret_cast<const void*>(&LiftTarget), 0x11, 0x22, 0x44, 0x88, 0xff);
    PrintFixtureRva("LoopTarget", reinterpret_cast<const void*>(&LoopTarget), 7, 0, 0, 0, 3280);
    PrintFixtureRva("BranchTarget", reinterpret_cast<const void*>(&BranchTarget), 3, 9, 0, 0, 6);
    PrintFixtureRva("ShiftTarget", reinterpret_cast<const void*>(&ShiftTarget), 0xF0, 0, 0, 0, 0x7BD);
    PrintFixtureRva("MemTarget", reinterpret_cast<const void*>(&MemTarget), 64, 0, 0, 0, 0);
    PrintFixtureRva("StackTarget", reinterpret_cast<const void*>(&StackTarget), 0, 0, 0, 0, 0);
    PrintFixtureRva("CpuIdTarget", reinterpret_cast<const void*>(&CpuIdTarget), 0, 0, 0, 0, 0);
    PrintFixtureRva("NegNotTarget", reinterpret_cast<const void*>(&NegNotTarget), 0xF0, 0, 0, 0, NegNotTarget(0xF0));
    PrintFixtureRva("ExtendTarget", reinterpret_cast<const void*>(&ExtendTarget), 0x123456789, 0, 0, 0, ExtendTarget(0x123456789));
    PrintFixtureRva("SetccTarget", reinterpret_cast<const void*>(&SetccTarget), 3, 9, 64, 0, 2);    PrintFixtureRva("MemImmTarget", reinterpret_cast<const void*>(&MemImmTarget), 64, 0, 0, 0, 0x126A);
    return 0;
}
