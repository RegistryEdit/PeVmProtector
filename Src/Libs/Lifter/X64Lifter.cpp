#include "VmImageCodec.h"
#include "X64Lifter.h"
#include "FileIo.h"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <vector>
#include <windows.h>
#include "PeVmCrypto.h"
#include "WrapperFormat.h"

namespace x64lift {
namespace {
using Bytes = std::vector<std::uint8_t>;

template <typename T> T Read(std::span<const std::uint8_t> Data, std::size_t Offset) {
    if (Offset > Data.size() || sizeof(T) > Data.size() - Offset) throw std::runtime_error("x64 decoder: truncated PE");
    T Value{}; std::memcpy(&Value, Data.data() + Offset, sizeof(Value)); return Value;
}
std::string OpName(vmprotect::LiftedOp Op) {
    using O = vmprotect::LiftedOp;
    switch (Op) {
    case O::MovI:return "MOVI"; case O::Mov:return "MOV"; case O::Add:return "ADD";
    case O::AddI:return "ADDI"; case O::Sub:return "SUB"; case O::SubI:return "SUBI";
    case O::Mul:return "MUL"; case O::MulI:return "MULI"; case O::Xor:return "XOR";
    case O::And:return "AND"; case O::Or:return "OR"; case O::AndI:return "ANDI";
    case O::Neg:return "NEG"; case O::Not:return "NOT"; case O::Bswap:return "BSWAP";
    case O::Test:return "TEST";
    case O::ShlI:return "SHLI"; case O::ShrI:return "SHRI"; case O::ShlR:return "SHLR";
    case O::ShrR:return "SHRR"; case O::SarI:return "SARI"; case O::SarR:return "SARR";
    case O::RolI:return "ROLI"; case O::RorI:return "RORI";
    case O::RolR:return "ROLR"; case O::RorR:return "RORR";
    case O::Cmp:return "CMP"; case O::Adc:return "ADC"; case O::Sbb:return "SBB"; case O::Jmp:return "JMP"; case O::Jz:return "JZ";
    case O::Jnz:return "JNZ"; case O::Ja:return "JA"; case O::Jae:return "JAE";
    case O::Jb:return "JB"; case O::Jbe:return "JBE"; case O::Js:return "JS";
    case O::Jns:return "JNS"; case O::Jl:return "JL"; case O::Jge:return "JGE";
    case O::Jle:return "JLE"; case O::Jg:return "JG"; case O::Jo:return "JO";
    case O::Jno:return "JNO"; case O::Jp:return "JP"; case O::Jnp:return "JNP";
    case O::Push:return "PUSH"; case O::Pop:return "POP";
    case O::LoadMem:return "LOADMEM"; case O::StoreMem:return "STOREMEM";
    case O::Call:return "CALL"; case O::Ret:return "RET"; case O::Nop:return "NOP";
    case O::Halt:return "HALT";
    default: return "?";
    }
}
bool IsBranch(vmprotect::LiftedOp Op) {
    using O = vmprotect::LiftedOp;
    switch (Op) {
    case O::Jmp: case O::Jz: case O::Jnz: case O::Ja: case O::Jae: case O::Jb:
    case O::Jbe: case O::Js: case O::Jns: case O::Jl: case O::Jge: case O::Jle:
    case O::Jg: case O::Jo: case O::Jno: case O::Jp: case O::Jnp: case O::Call:
        return true;
    default: return false;
    }
}
std::uint8_t RegFromModRm(std::uint8_t Value, bool RexBit) { return static_cast<std::uint8_t>(((Value >> 3) & 7U) | (RexBit ? 8U : 0U)); }
std::uint8_t RmFromModRm(std::uint8_t Value, bool RexBit) { return static_cast<std::uint8_t>((Value & 7U) | (RexBit ? 8U : 0U)); }

// Condition code low nibble (0x0..0xF as encoded in 70-7F / 0F 80-8F) mapped
// onto the lifted conditional branch set.
vmprotect::LiftedOp JccFromLowNibble(std::uint8_t Condition) {
    using O = vmprotect::LiftedOp;
    switch (Condition) {
    case 0x0: return O::Jo; case 0x1: return O::Jno;
    case 0x2: return O::Jb; case 0x3: return O::Jae;
    case 0x4: return O::Jz; case 0x5: return O::Jnz;
    case 0x6: return O::Jbe; case 0x7: return O::Ja;
    case 0x8: return O::Js; case 0x9: return O::Jns;
    case 0xA: return O::Jp; case 0xB: return O::Jnp;
    case 0xC: return O::Jl; case 0xD: return O::Jge;
    case 0xE: return O::Jle; case 0xF: return O::Jg;
    }
    throw std::runtime_error("x64 decoder: invalid condition code");
}

vmprotect::LiftedOp InvertJcc(vmprotect::LiftedOp Op) {
    using O = vmprotect::LiftedOp;
    switch (Op) {
    case O::Jo: return O::Jno; case O::Jno: return O::Jo;
    case O::Jb: return O::Jae; case O::Jae: return O::Jb;
    case O::Jz: return O::Jnz; case O::Jnz: return O::Jz;
    case O::Jbe: return O::Ja; case O::Ja: return O::Jbe;
    case O::Js: return O::Jns; case O::Jns: return O::Js;
    case O::Jp: return O::Jnp; case O::Jnp: return O::Jp;
    case O::Jl: return O::Jge; case O::Jge: return O::Jl;
    case O::Jle: return O::Jg; case O::Jg: return O::Jle;
    default: throw std::runtime_error("x64 decoder: not a conditional branch");
    }
}

struct MemOperand {
    std::uint8_t Base{};
    std::uint8_t Index{};
    bool HasBase{};
    bool HasIndex{};
    unsigned ScaleShift{};   // log2 of SIB scale, 0 when no index
    std::int64_t Displacement{};
    bool ViaSib{};
};

struct DecodeContext {
    std::span<const std::uint8_t> Data;
    std::size_t At{};
    std::size_t Limit{};
    std::uint32_t FunctionRva{};
    std::size_t Start{};

    std::uint64_t NeedImm(unsigned Count) {
        if (At + Count > Limit) throw std::runtime_error("x64 decoder: truncated immediate");
        std::uint64_t V = 0;
        for (unsigned N = 0; N < Count; ++N) V |= static_cast<std::uint64_t>(Data[At++]) << (N * 8);
        return V;
    }
    // Register-only ModRM; used where a memory form is not supported at all.
    std::uint8_t NeedRegModRm() {
        if (At >= Limit) throw std::runtime_error("x64 decoder: missing ModRM");
        const auto M = Data[At++];
        if ((M >> 6) != 3) {
            throw std::runtime_error("x64 decoder: memory operands for this instruction are not liftable");
        }
        return M;
    }
    std::uint8_t NeedModRm() {
        if (At >= Limit) throw std::runtime_error("x64 decoder: missing ModRM");
        return Data[At++];
    }
    // Base/index/displacement memory operand, including SIB. RIP-relative and
    // absolute disp32 addressing fail closed; stack-frame bases (RSP/RBP) are
    // rejected unless the caller only computes an address (LEA).
    MemOperand MemFromModRm(std::uint8_t ModRm, bool RexB, bool RexX, bool AllowStackBase,
                            bool AllowAbsolute = false) {
        const auto Mode = static_cast<std::uint8_t>(ModRm >> 6);
        const auto RawRm = static_cast<std::uint8_t>(ModRm & 7U);
        if (Mode == 0 && RawRm == 5U) throw std::runtime_error("x64 decoder: RIP-relative/absolute addressing is not liftable");
        if (RawRm != 4U) {
            MemOperand M{};
            M.Base = RmFromModRm(ModRm, RexB);
            M.HasBase = true;
            if (!AllowStackBase && (M.Base == 4U || M.Base == 5U)) {
                throw std::runtime_error("x64 decoder: stack-relative (RSP/RBP) memory operands are not liftable");
            }
            if (Mode == 1) M.Displacement = static_cast<std::int8_t>(NeedImm(1));
            else if (Mode == 2) M.Displacement = static_cast<std::int32_t>(NeedImm(4));
            return M;
        }
        if (At >= Limit) throw std::runtime_error("x64 decoder: missing SIB");
        const auto Sib = Data[At++];
        MemOperand M{};
        M.ViaSib = true;
        M.ScaleShift = (Sib >> 6) & 3U;
        const auto RawIndex = static_cast<std::uint8_t>((Sib >> 3) & 7U);
        const auto RawBase = static_cast<std::uint8_t>(Sib & 7U);
        M.HasIndex = RawIndex != 4U;
        if (M.HasIndex) M.Index = static_cast<std::uint8_t>(RawIndex | (RexX ? 8U : 0U));
        if (RawBase == 5U && Mode == 0) {
            if (!AllowAbsolute) throw std::runtime_error("x64 decoder: absolute disp32 addressing is not liftable");
            M.Displacement = static_cast<std::int32_t>(NeedImm(4));  // base-less [index*scale + disp32]
        } else {
            if (RawBase != 5U) {
                M.Base = static_cast<std::uint8_t>(RawBase | (RexB ? 8U : 0U));
                M.HasBase = true;
                if (!AllowStackBase && (M.Base == 4U || M.Base == 5U)) {
                    throw std::runtime_error("x64 decoder: stack-relative (RSP/RBP) memory operands are not liftable");
                }
            }
            if (Mode == 1) M.Displacement = static_cast<std::int8_t>(NeedImm(1));
            else if (Mode == 2) M.Displacement = static_cast<std::int32_t>(NeedImm(4));
        }
        return M;
    }
};

void RequireRexW(bool RexW, const char* What) {
    if (!RexW) {
        std::ostringstream Error;
        Error << "x64 decoder: " << What << " without REX.W (32-bit operand size) is not liftable";
        throw std::runtime_error(Error.str());
    }
}

} // namespace

static LiftResult LiftCode(std::span<const std::uint8_t> Code, std::uint32_t FunctionRva,
                           std::size_t MaximumBytes);

LiftResult LiftPeFunction(const std::filesystem::path& Input, std::uint32_t FunctionRva, std::size_t MaximumBytes) {
    const auto Data = util::ReadFile(Input);
    return LiftPeFunction(pevm::pe::ImageView(Data), FunctionRva, MaximumBytes);
}

LiftResult LiftPeFunction(const pevm::pe::ImageView& Image, std::uint32_t FunctionRva, std::size_t MaximumBytes) {
    Image.RequireX64();
    const auto Code = Image.CodeAtRva(FunctionRva, MaximumBytes);
    return LiftCode(Code, FunctionRva, Code.size());
}

LiftResult LiftRawCode(const std::vector<std::uint8_t>& Code, std::uint32_t FunctionRva,
                       std::size_t MaximumBytes) {
    return LiftCode(Code, FunctionRva, MaximumBytes);
}

static LiftResult LiftCode(std::span<const std::uint8_t> Code, std::uint32_t FunctionRva,
                           std::size_t MaximumBytes) {
    const auto& Data = Code;
    const auto Start = std::size_t{0};
    if (Data.empty()) throw std::runtime_error("x64 decoder: start outside input");
    const auto Limit = std::min(Data.size(), Start + MaximumBytes);
    vmprotect::LiftedProgram Program; Program.EntryAddress = FunctionRva;
    std::set<std::uint32_t> Targets{FunctionRva}; bool Terminated = false;
    std::set<std::uint32_t> SkippedAddresses;   // bytes of skipped padding NOPs
    DecodeContext Ctx{Data, Start, Limit, FunctionRva, Start};
    std::uint32_t SyntheticCounter = 0;
    // Synthetic IR instructions need addresses that cannot collide with real
    // instruction RVAs (branch targets) or with each other: 0xC0000000+ is
    // reserved for them, while LEA-style single synthetics stay at 0x80000000.
    auto SynthAddress = [&]{ return 0xC0000000U + (SyntheticCounter++); };
    // Native instruction addresses double as branch-target labels in the VM
    // bridge, so multi-instruction expansions begin with an anchored NOP that
    // carries the real address.
    auto EmitAnchor = [&](std::uint32_t AnchorAddress) {
        Program.Instructions.push_back({vmprotect::LiftedOp::Nop, 0, 0, 0, AnchorAddress, 0});
    };
    constexpr std::uint8_t KScratchAddr = 16;   // SIB address accumulator
    constexpr std::uint8_t KScratchScale = 17;  // scaled index inside address computation
    constexpr std::uint8_t KScratchValue = 18;  // loaded value for read-modify-write
    // Consumes the ModRM (+SIB+disp) of multibyte NOP padding, recording each
    // skipped byte so branch fall-throughs can slide past the padding.
    auto SkipNopOperands = [&](std::size_t From, std::set<std::uint32_t>& Skipped) {
        auto At = From;
        auto Consume = [&](unsigned Count) {
            for (unsigned I = 0; I < Count; ++I, ++At) {
                Skipped.insert(FunctionRva + static_cast<std::uint32_t>(At - Start));
            }
        };
        if (At >= Limit) throw std::runtime_error("x64 decoder: truncated NOP");
        auto M = Data[At++];
        auto Mode = static_cast<std::uint8_t>(M >> 6);
        auto Rm = static_cast<std::uint8_t>(M & 7U);
        if (Mode == 0 && Rm == 5U) { Consume(4); }
        else {
            if (Rm == 4U) {
                if (At >= Limit) throw std::runtime_error("x64 decoder: truncated NOP SIB");
                Rm = static_cast<std::uint8_t>(Data[At++] & 7U);
            }
            if (Mode == 1) Consume(1);
            else if (Mode == 2) Consume(4);
        }
        if (At > Limit) throw std::runtime_error("x64 decoder: truncated NOP");
        Ctx.At = At;
    };
    // Emits IR computing the effective address of Mem into a register and
    // returns it: the plain base register when no SIB is involved, otherwise
    // the scratch accumulator.
    auto EmitAddress = [&](const MemOperand& Mem) -> std::uint8_t {
        if (!Mem.ViaSib) return Mem.Base;
        bool Initialized = false;
        if (Mem.HasBase) {
            Program.Instructions.push_back({vmprotect::LiftedOp::Mov, KScratchAddr, Mem.Base, 0, SynthAddress(), 0});
            Initialized = true;
        }
        if (Mem.HasIndex) {
            Program.Instructions.push_back({vmprotect::LiftedOp::Mov, KScratchScale, Mem.Index, 0, SynthAddress(), 0});
            if (Mem.ScaleShift != 0) {
                Program.Instructions.push_back({vmprotect::LiftedOp::ShlI, KScratchScale, 0, Mem.ScaleShift, SynthAddress(), 0});
            }
            if (Initialized) {
                Program.Instructions.push_back({vmprotect::LiftedOp::Add, KScratchAddr, KScratchScale, 0, SynthAddress(), 0});
            } else {
                Program.Instructions.push_back({vmprotect::LiftedOp::Mov, KScratchAddr, KScratchScale, 0, SynthAddress(), 0});
                Initialized = true;
            }
        }
        if (!Initialized) throw std::runtime_error("x64 decoder: absolute addressing is not liftable");
        if (Mem.Displacement != 0) {
            Program.Instructions.push_back({vmprotect::LiftedOp::AddI, KScratchAddr, 0,
                static_cast<std::uint64_t>(Mem.Displacement), SynthAddress(), 0});
        }
        return KScratchAddr;
    };
    // Resumes decoding at the lowest branch target that has not been decoded
    // yet (branching over an early RET). Returns false when none is left.
    auto ResumeAtPendingTarget = [&]() {
        for (const auto T : Targets) {
            if (T < FunctionRva || std::uint64_t{T} >= std::uint64_t{FunctionRva} + Limit) continue;
            if (SkippedAddresses.count(T) != 0) continue;
            const auto Decoded = std::ranges::any_of(Program.Instructions, [&](const auto& I){ return I.Address == T; });
            if (Decoded) continue;
            Ctx.At = Start + (T - FunctionRva);
            return true;
        }
        return false;
    };
    for (; !Terminated;) {
        if (Ctx.At >= Limit) {
            if (!ResumeAtPendingTarget()) break;
        }
        const auto Begin = Ctx.At;
        const std::uint32_t Address = FunctionRva + static_cast<std::uint32_t>(Ctx.At - Start);
        bool RexW = false, RexR = false, RexX = false, RexB = false;
        // LOCK (F0) affects multiprocessor atomicity only; the lifted
        // single-threaded VM semantics are equivalent, so it is skipped.
        while (Ctx.At < Limit && ((Data[Ctx.At] >= 0x40 && Data[Ctx.At] <= 0x4f) || Data[Ctx.At] == 0xf0)) {
            const auto Rex = Data[Ctx.At++];
            if (Rex >= 0x40 && Rex <= 0x4f) { RexW = Rex & 8U; RexR = Rex & 4U; RexX = Rex & 2U; RexB = Rex & 1U; }
        }
        if (Ctx.At >= Limit) throw std::runtime_error("x64 decoder: prefix at end of function");
        const auto Opcode = Data[Ctx.At++]; vmprotect::LiftedInstruction I{}; I.Address = Address;
        auto PushBranch = [&](vmprotect::LiftedOp Op, std::uint64_t Displacement) {
            I.Op = Op;
            I.Target = static_cast<std::uint32_t>(FunctionRva + (Ctx.At - Start) + Displacement);
            Targets.insert(I.Target);
            Program.Instructions.push_back(I);
        };
        if (Opcode == 0x90) { SkippedAddresses.insert(Address); continue; }
        if (Opcode == 0x66) {
            // Operand-size prefix: tolerate it only as part of padding NOPs.
            const auto P1 = Ctx.At < Limit ? Data[Ctx.At] : 0;
            const auto P2 = Ctx.At + 1 < Limit ? Data[Ctx.At + 1] : 0;
            if (P1 == 0x90) { Ctx.At += 1; SkippedAddresses.insert(Address); continue; }
            if (P1 == 0x0f && P2 == 0x1f) { Ctx.At += 2; SkippedAddresses.insert(Address); SkipNopOperands(Ctx.At, SkippedAddresses); continue; }
            throw std::runtime_error("x64 decoder: 32-bit operand-size prefix is not liftable");
        }
        if (Opcode == 0xf3) {
            static constexpr std::array<std::uint8_t, 3> EndBr = {0x0f, 0x1e, 0xfa};
            if (Ctx.At + 2 < Limit && Data[Ctx.At] == EndBr[0] && Data[Ctx.At + 1] == EndBr[1] && Data[Ctx.At + 2] == EndBr[2]) {
                Ctx.At += 3; SkippedAddresses.insert(Address); continue;  // endbr64
            }
            throw std::runtime_error("x64 decoder: F3-prefixed instruction is not liftable");
        }        if (Opcode == 0xc3) { I.Op = vmprotect::LiftedOp::Ret; Program.Instructions.push_back(I); if (!ResumeAtPendingTarget()) Terminated = true; continue; }
        if (Opcode == 0xe8) { const auto Disp = static_cast<std::int32_t>(Ctx.NeedImm(4)); PushBranch(vmprotect::LiftedOp::Call, static_cast<std::uint64_t>(static_cast<std::int64_t>(Disp))); continue; }
        if (Opcode == 0xe9 || Opcode == 0xeb) {
            const auto Disp = Opcode == 0xe9 ? static_cast<std::int64_t>(static_cast<std::int32_t>(Ctx.NeedImm(4)))
                                             : static_cast<std::int64_t>(static_cast<std::int8_t>(Ctx.NeedImm(1)));
            PushBranch(vmprotect::LiftedOp::Jmp, static_cast<std::uint64_t>(Disp)); continue;
        }
        if (Opcode >= 0x70 && Opcode <= 0x7f) {
            const auto Disp = static_cast<std::int64_t>(static_cast<std::int8_t>(Ctx.NeedImm(1)));
            PushBranch(JccFromLowNibble(static_cast<std::uint8_t>(Opcode & 15U)), static_cast<std::uint64_t>(Disp));
            Targets.insert(static_cast<std::uint32_t>(FunctionRva + (Ctx.At - Start)));  // fall-through
            continue;
        }
        if (Opcode == 0x0f) {
            const auto Next = Ctx.At < Limit ? Data[Ctx.At++] : 0;
            if (Next == 0x1f) { SkippedAddresses.insert(Address); SkipNopOperands(Ctx.At, SkippedAddresses); continue; }  // multibyte NOP
            if (Next >= 0x80 && Next <= 0x8f) {
                const auto Disp = static_cast<std::int32_t>(Ctx.NeedImm(4));
                PushBranch(JccFromLowNibble(static_cast<std::uint8_t>(Next & 15U)), static_cast<std::uint64_t>(static_cast<std::int64_t>(Disp)));
                Targets.insert(static_cast<std::uint32_t>(FunctionRva + (Ctx.At - Start)));  // fall-through
                continue;
            }
            if (Next >= 0x40 && Next <= 0x4f) {  // CMOVcc r, r/m64
                RequireRexW(RexW, "CMOV");
                const auto M = Ctx.NeedModRm();
                const auto Dst = RegFromModRm(M, RexR);
                EmitAnchor(Address);
                const auto Inv = InvertJcc(JccFromLowNibble(static_cast<std::uint8_t>(Next & 15U)));
                if ((M >> 6) != 3) {
                    const auto Mem = Ctx.MemFromModRm(M, RexB, RexX, false);
                    const auto AddrReg = EmitAddress(Mem);
                    Program.Instructions.push_back({vmprotect::LiftedOp::LoadMem, KScratchValue, AddrReg,
                        Mem.ViaSib ? 0 : static_cast<std::uint64_t>(Mem.Displacement), SynthAddress(), 0});
                }
                // cmov dst, src  ->  Jinv skip; mov dst, src; skip (NOP landing).
                const auto Landing = SynthAddress();
                Program.Instructions.push_back({Inv, 0, 0, 0, SynthAddress(), Landing});
                if ((M >> 6) == 3) {
                    const auto Src = RmFromModRm(M, RexB);
                    Program.Instructions.push_back({vmprotect::LiftedOp::Mov, Dst, Src, 0, SynthAddress(), 0});
                } else {
                    Program.Instructions.push_back({vmprotect::LiftedOp::Mov, Dst, KScratchValue, 0, SynthAddress(), 0});
                }
                Program.Instructions.push_back({vmprotect::LiftedOp::Nop, 0, 0, 0, Landing, 0});
                continue;
            }
            if (Next == 0xaf) { const auto M = Ctx.NeedRegModRm(); I.Op = vmprotect::LiftedOp::Mul; RequireRexW(RexW, "IMUL"); I.Dst = RegFromModRm(M, RexR); I.Src = RmFromModRm(M, RexB); Program.Instructions.push_back(I); continue; }
            if (Next == 0xb6 || Next == 0xb7 || Next == 0xbe || Next == 0xbf) {
                // MOVZX/MOVSX r64, r/m8|r/m16. Zero-extension masks the loaded
                // value; sign-extension shifts left then arithmetic-right so
                // the sign bit propagates across the whole register. MOVZX is
                // also accepted without REX.W: a 32-bit zero-extended
                // destination leaves the identical 64-bit value.
                const bool IsSign = Next >= 0xbe;
                if (IsSign) RequireRexW(RexW, "MOVSX");
                const unsigned Width = (Next == 0xb6 || Next == 0xbe) ? 8U : 16U;
                const auto M = Ctx.NeedModRm();
                const auto Dst = RegFromModRm(M, RexR);
                EmitAnchor(Address);
                if ((M >> 6) == 3) {
                    Program.Instructions.push_back({vmprotect::LiftedOp::Mov, Dst, RmFromModRm(M, RexB), 0, SynthAddress(), 0});
                } else {
                    const auto Mem = Ctx.MemFromModRm(M, RexB, RexX, false);
                    const auto AddrReg = EmitAddress(Mem);
                    Program.Instructions.push_back({vmprotect::LiftedOp::LoadMem, Dst, AddrReg,
                        Mem.ViaSib ? 0 : static_cast<std::uint64_t>(Mem.Displacement), SynthAddress(), 0});
                }
                if (IsSign) {
                    Program.Instructions.push_back({vmprotect::LiftedOp::ShlI, Dst, 0, 64 - Width, SynthAddress(), 0});
                    Program.Instructions.push_back({vmprotect::LiftedOp::SarI, Dst, 0, 64 - Width, SynthAddress(), 0});
                } else {
                    Program.Instructions.push_back({vmprotect::LiftedOp::AndI, Dst, 0,
                        Width == 8 ? 0xFFULL : 0xFFFFULL, SynthAddress(), 0});
                }
                continue;
            }
            if (Next >= 0xc8 && Next <= 0xcf) {  // BSWAP r64 (no ModRM)
                RequireRexW(RexW, "BSWAP");
                vmprotect::LiftedInstruction Swap{};
                Swap.Op = vmprotect::LiftedOp::Bswap;
                Swap.Address = Address;
                Swap.Dst = static_cast<std::uint8_t>((Next & 7U) | (RexB ? 8U : 0U));
                Program.Instructions.push_back(Swap);
                continue;
            }
            if (Next >= 0x90 && Next <= 0x9f) {  // SETcc r/m8
                // Byte stores are not liftable, so only the register form is
                // accepted: dst = cond ? 1 : 0 expands to set/branch/set,
                // jumping over the zero-set when the condition HOLDS.
                const auto M = Ctx.NeedRegModRm();
                const auto Dst = RmFromModRm(M, RexB);
                EmitAnchor(Address);
                const auto Landing = SynthAddress();
                const auto Cond = JccFromLowNibble(static_cast<std::uint8_t>(Next & 15U));
                Program.Instructions.push_back({vmprotect::LiftedOp::MovI, Dst, 0, 1, SynthAddress(), 0});
                Program.Instructions.push_back({Cond, 0, 0, 0, SynthAddress(), Landing});
                Program.Instructions.push_back({vmprotect::LiftedOp::MovI, Dst, 0, 0, SynthAddress(), 0});
                Program.Instructions.push_back({vmprotect::LiftedOp::Nop, 0, 0, 0, Landing, 0});
                continue;
            }
            throw std::runtime_error("x64 decoder: unsupported 0F opcode");
        }
        if (Opcode >= 0x50 && Opcode <= 0x57) {
            I.Op = vmprotect::LiftedOp::Push;
            I.Dst = static_cast<std::uint8_t>((Opcode - 0x50) | (RexB ? 8U : 0U));
            Program.Instructions.push_back(I); continue;
        }
        if (Opcode >= 0x58 && Opcode <= 0x5f) {
            I.Op = vmprotect::LiftedOp::Pop;
            I.Dst = static_cast<std::uint8_t>((Opcode - 0x58) | (RexB ? 8U : 0U));
            Program.Instructions.push_back(I); continue;
        }
        if (Opcode == 0x8d) {
            RequireRexW(RexW, "LEA");
            const auto M = Ctx.NeedModRm();
            const auto Mode = static_cast<std::uint8_t>(M >> 6);
            if (Mode == 3) throw std::runtime_error("x64 decoder: LEA register form invalid");
            const auto Dst = RegFromModRm(M, RexR);
            const auto Mem = Ctx.MemFromModRm(M, RexB, RexX, true, true);
            EmitAnchor(Address);
            // LEA computes an address without accessing memory, so stack-frame
            // bases and base-less [index*scale+disp] arithmetic are legal;
            // emit dst = base + index<<scale + disp. Inputs are read before
            // dst is written (dst may alias base or index).
            if (Mem.HasIndex) {
                Program.Instructions.push_back({vmprotect::LiftedOp::Mov, KScratchScale, Mem.Index, 0, SynthAddress(), 0});
                if (Mem.ScaleShift != 0) {
                    Program.Instructions.push_back({vmprotect::LiftedOp::ShlI, KScratchScale, 0, Mem.ScaleShift, SynthAddress(), 0});
                }
            }
            if (!Mem.HasBase) {
                Program.Instructions.push_back({vmprotect::LiftedOp::MovI, Dst, 0,
                    static_cast<std::uint64_t>(Mem.Displacement), SynthAddress(), 0});
            } else {
                Program.Instructions.push_back({vmprotect::LiftedOp::Mov, Dst, Mem.Base, 0, SynthAddress(), 0});
            }
            if (Mem.HasIndex) {
                Program.Instructions.push_back({vmprotect::LiftedOp::Add, Dst, KScratchScale, 0, SynthAddress(), 0});
            }
            if (Mem.HasBase && Mem.Displacement != 0) {
                Program.Instructions.push_back({vmprotect::LiftedOp::AddI, Dst, 0,
                    static_cast<std::uint64_t>(Mem.Displacement), SynthAddress(), 0});
            }
            continue;
        }
        if (Opcode == 0xff) {
            const auto M = Ctx.NeedModRm();
            const auto Group = static_cast<std::uint8_t>((M >> 3) & 7U);
            if ((M >> 6) == 3 && Group == 0) {           // INC r/m64
                RequireRexW(RexW, "INC");
                I.Op = vmprotect::LiftedOp::AddI; I.Dst = RmFromModRm(M, RexB); I.Immediate = 1;
                Program.Instructions.push_back(I); continue;
            }
            if ((M >> 6) == 3 && Group == 1) {           // DEC r/m64
                RequireRexW(RexW, "DEC");
                I.Op = vmprotect::LiftedOp::SubI; I.Dst = RmFromModRm(M, RexB); I.Immediate = 1;
                Program.Instructions.push_back(I); continue;
            }
            if (Group == 2) throw std::runtime_error("x64 decoder: indirect calls are not liftable");
            if (Group == 4) throw std::runtime_error("x64 decoder: indirect jumps are not liftable");
            throw std::runtime_error("x64 decoder: unsupported FF group");
        }
        if (Opcode >= 0xb8 && Opcode <= 0xbf) {
            // mov r64, imm64 with REX.W; without it, mov r32, imm32 whose
            // zero-extension is exactly the 64-bit register value.
            I.Op=vmprotect::LiftedOp::MovI; I.Dst=static_cast<std::uint8_t>((Opcode-0xb8)|(RexB?8:0));
            I.Immediate = RexW ? Ctx.NeedImm(8) : Ctx.NeedImm(4);
            Program.Instructions.push_back(I); continue;
        }
        if (Opcode == 0x63) {  // MOVSXD r64, r/m32 (REX.W required)
            RequireRexW(RexW, "MOVSXD");
            const auto M = Ctx.NeedModRm();
            const auto Dst = RegFromModRm(M, RexR);
            EmitAnchor(Address);
            if ((M >> 6) == 3) {
                Program.Instructions.push_back({vmprotect::LiftedOp::Mov, Dst, RmFromModRm(M, RexB), 0, SynthAddress(), 0});
            } else {
                const auto Mem = Ctx.MemFromModRm(M, RexB, RexX, false);
                const auto AddrReg = EmitAddress(Mem);
                Program.Instructions.push_back({vmprotect::LiftedOp::LoadMem, Dst, AddrReg,
                    Mem.ViaSib ? 0 : static_cast<std::uint64_t>(Mem.Displacement), SynthAddress(), 0});
            }
            // Sign-extend the 32-bit value across the whole register.
            Program.Instructions.push_back({vmprotect::LiftedOp::ShlI, Dst, 0, 32, SynthAddress(), 0});
            Program.Instructions.push_back({vmprotect::LiftedOp::SarI, Dst, 0, 32, SynthAddress(), 0});
            continue;
        }
        if (Opcode == 0x04 || Opcode == 0x05 || Opcode == 0x0c || Opcode == 0x0d ||
            Opcode == 0x15 || Opcode == 0x24 || Opcode == 0x25 || Opcode == 0x2c || Opcode == 0x2d ||
            Opcode == 0x1d || Opcode == 0x34 || Opcode == 0x35 || Opcode == 0x3c || Opcode == 0x3d) {
            // Accumulator ALU short forms: <op> rax, imm. Only the 64-bit
            // (REX.W) encodings are accepted; imm32 is sign-extended.
            RequireRexW(RexW, "accumulator immediate operation");
            const auto Raw = static_cast<std::uint64_t>(static_cast<std::int64_t>(static_cast<std::int32_t>(Ctx.NeedImm(4))));
            const auto Kind = Opcode >> 3;   // ALU column: 0=ADD 1=OR 4=AND 5=SUB 6=XOR 7=CMP
            if (Kind == 0) I.Op = vmprotect::LiftedOp::AddI;              // 04/05 ADD
            else if (Kind == 1) {                                         // 0C/0D OR
                EmitAnchor(Address);
                Program.Instructions.push_back({vmprotect::LiftedOp::MovI, KScratchValue, 0, Raw, SynthAddress(), 0});
                Program.Instructions.push_back({vmprotect::LiftedOp::Or, 0, KScratchValue, 0, SynthAddress(), 0});
                continue;
            } else if (Kind == 4) I.Op = vmprotect::LiftedOp::AndI;       // 24/25 AND
            else if (Kind == 5) I.Op = vmprotect::LiftedOp::SubI;         // 2C/2D SUB
            else if (Kind == 2) {                                         // 15 ADC rax, imm32
                EmitAnchor(Address);
                Program.Instructions.push_back({vmprotect::LiftedOp::MovI, KScratchValue, 0, Raw, SynthAddress(), 0});
                Program.Instructions.push_back({vmprotect::LiftedOp::Adc, 0, KScratchValue, 0, SynthAddress(), 0});
                continue;
            } else if (Kind == 3) {                                       // 1D SBB rax, imm32
                EmitAnchor(Address);
                Program.Instructions.push_back({vmprotect::LiftedOp::MovI, KScratchValue, 0, Raw, SynthAddress(), 0});
                Program.Instructions.push_back({vmprotect::LiftedOp::Sbb, 0, KScratchValue, 0, SynthAddress(), 0});
                continue;
            } else if (Kind == 6) {                                       // 34/35 XOR
                EmitAnchor(Address);
                Program.Instructions.push_back({vmprotect::LiftedOp::MovI, KScratchValue, 0, Raw, SynthAddress(), 0});
                Program.Instructions.push_back({vmprotect::LiftedOp::Xor, 0, KScratchValue, 0, SynthAddress(), 0});
                continue;
            } else {                                                      // 3C/3D CMP
                EmitAnchor(Address);
                Program.Instructions.push_back({vmprotect::LiftedOp::MovI, KScratchValue, 0, Raw, SynthAddress(), 0});
                Program.Instructions.push_back({vmprotect::LiftedOp::Cmp, 0, KScratchValue, 0, SynthAddress(), 0});
                continue;
            }
            I.Dst = 0; I.Immediate = Raw;
            Program.Instructions.push_back(I); continue;
        }
        if (Opcode == 0xa9) {  // TEST rax, imm32 (REX.W; flag-only)
            RequireRexW(RexW, "TEST");
            const auto Raw = static_cast<std::uint64_t>(static_cast<std::int64_t>(static_cast<std::int32_t>(Ctx.NeedImm(4))));
            EmitAnchor(Address);
            Program.Instructions.push_back({vmprotect::LiftedOp::MovI, KScratchValue, 0, Raw, SynthAddress(), 0});
            Program.Instructions.push_back({vmprotect::LiftedOp::Test, 0, KScratchValue, 0, SynthAddress(), 0});
            continue;
        }
        if (Opcode == 0x68 || Opcode == 0x6a) {  // PUSH imm32 / imm8 (sign-extended)
            const auto Raw = Opcode == 0x68
                ? static_cast<std::uint64_t>(static_cast<std::int64_t>(static_cast<std::int32_t>(Ctx.NeedImm(4))))
                : static_cast<std::uint64_t>(static_cast<std::int64_t>(static_cast<std::int8_t>(Ctx.NeedImm(1))));
            EmitAnchor(Address);
            Program.Instructions.push_back({vmprotect::LiftedOp::MovI, KScratchValue, 0, Raw, SynthAddress(), 0});
            Program.Instructions.push_back({vmprotect::LiftedOp::Push, KScratchValue, 0, 0, SynthAddress(), 0});
            continue;
        }
        if (Opcode == 0x87) {  // XCHG r64, r/m64
            RequireRexW(RexW, "XCHG");
            const auto M = Ctx.NeedRegModRm();  // memory form is not liftable
            const auto Dst = RegFromModRm(M, RexR), Src = RmFromModRm(M, RexB);
            EmitAnchor(Address);
            Program.Instructions.push_back({vmprotect::LiftedOp::Push, Dst, 0, 0, SynthAddress(), 0});
            Program.Instructions.push_back({vmprotect::LiftedOp::Mov, Dst, Src, 0, SynthAddress(), 0});
            Program.Instructions.push_back({vmprotect::LiftedOp::Pop, Src, 0, 0, SynthAddress(), 0});
            continue;
        }
        if (Opcode == 0xc7) {  // MOV r/m64, imm32 (sign-extended), group /0
            RequireRexW(RexW, "MOV imm");
            const auto M = Ctx.NeedModRm();
            const auto Group = static_cast<std::uint8_t>((M >> 3) & 7U);
            if (Group != 0) throw std::runtime_error("x64 decoder: unsupported C7 group");
            const auto Raw = static_cast<std::uint64_t>(static_cast<std::int64_t>(static_cast<std::int32_t>(Ctx.NeedImm(4))));
            if ((M >> 6) == 3) {
                Program.Instructions.push_back({vmprotect::LiftedOp::MovI, RmFromModRm(M, RexB), 0, Raw, Address, 0});
                continue;
            }
            EmitAnchor(Address);
            const auto Mem = Ctx.MemFromModRm(M, RexB, RexX, false);
            const auto AddrReg = EmitAddress(Mem);
            const auto AddrDisp = Mem.ViaSib ? 0 : static_cast<std::uint64_t>(Mem.Displacement);
            Program.Instructions.push_back({vmprotect::LiftedOp::MovI, KScratchValue, 0, Raw, SynthAddress(), 0});
            Program.Instructions.push_back({vmprotect::LiftedOp::StoreMem, AddrReg, KScratchValue, AddrDisp, SynthAddress(), 0});
            continue;
        }
        if (Opcode == 0xf7) {  // escape group: TEST imm, NOT, NEG
            RequireRexW(RexW, "F7 group");
            const auto M = Ctx.NeedModRm();
            const auto Group = static_cast<std::uint8_t>((M >> 3) & 7U);
            if (Group == 0) {  // TEST r/m64, imm32 (flag-only)
                const auto Raw = static_cast<std::uint64_t>(static_cast<std::int64_t>(static_cast<std::int32_t>(Ctx.NeedImm(4))));
                EmitAnchor(Address);
                if ((M >> 6) == 3) {
                    Program.Instructions.push_back({vmprotect::LiftedOp::MovI, KScratchValue, 0, Raw, SynthAddress(), 0});
                    Program.Instructions.push_back({vmprotect::LiftedOp::Test, RmFromModRm(M, RexB), KScratchValue, 0, SynthAddress(), 0});
                } else {
                    const auto Mem = Ctx.MemFromModRm(M, RexB, RexX, false);
                    const auto AddrReg = EmitAddress(Mem);
                    const auto AddrDisp = Mem.ViaSib ? 0 : static_cast<std::uint64_t>(Mem.Displacement);
                    Program.Instructions.push_back({vmprotect::LiftedOp::LoadMem, KScratchValue, AddrReg, AddrDisp, SynthAddress(), 0});
                    Program.Instructions.push_back({vmprotect::LiftedOp::MovI, KScratchScale, 0, Raw, SynthAddress(), 0});
                    Program.Instructions.push_back({vmprotect::LiftedOp::Test, KScratchValue, KScratchScale, 0, SynthAddress(), 0});
                }
                continue;
            }
            if (Group == 2 || Group == 3) {  // NOT / NEG r/m64
                const auto Op = Group == 2 ? vmprotect::LiftedOp::Not : vmprotect::LiftedOp::Neg;
                if ((M >> 6) == 3) {
                    vmprotect::LiftedInstruction Update{};
                    Update.Op = Op; Update.Address = Address; Update.Dst = RmFromModRm(M, RexB);
                    Program.Instructions.push_back(Update);
                    continue;
                }
                EmitAnchor(Address);
                const auto Mem = Ctx.MemFromModRm(M, RexB, RexX, false);
                const auto AddrReg = EmitAddress(Mem);
                const auto AddrDisp = Mem.ViaSib ? 0 : static_cast<std::uint64_t>(Mem.Displacement);
                Program.Instructions.push_back({vmprotect::LiftedOp::LoadMem, KScratchValue, AddrReg, AddrDisp, SynthAddress(), 0});
                Program.Instructions.push_back({Op, KScratchValue, 0, 0, SynthAddress(), 0});
                Program.Instructions.push_back({vmprotect::LiftedOp::StoreMem, AddrReg, KScratchValue, AddrDisp, SynthAddress(), 0});
                continue;
            }
            throw std::runtime_error("x64 decoder: unsupported F7 group");
        }
        if (Opcode == 0x81 || Opcode == 0x83) {
            RequireRexW(RexW, "immediate group operation");
            const auto M = Ctx.NeedModRm();
            const auto Group = static_cast<std::uint8_t>((M >> 3) & 7U);
            const auto Raw = Opcode == 0x83 ? static_cast<std::uint64_t>(static_cast<std::int64_t>(static_cast<std::int8_t>(Ctx.NeedImm(1))))
                                            : static_cast<std::uint64_t>(static_cast<std::int64_t>(static_cast<std::int32_t>(Ctx.NeedImm(4))));
            if ((M >> 6) == 3) {
                I.Dst = RmFromModRm(M, RexB);
                I.Immediate = Raw;
                if (Group == 0) I.Op = vmprotect::LiftedOp::AddI;
                else if (Group == 4) I.Op = vmprotect::LiftedOp::AndI;
                else if (Group == 5) I.Op = vmprotect::LiftedOp::SubI;
                else if (Group == 1 || Group == 6 || Group == 7) {
                    // OR/XOR/CMP with an immediate go through a scratch
                    // register: the VM has no OrI/XorI/CmpI forms.
                    EmitAnchor(Address);
                    Program.Instructions.push_back({vmprotect::LiftedOp::MovI, KScratchValue, 0, Raw, SynthAddress(), 0});
                    const auto Operation = Group == 1 ? vmprotect::LiftedOp::Or
                                         : Group == 6 ? vmprotect::LiftedOp::Xor
                                                      : vmprotect::LiftedOp::Cmp;
                    Program.Instructions.push_back({Operation, I.Dst, KScratchValue, 0, SynthAddress(), 0});
                    continue;
                }
                else if (Group == 2 || Group == 3) {
                    // ADC/SBB with an immediate: immediate feeds the scratch
                    // register, the carry/borrow comes from the live flags.
                    EmitAnchor(Address);
                    Program.Instructions.push_back({vmprotect::LiftedOp::MovI, KScratchValue, 0, Raw, SynthAddress(), 0});
                    Program.Instructions.push_back({Group == 2 ? vmprotect::LiftedOp::Adc : vmprotect::LiftedOp::Sbb,
                        I.Dst, KScratchValue, 0, SynthAddress(), 0});
                    continue;
                }
                else throw std::runtime_error("x64 decoder: unsupported immediate group");
                Program.Instructions.push_back(I); continue;
            }
            // Memory forms become read-modify-write over the flat VM memory;
            // CMP is flag-only and never stores back.
            EmitAnchor(Address);
            const auto Mem = Ctx.MemFromModRm(M, RexB, RexX, false);
            const auto AddrReg = EmitAddress(Mem);
            const auto AddrDisp = Mem.ViaSib ? 0 : static_cast<std::uint64_t>(Mem.Displacement);
            Program.Instructions.push_back({vmprotect::LiftedOp::LoadMem, KScratchValue, AddrReg, AddrDisp, SynthAddress(), 0});
            auto StoreBack = [&]() {
                Program.Instructions.push_back({vmprotect::LiftedOp::StoreMem, AddrReg, KScratchValue, AddrDisp, SynthAddress(), 0});
            };
            switch (Group) {
            case 0:  // add [m], imm
                Program.Instructions.push_back({vmprotect::LiftedOp::AddI, KScratchValue, 0, Raw, SynthAddress(), 0});
                StoreBack(); break;
            case 4:  // and [m], imm
                Program.Instructions.push_back({vmprotect::LiftedOp::AndI, KScratchValue, 0, Raw, SynthAddress(), 0});
                StoreBack(); break;
            case 5:  // sub [m], imm
                Program.Instructions.push_back({vmprotect::LiftedOp::SubI, KScratchValue, 0, Raw, SynthAddress(), 0});
                StoreBack(); break;
            case 1:  // or [m], imm
            case 6:  // xor [m], imm
                Program.Instructions.push_back({vmprotect::LiftedOp::MovI, KScratchScale, 0, Raw, SynthAddress(), 0});
                Program.Instructions.push_back({Group == 1 ? vmprotect::LiftedOp::Or : vmprotect::LiftedOp::Xor,
                    KScratchValue, KScratchScale, 0, SynthAddress(), 0});
                StoreBack(); break;
            case 2:  // adc [m], imm
            case 3:  // sbb [m], imm
                Program.Instructions.push_back({vmprotect::LiftedOp::MovI, KScratchScale, 0, Raw, SynthAddress(), 0});
                Program.Instructions.push_back({Group == 2 ? vmprotect::LiftedOp::Adc : vmprotect::LiftedOp::Sbb,
                    KScratchValue, KScratchScale, 0, SynthAddress(), 0});
                StoreBack(); break;
            case 7:  // cmp [m], imm
                Program.Instructions.push_back({vmprotect::LiftedOp::MovI, KScratchScale, 0, Raw, SynthAddress(), 0});
                Program.Instructions.push_back({vmprotect::LiftedOp::Cmp, KScratchValue, KScratchScale, 0, SynthAddress(), 0});
                break;
            default:
                throw std::runtime_error("x64 decoder: unsupported immediate group");
            }
            continue;
        }
        if (Opcode == 0xc1 || Opcode == 0xd1 || Opcode == 0xd3) {
            RequireRexW(RexW, "shift");
            const auto M = Ctx.NeedRegModRm(); const auto Group = static_cast<std::uint8_t>((M >> 3) & 7U);
            I.Dst = RmFromModRm(M, RexB);
            // Groups: 0=ROL 1=ROR 4=SHL 5=SHR 7=SAR.
            if (Group != 0U && Group != 1U && Group != 4U && Group != 5U && Group != 7U) {
                throw std::runtime_error("x64 decoder: unsupported shift group");
            }
            if (Opcode == 0xc1) {
                I.Immediate = Ctx.NeedImm(1);
                if (Group == 0U) I.Op = vmprotect::LiftedOp::RolI;
                else if (Group == 1U) I.Op = vmprotect::LiftedOp::RorI;
                else I.Op = Group == 4U ? vmprotect::LiftedOp::ShlI : Group == 5U ? vmprotect::LiftedOp::ShrI : vmprotect::LiftedOp::SarI;
            } else if (Opcode == 0xd1) {
                I.Immediate = 1;
                if (Group == 0U) I.Op = vmprotect::LiftedOp::RolI;
                else if (Group == 1U) I.Op = vmprotect::LiftedOp::RorI;
                else I.Op = Group == 4U ? vmprotect::LiftedOp::ShlI : Group == 5U ? vmprotect::LiftedOp::ShrI : vmprotect::LiftedOp::SarI;
            } else {
                if (Group == 0U) I.Op = vmprotect::LiftedOp::RolR;
                else if (Group == 1U) I.Op = vmprotect::LiftedOp::RorR;
                else I.Op = Group == 4U ? vmprotect::LiftedOp::ShlR : Group == 5U ? vmprotect::LiftedOp::ShrR : vmprotect::LiftedOp::SarR;
                I.Src = 1;  // CL
            }
            Program.Instructions.push_back(I); continue;
        }
        if (Opcode == 0x69 || Opcode == 0x6b) {
            RequireRexW(RexW, "three-operand IMUL");
            if (Ctx.At >= Limit) throw std::runtime_error("x64 decoder: missing IMUL ModRM");
            const auto M = Ctx.NeedModRm();
            const auto Dst = RegFromModRm(M, RexR);
            const auto Raw = Opcode == 0x6b ? static_cast<std::uint64_t>(static_cast<std::int64_t>(static_cast<std::int8_t>(Ctx.NeedImm(1))))
                                            : static_cast<std::uint64_t>(static_cast<std::int64_t>(static_cast<std::int32_t>(Ctx.NeedImm(4))));
            if ((M >> 6) == 3) {
                vmprotect::LiftedInstruction Move{}; Move.Op = vmprotect::LiftedOp::Mov;
                Move.Address = Address; Move.Dst = Dst; Move.Src = RmFromModRm(M, RexB);
                Program.Instructions.push_back(Move);
            } else {
                const auto Mem = Ctx.MemFromModRm(M, RexB, RexX, false);
                EmitAnchor(Address);
                const auto AddrReg = EmitAddress(Mem);
                const auto AddrDisp = Mem.ViaSib ? 0 : static_cast<std::uint64_t>(Mem.Displacement);
                vmprotect::LiftedInstruction Load{}; Load.Op = vmprotect::LiftedOp::LoadMem;
                Load.Address = SynthAddress(); Load.Dst = Dst; Load.Src = AddrReg; Load.Immediate = AddrDisp;
                Program.Instructions.push_back(Load);
            }
            vmprotect::LiftedInstruction MulI{}; MulI.Op = vmprotect::LiftedOp::MulI;
            MulI.Address = 0x80000000U | static_cast<std::uint32_t>(Address);
            MulI.Dst = Dst; MulI.Immediate = Raw;
            Program.Instructions.push_back(MulI);
            continue;
        }
        if (Opcode == 0x11 || Opcode == 0x13 || Opcode == 0x19 || Opcode == 0x1b) {
            // ADC/SBB reg forms (carry/borrow chain ops). Memory forms use the
            // standard read-modify-write expansion.
            RequireRexW(RexW, "ADC/SBB");
            const auto ModRm = Ctx.NeedModRm();
            const auto Dst = RegFromModRm(ModRm, RexR), Src = RmFromModRm(ModRm, RexB);
            const auto Operation = (Opcode & 8U) ? vmprotect::LiftedOp::Sbb : vmprotect::LiftedOp::Adc;
            EmitAnchor(Address);
            if ((ModRm >> 6) == 3) {
                Program.Instructions.push_back({Operation, Dst, Src, 0, SynthAddress(), 0});
                continue;
            }
            const auto Mem = Ctx.MemFromModRm(ModRm, RexB, RexX, false);
            const auto AddrReg = EmitAddress(Mem);
            const auto AddrDisp = Mem.ViaSib ? 0 : static_cast<std::uint64_t>(Mem.Displacement);
            const bool ToReg = (Opcode & 2U) != 0;  // 13/1B: op r64, [m]
            Program.Instructions.push_back({vmprotect::LiftedOp::LoadMem, ToReg ? Dst : KScratchValue,
                AddrReg, AddrDisp, SynthAddress(), 0});
            Program.Instructions.push_back({Operation, ToReg ? Dst : KScratchValue,
                ToReg ? Src : Dst, 0, SynthAddress(), 0});
            if (!ToReg) {
                Program.Instructions.push_back({vmprotect::LiftedOp::StoreMem, AddrReg, KScratchValue, AddrDisp, SynthAddress(), 0});
            }
            continue;
        }
        // Two-operand ALU group: MOV/ADD/SUB/AND/OR/XOR/CMP/TEST. Register
        // forms lift 1:1. Memory forms map onto flat VM memory: plain
        // base+disp becomes a direct LoadMem/StoreMem, SIB forms compute the
        // address in scratch registers, and read-modify-write operations go
        // through a scratch value register.
        if (Opcode == 0x89 || Opcode == 0x8b || Opcode == 0x01 || Opcode == 0x03 || Opcode == 0x09 ||
            Opcode == 0x0b || Opcode == 0x21 || Opcode == 0x23 || Opcode == 0x29 || Opcode == 0x2b ||
            Opcode == 0x31 || Opcode == 0x33 || Opcode == 0x39 || Opcode == 0x3b || Opcode == 0x85) {
            const auto ModRm = Ctx.NeedModRm();
            const auto Dst = RegFromModRm(ModRm, RexR), Src = RmFromModRm(ModRm, RexB);
            if (!RexW) {
                // 32-bit operand forms are otherwise rejected; the classic
                // xor r32,r32 idiom is exact regardless of width (result is 0).
                if (Opcode == 0x33 && Dst == Src) {
                    Program.Instructions.push_back({vmprotect::LiftedOp::MovI, Dst, 0, 0, Address, 0});
                    continue;
                }
                RequireRexW(RexW, "ALU operation");
            }
            const auto MemoryForm = (ModRm >> 6) != 3;
            if (!MemoryForm) {
                switch (Opcode) {
                case 0x89: I.Op=vmprotect::LiftedOp::Mov; I.Dst=Src; I.Src=Dst; break;
                case 0x8b: I.Op=vmprotect::LiftedOp::Mov; I.Dst=Dst; I.Src=Src; break;
                case 0x01: I.Op=vmprotect::LiftedOp::Add; I.Dst=Src; I.Src=Dst; break;
                case 0x03: I.Op=vmprotect::LiftedOp::Add; I.Dst=Dst; I.Src=Src; break;
                case 0x09: I.Op=vmprotect::LiftedOp::Or; I.Dst=Src; I.Src=Dst; break;
                case 0x0b: I.Op=vmprotect::LiftedOp::Or; I.Dst=Dst; I.Src=Src; break;
                case 0x21: I.Op=vmprotect::LiftedOp::And; I.Dst=Src; I.Src=Dst; break;
                case 0x23: I.Op=vmprotect::LiftedOp::And; I.Dst=Dst; I.Src=Src; break;
                case 0x29: I.Op=vmprotect::LiftedOp::Sub; I.Dst=Src; I.Src=Dst; break;
                case 0x2b: I.Op=vmprotect::LiftedOp::Sub; I.Dst=Dst; I.Src=Src; break;
                case 0x31: I.Op=vmprotect::LiftedOp::Xor; I.Dst=Src; I.Src=Dst; break;
                case 0x33: I.Op=vmprotect::LiftedOp::Xor; I.Dst=Dst; I.Src=Src; break;
                case 0x39: I.Op=vmprotect::LiftedOp::Cmp; I.Dst=Src; I.Src=Dst; break;
                case 0x3b: I.Op=vmprotect::LiftedOp::Cmp; I.Dst=Dst; I.Src=Src; break;
                case 0x85: I.Op=vmprotect::LiftedOp::Test; I.Dst=Dst; I.Src=Src; break;
                }
                Program.Instructions.push_back(I);
                if (Ctx.At == Begin) throw std::runtime_error("x64 decoder: decoder made no progress");
                continue;
            }
            const auto Mem = Ctx.MemFromModRm(ModRm, RexB, RexX, false);
            EmitAnchor(Address);
            const auto AddrReg = EmitAddress(Mem);
            const auto AddrDisp = Mem.ViaSib ? 0 : static_cast<std::uint64_t>(Mem.Displacement);
            auto EmitLoad = [&](std::uint8_t Target) {
                Program.Instructions.push_back({vmprotect::LiftedOp::LoadMem, Target, AddrReg, AddrDisp, SynthAddress(), 0});
            };
            auto EmitStore = [&](std::uint8_t Source) {
                Program.Instructions.push_back({vmprotect::LiftedOp::StoreMem, AddrReg, Source, AddrDisp, SynthAddress(), 0});
            };
            switch (Opcode) {
            case 0x8b: EmitLoad(Dst); break;                 // mov r64, [m]
            case 0x89: EmitStore(Dst); break;                // mov [m], r64
            case 0x03: EmitLoad(KScratchValue);              // add r64, [m]
                Program.Instructions.push_back({vmprotect::LiftedOp::Add, Dst, KScratchValue, 0, SynthAddress(), 0}); break;
            case 0x01: EmitLoad(KScratchValue);              // add [m], r64
                Program.Instructions.push_back({vmprotect::LiftedOp::Add, KScratchValue, Dst, 0, SynthAddress(), 0});
                EmitStore(KScratchValue); break;
            case 0x2b: EmitLoad(KScratchValue);              // sub r64, [m]
                Program.Instructions.push_back({vmprotect::LiftedOp::Sub, Dst, KScratchValue, 0, SynthAddress(), 0}); break;
            case 0x29: EmitLoad(KScratchValue);              // sub [m], r64
                Program.Instructions.push_back({vmprotect::LiftedOp::Sub, KScratchValue, Dst, 0, SynthAddress(), 0});
                EmitStore(KScratchValue); break;
            case 0x23: EmitLoad(KScratchValue);              // and r64, [m]
                Program.Instructions.push_back({vmprotect::LiftedOp::And, Dst, KScratchValue, 0, SynthAddress(), 0}); break;
            case 0x21: EmitLoad(KScratchValue);              // and [m], r64
                Program.Instructions.push_back({vmprotect::LiftedOp::And, KScratchValue, Dst, 0, SynthAddress(), 0});
                EmitStore(KScratchValue); break;
            case 0x0b: EmitLoad(KScratchValue);              // or r64, [m]
                Program.Instructions.push_back({vmprotect::LiftedOp::Or, Dst, KScratchValue, 0, SynthAddress(), 0}); break;
            case 0x09: EmitLoad(KScratchValue);              // or [m], r64
                Program.Instructions.push_back({vmprotect::LiftedOp::Or, KScratchValue, Dst, 0, SynthAddress(), 0});
                EmitStore(KScratchValue); break;
            case 0x33: EmitLoad(KScratchValue);              // xor r64, [m]
                Program.Instructions.push_back({vmprotect::LiftedOp::Xor, Dst, KScratchValue, 0, SynthAddress(), 0}); break;
            case 0x31: EmitLoad(KScratchValue);              // xor [m], r64
                Program.Instructions.push_back({vmprotect::LiftedOp::Xor, KScratchValue, Dst, 0, SynthAddress(), 0});
                EmitStore(KScratchValue); break;
            case 0x3b: EmitLoad(KScratchValue);              // cmp r64, [m]
                Program.Instructions.push_back({vmprotect::LiftedOp::Cmp, Dst, KScratchValue, 0, SynthAddress(), 0}); break;
            case 0x39: EmitLoad(KScratchValue);              // cmp [m], r64
                Program.Instructions.push_back({vmprotect::LiftedOp::Cmp, KScratchValue, Dst, 0, SynthAddress(), 0}); break;
            case 0x85: EmitLoad(KScratchValue);              // test [m], r64
                Program.Instructions.push_back({vmprotect::LiftedOp::Test, KScratchValue, Dst, 0, SynthAddress(), 0}); break;
            }
            continue;
        }
        { std::ostringstream Error; Error << "x64 decoder: unsupported opcode 0x" << std::hex << unsigned(Opcode) << " at RVA 0x" << Address; throw std::runtime_error(Error.str()); }
    }
    if (!Terminated && !ResumeAtPendingTarget() && Program.Instructions.empty()) throw std::runtime_error("x64 decoder: no RET within byte limit");
    // A native RET returns to the caller: VM2 Ret with an empty call stack
    // behaves as Halt, so inner (inlined) returns keep VM2 call semantics.
    // Fall-through targets may land on padding NOPs that produced no IR; slide
    // them forward to the next real instruction boundary, in the branch
    // instructions themselves as well as in the validation set.
    std::set<std::uint32_t> Boundaries;
    for (const auto& Instr : Program.Instructions) Boundaries.insert(Instr.Address);
    const auto Slide = [&](std::uint32_t Target) -> std::uint32_t {
        while (SkippedAddresses.count(Target) != 0) {
            const auto It = Boundaries.upper_bound(Target);
            if (It == Boundaries.end()) throw std::runtime_error("x64 decoder: branch target is outside lifted function");
            Target = *It;
        }
        return Target;
    };
    for (auto& Instr : Program.Instructions) {
        if (IsBranch(Instr.Op)) Instr.Target = Slide(Instr.Target);
    }
    for (const auto OriginalTarget : Targets) {
        const auto Target = Slide(OriginalTarget);
        if (Boundaries.count(Target) == 0) {
            std::ostringstream Error;
            Error << "x64 decoder: branch target 0x" << std::hex << OriginalTarget
                  << " (resolved 0x" << Target << ") is outside lifted function";
            throw std::runtime_error(Error.str());
        }
    }
    std::size_t Blocks=1; for (const auto& I:Program.Instructions) if(IsBranch(I.Op)) ++Blocks;
    std::ostringstream Out; Out << "{\n  \"format\": \"pevm-x64-lift\",\n  \"functionRva\": \"0x" << std::hex << FunctionRva << "\",\n  \"basicBlocks\": " << std::dec << Blocks << ",\n  \"instructions\": [\n";
    for (std::size_t I=0; I<Program.Instructions.size(); ++I) { const auto& X=Program.Instructions[I]; Out << "    {\"rva\":\"0x" << std::hex << X.Address << "\",\"op\":\"" << OpName(X.Op) << "\",\"dst\":" << std::dec << unsigned(X.Dst) << ",\"src\":" << unsigned(X.Src) << ",\"imm\":\"0x" << std::hex << X.Immediate << "\",\"target\":\"0x" << X.Target << "\"}" << (I+1==Program.Instructions.size()?"\n":" ,\n"); }
    Out << "  ]\n}\n"; return {std::move(Program),Out.str(),Blocks};
}
void WriteManifest(const std::filesystem::path& Output, const LiftResult& Result) { std::ofstream File(Output,std::ios::binary|std::ios::trunc); if(!File) throw std::runtime_error("x64 decoder: cannot create manifest"); File << Result.Json; if(!File) throw std::runtime_error("x64 decoder: manifest write failed"); }
MultiLiftResult LiftPeFunctions(const std::filesystem::path& Input, const std::vector<std::uint32_t>& FunctionRvas) {
    const auto Data = util::ReadFile(Input);
    return LiftPeFunctions(pevm::pe::ImageView(Data), FunctionRvas);
}

MultiLiftResult LiftPeFunctions(const pevm::pe::ImageView& Image, const std::vector<std::uint32_t>& FunctionRvas) {
    Image.RequireX64();
    if (FunctionRvas.empty()) throw std::runtime_error("multi-lift requires at least one function RVA");
    MultiLiftResult Result;
    std::ostringstream Json;
    Json << "{\n  \"format\": \"pevm-x64-lift-manifest\",\n  \"functions\": [\n";
    for (std::size_t I = 0; I < FunctionRvas.size(); ++I) {
        auto Lifted = LiftPeFunction(Image, FunctionRvas[I]);
        Json << "    {\"rva\":\"0x" << std::hex << FunctionRvas[I] << "\",\"basicBlocks\":"
             << std::dec << Lifted.BasicBlockCount << ",\"instructions\":"
             << Lifted.Program.Instructions.size() << "}" << (I + 1 == FunctionRvas.size() ? "\n" : ",\n");
        Result.Functions.push_back(std::move(Lifted));
    }
    Json << "  ]\n}\n";
    Result.Json = Json.str();
    return Result;
}

MultiLiftAttempt LiftPeFunctionsTolerant(const std::filesystem::path& Input,
                                         const std::vector<std::uint32_t>& FunctionRvas) {
    const auto Data = util::ReadFile(Input);
    return LiftPeFunctionsTolerant(pevm::pe::ImageView(Data), FunctionRvas);
}

MultiLiftAttempt LiftPeFunctionsTolerant(const pevm::pe::ImageView& Image,
                                         const std::vector<std::uint32_t>& FunctionRvas) {
    Image.RequireX64();
    MultiLiftAttempt Attempt;
    std::ostringstream Json;
    Json << "{\n  \"format\": \"pevm-x64-lift-manifest\",\n  \"functions\": [\n";
    bool First = true;
    for (const auto Rva : FunctionRvas) {
        try {
            auto Lifted = LiftPeFunction(Image, Rva);
            if (!First) Json << ",\n";
            First = false;
            Json << "    {\"rva\":\"0x" << std::hex << Rva << "\",\"basicBlocks\":"
                 << std::dec << Lifted.BasicBlockCount << ",\"instructions\":"
                 << Lifted.Program.Instructions.size() << "}";
            Attempt.Lifted.Functions.push_back(std::move(Lifted));
        } catch (const std::exception& Error) {
            Attempt.Failures.push_back({Rva, Error.what()});
        }
    }
    Json << "\n  ]\n}\n";
    Attempt.Lifted.Json = Json.str();
    return Attempt;
}

// Enumerates function entries from the exception directory (.pdata) and
// annotates exported ones with their names. PE32+ only, matching the lifter.
std::vector<FunctionCandidate> ScanFunctions(const std::filesystem::path& Input,
                                             std::size_t MinimumBytes) {
    const auto Data = util::ReadFile(Input);
    return ScanFunctions(pevm::pe::ImageView(Data), MinimumBytes);
}

std::vector<FunctionCandidate> ScanFunctions(const pevm::pe::ImageView& Image,
                                             std::size_t MinimumBytes) {
    Image.RequireX64();
    std::map<std::uint32_t, FunctionCandidate> Candidates;
    const auto Exceptions = Image.DirectoryBytes(IMAGE_DIRECTORY_ENTRY_EXCEPTION);
    if (Exceptions.size() % 12) throw std::runtime_error("PE exception table has a partial record");
    for (std::size_t At = 0; At < Exceptions.size(); At += 12) {
        const auto Begin = Read<std::uint32_t>(Exceptions, At);
        const auto End = Read<std::uint32_t>(Exceptions, At + 4);
        const auto* Section = Image.SectionAt(Begin);
        if (End <= Begin || !Section || !Section->Executable() || Image.SectionAt(End - 1) != Section)
            throw std::runtime_error("PE exception function range invalid");
        Image.FileBytesAtRva(Begin, End - Begin);
        if (End - Begin >= MinimumBytes) Candidates[Begin] = {Begin, End - Begin, {}};
    }

    const auto Exports = Image.DirectoryBytes(IMAGE_DIRECTORY_ENTRY_EXPORT);
    if (!Exports.empty()) {
        if (Exports.size() < sizeof(IMAGE_EXPORT_DIRECTORY)) throw std::runtime_error("PE export directory truncated");
        const auto NumberOfFunctions = Read<std::uint32_t>(Exports, 20);
        const auto NumberOfNames = Read<std::uint32_t>(Exports, 24);
        const auto FunctionsRva = Read<std::uint32_t>(Exports, 28);
        const auto NamesRva = Read<std::uint32_t>(Exports, 32);
        const auto OrdinalsRva = Read<std::uint32_t>(Exports, 36);
        if (NumberOfNames && !NumberOfFunctions) throw std::runtime_error("PE export names without functions");
        const auto Functions = NumberOfFunctions ? Image.FileBytesAtRva(FunctionsRva, std::size_t{NumberOfFunctions} * 4) : std::span<const std::uint8_t>{};
        const auto Names = NumberOfNames ? Image.FileBytesAtRva(NamesRva, std::size_t{NumberOfNames} * 4) : std::span<const std::uint8_t>{};
        const auto Ordinals = NumberOfNames ? Image.FileBytesAtRva(OrdinalsRva, std::size_t{NumberOfNames} * 2) : std::span<const std::uint8_t>{};
        const auto ExportDirectory = Image.Directory(IMAGE_DIRECTORY_ENTRY_EXPORT);
        for (std::size_t I = 0; I < NumberOfNames; ++I) {
            const auto Ordinal = Read<std::uint16_t>(Ordinals, I * 2);
            if (Ordinal >= NumberOfFunctions) throw std::runtime_error("PE export ordinal outside function table");
            const auto Name = Image.StringAtRva(Read<std::uint32_t>(Names, I * 4));
            const auto Rva = Read<std::uint32_t>(Functions, std::size_t{Ordinal} * 4);
            if (Rva == 0) continue;
            if (Rva >= ExportDirectory.Address && Rva - ExportDirectory.Address < ExportDirectory.Size) continue;
            const auto* Section = Image.SectionAt(Rva);
            // Data exports and forwarders are not executable candidates.
            if (!Section || !Section->Executable()) continue;
            Image.FileBytesAtRva(Rva, 1);
            auto Match = Candidates.find(Rva);
            if (Match != Candidates.end()) Match->second.Name = Name;
            else Candidates[Rva] = {Rva, 0U, Name};
        }
    }
    std::vector<FunctionCandidate> Result;
    Result.reserve(Candidates.size());
    for (auto& [Rva, Candidate] : Candidates) Result.push_back(std::move(Candidate));
    return Result;
}
std::vector<std::uint8_t> SerializeVmp3(const LiftResult& Result, std::uint64_t Seed,
                                        std::string_view BuildSecret,
                                        std::span<const std::uint8_t> HandlerProfile,
                                        bool AntiDisassembly) {
    MultiLiftResult Single;
    Single.Functions.push_back(Result);
    return SerializeVmp3Multi(Single, Seed, BuildSecret, HandlerProfile, AntiDisassembly);
}

std::vector<std::uint8_t> SerializeVmp3Multi(const MultiLiftResult& Results, std::uint64_t Seed,
                                             std::string_view BuildSecret,
                                             std::span<const std::uint8_t> HandlerProfile,
                                             bool AntiDisassembly,
                                             std::vector<vmprotect::CompilationStats>* Statistics) {
    std::vector<vmprotect::LiftedProgram> Programs;
    Programs.reserve(Results.Functions.size());
    for (const auto& Function : Results.Functions) Programs.push_back(Function.Program);
    return pevm::EncodeVmImage(Programs, Seed, BuildSecret, HandlerProfile, AntiDisassembly, Statistics);
}

void MutateProgram(vmprotect::LiftedProgram& Program, std::uint64_t Seed) {
    using O = vmprotect::LiftedOp;
    auto State = Seed ^ 0x9E3779B97F4A7C15ULL;
    auto Next = [&]() {
        State ^= State >> 12;
        State ^= State << 25;
        State ^= State >> 27;
        return State * 0x2545F4914F6CDD1DULL;
    };

    // A rewrite may change flags only when the immediate successor overwrites
    // all of them without reading any. ADC/SBB consume CF; shifts can have a
    // zero count; rotates preserve ZF/SF/PF; CALL/RET propagate flags.
    const auto OverwritesFlagsWithoutReading = [](O Op) {
        switch (Op) {
        case O::Add: case O::AddI: case O::Sub: case O::SubI:
        case O::Xor: case O::And: case O::AndI: case O::Or: case O::Neg: case O::Test:
        case O::Cmp:
            return true;
        default:
            return false;
        }
    };
    const auto IsPowerOfTwo = [](std::uint64_t Value) { return Value != 0 && (Value & (Value - 1)) == 0; };

    std::vector<vmprotect::LiftedInstruction> Out;
    Out.reserve(Program.Instructions.size() * 2);
    std::uint32_t JunkAddress = 0xE0000000U;
    constexpr std::uint8_t JunkScratchA = 19;
    constexpr std::uint8_t JunkScratchB = 20;

    for (std::size_t I = 0; I < Program.Instructions.size(); ++I) {
        auto Instruction = Program.Instructions[I];
        const auto NextOp = I + 1 < Program.Instructions.size()
                                ? Program.Instructions[I + 1].Op
                                : O::Halt;

        const bool FlagsDead = OverwritesFlagsWithoutReading(NextOp);
        // ADD/SUB with a negated immediate produce the same value, but may
        // differ in flags; rewrite only when those flags cannot be observed.
        if ((Instruction.Op == O::AddI || Instruction.Op == O::SubI) &&
            Instruction.Immediate != 0 && FlagsDead && (Next() & 1U) != 0) {
            Instruction.Op = Instruction.Op == O::AddI ? O::SubI : O::AddI;
            Instruction.Immediate = ~Instruction.Immediate + 1ULL;
        }
        // VM MULI preserves flags; SHLI updates them for nonzero counts.
        if (Instruction.Op == O::MulI && IsPowerOfTwo(Instruction.Immediate) &&
            FlagsDead && (Next() & 1U) != 0) {
            unsigned Shift = 0;
            for (auto Value = Instruction.Immediate; Value > 1; ++Shift) Value >>= 1;
            Instruction.Op = O::ShlI;
            Instruction.Immediate = Shift;
        }
        Out.push_back(Instruction);

        // Junk instruction(s) between real ones: scratch registers no lifted
        // program reads, unique synthetic addresses no branch targets.
        if ((Next() & 1U) != 0) {
            Out.push_back({O::MovI, (Next() & 1U) != 0 ? JunkScratchA : JunkScratchB, 0,
                           Next(), JunkAddress++, 0});
            if ((Next() & 7U) == 0) {
                Out.push_back({O::MovI, JunkScratchB, 0, Next(), JunkAddress++, 0});
            }
        }
    }
    Program.Instructions = std::move(Out);
}
} // namespace x64lift
