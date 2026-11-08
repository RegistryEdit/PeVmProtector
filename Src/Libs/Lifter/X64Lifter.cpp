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
#include "VmSimd.h"

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
    case O::ZeroExtend:return "MOVZX"; case O::SignExtend:return "MOVSX";
    case O::Inc:return "INC"; case O::Dec:return "DEC"; case O::ImageAddress:return "IMAGEADDR";
    case O::NativeCall:return "NATIVECALL";
    case O::Simd:return "SIMD";
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
    bool RipRelative{};
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
    // Decode an effective address without reading memory. RIP is resolved
    // after trailing immediates have been consumed by the instruction decoder.
    MemOperand MemFromModRm(std::uint8_t ModRm, bool RexB, bool RexX, bool AllowStackBase,
                            bool AllowAbsolute = false) {
        const auto Mode = static_cast<std::uint8_t>(ModRm >> 6);
        const auto RawRm = static_cast<std::uint8_t>(ModRm & 7U);
        if (Mode == 0 && RawRm == 5U) {
            MemOperand M{};
            M.RipRelative = true;
            M.Displacement = static_cast<std::int32_t>(NeedImm(4));
            return M;
        }
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
        M.HasIndex = RawIndex != 4U || RexX;
        if (M.HasIndex) M.Index = static_cast<std::uint8_t>(RawIndex | (RexX ? 8U : 0U));
        if (RawBase == 5U && Mode == 0) {
            if (!AllowAbsolute) throw std::runtime_error("x64 decoder: absolute disp32 addressing is not liftable");
            M.Displacement = static_cast<std::int32_t>(NeedImm(4));  // base-less [index*scale + disp32]
        } else {
            {
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


} // namespace

static LiftResult LiftCode(std::span<const std::uint8_t> Code, std::uint32_t FunctionRva,
                           std::size_t MaximumBytes, bool NativeTargets = false,
                           std::size_t FragmentPrologue = SIZE_MAX);

LiftResult LiftPeFunction(const std::filesystem::path& Input, std::uint32_t FunctionRva, std::size_t MaximumBytes) {
    const auto Data = util::ReadFile(Input);
    return LiftPeFunction(pevm::pe::ImageView(Data), FunctionRva, MaximumBytes);
}

LiftResult LiftPeFunction(const pevm::pe::ImageView& Image, std::uint32_t FunctionRva, std::size_t MaximumBytes) {
    Image.RequireX64();
    // .pdata also describes fragments that share an earlier function's stack
    // frame. A chained epilogue is not an independently callable VM entry.
    const auto Exceptions = Image.DirectoryBytes(IMAGE_DIRECTORY_ENTRY_EXCEPTION);
    if (Exceptions.size() % sizeof(RUNTIME_FUNCTION))
        throw std::runtime_error("x64 decoder: partial exception record");
    std::size_t First = 0, Last = Exceptions.size() / sizeof(RUNTIME_FUNCTION);
    std::size_t FragmentPrologue=SIZE_MAX;
    while (First < Last) {
        const auto Middle = First + (Last - First) / 2;
        const auto At = Middle * sizeof(RUNTIME_FUNCTION);
        const auto Begin = Read<std::uint32_t>(Exceptions, At);
        const auto End = Read<std::uint32_t>(Exceptions, At + 4);
        if (FunctionRva < Begin) { Last = Middle; continue; }
        if (FunctionRva >= End) { First = Middle + 1; continue; }
        const auto UnwindRva = Read<std::uint32_t>(Exceptions, At + 8);
        const auto Unwind = Image.FileBytesAtRva(UnwindRva, 4);
        if ((Unwind[0] >> 3) & UNW_FLAG_CHAININFO)
            throw std::runtime_error("x64 decoder: chained unwind fragment requires its parent stack frame");
        if ((Unwind[0] >> 3) & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER)) {
            if(FunctionRva!=Begin) throw std::runtime_error("x64 decoder: EH fragment must begin at its unwind entry");
            FragmentPrologue=Unwind[1];
        }
        MaximumBytes = (std::min)(MaximumBytes, static_cast<std::size_t>(End - FunctionRva));
        break;
    }
    const auto Code = Image.CodeAtRva(FunctionRva, MaximumBytes);
    auto Result = LiftCode(Code, FunctionRva, Code.size(), true, FragmentPrologue);
    for (const auto& I : Result.Program.Instructions) {
        if (I.Op == vmprotect::LiftedOp::ImageAddress && I.Immediate >= Image.SizeOfImage())
            throw std::runtime_error("x64 decoder: image-relative address is outside image");
    }
    return Result;
}

LiftResult LiftRawCode(const std::vector<std::uint8_t>& Code, std::uint32_t FunctionRva,
                       std::size_t MaximumBytes) {
    return LiftCode(Code, FunctionRva, MaximumBytes);
}

static LiftResult LiftCode(std::span<const std::uint8_t> Code, std::uint32_t FunctionRva,
                           std::size_t MaximumBytes, bool NativeTargets, std::size_t FragmentPrologue) {
    using O = vmprotect::LiftedOp;
    using Ins = vmprotect::LiftedInstruction;
    constexpr std::uint8_t Addr = 16, Scale = 17, Value = 18, Temp = 21;
    constexpr std::uint8_t Quiet = 64 | vmprotect::KPreserveFlags;
    const auto Limit = (std::min)(Code.size(), MaximumBytes);
    if (!Limit || std::uint64_t{FunctionRva} + Limit >= 0x80000000ULL)
        throw std::runtime_error("x64 decoder: invalid code range");
    struct Record { std::vector<Ins> Ir; std::size_t End{}; bool Fallthrough = true; };
    std::map<std::size_t, Record> Records;
    std::set<std::size_t> Pending{0}, Occupied;
    std::uint32_t Synthetic = 0xC0000000;
    auto Label = [&] { return Synthetic++; };
    auto Queue = [&](std::int64_t Offset) {
        if (Offset < 0 || static_cast<std::uint64_t>(Offset) >= Limit)
            throw std::runtime_error("x64 decoder: branch target is outside lifted function");
        Pending.insert(static_cast<std::size_t>(Offset));
    };
    while (!Pending.empty()) {
        const auto Start = *Pending.begin(); Pending.erase(Pending.begin());
        if (Records.contains(Start)) continue;
        if (Occupied.contains(Start)) throw std::runtime_error("x64 decoder: overlapping instruction boundary");
        DecodeContext C{Code, Start, Limit, FunctionRva, 0};
        Record Rec;
        Rec.Ir.push_back({O::Nop, 0, 0, 0, FunctionRva + static_cast<std::uint32_t>(Start)});
        auto Emit = [&](O Op, std::uint8_t D = 0, std::uint8_t S = 0, std::uint64_t Imm = 0,
                        std::uint8_t W = 64, std::uint32_t Target = 0) {
            Rec.Ir.push_back({Op, D, S, Imm, Label(), Target, W});
        };
        std::uint8_t Rex = 0;
        bool Operand16 = false, Locked = false;
        std::uint8_t Rep = 0;
        for (;;) {
            if (C.At >= Limit) throw std::runtime_error("x64 decoder: truncated prefix");
            const auto P = Code[C.At];
            if (P >= 0x40 && P <= 0x4f) Rex = P;
            else if (P == 0x66) { Operand16 = true; Rex = 0; }
            else if (P == 0xf3 || P == 0xf2) { Rep = P; Rex = 0; }
            else if (P == 0xf0) { Locked = true; Rex = 0; }
            else break;
            if (++C.At - Start >= 15) throw std::runtime_error("x64 decoder: instruction too long");
        }
        const bool W = Rex & 8, R = Rex & 4, X = Rex & 2, B = Rex & 1;
        const std::uint8_t Bits = W ? 64 : Operand16 ? 16 : 32;
        auto ByteReg = [&](std::uint8_t Reg, unsigned Size) {
            if (Size == 8 && Rex == 0 && Reg >= 4 && Reg <= 7)
                throw std::runtime_error("x64 decoder: legacy high-byte register is not liftable");
            return Reg;
        };
        struct Operand { bool Memory{}; std::uint8_t Reg{}; MemOperand Mem{}; };
        auto Rm = [&](std::uint8_t M, unsigned Size) {
            Operand Result;
            Result.Memory = (M >> 6) != 3;
            if (Result.Memory) Result.Mem = C.MemFromModRm(M, B, X, true, true);
            else Result.Reg = ByteReg(RmFromModRm(M, B), Size);
            return Result;
        };
        auto EffectiveAddress = [&](const MemOperand& M) {
            if (M.RipRelative) Emit(O::ImageAddress, Addr, 0, FunctionRva + C.At + M.Displacement);
            else {
                if (M.HasBase) Emit(O::Mov, Addr, M.Base);
                else Emit(O::MovI, Addr, 0, 0);
                if (M.HasIndex) {
                    Emit(O::Mov, Scale, M.Index);
                    if (M.ScaleShift) Emit(O::ShlI, Scale, 0, M.ScaleShift, Quiet);
                    Emit(O::Add, Addr, Scale, 0, Quiet);
                }
                if (M.Displacement) Emit(O::AddI, Addr, 0, static_cast<std::uint64_t>(M.Displacement), Quiet);
            }
        };
        auto Load = [&](const Operand& P, std::uint8_t Size, std::uint8_t Scratch = 18) {
            if (!P.Memory) return P.Reg;
            EffectiveAddress(P.Mem);
            Emit(O::LoadMem, Scratch, Addr, 0, Size);
            return Scratch;
        };
        auto Store = [&](const Operand& P, std::uint8_t Source, std::uint8_t Size) {
            if (P.Memory) Emit(O::StoreMem, Addr, Source, 0, Size);
            else Emit(O::Mov, P.Reg, Source, 0, Size);
        };
        auto Immediate = [&](std::uint8_t Size, bool Short = false) {
            if (Short) return static_cast<std::uint64_t>(static_cast<std::int64_t>(static_cast<std::int8_t>(C.NeedImm(1))));
            const auto Raw = C.NeedImm(Size == 8 ? 1 : Size == 16 ? 2 : 4);
            return Size == 64 ? static_cast<std::uint64_t>(static_cast<std::int64_t>(static_cast<std::int32_t>(Raw))) : Raw;
        };
        const auto Opcode = static_cast<std::uint8_t>(C.NeedImm(1));
        auto Branch = [&](O Kind, std::int64_t Disp) {
            const auto Target = static_cast<std::int64_t>(C.At) + Disp;
            if (NativeTargets && (Target < 0 || static_cast<std::uint64_t>(Target) >= Limit) &&
                (Kind == O::Call || Kind == O::Jmp)) {
                Emit(O::ImageAddress, Temp, 0, FunctionRva + Target);
                Emit(O::NativeCall, Temp, 0, Kind == O::Jmp ? 1 : 0);
                if (Kind == O::Jmp) { Emit(O::Ret); Rec.Fallthrough = false; }
                return;
            }
            Queue(Target);
            Emit(Kind, 0, 0, 0, 64, FunctionRva + static_cast<std::uint32_t>(Target));
            if (Kind == O::Jmp) Rec.Fallthrough = false;
        };
        static constexpr O Alu[] = {O::Add, O::Or, O::Adc, O::Sbb, O::And, O::Sub, O::Xor, O::Cmp};
        auto Decode = [&] {
            if (Locked) throw std::runtime_error("x64 decoder: LOCK atomic memory operation is not liftable");
            if (Rep && Opcode!=0x0f) throw std::runtime_error("x64 decoder: REP-prefixed instruction is not liftable");
            if (Opcode == 0x90 && !B) return;
            if (Opcode == 0xc3) { Emit(O::Ret); Rec.Fallthrough = false; return; }
            if (Opcode == 0xe8 || Opcode == 0xe9 || Opcode == 0xeb) {
                const auto Disp = Opcode == 0xeb ? static_cast<std::int64_t>(static_cast<std::int8_t>(C.NeedImm(1)))
                                                : static_cast<std::int64_t>(static_cast<std::int32_t>(C.NeedImm(4)));
                Branch(Opcode == 0xe8 ? O::Call : O::Jmp, Disp); return;
            }
            if (Opcode >= 0x70 && Opcode <= 0x7f) {
                const auto Disp = static_cast<std::int8_t>(C.NeedImm(1));
                Branch(JccFromLowNibble(Opcode & 15), Disp); return;
            }
            if (Opcode >= 0x50 && Opcode <= 0x5f) {
                if (Operand16) throw std::runtime_error("x64 decoder: 16-bit stack operation is not liftable");
                Emit(Opcode < 0x58 ? O::Push : O::Pop, (Opcode & 7) | (B ? 8 : 0)); return;
            }
            if (Opcode == 0x68 || Opcode == 0x6a) {
                if (Operand16) throw std::runtime_error("x64 decoder: 16-bit stack operation is not liftable");
                Emit(O::MovI, Temp, 0, Immediate(64, Opcode == 0x6a)); Emit(O::Push, Temp); return;
            }
            if (Opcode >= 0xb0 && Opcode <= 0xbf) {
                const auto Size = static_cast<std::uint8_t>(Opcode < 0xb8 ? 8 : Bits);
                const auto D = ByteReg((Opcode & 7) | (B ? 8 : 0), Size);
                Emit(O::MovI, D, 0, C.NeedImm(Size / 8), Size); return;
            }
            if (Opcode == 0x8d) {
                const auto M = C.NeedModRm();
                if ((M >> 6) == 3) throw std::runtime_error("x64 decoder: invalid LEA register form");
                const auto Mem = C.MemFromModRm(M, B, X, true, true);
                EffectiveAddress(Mem); Emit(O::Mov, RegFromModRm(M, R), Addr, 0, Bits); return;
            }
            if (Opcode == 0x63) {
                if (!W) throw std::runtime_error("x64 decoder: MOVSXD without REX.W is not liftable");
                const auto M = C.NeedModRm(); const auto P = Rm(M, 32);
                const auto S = Load(P, 32);
                Emit(O::SignExtend, RegFromModRm(M, R), S, 32, Bits); return;
            }
            if (Opcode == 0x0f) {
                const auto Next = C.NeedImm(1);
                if (Rep==0xf3 && Next==0x1e && C.NeedImm(1)==0xfa) return;
                using V=vmprotect::SimdOp;
                using F=vmprotect::SimdForm;
                const unsigned Prefix=Rep==0xf3?2:Rep==0xf2?3:Operand16?1:0;
                V Vector=V::Count;
                bool StoreVector=false, Aligned=false, Shuffle=false;
                bool FromInteger=false, ToInteger=false;
                if (Next==0x10 || Next==0x11) {
                    Vector=Prefix==2?V::MovSS:Prefix==3?V::MovSD:V::Mov128; StoreVector=Next==0x11;
                } else if ((Next==0x28 || Next==0x29) && Prefix<2) {
                    Vector=V::Mov128; StoreVector=Next==0x29; Aligned=true;
                } else if ((Next==0x6f || Next==0x7f) && (Prefix==1 || Prefix==2)) {
                    Vector=V::Mov128; StoreVector=Next==0x7f; Aligned=Prefix==1;
                } else if (Next==0x6e && Prefix==1) { Vector=V::FromGpr; FromInteger=true; }
                else if (Next==0x7e && Prefix==1) { Vector=V::ToGpr; StoreVector=true; ToInteger=true; }
                else if (Next==0x7e && Prefix==2) Vector=V::MovQ;
                else if (Next==0xd6 && Prefix==1) { Vector=V::MovQ; StoreVector=true; }
                else if (Next>=0x54 && Next<=0x57 && Prefix<2) {
                    static constexpr V Logic[]={V::And,V::AndNot,V::Or,V::Xor}; Vector=Logic[Next-0x54];
                } else if (Next==0x58 || Next==0x59 || (Next>=0x5c && Next<=0x5f) || Next==0x51) {
                    const V Base=Next==0x58?V::AddPS:Next==0x59?V::MulPS:Next==0x5c?V::SubPS:
                        Next==0x5d?V::MinPS:Next==0x5e?V::DivPS:Next==0x5f?V::MaxPS:V::SqrtPS;
                    Vector=static_cast<V>(unsigned(Base)+Prefix);
                } else if (Next==0x5a && Prefix>=2) Vector=Prefix==2?V::CvtSS2SD:V::CvtSD2SS;
                else if (Next==0x5b && Prefix<3) Vector=Prefix==0?V::CvtDQ2PS:Prefix==1?V::CvtPS2DQ:V::CvttPS2DQ;
                else if (Next==0x2a && Prefix>=2) { Vector=Prefix==2?V::CvtSI2SS:V::CvtSI2SD; FromInteger=true; }
                else if ((Next==0x2c || Next==0x2d) && Prefix>=2) {
                    Vector=Next==0x2c?(Prefix==2?V::CvttSS2SI:V::CvttSD2SI):(Prefix==2?V::CvtSS2SI:V::CvtSD2SI);
                    ToInteger=true;
                } else if ((Next==0x2e || Next==0x2f) && Prefix<2)
                    Vector=Next==0x2e?(Prefix==0?V::Ucomiss:V::Ucomisd):(Prefix==0?V::Comiss:V::Comisd);
                else if (Next==0xc6 && Prefix<2) { Vector=Prefix?V::ShufflePD:V::ShufflePS; Shuffle=true; }
                else if (Next==0x70 && Prefix==1) { Vector=V::ShuffleD; Shuffle=true; }
                else if (Prefix==1) {
                    switch(Next) {
                    case 0xef: Vector=V::Xor; break; case 0xdb: Vector=V::And; break;
                    case 0xdf: Vector=V::AndNot; break; case 0xeb: Vector=V::Or; break;
                    case 0xfc: Vector=V::AddB; break; case 0xfd: Vector=V::AddW; break;
                    case 0xfe: Vector=V::AddD; break; case 0xd4: Vector=V::AddQ; break;
                    case 0xf8: Vector=V::SubB; break; case 0xf9: Vector=V::SubW; break;
                    case 0xfa: Vector=V::SubD; break; case 0xfb: Vector=V::SubQ; break;
                    case 0x74: Vector=V::EqB; break; case 0x75: Vector=V::EqW; break; case 0x76: Vector=V::EqD; break;
                    case 0x64: Vector=V::GtB; break; case 0x65: Vector=V::GtW; break; case 0x66: Vector=V::GtD; break;
                    case 0xd5: Vector=V::MulW; break;
                    case 0x60: Vector=V::UnpackLoB; break; case 0x61: Vector=V::UnpackLoW; break;
                    case 0x62: Vector=V::UnpackLoD; break; case 0x6c: Vector=V::UnpackLoQ; break;
                    case 0x68: Vector=V::UnpackHiB; break; case 0x69: Vector=V::UnpackHiW; break;
                    case 0x6a: Vector=V::UnpackHiD; break; case 0x6d: Vector=V::UnpackHiQ; break;
                    default: break;
                    }
                }
                if (Vector!=V::Count) {
                    const auto M=C.NeedModRm(); const auto P=Rm(M,64);
                    const auto G=RegFromModRm(M,R);
                    const unsigned Control=Shuffle?static_cast<unsigned>(C.NeedImm(1)):0;
                    if (P.Memory) EffectiveAddress(P.Mem);
                    const auto Size=static_cast<std::uint8_t>(FromInteger || ToInteger?(W?64:32):64);
                    if (StoreVector) {
                        if (P.Memory) Emit(O::Simd,0,Addr,vmprotect::EncodeSimd(Vector,F::MemoryDestination,G,0,Control,Aligned),Size);
                        else if (ToInteger) Emit(O::Simd,P.Reg,0,vmprotect::EncodeSimd(Vector,F::Gpr,0,G),Size);
                        else Emit(O::Simd,0,0,vmprotect::EncodeSimd(Vector,F::Registers,P.Reg,G,Control),Size);
                    } else {
                        const auto Form=P.Memory?F::MemorySource:FromInteger || ToInteger?F::Gpr:F::Registers;
                        const auto XmmDest=ToInteger?0:G;
                        const auto XmmSource=P.Memory?0:P.Reg;
                        Emit(O::Simd,ToInteger?G:0,P.Memory?Addr:FromInteger?P.Reg:0,
                            vmprotect::EncodeSimd(Vector,Form,XmmDest,XmmSource,Control,Aligned),Size);
                    }
                    return;
                }
                if (Rep) throw std::runtime_error("x64 decoder: unsupported SIMD prefix/opcode");
                if (Next == 0x1f) {
                    const auto M = C.NeedModRm();
                    if ((M >> 6) != 3) (void)C.MemFromModRm(M, B, X, true, true);
                    return;
                }
                if (Next >= 0x80 && Next <= 0x8f) {
                    const auto Disp = static_cast<std::int32_t>(C.NeedImm(4));
                    Branch(JccFromLowNibble(static_cast<std::uint8_t>(Next & 15)), Disp); return;
                }
                if (Next >= 0xc8 && Next <= 0xcf) {
                    if (Bits == 16) throw std::runtime_error("x64 decoder: undefined 16-bit BSWAP");
                    Emit(O::Bswap, (Next & 7) | (B ? 8 : 0), 0, 0, Bits); return;
                }
                if (Next == 0xb6 || Next == 0xb7 || Next == 0xbe || Next == 0xbf) {
                    const auto Size = static_cast<std::uint8_t>((Next & 1) ? 16 : 8);
                    const auto M = C.NeedModRm(); const auto P = Rm(M, Size);
                    const auto S = Load(P, Size);
                    Emit(Next >= 0xbe ? O::SignExtend : O::ZeroExtend, RegFromModRm(M, R), S, Size, Bits); return;
                }
                if (Next == 0xaf) {
                    const auto M = C.NeedModRm(); const auto P = Rm(M, Bits);
                    const auto S = Load(P, Bits);
                    Emit(O::Mul, RegFromModRm(M, R), S, 0, Bits); return;
                }
                if (Next >= 0x40 && Next <= 0x4f) {
                    const auto M = C.NeedModRm(); const auto P = Rm(M, Bits);
                    const auto S = Load(P, Bits), D = RegFromModRm(M, R);
                    // Even a false CMOV r32 clears the destination's upper half.
                    if (Bits == 32) Emit(O::Mov, D, D, 0, Bits);
                    const auto Skip = Label();
                    Emit(InvertJcc(JccFromLowNibble(static_cast<std::uint8_t>(Next & 15))), 0, 0, 0, 64, Skip);
                    Emit(O::Mov, D, S, 0, Bits);
                    Rec.Ir.push_back({O::Nop, 0, 0, 0, Skip}); return;
                }
                if (Next >= 0x90 && Next <= 0x9f) {
                    const auto M = C.NeedModRm(); const auto P = Rm(M, 8);
                    if (P.Memory) EffectiveAddress(P.Mem);
                    const auto D = P.Memory ? Value : P.Reg;
                    const auto Skip = Label();
                    Emit(O::MovI, D, 0, 1, 8);
                    Emit(JccFromLowNibble(static_cast<std::uint8_t>(Next & 15)), 0, 0, 0, 64, Skip);
                    Emit(O::MovI, D, 0, 0, 8);
                    Rec.Ir.push_back({O::Nop, 0, 0, 0, Skip});
                    if (P.Memory) Store(P, D, 8);
                    return;
                }
                throw std::runtime_error("x64 decoder: unsupported 0F opcode");
            }
            if (Opcode == 0xc6 || Opcode == 0xc7) {
                const auto Size = static_cast<std::uint8_t>(Opcode == 0xc6 ? 8 : Bits);
                const auto M = C.NeedModRm();
                if ((M & 0x38) != 0) throw std::runtime_error("x64 decoder: unsupported MOV group");
                const auto P = Rm(M, Size); const auto Imm = Immediate(Size);
                if (P.Memory) { EffectiveAddress(P.Mem); Emit(O::MovI, Value, 0, Imm, Size); Store(P, Value, Size); }
                else Emit(O::MovI, P.Reg, 0, Imm, Size);
                return;
            }
            if ((Opcode <= 0x3b && (Opcode & 7) <= 3) || Opcode == 0x84 || Opcode == 0x85 ||
                (Opcode >= 0x88 && Opcode <= 0x8b)) {
                const auto Size = static_cast<std::uint8_t>((Opcode & 1) ? Bits : 8);
                const auto M = C.NeedModRm(); const auto P = Rm(M, Size);
                const auto G = ByteReg(RegFromModRm(M, R), Size);
                const bool Move = Opcode >= 0x88;
                const auto Kind = Move ? O::Mov : Opcode >= 0x84 ? O::Test : Alu[Opcode >> 3];
                const bool ToReg = (Opcode & 2) != 0 && Opcode != 0x84 && Opcode != 0x85;
                if (Move && P.Memory && !ToReg) { EffectiveAddress(P.Mem); Store(P, G, Size); return; }
                const auto S = Load(P, Size);
                const auto D = ToReg ? G : S;
                Emit(Kind, D, ToReg ? S : G, 0, Size);
                if (P.Memory && !ToReg && Kind != O::Cmp && Kind != O::Test) Store(P, D, Size);
                return;
            }
            if ((Opcode <= 0x3d && ((Opcode & 7) == 4 || (Opcode & 7) == 5)) || Opcode == 0xa8 || Opcode == 0xa9) {
                const auto Size = static_cast<std::uint8_t>((Opcode & 1) ? Bits : 8);
                const auto Imm = Immediate(Size);
                Emit(O::MovI, Temp, 0, Imm, Size);
                Emit(Opcode >= 0xa8 ? O::Test : Alu[Opcode >> 3], 0, Temp, 0, Size); return;
            }
            if (Opcode == 0x80 || Opcode == 0x81 || Opcode == 0x83) {
                const auto Size = static_cast<std::uint8_t>(Opcode == 0x80 ? 8 : Bits);
                const auto M = C.NeedModRm(); const auto P = Rm(M, Size);
                const auto Imm = Immediate(Size, Opcode == 0x83);
                const auto D = Load(P, Size); const auto Kind = Alu[(M >> 3) & 7];
                Emit(O::MovI, Temp, 0, Imm, Size); Emit(Kind, D, Temp, 0, Size);
                if (P.Memory && Kind != O::Cmp) Store(P, D, Size);
                return;
            }
            if (Opcode == 0xf6 || Opcode == 0xf7 || Opcode == 0xfe || Opcode == 0xff) {
                const auto Size = static_cast<std::uint8_t>((Opcode & 1) ? Bits : 8);
                const auto M = C.NeedModRm(); const auto Group = (M >> 3) & 7;
                const auto P = Rm(M, Size);
                O Kind;
                if (Opcode >= 0xfe) {
                    if (NativeTargets && Opcode == 0xff && (Group == 2 || Group == 4)) {
                        const auto Destination = Load(P, 64);
                        Emit(O::NativeCall, Destination, 0, Group == 4 ? 1 : 0);
                        if (Group == 4) { Emit(O::Ret); Rec.Fallthrough = false; }
                        return;
                    }
                    if (Group > 1) throw std::runtime_error("x64 decoder: indirect call/jump or FF group is not liftable");
                    Kind = Group ? O::Dec : O::Inc;
                } else {
                    if (Group != 0 && Group != 2 && Group != 3) throw std::runtime_error("x64 decoder: unsupported F6/F7 group");
                    Kind = Group == 0 ? O::Test : Group == 2 ? O::Not : O::Neg;
                }
                const auto Imm = Kind == O::Test ? Immediate(Size) : 0;
                const auto D = Load(P, Size);
                if (Kind == O::Test) Emit(O::MovI, Temp, 0, Imm, Size);
                Emit(Kind, D, Temp, 0, Size);
                if (P.Memory && Kind != O::Test) Store(P, D, Size);
                return;
            }
            if (Opcode == 0x69 || Opcode == 0x6b) {
                const auto M = C.NeedModRm(); const auto P = Rm(M, Bits);
                const auto Imm = Immediate(Bits, Opcode == 0x6b);
                const auto S = Load(P, Bits), D = RegFromModRm(M, R);
                Emit(O::Mov, D, S, 0, Bits); Emit(O::MulI, D, 0, Imm, Bits); return;
            }
            if (Opcode == 0xc0 || Opcode == 0xc1 || (Opcode >= 0xd0 && Opcode <= 0xd3)) {
                const auto Size = static_cast<std::uint8_t>((Opcode & 1) ? Bits : 8);
                const auto M = C.NeedModRm(); const auto P = Rm(M, Size); const auto Group = (M >> 3) & 7;
                if (Group == 2 || Group == 3 || Group == 6) throw std::runtime_error("x64 decoder: unsupported shift group");
                const auto Count = Opcode <= 0xc1 ? C.NeedImm(1) : 1;
                const bool Variable = Opcode >= 0xd2;
                const auto D = Load(P, Size);
                static constexpr O Fixed[] = {O::RolI,O::RorI,O::Nop,O::Nop,O::ShlI,O::ShrI,O::Nop,O::SarI};
                static constexpr O Vary[] = {O::RolR,O::RorR,O::Nop,O::Nop,O::ShlR,O::ShrR,O::Nop,O::SarR};
                Emit(Variable ? Vary[Group] : Fixed[Group], D, 1, Count, Size);
                if (P.Memory) Store(P, D, Size);
                return;
            }
            if (Opcode == 0x86 || Opcode == 0x87) {
                const auto Size = static_cast<std::uint8_t>((Opcode & 1) ? Bits : 8);
                const auto M = C.NeedModRm(); const auto P = Rm(M, Size);
                if (P.Memory) throw std::runtime_error("x64 decoder: atomic XCHG memory form is not liftable");
                const auto G = ByteReg(RegFromModRm(M, R), Size);
                Emit(O::Mov, Temp, P.Reg, 0, Size); Emit(O::Mov, P.Reg, G, 0, Size); Emit(O::Mov, G, Temp, 0, Size); return;
            }
            std::ostringstream Error;
            Error << "x64 decoder: unsupported opcode 0x" << std::hex << unsigned(Opcode)
                  << " at RVA 0x" << FunctionRva + Start;
            throw std::runtime_error(Error.str());
        };
        Decode();
        if (C.At - Start > 15) throw std::runtime_error("x64 decoder: instruction too long");
        for (auto At = Start; At < C.At; ++At)
            if (!Occupied.insert(At).second) throw std::runtime_error("x64 decoder: overlapping instruction boundary");
        Rec.End = C.At;
        if (Rec.Fallthrough) Queue(static_cast<std::int64_t>(C.At));
        Records.emplace(Start, std::move(Rec));
    }
    vmprotect::LiftedProgram Program;
    Program.EntryAddress = FunctionRva;
    std::size_t NativeBytes=Records.rbegin()->second.End;
    if(FragmentPrologue!=SIZE_MAX) {
        // Keep the prologue, native calls, exception scopes and epilogue in
        // place. Only a nonfaulting register computation before the entry
        // block's first control transfer may run in a returning VM fragment.
        std::size_t Begin=0, End=0;
        bool Found=false;
        for(const auto& [Start,Rec]:Records) {
            if(Start<FragmentPrologue) continue;
            if(std::any_of(Rec.Ir.begin(),Rec.Ir.end(),[](const auto& I) {
                return IsBranch(I.Op) || I.Op==O::NativeCall || I.Op==O::Ret || I.Op==O::Halt;
            })) break;
            const bool Eligible=std::all_of(Rec.Ir.begin(),Rec.Ir.end(),vmprotect::NativeFragmentInstruction);
            if(!Eligible || (!Program.Instructions.empty() && Start!=End)) Program.Instructions.clear();
            if(!Eligible) continue;
            if(Program.Instructions.empty()) Begin=Start;
            End=Rec.End;
            Program.Instructions.insert(Program.Instructions.end(),Rec.Ir.begin(),Rec.Ir.end());
            if(End-Begin>=5) { Found=true; break; }
        }
        if(!Found) throw std::runtime_error("x64 decoder: EH entry block has no safe 5-byte register fragment");
        Program.EntryAddress=FunctionRva+static_cast<std::uint32_t>(Begin);
        Program.ResumeAddress=FunctionRva+static_cast<std::uint32_t>(End);
        Program.Instructions.push_back({O::Ret,0,0,0,Label()});
        NativeBytes=End-Begin;
    } else
    for (const auto& [Start, Rec] : Records) {
        Program.Instructions.insert(Program.Instructions.end(), Rec.Ir.begin(), Rec.Ir.end());
        const auto Next = Records.upper_bound(Start);
        if (Rec.Fallthrough && (Next == Records.end() || Next->first != Rec.End))
            Program.Instructions.push_back({O::Jmp, 0, 0, 0, Label(), FunctionRva + static_cast<std::uint32_t>(Rec.End)});
    }
    std::size_t Blocks = 1;
    std::ostringstream Out;
    Out << "{\n  \"format\":\"pevm-x64-lift\",\n  \"functionRva\":\"0x" << std::hex << FunctionRva
        << "\",\n  \"vmEntryRva\":\"0x"<<Program.EntryAddress<<"\",\n  \"nativeResumeRva\":\"0x"<<Program.ResumeAddress<<"\",\n  \"instructions\":[\n";
    for (std::size_t N = 0; N < Program.Instructions.size(); ++N) {
        const auto& I = Program.Instructions[N];
        Blocks += IsBranch(I.Op);
        Out << "    {\"rva\":\"0x" << std::hex << I.Address << "\",\"op\":\"" << OpName(I.Op)
            << "\",\"width\":" << std::dec << unsigned(I.Width & 127) << ",\"dst\":" << unsigned(I.Dst)
            << ",\"src\":" << unsigned(I.Src) << ",\"imm\":\"0x" << std::hex << I.Immediate
            << "\",\"target\":\"0x" << I.Target << "\"}" << (N + 1 == Program.Instructions.size() ? "\n" : ",\n");
    }
    Out << "  ]\n}\n";
    return {std::move(Program), Out.str(), Blocks, NativeBytes};
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

        const bool FlagsDead = OverwritesFlagsWithoutReading(NextOp) &&
            !(Program.Instructions[I + 1].Width & vmprotect::KPreserveFlags);
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
        if (Instruction.Op!=O::Ret && Instruction.Op!=O::Halt && (Next() & 1U) != 0) {
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
