#pragma once
#include "VmProtect.h"
#include <span>

namespace vmprotect {
enum class SimdOp : std::uint8_t {
    Mov128, MovSS, MovSD, MovQ, FromGpr, ToGpr,
    Xor, And, AndNot, Or,
    AddPS, AddPD, AddSS, AddSD, SubPS, SubPD, SubSS, SubSD,
    MulPS, MulPD, MulSS, MulSD, DivPS, DivPD, DivSS, DivSD,
    MinPS, MinPD, MinSS, MinSD, MaxPS, MaxPD, MaxSS, MaxSD,
    SqrtPS, SqrtPD, SqrtSS, SqrtSD,
    CvtSS2SD, CvtSD2SS, CvtSI2SS, CvtSI2SD,
    CvttSS2SI, CvttSD2SI, CvtSS2SI, CvtSD2SI,
    CvtDQ2PS, CvtPS2DQ, CvttPS2DQ,
    Ucomiss, Ucomisd, Comiss, Comisd,
    AddB, AddW, AddD, AddQ, SubB, SubW, SubD, SubQ,
    EqB, EqW, EqD, GtB, GtW, GtD, MulW,
    UnpackLoB, UnpackLoW, UnpackLoD, UnpackLoQ,
    UnpackHiB, UnpackHiW, UnpackHiD, UnpackHiQ,
    ShufflePS, ShufflePD, ShuffleD, Count
};
enum class SimdForm : std::uint8_t { Registers, MemorySource, MemoryDestination, Gpr };
// XMM numbers are independent of the randomized GPR map. Bit 10 records an
// alignment requirement; the final byte holds a shuffle control immediate.
inline std::uint64_t EncodeSimd(SimdOp Op, SimdForm Form, unsigned D, unsigned S,
                                unsigned Control=0, bool Aligned=false) {
    return unsigned(Op) | (unsigned(Form)<<8) | (unsigned(Aligned)<<10) |
           (D<<12) | (S<<16) | (std::uint64_t{Control}<<24);
}
void ExecuteSimd(std::uint64_t Encoding, unsigned Width, std::uint64_t& GprDestination,
                 std::uint64_t GprSource, VmBridgeContext& Context,
                 std::span<std::uint8_t> FlatMemory, bool NativeMemory);
inline bool NativeFragmentInstruction(const LiftedInstruction& I) {
    using O=LiftedOp;
    if(I.Op==O::Nop || I.Op==O::Ret) return true;
    if(I.Op==O::Simd) {
        const auto Op=static_cast<SimdOp>(I.Immediate&255);
        const auto Form=static_cast<SimdForm>((I.Immediate>>8)&3);
        return Form==SimdForm::Registers &&
            (Op<=SimdOp::Or || (Op>=SimdOp::AddB && Op<SimdOp::Count));
    }
    if(I.Dst==4 || I.Dst==5) return I.Op==O::Cmp || I.Op==O::Test;
    return I.Op<=O::Cmp || I.Op==O::ZeroExtend || I.Op==O::SignExtend ||
        I.Op==O::Inc || I.Op==O::Dec || I.Op==O::ImageAddress;
}
}
