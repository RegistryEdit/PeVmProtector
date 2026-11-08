#include "VmSimd.h"
#include <immintrin.h>
#include <cstring>
#include <stdexcept>
#include <array>

namespace vmprotect {
void ExecuteSimd(std::uint64_t E, unsigned Width, std::uint64_t& GprDestination,
                 std::uint64_t GprSource, VmBridgeContext& C,
                 std::span<std::uint8_t> Memory, bool NativeMemory) {
    using O=SimdOp;
    const auto Op=static_cast<O>(E&255);
    const auto Form=static_cast<SimdForm>((E>>8)&3);
    if (Op>=O::Count || (E & ~0xff0ff7ffULL) || (Width!=32 && Width!=64))
        throw std::runtime_error("VM invalid SIMD encoding");
    const auto D=(E>>12)&15, S=(E>>16)&15, Control=(E>>24)&255;
    const bool Aligned=(E&0x400)!=0;
    unsigned Size=16;
    switch(Op) {
    case O::MovSS: case O::AddSS: case O::SubSS: case O::MulSS: case O::DivSS:
    case O::MinSS: case O::MaxSS: case O::SqrtSS: case O::CvtSS2SD:
    case O::CvttSS2SI: case O::CvtSS2SI: case O::Ucomiss: case O::Comiss: Size=4; break;
    case O::MovSD: case O::MovQ: case O::AddSD: case O::SubSD: case O::MulSD: case O::DivSD:
    case O::MinSD: case O::MaxSD: case O::SqrtSD: case O::CvtSD2SS:
    case O::CvttSD2SI: case O::CvtSD2SI: case O::Ucomisd: case O::Comisd: Size=8; break;
    case O::FromGpr: case O::ToGpr: case O::CvtSI2SS: case O::CvtSI2SD: Size=Width/8; break;
    default: break;
    }
    auto* Address=reinterpret_cast<std::uint8_t*>(GprSource);
    if (Form==SimdForm::MemorySource || Form==SimdForm::MemoryDestination) {
        if (Aligned && GprSource%16) throw std::runtime_error("VM misaligned SIMD operand");
        if (!NativeMemory) {
            if (GprSource>Memory.size() || Size>Memory.size()-GprSource) throw std::runtime_error("VM SIMD memory OOB");
            Address=Memory.data()+GprSource;
        }
    }
    if (Form==SimdForm::MemoryDestination) {
        if (Op!=O::Mov128 && Op!=O::MovSS && Op!=O::MovSD && Op!=O::MovQ && Op!=O::ToGpr)
            throw std::runtime_error("VM invalid SIMD store");
        std::memcpy(Address,C.Xmm[D].data(),Size);
        return;
    }
    alignas(16) std::array<std::uint8_t,16> Source{};
    if (Form==SimdForm::MemorySource) std::memcpy(Source.data(),Address,Size);
    else if (Form==SimdForm::Gpr && (Op==O::FromGpr || Op==O::CvtSI2SS || Op==O::CvtSI2SD))
        std::memcpy(Source.data(),&GprSource,Size);
    else Source=C.Xmm[S];
    const auto A=_mm_loadu_ps(reinterpret_cast<const float*>(C.Xmm[D].data()));
    const auto B=_mm_loadu_ps(reinterpret_cast<const float*>(Source.data()));
    const auto Ai=_mm_castps_si128(A), Bi=_mm_castps_si128(B);
    const auto Ad=_mm_castps_pd(A), Bd=_mm_castps_pd(B);
    auto R=A;
    std::int64_t Integer{}; std::memcpy(&Integer,Source.data(),Size<8?Size:8);
    if (Width==32) Integer=static_cast<std::int32_t>(Integer);
    auto WriteGpr=[&](std::int64_t Value) { GprDestination=Width==32?static_cast<std::uint32_t>(Value):static_cast<std::uint64_t>(Value); };
    switch(Op) {
    case O::Mov128: case O::FromGpr: R=B; break;
    case O::MovQ: R=_mm_castsi128_ps(_mm_unpacklo_epi64(Bi,_mm_setzero_si128())); break;
    case O::MovSS: R=Form==SimdForm::MemorySource?B:_mm_move_ss(A,B); break;
    case O::MovSD: R=Form==SimdForm::MemorySource?B:_mm_castpd_ps(_mm_move_sd(Ad,Bd)); break;
    case O::ToGpr: WriteGpr(Integer); return;
    case O::Xor: R=_mm_xor_ps(A,B); break;
    case O::And: R=_mm_and_ps(A,B); break;
    case O::AndNot: R=_mm_andnot_ps(A,B); break;
    case O::Or: R=_mm_or_ps(A,B); break;
#define FP4(Name, Fn) \
    case O::Name##PS: R=_mm_##Fn##_ps(A,B); break; \
    case O::Name##PD: R=_mm_castpd_ps(_mm_##Fn##_pd(Ad,Bd)); break; \
    case O::Name##SS: R=_mm_##Fn##_ss(A,B); break; \
    case O::Name##SD: R=_mm_castpd_ps(_mm_##Fn##_sd(Ad,Bd)); break
    FP4(Add,add); FP4(Sub,sub); FP4(Mul,mul); FP4(Div,div); FP4(Min,min); FP4(Max,max);
#undef FP4
    case O::SqrtPS: R=_mm_sqrt_ps(B); break;
    case O::SqrtPD: R=_mm_castpd_ps(_mm_sqrt_pd(Bd)); break;
    case O::SqrtSS: R=_mm_move_ss(A,_mm_sqrt_ss(B)); break;
    case O::SqrtSD: R=_mm_castpd_ps(_mm_sqrt_sd(Ad,Bd)); break;
    case O::CvtSS2SD: R=_mm_castpd_ps(_mm_cvtss_sd(Ad,B)); break;
    case O::CvtSD2SS: R=_mm_cvtsd_ss(A,Bd); break;
    case O::CvtSI2SS: R=_mm_cvtsi64_ss(A,Integer); break;
    case O::CvtSI2SD: R=_mm_castpd_ps(_mm_cvtsi64_sd(Ad,Integer)); break;
    case O::CvttSS2SI: WriteGpr(Width==64?_mm_cvttss_si64(B):_mm_cvttss_si32(B)); return;
    case O::CvttSD2SI: WriteGpr(Width==64?_mm_cvttsd_si64(Bd):_mm_cvttsd_si32(Bd)); return;
    case O::CvtSS2SI: WriteGpr(Width==64?_mm_cvtss_si64(B):_mm_cvtss_si32(B)); return;
    case O::CvtSD2SI: WriteGpr(Width==64?_mm_cvtsd_si64(Bd):_mm_cvtsd_si32(Bd)); return;
    case O::CvtDQ2PS: R=_mm_cvtepi32_ps(Bi); break;
    case O::CvtPS2DQ: R=_mm_castsi128_ps(_mm_cvtps_epi32(B)); break;
    case O::CvttPS2DQ: R=_mm_castsi128_ps(_mm_cvttps_epi32(B)); break;
    case O::Ucomiss: case O::Ucomisd: case O::Comiss: case O::Comisd: {
        // Force the matching comparison's exception semantics (QNaN differs
        // for COMI/UCOMI), then derive flags using bits without another FP op.
        volatile int Comparison=Op==O::Ucomiss?_mm_ucomieq_ss(A,B):Op==O::Comiss?_mm_comieq_ss(A,B):
            Op==O::Ucomisd?_mm_ucomieq_sd(Ad,Bd):_mm_comieq_sd(Ad,Bd);
        (void)Comparison;
        std::uint64_t X{},Y{};
        std::memcpy(&X,C.Xmm[D].data(),Size); std::memcpy(&Y,Source.data(),Size);
        const auto Sign=Size==4?0x80000000ULL:0x8000000000000000ULL;
        const auto Exponent=Size==4?0x7f800000ULL:0x7ff0000000000000ULL;
        const auto Magnitude=Sign-1;
        if(C.Mxcsr&0x40) {
            if((X&Exponent)==0) X&=Sign;
            if((Y&Exponent)==0) Y&=Sign;
        }
        std::uint64_t Flags;
        if ((X&Magnitude)>Exponent || (Y&Magnitude)>Exponent) Flags=0x45;
        else if (X==Y || ((X|Y)&Magnitude)==0) Flags=0x40;
        else {
            const auto OrderedX=(X&Sign)?(~X & (Sign|Magnitude)):(X|Sign);
            const auto OrderedY=(Y&Sign)?(~Y & (Sign|Magnitude)):(Y|Sign);
            Flags=OrderedX<OrderedY?1:0;
        }
        C.Rflags=(C.Rflags&~0x8d5ULL)|Flags;
        return;
    }
#define PI(Name,Fn) case O::Name: R=_mm_castsi128_ps(_mm_##Fn(Ai,Bi)); break
    PI(AddB,add_epi8); PI(AddW,add_epi16); PI(AddD,add_epi32); PI(AddQ,add_epi64);
    PI(SubB,sub_epi8); PI(SubW,sub_epi16); PI(SubD,sub_epi32); PI(SubQ,sub_epi64);
    PI(EqB,cmpeq_epi8); PI(EqW,cmpeq_epi16); PI(EqD,cmpeq_epi32);
    PI(GtB,cmpgt_epi8); PI(GtW,cmpgt_epi16); PI(GtD,cmpgt_epi32); PI(MulW,mullo_epi16);
    PI(UnpackLoB,unpacklo_epi8); PI(UnpackLoW,unpacklo_epi16); PI(UnpackLoD,unpacklo_epi32); PI(UnpackLoQ,unpacklo_epi64);
    PI(UnpackHiB,unpackhi_epi8); PI(UnpackHiW,unpackhi_epi16); PI(UnpackHiD,unpackhi_epi32); PI(UnpackHiQ,unpackhi_epi64);
#undef PI
    case O::ShufflePS: case O::ShufflePD: case O::ShuffleD: {
        auto Out=C.Xmm[D];
        if (Op==O::ShufflePD) {
            std::memcpy(Out.data(),C.Xmm[D].data()+8*(Control&1),8);
            std::memcpy(Out.data()+8,Source.data()+8*((Control>>1)&1),8);
        } else for (unsigned I=0;I<4;++I) {
            const auto* Input=Op==O::ShuffleD || I>=2?Source.data():C.Xmm[D].data();
            std::memcpy(Out.data()+4*I,Input+4*((Control>>(2*I))&3),4);
        }
        C.Xmm[D]=Out; return;
    }
    default: throw std::runtime_error("VM unsupported SIMD operation");
    }
    // Optimizers may commute ADD/MUL intrinsics. SSE chooses the first NaN's
    // payload when both operands are NaNs, so preserve architectural ordering
    // explicitly while retaining the hardware exception/rounding result.
    if(Op>=O::AddPS && Op<=O::DivSD) {
        std::array<std::uint8_t,16> Result;
        _mm_storeu_ps(reinterpret_cast<float*>(Result.data()),R);
        const auto FormIndex=(unsigned(Op)-unsigned(O::AddPS))%4;
        const unsigned LaneSize=(FormIndex&1)?8:4;
        const unsigned Lanes=FormIndex>=2?1:16/LaneSize;
        const auto Magnitude=LaneSize==4?0x7fffffffULL:0x7fffffffffffffffULL;
        const auto Infinity=LaneSize==4?0x7f800000ULL:0x7ff0000000000000ULL;
        const auto Quiet=LaneSize==4?0x00400000ULL:0x0008000000000000ULL;
        for(unsigned I=0;I<Lanes;++I) {
            std::uint64_t Left{},Right{};
            std::memcpy(&Left,C.Xmm[D].data()+I*LaneSize,LaneSize);
            std::memcpy(&Right,Source.data()+I*LaneSize,LaneSize);
            if((Left&Magnitude)>Infinity || (Right&Magnitude)>Infinity) {
                const auto Nan=((Left&Magnitude)>Infinity?Left:Right)|Quiet;
                std::memcpy(Result.data()+I*LaneSize,&Nan,LaneSize);
            }
        }
        C.Xmm[D]=Result;
    } else _mm_storeu_ps(reinterpret_cast<float*>(C.Xmm[D].data()),R);
}
}
