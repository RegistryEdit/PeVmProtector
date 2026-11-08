#include "VmProtect.h"
#include "X64Lifter.h"
#include <windows.h>
#include <array>
#include <vector>
#include <cstring>
#include <iostream>
#include <sstream>
#include <stdexcept>
namespace vmprotect { extern "C" void PeVmCallNative(VmBridgeContext*); }
void TestSimd() {
    using namespace vmprotect;
    using Bytes=std::vector<std::uint8_t>;
    std::vector<Bytes> Cases;
    auto Add=[&](unsigned Prefix,unsigned Op,unsigned Modrm=0xc1,bool Rex=false,int Imm=-1) {
        Bytes B;
        if(Prefix) B.push_back(static_cast<std::uint8_t>(Prefix));
        if(Rex) B.push_back(0x48);
        B.insert(B.end(),{0x0f,static_cast<std::uint8_t>(Op),static_cast<std::uint8_t>(Modrm)});
        if(Imm>=0) B.push_back(static_cast<std::uint8_t>(Imm));
        B.push_back(0xc3); Cases.push_back(std::move(B));
    };
    for(auto P:{0,0x66,0xf3,0xf2}) for(auto Op:{0x10,0x11,0x58,0x59,0x5c,0x5d,0x5e,0x5f,0x51}) { Add(P,Op); Add(P,Op,0x01); }
    for(auto P:{0,0x66}) {
        for(auto Op:{0x28,0x29,0x54,0x55,0x56,0x57,0x2e,0x2f}) { Add(P,Op); Add(P,Op,0x01); }
        for(auto Imm:{0,1,27,228,255}) Add(P,0xc6,0xc1,false,Imm);
    }
    for(auto P:{0x66,0xf3}) { Add(P,0x6f); Add(P,0x6f,0x01); Add(P,0x7f,0x01); }
    for(auto Op:{0x6e,0x7e}) for(bool Wide:{false,true}) { Add(0x66,Op,0xc2,Wide); Add(0x66,Op,0x01,Wide); }
    Add(0xf3,0x7e); Add(0xf3,0x7e,0x01); Add(0x66,0xd6); Add(0x66,0xd6,0x01);
    for(auto P:{0xf3,0xf2}) {
        Add(P,0x5a); Add(P,0x5a,0x01);
        for(auto Op:{0x2a,0x2c,0x2d}) for(bool Wide:{false,true}) { Add(P,Op,0xc2,Wide); Add(P,Op,0x01,Wide); }
    }
    for(auto P:{0,0x66,0xf3}) Add(P,0x5b);
    for(auto Op:{0xef,0xdb,0xdf,0xeb,0xfc,0xfd,0xfe,0xd4,0xf8,0xf9,0xfa,0xfb,0x74,0x75,0x76,0x64,0x65,0x66,0xd5,0x60,0x61,0x62,0x6c,0x68,0x69,0x6a,0x6d}) { Add(0x66,Op); Add(0x66,Op,0x01); }
    for(auto Imm:{0,1,27,228,255}) Add(0x66,0x70,0xc1,false,Imm);
    Cases.push_back({0x45,0x0f,0x57,0xc9,0xc3});
    auto* Code=static_cast<std::uint8_t*>(VirtualAlloc(nullptr,4096,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));
    if(!Code) throw std::runtime_error("SIMD test allocation failed");
    struct Owner { void* P; ~Owner(){ VirtualFree(P,0,MEM_RELEASE); } } CodeOwner{Code};
    std::array<std::uint64_t,128> Stack{};
    alignas(16) std::array<std::uint8_t,64> Memory{};
    const std::array<std::uint64_t,12> Patterns{0,0x8000000080000000ULL,0x3ff8000040200000ULL,0xbff80000c0200000ULL,0x7ff000007f800000ULL,0x7ff800007fc00000ULL,0x7ff000017f800001ULL,1,0x0010000000800000ULL,0x7fefffff7f7fffffULL,0xffeffffffffeffffULL,UINT64_MAX};
    std::size_t Checks=0;
    for(std::size_t Case=0;Case<Cases.size();++Case) {
        DWORD Old; VirtualProtect(Code,4096,PAGE_READWRITE,&Old);
        std::memcpy(Code,Cases[Case].data(),Cases[Case].size());
        VirtualProtect(Code,4096,PAGE_EXECUTE_READ,&Old); FlushInstructionCache(GetCurrentProcess(),Code,Cases[Case].size());
        const auto Lifted=x64lift::LiftRawCode(Cases[Case],0).Program;
        for(auto Seed:{1ULL,17ULL}) {
            auto P=Lifted; x64lift::MutateProgram(P,Seed);
            const auto Compiled=CompileLiftedProgram(P,Seed);
            for(unsigned Mode=0;Mode<16;++Mode) for(std::size_t Pattern=0;Pattern<Patterns.size();++Pattern) {
                VmBridgeContext Input{};
                for(unsigned R=0;R<16;++R) for(unsigned Lane=0;Lane<2;++Lane) {
                    const auto Value=Patterns[(Pattern+R+Lane)%Patterns.size()];
                    std::memcpy(Input.Xmm[R].data()+8*Lane,&Value,8);
                }
                for(unsigned I=0;I<Memory.size();++I) Memory[I]=Input.Xmm[1][I%16];
                const auto Original=Memory;
                Input.Registers[1]=reinterpret_cast<std::uint64_t>(Memory.data());
                Input.Registers[2]=Patterns[Pattern]; Input.Registers[4]=reinterpret_cast<std::uint64_t>(Stack.data());
                Input.NativeArguments=Input.Registers[4]; Input.CallTarget=reinterpret_cast<std::uint64_t>(Code);
                Input.Mxcsr=0x1f80|((Mode&3)<<13)|(Mode&4?0x40:0)|(Mode&8?0x8000:0);
                auto Native=Input; PeVmCallNative(&Native);
                const auto ExpectedMemory=Memory; Memory=Original;
                auto Actual=Input; RunConfig Config; Config.NativeMemory=true;
                InvokeCompiledProgram(Compiled,Actual,false,Config);
                if(Native.Xmm!=Actual.Xmm || Native.Registers[0]!=Actual.Registers[0] || Native.Registers[2]!=Actual.Registers[2] || Native.Mxcsr!=Actual.Mxcsr || (Native.Rflags&0x8c5)!=(Actual.Rflags&0x8c5) || ExpectedMemory!=Memory) {
                    std::ostringstream E;
                    E<<"SIMD mismatch case="<<Case<<" seed="<<Seed<<" mode="<<Mode<<" pattern="<<Pattern<<" xmm="<<(Native.Xmm!=Actual.Xmm)<<" memory="<<(Memory!=ExpectedMemory)<<" mxcsr="<<std::hex<<Native.Mxcsr<<"/"<<Actual.Mxcsr<<" flags="<<(Native.Rflags&0x8c5)<<"/"<<(Actual.Rflags&0x8c5)<<" rax="<<Native.Registers[0]<<"/"<<Actual.Registers[0];
                    for(unsigned R=0;R<16;++R) if(Native.Xmm[R]!=Actual.Xmm[R]) {
                        E<<" xmm"<<R<<":";
                        for(auto V:Native.Xmm[R]) E<<unsigned(V)<<",";
                        E<<"/"; for(auto V:Actual.Xmm[R]) E<<unsigned(V)<<",";
                    }
                    throw std::runtime_error(E.str());
                }
                ++Checks;
            }
        }
    }
    auto* Guard=static_cast<std::uint8_t*>(VirtualAlloc(nullptr,8192,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));
    if(!Guard) throw std::runtime_error("SIMD guard allocation failed");
    Owner GuardOwner{Guard}; DWORD Old; VirtualProtect(Guard+4096,4096,PAGE_NOACCESS,&Old);
    for(auto Size:{4,8}) {
        const auto P=x64lift::LiftRawCode({static_cast<std::uint8_t>(Size==4?0xf3:0xf2),0x0f,0x10,0x01,0xc3},0).Program;
        VmBridgeContext C{}; C.Registers[1]=reinterpret_cast<std::uint64_t>(Guard+4096-Size);
        InvokeLiftedProgram(P,C,1,false,{1000,4096,true});
    }
    std::cout<<"SIMD native differential: "<<Checks<<" checks passed; scalar guard-page loads passed\n";
}
