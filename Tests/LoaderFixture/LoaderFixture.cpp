#include <windows.h>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <array>
#include <atomic>
#include <string>
#include <thread>
#include <vector>
#include <immintrin.h>

extern "C" IMAGE_DOS_HEADER __ImageBase;
extern "C" __declspec(dllexport, noinline) unsigned long long LoaderArithmetic(
    unsigned long long A, unsigned long long B, unsigned long long C, unsigned long long D) {
    return A ^ B ^ C ^ D;
}

using SixArguments = unsigned long long(*)(unsigned long long,unsigned long long,unsigned long long,
                                          unsigned long long,unsigned long long,unsigned long long);
__declspec(noinline) unsigned long long NativeSix(unsigned long long A,unsigned long long B,
    unsigned long long C,unsigned long long D,unsigned long long E,unsigned long long F) {
    return A*3+B*5+C*7+D*11+E*13+F*17;
}
extern "C" __declspec(dllexport, noinline) unsigned long long LoaderCallWithStack(
    SixArguments Callback, unsigned long long A, unsigned long long B, unsigned long long C,
    unsigned long long D, unsigned long long E, unsigned long long F) {
    volatile unsigned long long Local[6];
    Local[0]=A; Local[1]=B; Local[2]=C; Local[3]=D; Local[4]=E; Local[5]=F;
    return Callback(Local[0],Local[1],Local[2],Local[3],Local[4],Local[5]) + A;
}
__declspec(noinline) unsigned long long ReenterSix(unsigned long long A,unsigned long long B,
    unsigned long long C,unsigned long long D,unsigned long long E,unsigned long long F) {
    return LoaderCallWithStack(NativeSix,A,B,C,D,E,F);
}
using UnaryCallback=unsigned long long(*)(unsigned long long);
extern "C" __declspec(dllexport,noinline) unsigned long long LoaderExceptionFragment(
    UnaryCallback Callback,unsigned long long A,unsigned long long B) {
    volatile unsigned long long Mixed=((A*7)^B)+11;
    try { return Callback(Mixed); }
    catch(const std::runtime_error&) { return Mixed+900; }
}
extern "C" __declspec(dllexport,noinline) unsigned long long LoaderSehFragment(
    UnaryCallback Callback,unsigned long long A,unsigned long long B) {
    volatile unsigned long long Mixed=((A*7)^B)+11;
    __try { return Callback(Mixed); }
    __except(GetExceptionCode()==0xe0424242?EXCEPTION_EXECUTE_HANDLER:EXCEPTION_CONTINUE_SEARCH) { return Mixed+800; }
}
__declspec(noinline) unsigned long long ReturnValue(unsigned long long A) { return A; }
__declspec(noinline) unsigned long long ThrowCpp(unsigned long long) { throw std::runtime_error("EH fragment test"); }
__declspec(noinline) unsigned long long ThrowSeh(unsigned long long) { RaiseException(0xe0424242,0,0,nullptr); return 0; }
extern "C" __declspec(dllexport,noinline) void LoaderSimd(const float* Input,float* Output) {
    _mm_storeu_ps(Output,_mm_add_ps(_mm_loadu_ps(Input),_mm_set1_ps(0.25f)));
}

thread_local unsigned Marker = 0x12345678;
thread_local std::string Greeting = "initialized TLS";
std::atomic<unsigned> Constructed{}, Destroyed{};
struct Catalog {
    std::string Text = "thread catalog";
    std::array<unsigned char, 512> Storage{};
    Catalog() { ++Constructed; }
    ~Catalog() { ++Destroyed; }
};
bool CheckTls() {
    static thread_local Catalog Cache;
    if (Marker != 0x12345678 || Greeting != "initialized TLS" || Cache.Text != "thread catalog") return false;
    for (auto Byte : Cache.Storage) if (Byte) return false;
    Marker = 42;
    Greeting = "changed";
    Cache.Storage[0] = 1;
    if(LoaderCallWithStack(ReenterSix,1,2,3,4,5,6)!=247) return false;
    return true;
}
bool CheckUnalignedLeafCall() {
    std::array<unsigned char, 21> Code = {
        0x48,0x83,0xEC,0x20, 0x48,0xB8,0,0,0,0,0,0,0,0,
        0xFF,0xD0, 0x48,0x83,0xC4,0x20, 0xC3
    };
    const auto Address = reinterpret_cast<unsigned long long>(&LoaderArithmetic);
    std::memcpy(Code.data() + 6, &Address, sizeof(Address));
    void* Memory = VirtualAlloc(nullptr, Code.size(), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!Memory) return false;
    std::memcpy(Memory, Code.data(), Code.size());
    DWORD Old = 0;
    if (!VirtualProtect(Memory, Code.size(), PAGE_EXECUTE_READ, &Old)) { VirtualFree(Memory, 0, MEM_RELEASE); return false; }
    FlushInstructionCache(GetCurrentProcess(), Memory, Code.size());
    const auto Result = reinterpret_cast<decltype(&LoaderArithmetic)>(Memory)(0x11, 0x22, 0x44, 0x88);
    VirtualFree(Memory, 0, MEM_RELEASE);
    return Result == 0xff;
}

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    if (LoaderArithmetic(0x11, 0x22, 0x44, 0x88) != 0xff) return 16;
    if (!CheckUnalignedLeafCall()) return 17;
    if (LoaderCallWithStack(NativeSix,1,2,3,4,5,6) != 246) return 18;
    std::puts("PEVM_NATIVE_CALL_STACK_OK");
    const auto Mixed=((5*7)^9)+11;
    if(LoaderExceptionFragment(ReturnValue,5,9)!=Mixed || LoaderExceptionFragment(ThrowCpp,5,9)!=Mixed+900) return 19;
    if(LoaderSehFragment(ReturnValue,5,9)!=Mixed || LoaderSehFragment(ThrowSeh,5,9)!=Mixed+800) return 20;
    float Input[4]{1,2,3,4},Output[4]{};
    LoaderSimd(Input,Output);
    for(unsigned I=0;I<4;++I) if(Output[I]!=Input[I]+0.25f) return 21;
    std::puts("PEVM_SIMD_EH_OK");
    if (__ImageBase.e_magic != IMAGE_DOS_SIGNATURE) return 10;
    const auto Base = reinterpret_cast<const unsigned char*>(&__ImageBase);
    const auto Nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(Base + __ImageBase.e_lfanew);
    if (Nt->Signature != IMAGE_NT_SIGNATURE) return 11;
    std::puts("PEVM_HEADERS_OK");
    if (!CheckTls()) return 14;
    std::atomic<bool> Passed = true;
    std::vector<std::thread> Threads;
    for (unsigned I = 0; I < 8; ++I) Threads.emplace_back([&] { if (!CheckTls()) Passed = false; });
    for (auto& Thread : Threads) Thread.join();
    if (!Passed || Constructed != 9 || Destroyed != 8) return 15;
    std::puts("PEVM_TLS_OK");
    // The x64 C++ handler also needs to locate the image containing this frame.
    try { throw std::runtime_error("loader exception regression"); }
    catch (const std::runtime_error&) { std::puts("PEVM_LOADER_OK"); }
    return 0;
}
