#include "VmProtect.h"
#include "X64Lifter.h"
#include "VmImageCodec.h"
#include "WrapperFormat.h"

#include <algorithm>
#include <array>
#include <bit>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <future>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <set>
#include <sstream>
#include <utility>
#include <vector>

namespace {
using namespace vmprotect;
using O = LiftedOp;

void Require(bool Condition, const char* Message) {
    if (!Condition) throw std::runtime_error(Message);
}

template <typename F> void ExpectRejected(F&& Run, std::string_view Message) {
    try { Run(); }
    catch (const std::runtime_error& Error) {
        if (std::string_view(Error.what()).find(Message) == std::string_view::npos) {
            throw std::runtime_error(std::string("unexpected rejection reason: ") + Error.what());
        }
        return;
    }
    throw std::runtime_error("invalid program/configuration was accepted");
}

LiftedProgram ArithmeticProgram() {
    return {{{O::Mov, 0, 1, 0, 0x1000}, {O::Add, 0, 2, 0, 0x1001},
             {O::Xor, 0, 8, 0, 0x1002}, {O::Ret, 0, 0, 0, 0x1003}}, 0x1000};
}

VmBridgeContext Inputs(std::uint64_t Value) {
    VmBridgeContext Context{};
    for (std::size_t I = 0; I < Context.Registers.size(); ++I) Context.Registers[I] = Value ^ I;
    Context.Registers[0] = Value;
    Context.Registers[1] = Value;
    Context.Registers[2] = 7;
    Context.Registers[8] = 0;
    return Context;
}

void TestCompiledPrograms() {
    auto Source = ArithmeticProgram();
    for (const auto Seed : {1ULL, 2ULL, 0x123456789abcdef0ULL}) {
        const auto Compiled = CompileLiftedProgram(Source, Seed);
        for (std::uint64_t I = 0; I < 256; ++I) {
            auto Cached = Inputs(I), OneShot = Cached;
            InvokeCompiledProgram(Compiled, Cached, false);
            InvokeLiftedProgram(Source, OneShot, Seed, false);
            Require(Cached.Registers == OneShot.Registers, "compiled/one-shot register mismatch");
            Require(Cached.Registers[0] == I + 7, "compiled arithmetic mismatch");
        }
    }
    const auto Snapshot = CompileLiftedProgram(Source, 1);
    Source.Instructions[1].Op = O::Sub;
    auto Cached = Inputs(10), Changed = Cached;
    InvokeCompiledProgram(Snapshot, Cached, false);
    InvokeLiftedProgram(Source, Changed, 1, false);
    Require(Cached.Registers[0] == 17 && Changed.Registers[0] == 3,
            "compiled program is not an independent snapshot");

    // One immutable handle shared by concurrent invocations with distinct inputs.
    std::vector<std::future<void>> Jobs;
    for (std::uint64_t Worker = 0; Worker < 4; ++Worker) {
        Jobs.push_back(std::async(std::launch::async, [Snapshot, Worker] {
            for (std::uint64_t I = 0; I < 1000; ++I) {
                const auto Input = Worker * 1000 + I;
                auto Context = Inputs(Input);
                InvokeCompiledProgram(Snapshot, Context, false);
                Require(Context.Registers[0] == Input + 7, "concurrent VM state leaked");
            }
        }));
    }
    for (auto& Job : Jobs) Job.get();

    // Memory must be fresh on every call, even after failure.
    const LiftedProgram MemorySource{{
        {O::LoadMem, 0, 1, 0, 0x1000}, {O::Add, 0, 2, 0, 0x1001},
        {O::StoreMem, 1, 0, 0, 0x1002}, {O::Push, 0, 0, 0, 0x1003},
        {O::Ret, 0, 0, 0, 0x1004}}, 0x1000};
    const auto Memory = CompileLiftedProgram(MemorySource, 7);
    for (std::uint64_t I = 0; I < 128; ++I) {
        VmBridgeContext Context{};
        Context.Registers[2] = I;
        InvokeCompiledProgram(Memory, Context, false);
        Require(Context.Registers[0] == I, "VM memory leaked across calls");
    }
    VmBridgeContext Context{};
    Context.Registers[1] = 4090;
    ExpectRejected([&] { InvokeCompiledProgram(Memory, Context, false); }, "OOB");
    Context = {};
    Context.Registers[2] = 9;
    InvokeCompiledProgram(Memory, Context, false);
    Require(Context.Registers[0] == 9, "failed call affected subsequent memory state");

    const LiftedProgram StackSource{{
        {O::Test, 2, 2, 0, 0x1000}, {O::Jz, 0, 0, 0, 0x1001, 0x1004},
        {O::Push, 2, 0, 0, 0x1002}, {O::Ret, 0, 0, 0, 0x1003},
        {O::Pop, 0, 0, 0, 0x1004}, {O::Ret, 0, 0, 0, 0x1005}}, 0x1000};
    const auto Stack = CompileLiftedProgram(StackSource, 7);
    InvokeCompiledProgram(Stack, Context, false); // leaves a value on this call's stack
    Context = {};
    ExpectRejected([&] { InvokeCompiledProgram(Stack, Context, false); }, "stack underflow");
    Context = {};
    ExpectRejected([&] { InvokeCompiledProgram(Snapshot, Context, false, {1, 4096}); }, "fuel");
    InvokeCompiledProgram(Snapshot, Context, false);
    ExpectRejected([&] { InvokeCompiledProgram({}, Context, false); }, "empty compiled");
    ExpectRejected([&] { (void)CompileLiftedProgram({}, 1); }, "empty program");
    const LiftedProgram BadBranch{{{O::Jmp, 0, 0, 0, 0x1000, 0x1234}}, 0x1000};
    ExpectRejected([&] { (void)CompileLiftedProgram(BadBranch, 1); }, "branch target");
    const LiftedProgram Loop{{{O::Jmp, 0, 0, 0, 0x1000, 0x1000}}, 0x1000};
    const auto Spin = CompileLiftedProgram(Loop, 1);
    ExpectRejected([&] { InvokeCompiledProgram(Spin, Context, false, {10, 4096}); }, "fuel");
    const LiftedProgram NonFirstEntry{{
        {O::MovI, 0, 0, 999, 0x1000}, {O::Ret, 0, 0, 0, 0x1001},
        {O::MovI, 0, 0, 42, 0x2000}, {O::Ret, 0, 0, 0, 0x2001}}, 0x2000};
    InvokeLiftedProgram(NonFirstEntry, Context, 1, false);
    Require(Context.Registers[0] == 42, "VM ignored a non-first entry address");
    auto Malformed = ArithmeticProgram();
    Malformed.Instructions[0].Dst = 24;
    ExpectRejected([&] { (void)CompileLiftedProgram(Malformed, 1); }, "register");
    Malformed = ArithmeticProgram();
    Malformed.Instructions[0].Op = static_cast<O>(255);
    ExpectRejected([&] { (void)CompileLiftedProgram(Malformed, 1); }, "opcode");
    Malformed = ArithmeticProgram();
    Malformed.Instructions[1].Address = Malformed.Instructions[0].Address;
    ExpectRejected([&] { (void)CompileLiftedProgram(Malformed, 1); }, "duplicate");
    std::cout << "compiled programs: OK (reuse, snapshot, 4000 concurrent calls, memory, OOB, fuel)\n";
}

void TestVmImage() {
    using namespace pevm;
    using namespace pevm::crypto;
    // RFC 4231, test case 1: verify the shared HMAC primitive independently.
    const std::array<std::uint8_t, 20> HmacKey = [] {
        std::array<std::uint8_t, 20> Key{}; Key.fill(0x0b); return Key;
    }();
    HmacSha256 Vector(HmacKey);
    const std::string Message = "Hi There";
    Vector.Update({reinterpret_cast<const std::uint8_t*>(Message.data()), Message.size()});
    Require(Hex(Vector.Finish()) == "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            "HMAC-SHA256 standard vector mismatch");

    const std::string Secret = "vm-image-regression-secret";
    const auto Profile = MakeHandlerProfile(123);
    constexpr std::uint64_t Seed = 0x1234567812345678ULL;
    x64lift::MultiLiftResult Input;
    Input.Functions.push_back({ArithmeticProgram()});
    auto Second = ArithmeticProgram();
    for (auto& Instruction : Second.Instructions) Instruction.Address += 0x1000;
    Second.EntryAddress += 0x1000;
    Input.Functions.push_back({Second});
    std::size_t Rejections = 0;
    auto Load = [&](const Bytes& Image, std::string_view Password, const auto& HandlerProfile) {
        auto Functions = DecodeVmImage(Image, Password, HandlerProfile);
        for (const auto& Function : Functions) (void)CompileLiftedProgram(Function.Program, Function.Seed);
        return Functions;
    };
    auto Reject = [&](const Bytes& Image) {
        ExpectRejected([&] { (void)Load(Image, Secret, Profile); }, "VM");
        ++Rejections;
    };

    // This test owns the build secret and can re-authenticate malformed input,
    // so parser/IR validation is exercised behind the authentication boundary.
    auto DeriveForTest = [&](std::string_view Purpose) {
        HmacSha256 Hash({reinterpret_cast<const std::uint8_t*>(Secret.data()), Secret.size()});
        Hash.Update({reinterpret_cast<const std::uint8_t*>(Purpose.data()), Purpose.size()});
        std::array<std::uint8_t, 12> Context{};
        for (unsigned I = 0; I < 4; ++I) Context[I] = static_cast<std::uint8_t>(KVmImageVersion >> (8 * I));
        for (unsigned I = 0; I < 8; ++I) Context[4 + I] = static_cast<std::uint8_t>(Seed >> (8 * I));
        Hash.Update(Context); Hash.Update(Profile);
        return Hash.Finish();
    };
    const auto AuthenticationKey = DeriveForTest("PEVM-VM-AUTHENTICATION");
    auto Resign = [&](Bytes& Image) {
        HmacSha256 Hash(AuthenticationKey);
        const std::string Domain = "PEVM-VM-IMAGE";
        Hash.Update({reinterpret_cast<const std::uint8_t*>(Domain.data()), Domain.size()});
        Hash.Update(std::span(Image).first(Image.size() - KVmImageTagSize));
        const auto Tag = Hash.Finish();
        std::copy(Tag.begin(), Tag.end(), Image.end() - KVmImageTagSize);
    };
    auto Set32 = [](Bytes& Image, std::size_t Offset, std::uint32_t Value) {
        for (unsigned I = 0; I < 4; ++I) Image.at(Offset + I) = static_cast<std::uint8_t>(Value >> (8 * I));
    };
    for (const bool Decoys : {false, true}) {
        std::vector<CompilationStats> Statistics;
        const auto Image = x64lift::SerializeVmp3Multi(Input, Seed, Secret, Profile, Decoys, &Statistics);
        const auto Loaded = Load(Image, Secret, Profile);
        Require(Loaded.size() == 2 && Loaded[0].Seed != Loaded[1].Seed, "per-function seeds not separated");
        Require(Statistics.size() == Loaded.size(), "build statistics lost a function");
        for (std::size_t F = 0; F < Loaded.size(); ++F) {
            const auto& Function = Loaded[F];
            const auto Compiled = CompileLiftedProgram(Function.Program, Function.Seed);
            const auto Actual = GetCompilationStats(Compiled);
            Require(Actual.BasicBlocks == Statistics[F].BasicBlocks && Actual.RelocatedBlocks == Statistics[F].RelocatedBlocks &&
                    Actual.LinkInstructions == Statistics[F].LinkInstructions && Actual.BytecodeInstructions == Statistics[F].BytecodeInstructions &&
                    Actual.BytecodeBytes == Statistics[F].BytecodeBytes, "build metrics differ from loader compilation");
            auto Context = Inputs(35);
            InvokeCompiledProgram(Compiled, Context, false);
            Require(Context.Registers[0] == 42, "VM image round trip changed program result");
        }
        for (std::size_t I = 0; I < Image.size(); ++I) {
            for (unsigned Bit = 0; Bit < 8; ++Bit) {
                auto Changed = Image; Changed[I] ^= static_cast<std::uint8_t>(1U << Bit); Reject(Changed);
            }
        }
        for (std::size_t Size = 0; Size < Image.size(); ++Size) Reject(Bytes(Image.begin(), Image.begin() + Size));
        auto Changed = Image; Changed.push_back(0); Reject(Changed);
        ExpectRejected([&] { (void)Load(Image, "wrong-secret", Profile); }, "authentication");
        auto BadProfile = Profile; BadProfile[0] ^= 1;
        ExpectRejected([&] { (void)Load(Image, Secret, BadProfile); }, "authentication");
        ExpectRejected([&] { (void)DecodeVmImage(Image, Secret, std::span(Profile).first(31)); }, "context");
        // Header and both entries: reserved fields, zero count, overflow,
        // overlap, gap, duplicate entry RVA and invalid entry boundary.
        for (const auto [Offset, Value] : std::vector<std::pair<std::size_t, std::uint32_t>>{
            {8, 3}, {12, 0}, {12, UINT32_MAX}, {24, 1}, {24, UINT32_MAX}, {28, 1},
            {32, 0x3333}, {36, 1}, {40, 0}, {40, UINT32_MAX}, {44, 1},
            {48, 0x1000}, {52, 0}, {52, 5}, {56, 0}, {56, 3}, {60, 1}}) {
            Changed = Image; Set32(Changed, Offset, Value); Resign(Changed); Reject(Changed);
        }
        Changed = Image; Changed.insert(Changed.end() - KVmImageTagSize, 0);
        Resign(Changed); Reject(Changed);

        const auto Encryption = DeriveForTest("PEVM-VM-ENCRYPTION");
        XteaKey Key{};
        for (std::size_t I = 0; I < Key.size(); ++I) {
            for (unsigned B = 0; B < 4; ++B) Key[I] |= static_cast<std::uint32_t>(Encryption[I * 4 + B]) << (8 * B);
        }
        constexpr std::size_t TableOffset = sizeof(Vmp3Header) + 2 * sizeof(Vmp3Entry);
        constexpr std::size_t TableSize = 8 * sizeof(Vmp3Instruction);
        for (const auto [Offset, Value] : std::vector<std::pair<std::size_t, unsigned>>{
            {0, 255}, {1, 24}, {2, 255}, {3, 1}, {12, 0xff}}) {
            Changed = Image;
            Bytes Table(Changed.begin() + TableOffset, Changed.begin() + TableOffset + TableSize);
            XteaCtr(Table, Key, Seed); Table.at(Offset) = static_cast<std::uint8_t>(Value); XteaCtr(Table, Key, Seed);
            std::copy(Table.begin(), Table.end(), Changed.begin() + TableOffset);
            Resign(Changed); Reject(Changed);
        }
    }
    auto Duplicate = Input; Duplicate.Functions[1] = Duplicate.Functions[0];
    ExpectRejected([&] { (void)x64lift::SerializeVmp3Multi(Duplicate, Seed, Secret, Profile); }, "duplicate");
    ExpectRejected([&] { (void)x64lift::SerializeVmp3Multi({}, Seed, Secret, Profile); }, "count");
    std::cout << "VM image: OK (HMAC standard vector, round trip, independent function seeds, "
              << Rejections << " tamper/truncation/malformed-image rejections)\n";
}

void TestMutation() {
    std::vector<std::pair<std::string, LiftedProgram>> Cases;
    for (const auto First : {O::AddI, O::SubI}) {
        for (const auto Second : {O::Adc, O::Sbb}) {
            Cases.push_back({std::to_string(static_cast<int>(First)) + "/carry/" +
                             std::to_string(static_cast<int>(Second)),
                {{{First, 0, 0, 1, 0x1000}, {Second, 0, 2, 0, 0x1001},
                  {O::Ret, 0, 0, 0, 0x1002}}, 0x1000}});
        }
    }
    for (const auto Shift : {O::ShlI, O::ShrI, O::SarI, O::RolI, O::RorI,
                            O::ShlR, O::ShrR, O::SarR, O::RolR, O::RorR}) {
        Cases.push_back({"zero-count/" + std::to_string(static_cast<int>(Shift)),
            {{{O::AddI, 0, 0, 1, 0x1000}, {Shift, 0, 8, 0, 0x1001},
              {O::Adc, 0, 2, 0, 0x1002}, {O::Ret, 0, 0, 0, 0x1003}}, 0x1000}});
    }
    Cases.push_back({"flags across call",
        {{{O::AddI, 0, 0, 1, 0x1000}, {O::Call, 0, 0, 0, 0x1001, 0x1003},
          {O::Ret, 0, 0, 0, 0x1002}, {O::Adc, 0, 2, 0, 0x1003},
          {O::Ret, 0, 0, 0, 0x1004}}, 0x1000}});
    Cases.push_back({"flags across return",
        {{{O::Call, 0, 0, 0, 0x1000, 0x1003}, {O::Adc, 0, 2, 0, 0x1001},
          {O::Ret, 0, 0, 0, 0x1002}, {O::AddI, 0, 0, 1, 0x1003},
          {O::Ret, 0, 0, 0, 0x1004}}, 0x1000}});
    Cases.push_back({"multiply preserves carry",
        {{{O::Cmp, 1, 1, 0, 0x1000}, {O::MulI, 0, 0, 2, 0x1001},
          {O::Adc, 0, 2, 0, 0x1002}, {O::Ret, 0, 0, 0, 0x1003}}, 0x1000}});
    Cases.push_back({"overwritten flags",
        {{{O::AddI, 0, 0, 1, 0x1000}, {O::Cmp, 0, 2, 0, 0x1001},
          {O::Adc, 0, 2, 0, 0x1002}, {O::MulI, 0, 0, 8, 0x1003},
          {O::Test, 0, 0, 0, 0x1004}, {O::Adc, 0, 2, 0, 0x1005},
          {O::Ret, 0, 0, 0, 0x1006}}, 0x1000}});

    std::size_t Count = 0;
    for (const auto& [Name, Source] : Cases) {
        const auto Original = CompileLiftedProgram(Source, 1);
        for (std::uint64_t Seed = 0; Seed < 64; ++Seed) {
            auto Mutated = Source;
            x64lift::MutateProgram(Mutated, Seed);
            const auto Compiled = CompileLiftedProgram(Mutated, Seed);
            for (const auto Input : {0ULL, 1ULL, 0x8000000000000000ULL, 0xffffffffffffffffULL}) {
                auto Expected = Inputs(Input), Actual = Expected;
                InvokeCompiledProgram(Original, Expected, false);
                InvokeCompiledProgram(Compiled, Actual, false);
                if (Expected.Registers != Actual.Registers) {
                    throw std::runtime_error("mutation changed registers: " + Name +
                                             ", seed=" + std::to_string(Seed));
                }
                ++Count;
            }
        }
    }
    std::cout << "mutation flags: OK (" << Count << " differential cases)\n";
}

LiftedProgram SumLoop() {
    return {{{O::MovI, 0, 0, 0, 0x1000}, {O::MovI, 2, 0, 0, 0x1001},
             {O::Cmp, 1, 2, 0, 0x1002}, {O::Jz, 0, 0, 0, 0x1003, 0x1007},
             {O::Add, 0, 1, 0, 0x1004}, {O::SubI, 1, 0, 1, 0x1005},
             {O::Jmp, 0, 0, 0, 0x1006, 0x1002}, {O::Ret, 0, 0, 0, 0x1007}}, 0x1000};
}

void TestControlFlow() {
    const auto Loop = SumLoop();
    const LiftedProgram Calls{{
        {O::Mov, 0, 1, 0, 0x1000}, {O::Cmp, 1, 2, 0, 0x1001},
        {O::Jb, 0, 0, 0, 0x1002, 0x1010}, {O::Call, 0, 0, 0, 0x1003, 0x1020},
        {O::AddI, 0, 0, 1, 0x1004}, {O::Ret, 0, 0, 0, 0x1005},
        {O::AddI, 0, 0, 5, 0x1010}, {O::Jmp, 0, 0, 0, 0x1011, 0x1005},
        {O::Call, 0, 0, 0, 0x1020, 0x1030}, {O::AddI, 0, 0, 2, 0x1021},
        {O::Ret, 0, 0, 0, 0x1022}, {O::MulI, 0, 0, 3, 0x1030},
        {O::Ret, 0, 0, 0, 0x1031}}, 0x1000};
    const LiftedProgram MiddleTarget{{
        {O::Jmp, 0, 0, 0, 0x1000, 0x1003}, {O::MovI, 0, 0, 999, 0x1001},
        {O::Halt, 0, 0, 0, 0x1002}, {O::Mov, 0, 1, 0, 0x1003},
        {O::AddI, 0, 0, 9, 0x1004}, {O::Ret, 0, 0, 0, 0x1005}}, 0x1000};
    // Original last instruction has no successor: moving its block must not
    // accidentally turn the next physical block into a valid fallthrough.
    const LiftedProgram LastBranch{{
        {O::Ret, 0, 0, 0, 0x1000}, {O::Test, 1, 1, 0, 0x2000},
        {O::Jz, 0, 0, 0, 0x2001, 0x1000}}, 0x2000};
    const LiftedProgram LastCall{{
        {O::AddI, 0, 0, 7, 0x1000}, {O::Ret, 0, 0, 0, 0x1001},
        {O::Call, 0, 0, 0, 0x2000, 0x1000}}, 0x2000};

    std::size_t Cases = 0, Relocated = 0;
    std::set<std::string> Traces;
    for (std::uint64_t Seed = 0; Seed < 64; ++Seed) {
        const auto CompiledLoop = CompileLiftedProgram(Loop, Seed);
        const auto CompiledCalls = CompileLiftedProgram(Calls, Seed);
        const auto CompiledMiddle = CompileLiftedProgram(MiddleTarget, Seed);
        const auto Stats = GetCompilationStats(CompiledLoop);
        Require(Stats.BasicBlocks == 4 && Stats.BytecodeInstructions >= Loop.Instructions.size(), "invalid loop compilation stats");
        Relocated += Stats.RelocatedBlocks;
        for (const auto Input : {0ULL, 1ULL, 2ULL, 5ULL, 7ULL, 17ULL}) {
            auto Context = Inputs(Input);
            InvokeCompiledProgram(CompiledLoop, Context, false);
            Require(Context.Registers[0] == Input * (Input + 1) / 2, "shuffled loop differs from native sum");
            Context = Inputs(Input);
            InvokeCompiledProgram(CompiledCalls, Context, false);
            Require(Context.Registers[0] == (Input < 7 ? Input + 5 : Input * 3 + 3), "nested call continuation changed");
            Context = Inputs(Input);
            InvokeCompiledProgram(CompiledMiddle, Context, false);
            Require(Context.Registers[0] == Input + 9, "branch into a former instruction run failed");
            Cases += 3;
        }
        const auto TailBranch = CompileLiftedProgram(LastBranch, Seed);
        auto Context = Inputs(0);
        InvokeCompiledProgram(TailBranch, Context, false);
        Require(Context.Registers[0] == 0, "taken tail branch failed");
        Context = Inputs(1);
        const auto Before = Context.Registers;
        ExpectRejected([&] { InvokeCompiledProgram(TailBranch, Context, false); }, "falls past");
        Require(Context.Registers == Before, "failed tail branch committed register changes");
        ExpectRejected([&] { InvokeLiftedProgram(LastCall, Context, Seed, false); }, "falls past");
        Require(Context.Registers == Before, "failed tail call committed register changes");
        Cases += 3;

        // Trace is existing diagnostics. Compare the VIP/op path only, so
        // opcode randomization alone cannot make a layout-diversity test pass.
        std::ostringstream Output;
        auto* OldBuffer = std::cout.rdbuf(Output.rdbuf());
        const auto OldFlags = std::cout.flags();
        const auto OldFill = std::cout.fill();
        try { Context = Inputs(2); InvokeCompiledProgram(CompiledLoop, Context, true); }
        catch (...) { std::cout.rdbuf(OldBuffer); std::cout.flags(OldFlags); std::cout.fill(OldFill); throw; }
        std::cout.rdbuf(OldBuffer); std::cout.flags(OldFlags); std::cout.fill(OldFill);
        std::istringstream Lines(Output.str());
        std::string Line, Path;
        while (std::getline(Lines, Line)) Path += Line.substr(0, Line.find(" enc=")) + ";";
        Traces.insert(Path);
    }
    Require(Relocated > 0 && Traces.size() > 8, "block layout does not vary across seeds");

    // Independent native predicates exercise every conditional edge after
    // shuffled placement; they do not use the VM to compute expected flags.
    const std::array Branches{O::Jz,O::Jnz,O::Ja,O::Jae,O::Jb,O::Jbe,O::Js,O::Jns,
                              O::Jl,O::Jge,O::Jle,O::Jg,O::Jo,O::Jno,O::Jp,O::Jnp};
    const std::array<std::pair<std::uint64_t, std::uint64_t>, 8> Pairs{{
        {0,0}, {1,2}, {2,1}, {UINT64_MAX,0}, {0,UINT64_MAX},
        {0x8000000000000000ULL,1}, {0x7fffffffffffffffULL,UINT64_MAX}, {0xff,0}}};
    for (const auto Branch : Branches) {
        const LiftedProgram Diamond{{
            {O::Cmp, 1, 2, 0, 0x1000}, {Branch, 0, 0, 0, 0x1001, 0x1004},
            {O::MovI, 0, 0, 10, 0x1002}, {O::Ret, 0, 0, 0, 0x1003},
            {O::MovI, 0, 0, 20, 0x1004}, {O::Ret, 0, 0, 0, 0x1005}}, 0x1000};
        for (std::uint64_t Seed = 0; Seed < 64; ++Seed) {
            const auto Compiled = CompileLiftedProgram(Diamond, Seed);
            for (const auto [Left, Right] : Pairs) {
                const auto Difference = Left - Right;
                const bool Negative = (Difference >> 63) != 0;
                const bool Overflow = ((Left ^ Right) & (Left ^ Difference) & (1ULL << 63)) != 0;
                const bool Parity = (std::popcount(static_cast<std::uint8_t>(Difference)) % 2) == 0;
                const auto SignedLeft = std::bit_cast<std::int64_t>(Left), SignedRight = std::bit_cast<std::int64_t>(Right);
                bool Taken = false;
                switch (Branch) {
                case O::Jz: Taken=Left==Right; break; case O::Jnz: Taken=Left!=Right; break;
                case O::Ja: Taken=Left>Right; break; case O::Jae: Taken=Left>=Right; break;
                case O::Jb: Taken=Left<Right; break; case O::Jbe: Taken=Left<=Right; break;
                case O::Js: Taken=Negative; break; case O::Jns: Taken=!Negative; break;
                case O::Jl: Taken=SignedLeft<SignedRight; break; case O::Jge: Taken=SignedLeft>=SignedRight; break;
                case O::Jle: Taken=SignedLeft<=SignedRight; break; case O::Jg: Taken=SignedLeft>SignedRight; break;
                case O::Jo: Taken=Overflow; break; case O::Jno: Taken=!Overflow; break;
                case O::Jp: Taken=Parity; break; case O::Jnp: Taken=!Parity; break;
                default: throw std::runtime_error("invalid test predicate");
                }
                auto Context = Inputs(Left); Context.Registers[2] = Right;
                InvokeCompiledProgram(Compiled, Context, false);
                Require(Context.Registers[0] == (Taken ? 20ULL : 10ULL), "shuffled conditional differs from native predicate");
                ++Cases;
            }
        }
    }
    std::cout << "VM control flow: OK (" << Cases << " native-result/edge cases, " << Traces.size()
              << " distinct loop layouts, nested calls and terminal fallthrough rejection)\n";
}

void Benchmark() {
    using Clock = std::chrono::steady_clock;
    constexpr std::uint64_t Iterations = 20000;
    const auto Source = ArithmeticProgram();
    const auto Compiled = CompileLiftedProgram(Source, 1);
    auto Measure = [&](bool Reuse) {
        std::uint64_t Checksum = 0;
        const auto Start = Clock::now();
        for (std::uint64_t I = 0; I < Iterations; ++I) {
            auto Context = Inputs(I);
            if (Reuse) InvokeCompiledProgram(Compiled, Context, false);
            else InvokeLiftedProgram(Source, Context, 1, false);
            Checksum += Context.Registers[0];
        }
        const auto Ns = std::chrono::duration<double, std::nano>(Clock::now() - Start).count();
        Require(Checksum == Iterations * (Iterations - 1) / 2 + 7 * Iterations,
                "benchmark result mismatch");
        return Ns / static_cast<double>(Iterations);
    };
    (void)Measure(false);
    (void)Measure(true);
    std::array<double, 5> OneShot{}, Cached{};
    for (std::size_t I = 0; I < OneShot.size(); ++I) {
        if (I % 2 == 0) { OneShot[I] = Measure(false); Cached[I] = Measure(true); }
        else { Cached[I] = Measure(true); OneShot[I] = Measure(false); }
    }
    std::sort(OneShot.begin(), OneShot.end());
    std::sort(Cached.begin(), Cached.end());
    std::cout << std::fixed << std::setprecision(1)
              << "VM call benchmark (4 IR instructions, 20000 calls/sample, median of 5)\n"
              << "compile each call: " << OneShot[2] << " ns/call\n"
              << "reuse compiled:    " << Cached[2] << " ns/call\n"
              << "speedup:           " << OneShot[2] / Cached[2] << "x\n";

    const auto Loop = CompileLiftedProgram(SumLoop(), 1);
    std::array<double, 5> LoopTimes{};
    for (auto& Time : LoopTimes) {
        std::uint64_t Checksum = 0;
        const auto Start = Clock::now();
        for (std::uint64_t I = 0; I < Iterations; ++I) {
            auto Context = Inputs(16);
            InvokeCompiledProgram(Loop, Context, false);
            Checksum += Context.Registers[0];
        }
        Time = std::chrono::duration<double, std::nano>(Clock::now() - Start).count() / static_cast<double>(Iterations);
        Require(Checksum == 136 * Iterations, "loop benchmark result mismatch");
    }
    std::sort(LoopTimes.begin(), LoopTimes.end());
    const auto Stats = GetCompilationStats(Loop);
    std::cout << "cached sum loop (N=16): " << LoopTimes[2] << " ns/call"
              << " | blocks=" << Stats.BasicBlocks << " relocated=" << Stats.RelocatedBlocks
              << " links=" << Stats.LinkInstructions << " encrypted bytes=" << Stats.BytecodeBytes << '\n';
}
} // namespace

int main(int Argc, char** Argv) {
    try {
        if (Argc == 2 && std::string_view(Argv[1]) == "--benchmark") Benchmark();
        else if (Argc == 1) { TestCompiledPrograms(); TestVmImage(); TestMutation(); TestControlFlow(); }
        else throw std::runtime_error("usage: VmRegression [--benchmark]");
        return 0;
    } catch (const std::exception& Error) {
        std::cerr << Error.what() << '\n';
        return 1;
    }
}
