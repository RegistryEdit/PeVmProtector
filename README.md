# PeVmProtector

A C++20 PE protector research prototype: it virtualizes native x64 functions
into a custom VM, encrypts whole images into `.pvm` containers, and hardens
the runtime with anti-debug, anti-dump and licensing layers — VMProtect-style
functionality rebuilt from scratch and strengthened.

[中文说明 → README_zh.md](README_zh.md)

- Verifies inputs are PE32/PE32+ (including native-subsystem driver `.sys`
  images);
- Encrypts the whole PE into a `.pvm` container (v5) carrying version,
  architecture, subsystem, compression state and integrity data;
- Derives the 128-bit content key by running randomized key-VM bytecode; every
  container gets its own opcode mapping;
- XTEA-CTR payload encryption with SHA-256 verification of the password and
  the unpacked result;
- Password derivation via scrypt (RFC 7914, default N=2^14, r=8, p=1, ~16 MiB
  memory hardness);
- `pack`, `unpack`, `inspect`, `vm-demo` and `self-test` commands.

The current version ships a runnable wrapper, manual PE mapping, a VM2
runtime and an x64 decoder/IR lifter. Functions are translated by RVA into
VM2 and executed through `.vmp3` plus runtime trampolines.

## Build

The project uses MSBuild `vcxproj` + an XML solution (`PeVmProtector.slnx`,
native format for VS 2022 17.13+ / VS 2026), organized by component:

```
PeVmProtector.slnx          Directory.Build.props        README.md / README_zh.md
Src\
  Apps\Cli\                 PeVmMain.cpp + PeVmCli.vcxproj     (command line)
  Apps\Stub\                Stub.cpp + PeVmStub.vcxproj        (loader)
  Apps\Gui\                 QtGui.cpp + PeVmProtectorGui.vcxproj (Qt6 GUI)
  Libs\Container\           .pvm container format/crypto/key-VM (PeVmContainer)
  Libs\Pe\                  validated PE file views and transactional file I/O
  Libs\Crypto\              SHA-256/HMAC/scrypt/XTEA-CTR/LZSS/Base64
  Libs\License\             product/device-bound ECDSA P-256 licenses (PEVM-LICENSE)
  Libs\Lifter\              x64 decoder/IR lifter/mutation
  Libs\Vm\                  VM2 runtime
  Libs\PeVmCore\            static-library project aggregating the libs
Tests\
  LifterFixture\  DependencyFixture\  VmRegression\  PeRegression\  RunTests.ps1
```

`PeVmCore.vcxproj` is a static library linked by the CLI, loader and VM
regression project via `ProjectReference`; the GUI launches the CLI as a
subprocess. Header directories are injected by
`Directory.Build.props` so `#include`s stay flat.

The PE build pipeline shares one immutable input snapshot across inspection,
batch lifting and in-memory container construction. Bounded RVA views reject
zero-fill and cross-section reads; output replacement preserves the previous
file when commit fails. Section layout is planned with checked arithmetic;
relocations are preflighted and mapped memory has exception-safe ownership.
See [PE architecture](Docs/PeArchitecture.md) for
module boundaries, compatibility changes and regression coverage.

```powershell
# Full build (or open PeVmProtector.slnx in Visual Studio)
msbuild PeVmProtector.slnx -p:Configuration=Release -m

# Tests
powershell -ExecutionPolicy Bypass -File Tests\RunTests.ps1 -Configuration Release

# Repeated VM-call microbenchmark (compile each call / reuse, median of 5)
bin\Release\VmRegression.exe --benchmark
```

- Output lands in `bin\Release\`: `PeVm.exe` (CLI), `PeVmStub.exe` (loader),
  `PeVmProtectorGui.exe` (Qt6 GUI) and test fixtures.
- The Qt6 GUI needs a Qt 6.x MSVC kit with **QFluentWidgets** (default
  `D:\Qt\6.7.3\msvc2022_64`, override with `msbuild ... /p:QtDir=<kit>`);
  Qt6Core/Gui/Widgets/Svg/Xml, QFluent/QWKCore/QWKWidgets DLLs and
  platforms/imageformats plugins are copied automatically after build.
- GUI theming uses `Theme::setThemeMode(Fluent::ThemeMode::DARK)`; controls
  are QFluent `PushButton`/`PrimaryPushButton`/`LineEdit`/`PasswordLineEdit`/
  `CheckBox`/`IndeterminateProgressRing`, notifications use `InfoBar`. Navigation uses
  `ToggleButton`; function selection uses `TableWidget`; labels, logs and scrolling
  use `BodyLabel`/`CaptionLabel`, `PlainTextEdit` and `ScrollArea`/`ScrollBar`.
- The GUI does not use moc: all signal connections are lambdas and the
  projects are plain vcxproj.
- UI language: English / 中文 one-click switching (persisted via QSettings).
- Code style: every identifier (types, functions, variables, parameters) is
  PascalCase across the codebase, file and directory names included; Windows/
  Qt/STL API names, entry points and string literals stay as-is.

### Select individual functions and resolve names

In **Function Virtualization**, click **Scan functions**, search by name or RVA,
check the desired rows, then click **Virtualize checked**. The checkbox state
controls the build; filtering retains checks on hidden rows and the counter
includes them. Scans start with no functions selected. Changing the input or
PDB clears stale choices. Manual RVA input remains available separately.

Names are recovered from PE exports, COFF function symbols and a matching local
PDB. PDBs are searched beside the input (including the recorded PDB filename)
and at the recorded build path; **Browse PDB** selects a different local file.
PDB GUID and age must match the PE. C++ names are demangled; original decorated
names and aliases appear in tooltips and scan JSON. An unavailable/mismatched
PDB is reported; unknown names remain `sub_RVA`, rather than invented names.
Inlined/removed functions and stripped binaries may have no recoverable name.
The GUI and CLI scanner include small functions by default; `--min-bytes=N`
can filter known sizes. The existing `protect-all` discovery policy is unchanged.

```powershell
bin\Release\PeVm.exe scan-functions app.exe functions.json --pdb=C:\symbols\app.pdb
bin\Release\PeVm.exe protect-functions app.exe selected.exe "build key" 0x1000 0x1234 --seed=12345
```

A name or checkbox does not imply that the x64 lifter supports that function.
Unsupported selected instructions still fail with an explicit error.

## Usage

```powershell
bin\Release\PeVmProtectorGui.exe
bin\Release\PeVm.exe wrap app.exe app.protected.exe "strong passphrase"
bin\Release\PeVm.exe pack app.exe app.pvm "strong passphrase"
bin\Release\PeVm.exe pack driver.sys driver.sys.pvm "strong passphrase"   # native .sys image
bin\Release\PeVm.exe inspect app.pvm          # also inspects wrappers
bin\Release\PeVm.exe vm-dump app.pvm
bin\Release\PeVm.exe unpack app.pvm restored.exe "strong passphrase"
bin\Release\PeVm.exe vm-demo "strong passphrase"
bin\Release\PeVm.exe virtualize-demo 10 12345 --trace
bin\Release\PeVm.exe call-memory-demo 10 12345 --trace
bin\Release\PeVm.exe vm2-self-test
bin\Release\PeVm.exe protect-function app.exe app.virtualized.exe "build key" 0x1000 0x1234
bin\Release\PeVm.exe protect-functions app.exe app.multi.exe "build key" 0x1000 0x1234 --anti-disasm
bin\Release\PeVm.exe protect-all app.exe app.all.exe "build key" 0x1234 --anti-disasm
bin\Release\PeVm.exe scan-functions app.exe scan.json
bin\Release\PeVm.exe lift-raw 4887D14889D0C3 0 --rcx=0x11 --rdx=0x22   # lift raw hex machine code
bin\Release\PeVm.exe license-machine-id
bin\Release\PeVm.exe license-keygen issuer.private issuer.pub
bin\Release\PeVm.exe license-issue issuer.private 30 --machine=<64hex> --product=my-product --output=customer.license
```

The GUI is a bilingual Qt6 / QFluent front-end driving the sibling `PeVm.exe`
with QProcess. All 22 existing CLI commands have GUI entries:

| Page | Operations |
| --- | --- |
| Container & Wrapper | `wrap`, `pack`, `unpack`, `inspect`, `vm-dump` |
| Function Virtualization | `scan-functions`, `protect-function`, `protect-functions`, `protect-all`, `lift-x64`, `lift-x64-multi` |
| License issuance | `license-keygen`, `license-export-public`, `license-machine-id`, `license-issue`, `license-verify` |
| Raw machine code | `lift-raw`, with entry RVA, seed, RCX/RDX/R8/R9 and trace |
| VM Demo | `virtualize-demo`, `call-memory-demo`, `vm-demo`, `vm2-self-test`, `self-test` |
| Protection options | Shared compression, watermark, signed-license public key and product ID |

Input/output/password fields appear on the container and function pages;
drag-and-drop, automatic output suggestion and password visibility remain
available. Function selection supports checked rows and manual comma-separated
RVAs. The function page also exposes scan and Protect ALL minimum sizes,
Protect ALL's `--allow-mem`, bridge trace, explicit manifest paths and export
of the current scan JSON. Blank manifest paths use the previous suffix-based
defaults. Demo seed/trace are independent of function analysis settings.

For licensing, choose **new** private/public file paths and generate a pair,
or open existing keys. Enter the product ID, customer machine ID and days
(0 = perpetual), then issue a license. A blank license path displays the card
for copying; a new file path also saves it. Verification uses the selected
license file and defaults to this machine when its ID field is blank.
**Use for protection** transfers the public key and product ID into Protection
options and enables licensing. Private keys use the current Windows user's
DPAPI; existing key/license files are never overwritten. See
[Licensing](Docs/Licensing.md) for deployment and recovery details.

The shared log supports clear/save, busy status and command timing. Build and
Key-VM passwords are redacted from command logs; issued card text appears only
in the license result field. `GuiFeatures.exe` exercises every command through
the real GUI, verifies the license lifecycle and a licensed wrapper execution,
and saves bilingual offscreen page renders under `bin/Release/TestArtifacts/GuiFeatures`.
It runs as part of `Tests/RunTests.ps1`; pass `-QtDir` when using another Qt kit.

`pack`, `wrap` and `protect-*` print a detailed build transcript by default.
Stages flush immediately, including when the CLI is launched by the GUI:
PE architecture/subsystem/entry and section layout; compression request and
actual result; cipher/KDF settings; function selection, skip reasons and
instruction counts before/after mutation; public license policy; wrapper
layout; final file size, output/input ratio, SHA-256 and elapsed times.
The selection rate counts discovered candidates, not all code in the PE.
Compression ratios describe stored payload bytes; the final executable also
includes the loader and metadata. Passwords, signing keys, full license tokens
and raw watermark text are excluded. `[complete]` appears only after the final
output is committed; failures identify the active stage and retain a nonzero
exit code. A nested temporary container does not emit a completion message.

Protected PEs use `.vmp0` as the loader/runtime section, `.vmp1` as the
read-only encrypted payload/VM data section. The original `.text` never
appears as a section inside the wrapper.

### Driver (.sys) support and delivery boundary

`.pvm` v5 records and verifies the PE subsystem: native (driver) images go
through the full container flow — `pack`/`unpack` round-trips byte-exact,
`inspect` reports `subsystem: native`, and `lift-x64`/`lift-x64-multi` plus
function-virtualization analysis work as usual. **Runnable wrappers are
user-mode only** (GUI/CUI): the stub's model is "in-process manual mapping +
entry call", which does not apply to drivers; native payloads are rejected
by `wrap`/`protect-function` with a clear message. Driver delivery (signing,
kernel loading) stays an external trusted step — the protected artifact is
the container itself.

### VMP feature comparison

- **Mutation**: `--mutate` performs per-build random mutation on the VM IR —
  `ADDI/SUBI` two's-complement swaps and power-of-two `MULI` → shift demotion
  both require an immediate successor that overwrites all flags without
  reading them. ADC/SBB, shifts/rotates and CALL/RET do not qualify.
  Junk instructions write scratch
  registers between real instructions (unique synthetic addresses, never
  branch targets). Seeded: one seed reproduces one mutation layout.
- **Watermark**: `--watermark=text` embeds a customer watermark XOR-obfuscated
  into the `.vmp2` metadata (v5); `inspect` decodes it. Not greppable in the
  binary.
- **Payload compression**: `pack --compress` (same option on wrap/protect-*)
  LZSS-compresses before encryption (4 KiB window, 3..18 byte matches);
  decompression happens before the SHA-256 check; incompressible inputs stay
  stored, so containers never grow.
- **Licensing**: `--license --license-public-key=<file> --license-product=<id>`
  enables ECDSA P-256/SHA-256 verification before payload execution.
  The wrapper contains a public key; the signing key stays in a DPAPI-protected
  file on the issuing machine. Licenses bind a case-sensitive product ID and
  a 64-hex-digit device ID, with optional expiry. Only `PEVM-LICENSE` is accepted;
  reissue all old cards and rebuild/distribute wrappers. There is no legacy
  compatibility switch. See [license issuance and migration](Docs/Licensing.md).
  Startup checks `PEVM_LICENSE`, then `<wrapper.exe>.license`, then a DPAPI-encrypted
  per-user cache. Invalid sources fall through only after their own signature,
  product, device and time checks fail. If no source validates, a native Windows
  dialog accepts and verifies a license; a successful entry is cached for that
  user and wrapper path. Cache entries are revalidated on every startup.
  The dialog uses Windows controls and needs no Qt/QFluent DLLs. Rebuild protected
  EXEs with the updated stub to enable it; existing valid signed licenses still work.
  Verification runs at startup. This offline scheme has no trusted time source
  or online revocation and does not prevent arbitrary clock rollback or client patching.
- **Import protection**: manual mapping plus runtime resolution means the
  on-disk IAT is never used — import protection is inherent.
- **Anti-debug / anti-dump**: see below.
- Honest gaps: virtual file system (VFS) and native-level mutation (mutation
  operates on the VM IR) are not implemented; full virtualization of
  pointer-dereferencing functions would need a pointer-emulation layer.

### Full virtualization (VMP style) and its boundary

`protect-all` is VMP-style "virtualize everything":

1. `scan-functions` discovers every function entry — RUNTIME_FUNCTION records
   from the exception directory (`.pdata`) provide candidates, exports add
   names;
2. each candidate is lifted independently (fail closed per function): the
   liftable ones land in **one multi-entry .vmp3**, and the loader installs a
   trampoline per entry;
3. unsupported functions are skipped with a precise reason. Common SSE/SSE2
   operations are supported. Eligible functions with EH/SEH handlers can use a
   register-only VM fragment while their exception frame stays native. AVX,
   legacy high-byte registers, atomic operations and chained unwind remain excluded.

Protected functions now use native pointers, image-relative address resolution,
an isolated VM stack, and native call bridges. Memory operands are enabled by
default; `--allow-mem` remains accepted for command-line compatibility.
Standalone `lift-raw`/analysis smoke execution retains its bounded flat-memory
model and cannot execute native calls.

`--min-bytes=N` (default 16) filters tiny IAT-thunk-grade candidates.

Container v5 adds a Compression byte (0=stored, 1=LZSS) over v4 and
redefines OriginalSize as the decompressed size; only v5 is accepted, older
containers fail with "unsupported container version". `.vmp2` metadata v5 replaces the shared license secret with a public verification key and product digest; older wrapper metadata is rejected.

The wrapper runs by double-click without a password. The build password is
sealed into per-build salt + stub/payload fingerprint key material with its
own integrity tag; the stub recovers it, decrypts the in-memory payload and
the `.vmp3` instruction table, then wipes the key buffers and the whole
wrapper image. Relocations/imports/TLS/unwind are processed before execution
— no temporary `Payload.exe` is created. Dependency DLLs load from the
wrapper's directory; working directory and command line stay compatible.

### Loader runtime hardening

- **Anti-debug checks** (fail-closed, at startup with a light re-check after
  unpacking):
  - Direct PEB reads: `BeingDebugged` (not the hookable API) and the
    `NtGlobalFlag` debug-heap flags;
  - `CheckRemoteDebuggerPresent`;
  - Hidden `NtQueryInformationProcess` triple check: `ProcessDebugPort`,
    `ProcessDebugObjectHandle`, `ProcessDebugFlags` (NoDebugInherit);
  - Hardware breakpoint registers Dr0-Dr3/Dr7;
  - Process scan (x64dbg/x32dbg/OllyDbg/IDA/WinDbg/dnSpy/Cheat Engine names)
    and loaded-module scan (Sandboxie/CE injection DLLs via the PEB LDR walk);
  - Classic debugger window-class scan (best effort, skipped when user32 is
    absent);
  - `OutputDebugString` last-error trick;
  - `int3` delivery check (a debugger swallowing the breakpoint counts as a
    hit);
  - Invalid-handle exception check (`CloseHandle` raising
    `STATUS_INVALID_HANDLE` under a debugger);
  - Fine-grained timing anomaly (a microsecond loop taking >2s) plus a 10s
    budget for the whole unpack+map phase;
  - Active hardening: `ThreadHideFromDebugger`;
  - **Resident watchdog thread**: every 250 ms it re-runs light checks (PEB
    reads + debug port) to catch debuggers attached after startup; hits exit
    fast (a foreign thread cannot unwind into the main handler).
  - Any hit exits with "loader integrity check failed", indistinguishable
    from other integrity failures.
- Development/CI escape hatch: `PEVM_ALLOW_DEBUGGER=1` disables all startup
  checks and the watchdog; `PEVM_TEST_FAKE_DEBUGGER=1` simulates a hit (used
  by the test runner to verify the fail-closed pipeline).
- Every bridge trampoline is read back after patching; function entries and
  the thunk page converge to `PAGE_EXECUTE_READ`; double-wrapping (entry
  already a trampoline) is rejected explicitly.
- Each mapped section is compared against the source buffer right after
  copying (headers + every section), before protections apply.
- **Runtime compatibility**: mapped PE headers remain read-only for CRT TLS
  guards, resources and exception handling. Static TLS uses an enlarged,
  Windows-managed wrapper slot; the loader restores the payload template and
  forwards process/thread notifications, including TLS destructors. Rebuild
  existing wrappers with the updated CLI and stub to reserve the correct size.
- **VM bridge compatibility**: trampolines align the stack before entering C++
  even for optimized internal leaf calls and register their x64 unwind data.
  MSVC exception image lookups recognize the mapped payload as well as loaded modules.
- Chained unwind fragments (such as shared epilogues) are rejected as VM entries;
  `protect-all` records the reason and leaves those fragments running natively.
  If no eligible functions remain, it emits an encrypted wrapper and explicitly
  reports zero virtualized functions; VM mutation and decoys are not applied.
- **At-rest code-page encryption (TextVault)**: every executable section is
  XTEA-CTR encrypted per page (key derived from the build password, domain
  `PEVM-TEXT-v1`), pages converge to `PAGE_NOACCESS`, and a front VEH
  decrypts a page on first execution/access (RW decrypt →
  `PAGE_EXECUTE_READ`, per-page atomic state machine, multi-thread safe);
  decrypted pages stay plaintext afterwards. A dump of a running (or
  suspended) process yields ciphertext + NOACCESS pages instead of a
  plaintext image. Limitations: an executed page stays plaintext for the
  process lifetime; the VEH is user-mode and payload-registered front VEHs
  sort after it.
- Error messages exposing the protection internals (`.vmp*` integrity, VM
  bridge, anti-debug, import/relocation) are compiled in as `consteval` XOR
  blobs and only reassembled at runtime; `PEVM_*` environment variable names
  and window class names are obfuscated the same way. None of these strings
  are greppable in the binary.
- **Sensitive IAT fully cleared**: all intent-revealing APIs (anti-debug,
  `VirtualAlloc/VirtualProtect`, VEH, Toolhelp, `NtQuery*`,
  `GetEnvironmentVariableW`, and the payload-import `LoadLibraryA`) are
  resolved at runtime via a **PEB LDR walk + export-table FNV-1a hash match**
  — never `GetModuleHandleW`/`GetProcAddress`/`LoadLibraryA`; forwarded
  exports (kernel32 → KERNELBASE etc.) are followed. The import table keeps
  only CRT boilerplate and fully generic runtime entries; module, function,
  environment-variable and window-class names are absent from the binary.
- Extra checks: `NtQuerySystemInformation(SystemKernelDebuggerInformation)`
  kernel-debugger detection and a classic debugger window-class scan.
- **VM program runtime validation**: the loader authenticates and validates the
  lifted image, compiles it once, then freezes encrypted bytecode, maps, offsets
  and tags in read-only pages. Source IR is released after compilation.
  Instruction tags, boundary CFI and fuel are checked during execution; calls
  no longer rescan the entire IR or bytecode.

Container password derivation (scrypt) happens at unpack time; the runtime
key material must ultimately be recoverable by the local loader, so this
raises the cost of static extraction — it does not claim unbreakable
client-side protection.

## VM image authentication and execution validation

VM images now use a full 32-byte HMAC-SHA256 tag over the header, function
entry table, encrypted instructions and decoy bytes. The loader authenticates
before allocating or decrypting the instruction table. Encryption,
authentication and per-function runtime seeds use separate derivation
purposes, bound to the build secret, seed and handler profile. XTEA-CTR
remains the instruction-table cipher.

The shared codec rejects unsupported internal formats, reserved fields,
empty/overlapping/gapped function ranges, duplicate function entries,
unclaimed bytes and truncated data. Functions are published to the bridge
only after every function has compiled successfully. The decoder wipes its
temporary decrypted table when it leaves scope, including exception paths.

Compilation validates instruction offsets, the whole-program checksum,
opcode/register maps, handler variants and operand lengths before freezing the
program. Execution verifies per-instruction tags and exact branch boundaries.
Lifted entry addresses are honored even when the entry is not the first
instruction. Runtime checksums detect corruption; they are not cryptographic
MACs or a guarantee against an attacker controlling the running process.

The compiler now shuffles basic blocks by function seed and reconnects
fallthrough and call-continuation edges. An explicit trap closes paths past
the last source instruction. Each instruction has an address-bound rolling
decode state with plaintext-prefix feedback; existing arithmetic handler
variants are selected per instruction. This is interpreter obfuscation;
whole-image HMAC authentication remains a separate layer.

On a same-machine Release microbenchmark, a four-IR instruction cached call
rose from about 265 ns to 287 ns; compiling on every call costs about 2,516 ns.
A cached sum loop with 16 iterations costs about 2.76 microseconds. Generated
link instructions consume fuel, so limits count emitted VM instructions.
These measurements are not whole-application estimates. Build output lists
authentication, decoding mode and per-function block/relocation/link/bytecode
counts. See `Docs/VmProtection.md` for implementation and verification details.

## VM instruction set

The VM has 16 64-bit logical registers (x64-numbered) + 8 physical scratch
registers, 4 KiB (configurable) flat virtual memory, data and call stacks and
a full x86-style flag set (ZF/CF/SF/OF/PF).

Arithmetic/logic: `MOVI`, `MOV`, `ADD/ADDI`, `SUB/SUBI`, `ADC/SBB` (carry and
borrow), `MUL/MULI`, `XOR`, `AND`, `ANDI`, `OR`, `NEG`, `NOT`, `BSWAP`,
`TEST`, `SHLI/SHRI/SARI` (immediate), `SHLR/SHRR/SARR` (register, count & 63),
`ROLI/RORI` (immediate rotate), `ROLR/RORR` (register rotate).

`ADD/ADDI/SUB/SUBI/XOR/AND/OR` each have **4 equivalent handler
implementations** (algebraic identities such as
`a+b = (a|b)+(a&b) = 2*(a&b)+(a^b)`), selected from the function profile and
each instruction's decoding context; rotates
follow x86 rotate semantics (only CF/OF move, ZF/SF/PF preserved), `BSWAP` is
a pure byte-order reversal.

Control flow: `JMP`, `JZ/JNZ`, `JA/JAE/JB/JBE` (unsigned), `JS/JNS`,
`JL/JGE/JLE/JG` (signed), `JO/JNO`, `JP/JNP` (parity), `CALL/RET` (RET on an
empty call stack returns to the native caller, i.e. Halt semantics). All
branch targets are decrypted on the fly by VIP and must land on instruction
boundaries (CFI).

Memory: `LOAD64/STORE64` (register offset) and `LOAD64D/STORE64D` (base
register + immediate displacement); out-of-bounds fails closed.

Every VM instruction carries an independent 64-bit corruption-check tag — tampering
with a single instruction fails before the dispatcher. `ADD/ADDI/SUB/SUBI/
XOR/AND/OR` have equivalent handler implementations selected per
instruction; `Cmp/Test/Add/Sub/Adc/Sbb` and shifts derive all flags from operands
and result. Fuel (default 100000) and memory size are configurable per run.

`vm2-self-test` runs differential tests over 3 opcode maps: factorial (63
cases), call/memory (303), branch/flags (792, all 16 condition codes),
arith/memory (792, extended ALU + base+displacement addressing + data stack +
scratch), logic (792, AndI/Neg/Not/Adc/Rol/Ror/Bswap), a handler-variant
sweep (each variant value 0..3 pinned, factorial/call-memory reruns), 39
tamper/layout cases, and OOB/fuel rejection.

## VMProtect-style virtualization core

The factorial logic in `virtualize-demo` never executes as a native loop — it
is assembled into VM2 bytecode first:

1. every seed gets its own opcode and register mapping;
2. each bytecode record is encoded with an address-bound rolling state;
3. the runtime decrypts and executes it through a handler dispatcher;
4. the VM maintains VIP, 16 virtual registers, full flags, data/call stacks
   and virtual memory;
5. the interpreter never materializes the full plaintext bytecode.

`call-memory-demo` covers the virtual data stack, CALL/RET, encrypted branch
targets, virtual memory `STORE64/LOAD64` and instruction-boundary CFI.

## x64 function lifting (VM2)

The loader calls `CompileLiftedProgram` once per function when loading
`.vmp3`; subsequent bridge calls reuse encrypted bytecode in read-only pages
through `InvokeCompiledProgram`. Registers, flags and VM state remain local
to each invocation. Full layout/integrity validation happens before publication;
instruction authentication, CFI and fuel remain active during execution.
Sequential instructions use a boundary cursor and opcode lookup table.
Source IR is released, and register-only native leaf functions skip VM stack
allocation and copying. `InvokeLiftedProgram` remains the one-shot API.
Rebuild existing wrappers with matching CLI and loader binaries.

`VmRegression.exe` checks reuse, snapshot independence from modified source
IR, 4,000 concurrent calls, state isolation, OOB/fuel rejection, a non-first
entry address, 5,808 image tamper/truncation/structural rejections, and 4,608
mutation/flags differential cases. Another 9,536 native-result/control-flow
checks cover all conditional branches, shuffled loops, nested calls and
terminal fallthrough; 64 seeds produce 23 distinct loop layouts.
`--benchmark` compares compilation per call against reuse for four IR
instructions and reports a cached loop workload; it is not an application-level
speedup measurement. GUI command logs redact build passwords. License settings accept only a public key file and product ID; private signing keys are never passed to protection commands.

The conservative x64 lifter accepts an RVA in a PE32+ x64 executable, decodes
basic blocks (linear sweep plus a branch-target worklist so code past an
early `ret` is still covered), emits a JSON IR manifest (`pevm-x64-lift`),
assembles the IR into the randomized/encrypted VM2 format and invokes it
through the native/VM register bridge:

```powershell
PeVm lift-x64 Input.exe 0x1000 Function.vm2.json 0x1234 --rcx=1 --rdx=2 --r8=4 --r9=8 --trace
```

The bridge captures all 16 integer registers, XMM0–XMM15 and flags. The entry
uses a five-byte relative jump to a nearby thunk, with registered x64 unwind
metadata. The instruction stream carries explicit operand widths (VM image
revision 6; rebuild older wrappers to use the new runtime).

Supported integer operations include 8/16/32/64-bit MOV and ALU operations,
ADC/SBB, IMUL, NEG/NOT, INC/DEC, shifts/rotates, MOVZX/MOVSX/MOVSXD,
32/64-bit BSWAP, SETcc register/memory forms, CMOVcc, LEA, PUSH/POP,
conditional branches, and direct/indirect native CALL and tail JMP. Instruction
forms with legacy AH/BH/CH/DH operands remain rejected. Address arithmetic and
extensions preserve flags; 32-bit writes clear the upper half, and 8/16-bit
writes preserve it. Memory loads/stores use the actual operand width.

Native pointer, RSP/RBP, SIB and RIP-relative operands are supported in protected
executables. Functions needing a stack lease a 72 KiB buffer from a per-thread
FLS pool, with separate buffers for recursive/reentrant calls. This provides
64 KiB of local stack and copies up to 4 KiB of incoming data within the thread
stack bounds, without repeatedly allocating and clearing the entire buffer.
Native calls copy a 512-byte outgoing argument area onto a real Windows stack
and preserve XMM arguments/results and MXCSR. Native callee C++ exceptions can
unwind through the bridge. Eligible EH/SEH functions virtualize a straight-line,
nonfaulting register fragment after their prologue; native calls, exception
scopes, handlers and epilogues stay in place. Logs report `full VM functions`
and `native EH fragments` separately. Chained unwind, segment-based TLS operands,
legacy high-byte registers, LOCK/atomic memory operations, setjmp/longjmp and
arbitrary stack switching remain unsupported.

The test runner (`Tests/RunTests.ps1`) has the fixture self-report function
RVAs, runs bridge differentials per function (loops, branches, shifts, VM
memory access, MOVZX/MOVSX/MOVSXD, NEG/NOT, SETcc, Group1 memory+immediate,
accumulator short forms), plus 34 deterministic `lift-raw` decode differentials
over hand-assembled bytes (XCHG, PUSH imm, SETcc, ADC/SBB carry chains, rotations,
etc.); it verifies stack-parameter execution and explicitly rejects CPUID and
LOCK operations. `VmRegression.exe` also compares 164,640 operand-width cases
against native CPU execution, checks a byte load beside a guard page, and
exercises six-argument calls, XMM returns and C++ exception unwinding.
`loader_tls_and_qt` explicitly virtualizes `LoaderCallWithStack`, `LoaderSimd`,
`LoaderExceptionFragment` and `LoaderSehFragment`. It requires actual VM entry
markers and checks stack arguments, thread/reentrant calls, SIMD results,
C++ catch and SEH behavior with mutation enabled.
Bridge tracing initializes its state before payload TLS is bound, so enabling
the test log does not depend on the payload's CRT static-initialization epoch.
`protected_function_vm_bridge` proves
end-to-end that protect-function trampolines reach VM2;
`protected_multi_vm_bridge` proves one command can virtualize two functions
with both trampolines hitting VM2 correctly; `protect_all_virtualization`
covers the full-virtualization pipeline; `mutation_and_watermark` covers
mutation differentials and watermark round-trips; `licensing_and_compression`
covers signed license issuance, all protection commands, source fallback, invalid/legacy license rejection, public-only wrapper metadata, and compression round-trips. `LicenseRegression.exe` additionally covers cryptographic tampering, time boundaries, malformed inputs, and DPAPI key lifecycle. `LicenseRuntime.exe` exercises the real bilingual native dialog, retry/cancel, encrypted-cache isolation, first activation, remembered startup, corruption recovery and cache-write failure. Tests require the current Windows user DPAPI profile and an interactive desktop; dialog screenshots are saved under `bin/Release/TestArtifacts/license-runtime-*`.


## SIMD coverage and Qt performance verification

Supported SSE/SSE2 forms include packed/scalar moves; PS/PD/SS/SD arithmetic,
MIN/MAX/SQRT; logical operations; COMI/UCOMI and conversions; packed integer
add/subtract, comparisons, low-word multiply, unpack and shuffle. The bridge
preserves XMM0–XMM15 and MXCSR. Scalar memory access uses its actual 4/8-byte
width. This is a subset of SSE/SSE2, not complete AVX/AVX2/AVX-512 support.

`VmRegression.exe` compares 85,632 SIMD cases against the CPU, including four
rounding modes, DAZ/FTZ, NaN payloads, flags and memory boundaries. It also tests
SIMD image round trips, authenticated EH resume metadata and unsafe-fragment
rejection. `Tests/QtPerformance.ps1` measures 31 Qt timer callbacks with 2,000
calls each to the same explicitly protected export, checking the final checksum.
Pass `-BaselineExe` to compare an earlier protected fixture. Timings are recorded,
not enforced as fixed thresholds on a shared machine. `Tests/WindowResponsiveness.ps1`
samples WM_NULL response latency of freshly started applications; it does not
exercise post-login business operations. Whole-application performance needs a
representative workload: hot UI/rendering functions can still incur VM overhead.
