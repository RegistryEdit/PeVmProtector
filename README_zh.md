# PeVmProtector

一个 C++20 的 PE 保护器研究原型：

- 校验输入是否为 PE32/PE32+（含 native 子系统的驱动 `.sys` 镜像）；
- 将完整 PE 加密为带版本、架构、子系统、压缩状态与完整性信息的 `.pvm` 容器（v5）；
- 用自定义寄存器 VM 执行 bytecode 派生 128-bit 内容密钥；每个容器随机化 opcode 编码；
- 使用 XTEA-CTR 加密，SHA-256 校验口令和解包结果；
- 容器口令派生使用 scrypt（RFC 7914，默认 N=2^14、r=8、p=1，约 16 MiB 内存难度）；
- 支持 `pack`、`unpack`、`inspect`、`vm-demo` 和 `self-test`。

当前版本包含可运行 wrapper、手工 PE 映射、VM2 runtime，以及 x64 decoder/IR lifter。用户可按函数 RVA 把受支持的基本块翻译到 VM2，并通过 `.vmp3` 与运行时 trampoline 执行。

PE 构建流程现已统一使用经过校验的 `ImageView`：容器、Lifter、构建日志和加载器共用结构规则；批量虚拟化从同一份输入快照解码，禁止把零填充区或下一个节当作当前代码读取。`PackContainer()` 在内存中传递容器，wrapper 不再读写 `.payload.tmp`。最终输出采用独占临时文件、刷盘和替换提交，提交失败保留旧文件。模块职责、兼容性变化与测试说明见 [PE 架构文档](Docs/PeArchitecture.md)。
新增节区先完成整数边界和布局检查；构建端与运行时共享重定位校验，映射内存通过 RAII 在异常路径自动释放。

## 构建

工程形式为 MSBuild `vcxproj` + XML 解决方案（`PeVmProtector.slnx`，VS 2022 17.13+ / VS 2026 原生格式），目录按组件分层：

```
PeVmProtector.slnx          Directory.Build.props        README.md / README_zh.md
Src\
  Apps\Cli\                 PeVmMain.cpp + PeVmCli.vcxproj     （命令行入口）
  Apps\Stub\                Stub.cpp + PeVmStub.vcxproj        （loader）
  Apps\Gui\                 QtGui.cpp + PeVmProtectorGui.vcxproj（Qt6 界面）
  Libs\Container\           .pvm 容器格式/加解密/key-VM（PeVmContainer）
  Libs\Pe\                  PE 文件视图、边界校验与文件提交
  Libs\Crypto\              SHA-256/HMAC/scrypt/XTEA-CTR/LZSS/Base64
  Libs\License\             产品/机器绑定签名卡密（ECDSA P-256）
  Libs\Lifter\              x64 解码器/IR lifter/变异
  Libs\Vm\                  VM2 runtime
  Libs\PeVmCore\            静态库工程（聚合以上库源）
Tests\
  LifterFixture\  DependencyFixture\  VmRegression\  PeRegression\  RunTests.ps1
```

`PeVmCore.vcxproj` 是静态库，CLI、loader 与 VM 回归测试经 `ProjectReference` 链接它；GUI 通过子进程调用 CLI。头文件目录由 `Directory.Build.props` 统一注入，`#include` 保持平铺文件名。

```powershell
# 全量构建（或用 Visual Studio 打开 PeVmProtector.slnx）
msbuild PeVmProtector.slnx -p:Configuration=Release -m

# 测试
powershell -ExecutionPolicy Bypass -File Tests\RunTests.ps1 -Configuration Release

# VM 重复调用微基准（每次编译 / 复用编译结果，5 轮中位数）
bin\Release\VmRegression.exe --benchmark
```

- 输出位于 `bin\Release\`（`PeVm.exe`、`PeVmStub.exe`、`PeVmProtectorGui.exe` 与测试夹具）。
- Qt6 GUI 需要 Qt 6.x MSVC kit 且内置 **QFluentWidgets**（默认路径 `D:\Qt\6.7.3\msvc2022_64`，可用 `msbuild ... /p:QtDir=<kit路径>` 覆盖）；构建后自动拷贝 Qt6Core/Gui/Widgets/Svg/Xml、QFluent/QWKCore/QWKWidgets DLL 与 platforms/imageformats 插件。
- GUI 主题用 `Theme::setThemeMode(Fluent::ThemeMode::DARK)`，控件为 QFluent 的 `PushButton`/`PrimaryPushButton`/`LineEdit`/`PasswordLineEdit`/`CheckBox`/`IndeterminateProgressRing`，提示用 `InfoBar`；导航列因 QFluent `NavigationBar` 无公开展开 API 而采用原生可勾选按钮（选中高亮）。
- GUI 不使用 moc：全部信号连接走 lambda，工程为普通 vcxproj。界面支持中英文一键切换（QSettings 持久化）。
- 代码规范：全库标识符（类型、函数、变量、参数）统一大驼峰（PascalCase），文件与目录名同样大驼峰（`Src/`、`Tests/`、`PeVmMain.cpp` 等）；Windows/Qt/标准库 API 名、入口函数与字符串字面量保持原样。

## 使用

```powershell
bin\Release\PeVmProtectorGui.exe
bin\Release\PeVm.exe wrap app.exe app.protected.exe "strong passphrase"
bin\Release\PeVm.exe pack app.exe app.pvm "strong passphrase"
bin\Release\PeVm.exe pack driver.sys driver.sys.pvm "strong passphrase"   # native .sys 镜像
bin\Release\PeVm.exe inspect app.pvm          # 也可 inspect 一个 wrapper EXE
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
bin\Release\PeVm.exe lift-raw 4887D14889D0C3 0 --rcx=0x11 --rdx=0x22   # 直接提升十六进制机器码
bin\Release\PeVm.exe license-machine-id
bin\Release\PeVm.exe license-keygen issuer.private issuer.pub
bin\Release\PeVm.exe license-issue issuer.private 30 --machine=<64hex> --product=my-product --output=customer.license
```

GUI 为 Qt6 界面（QProcess 驱动同目录的 `PeVm.exe`）：顶部是输入/输出/口令共享区（支持把文件直接拖到输入框，自动建议输出路径，口令可切换明文显示），左侧为 Fluent 导航列，右侧按「Container & Wrapper / Function Virtualization / VM Demo」三个页面组织操作，底部是等宽字体的运行日志、忙碌指示环与状态栏（显示每步用时）。函数虚拟化页的 RVA 输入框可填多个（逗号分隔时自动走多函数 `protect-functions`），并提供 Scan functions（自动发现函数）与 Protect ALL（全量虚拟化）按钮。

`pack`、`wrap` 和 `protect-*` 默认输出详细构建日志，各阶段即时刷新到终端或 GUI 日志区：

- 输入 PE 的大小、架构、子系统、入口 RVA，以及各节的地址、文件偏移、大小和读写执行属性。
- 压缩是否启用、实际采用 LZSS 还是原样存储、压缩后大小与节省字节数，加密算法与 KDF 参数。
- 函数候选数、选中数、跳过原因、基本块数、变异前后指令数，以及卡密公钥指纹和产品摘要。
- wrapper 布局、最终文件大小、相对输入的比例、SHA-256、阶段耗时及总耗时。

函数选择率仅针对已发现候选，不代表整个 PE 的代码覆盖率；压缩比例针对载荷，最终 EXE 还包含 loader 和元数据。日志不输出口令、签发私钥、完整卡密或原始水印。只有最终文件成功写入才输出一次 `[complete]`；失败会标出当前阶段、输出原因并返回非零退出码，中间临时容器不会误报整个任务完成。

保护后的 PE 使用 `.vmp0` 作为 loader/runtime 代码节，`.vmp1` 作为只读加密 payload/VM 数据节。原始程序的 `.text` 不以原 section 形式出现在 wrapper 中。

### 驱动 (.sys) 支持与交付边界

`.pvm` 容器 v5 记录并校验 PE 子系统：native（驱动）镜像可以走完整的容器保护流程——`pack`/`unpack` 往返字节一致、`inspect` 显示 `subsystem: native`、`lift-x64`/`lift-x64-multi` 与函数虚拟化分析照常工作。**可运行 wrapper 仅支持用户态子系统**（GUI/CUI）：stub 的保护与执行模型是"进程内手工映射 + 调用入口"，对驱动不适用；对 native 载荷 `wrap`/`protect-function` 会明确拒绝。驱动的交付（签名、内核加载）是外部可信环节——保护产物是容器本身。

### VMP 对照功能

- **Mutation 变异**：`--mutate` 在 VM IR 层做逐构建随机变异——`ADDI/SUBI` 按补码互换、2 的幂 `MULI` 降为移位；两者都要求紧接的指令不读取旧 flags 且完整覆写 flags。`ADC/SBB`、移位/循环移位、`CALL/RET` 不满足此条件。另在真实指令之间注入写 scratch 的垃圾指令（唯一合成地址、永不被分支引用）。种子化：同一 seed 复现同一变异布局。
- **水印**：`--watermark=text` 把客户水印以 XOR 混淆写入 `.vmp2` 元数据（v5），`inspect` 解码显示；二进制里 grep 不到明文。
- **payload 压缩**：`pack --compress`（wrap/protect-* 同名选项）在加密前做 LZSS 压缩（4 KiB 窗口、3..18 字节匹配）；解密后先解压再校验 SHA-256；不可压的输入自动保持存储形态，容器永不膨胀。
- **许可系统**：`--license --license-public-key=<file> --license-product=<id>` 启用 ECDSA P-256/SHA-256 签名验证。wrapper 仅嵌入公钥和产品摘要，签发私钥由签发端 Windows 用户 DPAPI 保护；卡密绑定产品 ID、64 位十六进制机器码和可选有效期。仅接受 `PEVM-LICENSE`，旧卡需重新签发，旧 EXE 需重新构建并分发，没有兼容开关。环境变量 `PEVM_LICENSE` 优先，只有变量不存在才读取 `<完整EXE文件名>.license`；错误/空值/超长输入拒绝执行。离线校验在启动时进行，不提供在线吊销或完整防时钟回拨能力。详见[签发与迁移说明](Docs/Licensing.md)。
- **导入保护**：手工映射 + 运行期解析意味着磁盘 IAT 从不使用，导入保护天然成立。
- **反调试/反 dump**：见下节。
- 差距（诚实声明）：虚拟文件系统（VFS）、native 级 mutation（我们变异的是 VM IR）尚未实现；内存访问函数的全量虚拟化需要指针模拟层。

### 全量虚拟化（VMP 风格）与边界

`protect-all` 是 VMP 式 "virtualize everything"：

1. `scan-functions` 自动发现全部函数入口——异常目录（`.pdata`）的 RUNTIME_FUNCTION 提供候选，导出表补充函数名；
2. 每个候选独立尝试提升（fail closed per function）：能提升的打进**同一个多入口 .vmp3**，loader 为每个函数安装独立 trampoline；
3. 不能提升的跳过并逐个报告原因（间接调用、RSP 基址、CPUID、RIP-relative 等都会 fail closed 而非错误翻译）。

安全边界：lifter 把内存操作数翻译为 **VM 平坦内存偏移**而非 native 指针，因此 `protect-all` 默认**跳过任何含内存访问的函数**（它们保持 native 原样执行），`--allow-mem` 可显式接受 VM 内存语义（用于明知指针实为 VM 偏移的载荷）；非叶子函数（CALL 外部目标）会因分支目标校验失败被跳过。这正是与 VMP 真实全量虚拟化的本质差距——VMP 用完整指针模拟层解决重定位，本原型对"叶子、无指针"函数做真虚拟化，其余保持原生，绝不错误翻译。

`--min-bytes=N`（默认 16）过滤微小的 IAT thunk 级候选。

`.pvm` 容器 v5 在 v4 基础上增加了 Compression 字节（0=存储，1=LZSS）并重定义 OriginalSize 为解压后大小；只接受 v5，v4 及更早容器会得到明确的 "unsupported container version" 错误。`.vmp2` 元数据 v5 用公钥和产品摘要替代旧共享密钥字段，拒绝旧版 wrapper 元数据。

Wrapper 双击直接运行，不要求最终用户输入口令。构建口令经逐构建 salt、stub 指纹和 payload 指纹封装为运行密钥材料，并带独立完整性标签；stub 自动恢复后立即解密内存 payload 与 `.vmp3` 指令表，再清零密钥缓冲与整段 wrapper 镜像。随后处理重定位/import/TLS/unwind 后执行，不创建临时 `Payload.exe`。依赖 DLL 从 wrapper 原目录加载，工作目录和命令行参数保持兼容。

### Loader 运行时加固

- **反调试检查**（fail-closed，全部在启动时执行，解包后还会轻量复查一次）：
  - 直接 PEB 直读：`BeingDebugged`（不经过可被 hook 的 API）与 `NtGlobalFlag` 调试堆标志；
  - `CheckRemoteDebuggerPresent`；
  - 动态解析 `NtQueryInformationProcess` 三重检查：`ProcessDebugPort`、`ProcessDebugObjectHandle`、`ProcessDebugFlags`（NoDebugInherit）；
  - 硬件断点寄存器 Dr0-Dr3/Dr7；
  - 进程列表扫描（x64dbg/x32dbg/OllyDbg/IDA/WinDbg/dnSpy/Cheat Engine 等已知调试器进程名）与已加载模块扫描（Sandboxie/Cheat Engine 注入 DLL 等，复用 PEB LDR 遍历）；
  - 经典调试器窗口类扫描（best-effort，user32 未映射时跳过）；
  - `OutputDebugString` last-error 技巧；
  - `int3` 投递检查（调试器吞掉断点异常则视为命中）；
  - 无效句柄异常检查（`CloseHandle` 在调试器下抛 `STATUS_INVALID_HANDLE`）；
  - 细粒度时序异常（微秒级循环超 2 秒即触发）与整体解包+映射耗时预算（10 秒）；
  - 主动加固：`ThreadHideFromDebugger` 隐藏加载线程；
  - **常驻看门狗线程**：每 250ms 重跑轻量检查（PEB 直读 + debug port），捕捉启动检查之后才 attach 的调试器；命中即快速退出（外部线程无法向主线程的异常处理器 unwind，只能 fail-fast）。
  - 任何一项命中都以与其他完整性失败不可区分的 "loader integrity check failed" 退出。
- 开发/CI 逃生阀：`PEVM_ALLOW_DEBUGGER=1` 同时禁用全部启动检查与看门狗线程；`PEVM_TEST_FAKE_DEBUGGER=1` 模拟检查命中（供 `loader_anti_debug` 测试验证 fail-closed 管线）。
- 每个函数的桥接 trampoline 写入后读回比对；函数入口与 thunk 页统一收敛 `PAGE_EXECUTE_READ`；重复 wrap（入口已是 trampoline）会被明确拒绝。
- 明文 payload 逐节拷贝到映射镜像后立即与源 buffer 比对（头部 + 每节），再应用节保护。
- **反 dump**：重定位/import/TLS 处理完成后、移交入口前，擦除映射镜像的 PE 头（节保护改为可写→清零→只读）。
- **代码页 at-rest 加密（TextVault）**：payload 的全部可执行节逐页用 XTEA-CTR 加密（密钥由构建口令派生，域 `PEVM-TEXT-v1`），页保护收敛为 `PAGE_NOACCESS`，并注册前端 VEH：首次执行/访问某页时按需解密该页（RW 解密 → `PAGE_EXECUTE_READ`，进程内以原子状态机去重，多线程竞态安全），之后该页保持明文。运行中（或挂起后）对进程做内存 dump 得到的是密文 + NOACCESS 页，而不是完整明文代码镜像。限制：页面一旦执行过在本进程内保持明文；VEH 属用户态，先于帧 SEH 运行，payload 自注册的前端 VEH 会排在其后。
- loader 中暴露保护内部结构的错误消息（`.vmp*` 完整性、VM 桥、反调试、import/relocation 等）以 `consteval` XOR 形式编译进二进制，运行期才还原；`PEVM_*` 环境变量名与窗口类名同样混淆。二进制中不再能 grep 到这些明文。
- **敏感 IAT 彻底清除**：所有意图性 API（反调试、`VirtualAlloc/VirtualProtect`、VEH、Toolhelp、`NtQuery*`、`GetEnvironmentVariableW`，以及 payload 依赖解析用的 `LoadLibraryA`）全部经 **PEB LDR 遍历 + 导出表 FNV-1a 哈希匹配**在运行期解析——不经 `GetModuleHandleW`/`GetProcAddress`/`LoadLibraryA`，转发导出（kernel32 → KERNELBASE 等）会被跟随解析。导入表只剩 CRT 样板与完全通用的运行时入口，静态导入分析不再暴露任何加载意图；模块/函数/环境变量/窗口类名在二进制中均无明文。
- **新增检测**：`NtQuerySystemInformation(SystemKernelDebuggerInformation)` 内核调试器检测（捕捉不进用户态 PEB/handle 视野的内核调试），以及经典调试器窗口类扫描（best-effort，user32 未映射时跳过）。
- **VM 程序运行时防篡改**：loader 在载入每个 lifted program 时计算摘要，VM 桥每次调用前重新校验——VM 逐指令认证标签在装配时生成，防不住运行期对内存中 lifted program 的堆补丁，摘要校验封住了这个向量。

容器口令派生（scrypt）在解包时执行；运行所需密钥最终必须可由本机 loader 恢复，因此该封装用于提高静态提取成本，而不是宣称密钥在客户端绝对不可恢复。

## VM 指令集

VM 有 16 个 64-bit 逻辑寄存器（x64 编号映射）+ 8 个物理 scratch 寄存器、4 KiB（可配置）flat 虚拟内存、数据栈、调用栈和完整 x86 风格标志（ZF/CF/SF/OF/PF）。

算术/逻辑：`MOVI`、`MOV`、`ADD/ADDI`、`SUB/SUBI`、`ADC/SBB`（进位/借位）、`MUL/MULI`、`XOR`、`AND`、`ANDI`、`OR`、`NEG`、`NOT`、`BSWAP`、`TEST`、`SHLI/SHRI/SARI`（立即数）、`SHLR/SHRR/SARR`（按寄存器移位，count & 63）、`ROLI/RORI`（立即数循环移位）、`ROLR/RORR`（按寄存器循环移位）。

`ADD/ADDI/SUB/SUBI/XOR/AND/OR` 每个拥有 **4 种等价 handler 实现**（代数恒等式，如 `a+b = (a|b)+(a&b) = 2*(a&b)+(a^b)`），逐构建随机选择；循环移位遵循 x86 rotate 语义（只动 CF/OF，ZF/SF/PF 保持），`BSWAP` 为纯字节序反转。

控制流：`JMP`、`JZ/JNZ`、`JA/JAE/JB/JBE`（无符号）、`JS/JNS`、`JL/JGE/JLE/JG`（有符号）、`JO/JNO`、`JP/JNP`（奇偶）、`CALL/RET`（RET 在空调用栈时返回 native 调用方，即 Halt 语义）。所有分支目标按 VIP 即时解密并要求落在指令边界上（CFI）。

内存：`LOAD64/STORE64`（寄存器偏移）与 `LOAD64D/STORE64D`（基址寄存器 + 立即数偏移），越界即 fail closed。

每条 VM 指令都有独立认证标签，篡改单条指令会在 dispatcher 进入前失败。`ADD/ADDI/SUB/SUBI/XOR/AND/OR` 有逐构建随机选择的等价 handler 实现；`Cmp/Test/Add/Sub/Adc/Sbb` 及移位按操作数和结果推导全部标志。fuel（默认 100000）与内存大小可按次执行配置。

`vm2-self-test` 对 3 套指令映射做差分测试：factorial 63 组、call/memory 303 组、branch/flags 792 组（覆盖全部 16 个条件码）、arith/memory 792 组（覆盖扩展 ALU、基址+位移寻址、数据栈与 scratch）、logic 792 组（AndI/Neg/Not/Adc/Rol/Ror/Bswap），外加 handler 变体全值扫描（每个 variant 值 0..3 固定后重跑 factorial/call-memory 差分）与 6 组防篡改、越界与 fuel 用例。

## VMProtect 风格虚拟化核心

`virtualize-demo` 中的 factorial 逻辑不会以 native factorial 循环执行，而是先汇编成 VM2 bytecode，随后：

1. 每个 seed 生成独立 opcode 映射与寄存器映射；
2. bytecode 整体流加密；
3. runtime 解密后由 handler dispatcher 执行；
4. VM 内维护 VIP、16 个虚拟寄存器、完整 flags、数据栈、调用栈和虚拟内存；
5. 解释器执行时不再复制出完整明文 bytecode。

`call-memory-demo` 覆盖虚拟数据栈、CALL/RET、加密分支目标、虚拟内存 `STORE64/LOAD64` 和 instruction-boundary CFI。

## VM 数据认证与执行检查

VM 镜像使用完整的 32 字节 HMAC-SHA256 标签，覆盖头部、函数入口表、加密指令和干扰区；加载器在分配、解密指令表之前验证标签。加密、认证和各函数的运行时种子分别派生，并绑定构建口令、种子和 handler profile。磁盘指令表仍使用 XTEA-CTR。

共享编解码器拒绝保留字段异常、空函数、范围重叠或空洞、重复入口、未归属字节和截断数据。所有函数编译成功后才发布到桥接表；临时解密表在正常返回及异常退出时清零。

运行时把指令边界表和 64 位逐指令标签纳入整段校验，验证 opcode/register 映射与 handler 变体，执行前检查指令长度，操作数读取限定在当前指令内。入口不在首条指令时也从指定入口执行。运行时校验属于损坏检测，不是密码学 MAC；原有 IR 摘要检查仍保留。

VM 编译器按函数种子重排基本块，并连接条件分支的未跳转路径、CALL 返回位置与其他顺序执行边。末尾没有合法后继时生成终止陷阱，避免重排后意外执行相邻块。每条指令建立独立解码状态，opcode 与操作数前缀逐字节参与后续解码；已有算术 handler 的选择也随指令位置变化。这些属于运行时混淆，整段 HMAC 认证继续独立生效。

新增 9,536 个控制流结果/边界用例，64 个种子下观察到 23 种循环布局；原有 5,808 个镜像拒绝用例、39 个运行时篡改/布局场景和 4,608 个变异差分继续通过。一次同机 Release 基准中，4 条 IR 的缓存调用从约 265 ns 增至 287 ns；固定 16 次迭代的求和循环约 2.76 微秒。构建日志逐函数显示块数、重排块数、连接指令数和加密字节数。实现细节及验证命令见 `Docs/VmProtection.md`。

## x64 function lifting (VM2)

loader 在加载 `.vmp3` 时为每个函数调用一次 `CompileLiftedProgram`，后续桥接通过 `InvokeCompiledProgram` 复用不可变的加密字节码。每次调用仍独立创建寄存器、flags、数据栈、调用栈和 VM 内存，并保留 IR 摘要、字节码完整性、逐指令标签、CFI 与 fuel 检查。`InvokeLiftedProgram` 保留为一次性编译并执行的兼容入口。缓存会增加每个已加载函数的常驻字节码内存，换取重复调用时省去组装和加密的开销。本次块重排与滚动解码沿用已升级的认证镜像格式；已有 wrapper 需要重新生成才会使用新 loader，命令名称保持不变。

`VmRegression.exe` 覆盖编译结果复用、源 IR 修改后的快照独立性、4,000 次并发调用、跨调用状态隔离、越界/fuel 拒绝，以及 4,608 组变异 flags 差分。`--benchmark` 对 4 条 IR 指令比较每次编译与复用执行，不能据此推算完整应用的加速倍数。GUI 的命令日志将构建口令显示为 `<redacted>`；卡密设置使用公钥文件和产品 ID，签发私钥不传给保护命令。

The conservative x64 lifter accepts an RVA in a PE32+ x64 executable, decodes
basic blocks (linear sweep plus branch-target worklist so code past an early
`ret` is still covered), emits a JSON IR manifest (`pevm-x64-lift`),
assembles the IR into the randomized/encrypted VM2 format, and invokes it
through the native/VM register bridge:

```powershell
PeVm lift-x64 Input.exe 0x1000 Function.vm2.json 0x1234 --rcx=1 --rdx=2 --r8=4 --r9=8 --trace
```

The bridge maps x64 register numbers `RAX..R15` to the 16-register VM2 file and
returns the result through `RAX`. Supported instructions currently include:

- `MOV r64, r64`, `MOV r64, imm64`（含 `mov r32, imm32` 的零扩展形式、`mov r/m64, imm32` 符号扩展（`C7 /0`）与 `xor r32,r32` 惯用法）
- `ADD/SUB/AND/OR/XOR/CMP/TEST`（寄存器形式，以及基址寄存器+位移的内存形式，含读改写）；`ADC/SBB`（寄存器、内存与立即数形式，进位/借位取自 VM 实时 flags）
- 立即数形式：Group1 `0x81/0x83` 全部可提升组（ADD/AND/OR/XOR/SUB/CMP/ADC/SBB，寄存器+内存）、累加器短形式（`04/05/0C/0D/15/1D/24/25/2C/2D/34/35/3C/3D`）、`TEST rax, imm32`（`F7 /0`、`A9`）
- `IMUL r64, r64` 与三操作数 `IMUL r64, r/m64, imm`（展开为 MOV/MulI）
- 移位与循环移位：`SHL/SHR/SAR` 与 `ROL/ROR`（立即数 0xC1/0xD1 与按 CL 0xD3，count & 63）；`BSWAP`（0F C8+r）
- `MOVZX/MOVSX r64, r/m8|r/m16` 与 `MOVSXD`（符号扩展按 ShlI+SarI 展开；MOVZX 亦接受 32 位目标形式）
- `NEG/NOT`（reg/mem，NEG 按完整 x86 flags、NOT 不改 flags）
- `SETcc`（寄存器形式，mem 形式因字节写不支持而 fail-closed）、`XCHG r64,r64`（经 VM 数据栈展开）、`PUSH imm32/imm8`
- `LEA`（含 `[base+index*scale+disp]` SIB 形式，按 VM 算术展开）
- `PUSH/POP r64`、`INC/DEC r64`、`NOP` 家族（含多字节 NOP、endbr64）；`LOCK`（F0）前缀被跳过（单线程语义等价）
- 全部 16 个条件跳转（rel8/rel32）与 `CMOVcc`（提升为反转条件分支 + 条件 Mov）
- 直接 `CALL rel32` 与 `RET`

Memory addressing maps VM-space offsets: base+disp loads/stores address the VM
flat memory（`--rcx=N` 传给 bridge 的值即 VM 内存偏移）。SIB 地址在 scratch 寄存器中计算；read-modify-write（`add [mem], reg` 等）通过 scratch 值寄存器展开。任何 native 指针语义的访问都不可能在 VM 内实现，因此以下形式明确 fail closed：RSP/RBP 基址（栈相对访问需要影子栈）、RIP-relative 与绝对 disp32 内存访问、间接 CALL/JMP、SIMD、0x66 前缀的一般 32 位运算。不支持的 native 指令会在生成 wrapper 前明确失败。

`protect-function` 将 lifted program 序列化到加密的 `.vmp3`；`protect-functions` 一次虚拟化多个函数到同一个 wrapper（同一 `.vmp3` 内每个函数一条入口记录，loader 为每条入口安装独立 trampoline 并通过第 5 参数函数下标分发到同一个 VM2 桥）。原始 PE 被手工映射后，loader 在指定函数 RVA 写入 12-byte `mov rax, imm64; jmp rax` trampoline，调用进入 thunk 再进入 VM2 runtime。当前落地 ABI 支持 Windows x64 前四个整数/指针参数：`RCX/RDX/R8/R9` 输入、`RAX` 返回。

测试运行器（`Tests/RunTests.ps1`）会让 fixture 自报告各函数 RVA，逐个做 bridge 差分（含循环、分支、移位、VM 内存访问、MOVZX/MOVSX/MOVSXD、NEG/NOT、SETcc、Group1 内存+立即数、累加器短形式），并通过 `lift-raw` 对 35 组手工汇编字节做确定性解码差分（XCHG、PUSH imm、SETcc、ADC/SBB 进位链、LOCK 前缀等），验证含栈参数与 CPUID 的函数会以明确的 fail-closed 错误拒绝提升；`protected_function_vm_bridge` 端到端验证 protect-function 产物中的 trampoline 确实调用了 VM2；`protected_multi_vm_bridge` 端到端验证一条命令虚拟化两个函数后两个 trampoline 都进入 VM2 且结果正确；`protect_all_virtualization` 验证全量虚拟化管线；`mutation_and_watermark` 验证变异差分与水印往返；`licensing_and_compression` 验证 签名卡密签发、各保护命令、旁挂优先级、旧卡/错误卡拒绝、公钥元数据和压缩往返；`LicenseRegression.exe` 覆盖逐位篡改、时间边界、输入校验及 DPAPI 密钥生命周期。测试需要访问当前 Windows 用户的 DPAPI 状态。
