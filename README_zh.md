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
- GUI 统一使用 QFluent：导航为 `ToggleButton`，按钮和输入框为 `PushButton`/`PrimaryPushButton`/`LineEdit`，函数表为 `TableWidget`，文字为 `BodyLabel`/`CaptionLabel`，日志为 `PlainTextEdit`，滚动区域为 `ScrollArea`/`ScrollBar`，通知为 `InfoBar`。
- GUI 不使用 moc：全部信号连接走 lambda，工程为普通 vcxproj。界面支持中英文一键切换（QSettings 持久化）。
- 代码规范：全库标识符（类型、函数、变量、参数）统一大驼峰（PascalCase），文件与目录名同样大驼峰（`Src/`、`Tests/`、`PeVmMain.cpp` 等）；Windows/Qt/标准库 API 名、入口函数与字符串字面量保持原样。

### 按函数勾选与名称解析

进入“函数虚拟化”页，点击“扫描函数”，按函数名或 RVA 搜索，勾选目标后点击“虚拟化勾选函数”。只有复选框勾选的函数参与该次构建；筛选不会取消隐藏行的勾选，计数包含隐藏项。每次扫描默认不勾选，切换输入文件或 PDB 会清空旧选择。手动 RVA 输入仍单独保留。

函数名来自 PE 导出表、COFF 函数符号和匹配的本地 PDB。自动查找输入文件同目录的 PDB（包括调试信息记录的文件名）及原构建路径，也可点“选择 PDB”指定文件。PDB 的 GUID/age 必须与 PE 匹配；C++ 名字自动反修饰，原始修饰名及别名保留在提示和扫描 JSON 中。缺失或不匹配的 PDB 会显示诊断。没有符号的函数显示 `sub_RVA`；已内联、被优化移除或符号被剥离的函数可能无法恢复名称。

GUI 和 `scan-functions` 默认包含小函数，可用 `--min-bytes=N` 筛选已知长度。`protect-all` 保留原有发现策略。函数名可见不代表 lifter 支持该函数；所选函数包含不支持的指令时仍会明确报错。

```powershell
bin\Release\PeVm.exe scan-functions app.exe functions.json --pdb=C:\symbols\app.pdb
bin\Release\PeVm.exe protect-functions app.exe selected.exe "build key" 0x1000 0x1234 --seed=12345
```

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

GUI 采用中英文 Qt6 / QFluent 界面，通过 QProcess 调用同目录的 `PeVm.exe`，现有 22 个 CLI 命令均有界面入口：

| 页面 | 功能 |
| --- | --- |
| 容器与封装 | `wrap`、`pack`、`unpack`、`inspect`、`vm-dump` |
| 函数虚拟化 | `scan-functions`、`protect-function`、`protect-functions`、`protect-all`、`lift-x64`、`lift-x64-multi` |
| 卡密签发与验证 | 生成密钥对、从私钥导出公钥、获取/复制本机机器码、签发/复制卡密、验证卡密文件 |
| 原始机器码分析 | `lift-raw`，可设入口 RVA、种子、RCX/RDX/R8/R9 和 Trace |
| VM 演示 | 阶乘 VM、Call/Memory VM、密钥 VM、VM2 自测、完整自检 |
| 保护选项 | 共用的压缩、水印、卡密开关、公钥文件和产品 ID |

输入/输出/口令共享区仅在容器与函数页显示，保留拖放文件、建议输出路径和显示口令。函数页可勾选目标函数，也可手动填写逗号分隔的 RVA；另可设置扫描与全量虚拟化各自的最小字节数、全量虚拟化 `--allow-mem`、桥接 Trace、清单 JSON 路径，并导出当前扫描 JSON。清单路径留空时仍按原有后缀生成。演示页使用自己的种子和 Trace。

签发卡密时，先选择尚不存在的私钥/公钥路径并生成密钥对，或打开已有密钥；填写产品 ID、客户机器码、有效天数（0 为永久），然后签发。卡密路径留空时直接显示并可复制，填写新路径时同时写入文件。验证时选择已有卡密文件；机器码留空表示验证本机。点击“用于程序保护”会把公钥和产品 ID 带入“保护选项”，并启用卡密。私钥受当前 Windows 用户 DPAPI 保护，密钥和卡密文件均拒绝覆盖；安装与恢复见 [卡密说明](Docs/Licensing.md)。

底部日志支持保存、清空，显示忙碌状态和每步用时。构建与密钥 VM 口令在命令日志中显示为 `<redacted>`，签发卡密正文仅显示在专用结果框。`GuiFeatures.exe` 通过真实界面执行全部命令，验证卡密生命周期及带卡密 EXE 的运行，并将中英文离屏截图写入 `bin/Release/TestArtifacts/GuiFeatures`。该回归已纳入 `Tests/RunTests.ps1`，Qt 安装在其他路径时可传 `-QtDir`。

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
- **许可系统**：`--license --license-public-key=<file> --license-product=<id>` 启用 ECDSA P-256/SHA-256 签名验证。wrapper 仅嵌入公钥和产品摘要，签发私钥由签发端 Windows 用户 DPAPI 保护；卡密绑定产品 ID、64 位十六进制机器码和可选有效期。仅接受 `PEVM-LICENSE`，旧卡需重新签发；已分发的 EXE 需重新构建并分发新版加载器。启动时依次验证 `PEVM_LICENSE`、同目录旁挂卡密、当前 Windows 用户的 DPAPI 缓存；均无效时显示 Windows 原生卡密弹窗。成功输入会记住在当前用户和 EXE 路径绑定的加密缓存中，每次启动都会重新验证。离线校验不提供在线吊销或完整防时钟回拨能力。详见[签发与迁移说明](Docs/Licensing.md)。
- 受保护 EXE 的卡密弹窗使用 Windows 原生控件，无需 Qt/QFluent DLL。使用新版工具重新构建 EXE 后生效；本次弹窗更新不改变签名协议，现有有效卡密可继续使用。
- **导入保护**：手工映射 + 运行期解析意味着磁盘 IAT 从不使用，导入保护天然成立。
- **反调试/反 dump**：见下节。
- 差距（诚实声明）：虚拟文件系统（VFS）、native 级 mutation（我们变异的是 VM IR）尚未实现；内存访问函数的全量虚拟化需要指针模拟层。

### 全量虚拟化（VMP 风格）与边界

`protect-all` 是 VMP 式 "virtualize everything"：

1. `scan-functions` 自动发现全部函数入口——异常目录（`.pdata`）的 RUNTIME_FUNCTION 提供候选，导出表补充函数名；
2. 每个候选独立尝试提升（fail closed per function）：能提升的打进**同一个多入口 .vmp3**，loader 为每个函数安装独立 trampoline；
3. 常用 SSE/SSE2 指令可虚拟化；部分 EH/SEH 函数支持保留原生异常框架的寄存器计算片段。AVX、传统高位字节寄存器、LOCK/原子操作及链式展开等仍逐项报告原因并保持原生执行。

保护后的函数默认使用原生指针、RIP 相对地址、独立 VM 栈和原生调用桥接；`--allow-mem` 保留为兼容参数。分析命令的 smoke 执行仍使用有边界的 VM 平坦内存，不能执行原生调用。


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
- **运行兼容性**：映射镜像的 PE 头保持只读，供 CRT TLS guard、资源与异常处理继续使用。静态 TLS 使用扩大的 Windows 管理槽位，恢复原程序的初始化模板并转发进程/线程通知及析构回调。现有保护产物需使用新版 CLI 和 stub 重新生成，以预留正确的 TLS 大小。
- **VM 桥接兼容性**：进入 C++ 前动态对齐栈，兼容优化后的内部 leaf 调用，并注册桥接代码的 x64 unwind 信息。MSVC 异常运行库可识别内存映射的原程序镜像。
- 链式 unwind 片段（例如共享尾声）不能作为独立 VM 入口；`protect-all` 记录跳过原因，保留这些片段的原生执行。
- 无可用候选时仍生成加密 wrapper，日志明确显示虚拟化数量为 0，此时不应用 VM 指令变异和诱饵。
- **代码页 at-rest 加密（TextVault）**：payload 的全部可执行节逐页用 XTEA-CTR 加密（密钥由构建口令派生，域 `PEVM-TEXT-v1`），页保护收敛为 `PAGE_NOACCESS`，并注册前端 VEH：首次执行/访问某页时按需解密该页（RW 解密 → `PAGE_EXECUTE_READ`，进程内以原子状态机去重，多线程竞态安全），之后该页保持明文。运行中（或挂起后）对进程做内存 dump 得到的是密文 + NOACCESS 页，而不是完整明文代码镜像。限制：页面一旦执行过在本进程内保持明文；VEH 属用户态，先于帧 SEH 运行，payload 自注册的前端 VEH 会排在其后。
- loader 中暴露保护内部结构的错误消息（`.vmp*` 完整性、VM 桥、反调试、import/relocation 等）以 `consteval` XOR 形式编译进二进制，运行期才还原；`PEVM_*` 环境变量名与窗口类名同样混淆。二进制中不再能 grep 到这些明文。
- **敏感 IAT 彻底清除**：所有意图性 API（反调试、`VirtualAlloc/VirtualProtect`、VEH、Toolhelp、`NtQuery*`、`GetEnvironmentVariableW`，以及 payload 依赖解析用的 `LoadLibraryA`）全部经 **PEB LDR 遍历 + 导出表 FNV-1a 哈希匹配**在运行期解析——不经 `GetModuleHandleW`/`GetProcAddress`/`LoadLibraryA`，转发导出（kernel32 → KERNELBASE 等）会被跟随解析。导入表只剩 CRT 样板与完全通用的运行时入口，静态导入分析不再暴露任何加载意图；模块/函数/环境变量/窗口类名在二进制中均无明文。
- **新增检测**：`NtQuerySystemInformation(SystemKernelDebuggerInformation)` 内核调试器检测（捕捉不进用户态 PEB/handle 视野的内核调试），以及经典调试器窗口类扫描（best-effort，user32 未映射时跳过）。
- **VM 程序运行时校验**：loader 认证并校验 lifted image 后一次性编译，把加密字节码、映射、边界和标签冻结在只读页中，随后释放源 IR。每条指令仍检查标签，保留边界 CFI 和 fuel；每次调用不再重复全量扫描 IR 与字节码。只读页与运行时校验不构成对完全控制进程的攻击者的绝对保护。

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

loader 在加载 `.vmp3` 时为每个函数调用一次 `CompileLiftedProgram`，后续通过 `InvokeCompiledProgram` 复用只读页中的加密字节码。寄存器、flags 和 VM 状态仍按调用隔离；完整布局与完整性校验在发布前完成，执行时保留逐指令认证、CFI 和 fuel。顺序指令使用边界游标，opcode 使用反查表。源 IR 编译后释放；不使用栈的原生叶子函数跳过 VM 栈分配和复制。`InvokeLiftedProgram` 保留为一次性入口。旧产物需配套使用新版 CLI 和 stub 重新生成。

`VmRegression.exe` 覆盖编译结果复用、源 IR 修改后的快照独立性、4,000 次并发调用、跨调用状态隔离、越界/fuel 拒绝，以及 4,608 组变异 flags 差分。`--benchmark` 对 4 条 IR 指令比较每次编译与复用执行，不能据此推算完整应用的加速倍数。GUI 的命令日志将构建口令显示为 `<redacted>`；卡密设置使用公钥文件和产品 ID，签发私钥不传给保护命令。

The conservative x64 lifter accepts an RVA in a PE32+ x64 executable, decodes
basic blocks (linear sweep plus branch-target worklist so code past an early
`ret` is still covered), emits a JSON IR manifest (`pevm-x64-lift`),
assembles the IR into the randomized/encrypted VM2 format, and invokes it
through the native/VM register bridge:

```powershell
PeVm lift-x64 Input.exe 0x1000 Function.vm2.json 0x1234 --rcx=1 --rdx=2 --r8=4 --r9=8 --trace
```

桥接保存 16 个通用寄存器、XMM0–XMM15、MXCSR 和标志位，入口使用 5 字节相对跳转，thunk 和原生调用桥均有 x64 展开信息。VM 镜像格式升级到版本 6，旧产物需重新保护。

- 支持 8/16/32/64 位 MOV 与整数 ALU、ADC/SBB、IMUL、NEG/NOT、INC/DEC、移位/循环移位、MOVZX/MOVSX/MOVSXD、32/64 位 BSWAP、SETcc 寄存器/内存形式、CMOVcc、LEA、PUSH/POP、条件分支、直接/间接原生 CALL 和尾调用 JMP。
- 32 位写回清除高 32 位，8/16 位写回保留其余位；扩展和地址计算保留标志位；内存读写使用实际操作数宽度。
- 支持原生指针、RSP/RBP、SIB、RIP 相对寻址。需要栈的函数从每线程 FLS 池租用 72 KiB 缓冲，递归/重入调用使用独立缓冲；提供 64 KiB 局部栈并按线程栈边界复制最多 4 KiB 入参，省去重复分配和全量清零。原生调用在真实 Windows 栈上放置 512 字节出参区，传递 XMM 参数、返回值和 MXCSR。
- 原生被调用函数的 C++ 异常可以穿过桥接展开。部分 EH/SEH 函数在 prologue 后选择不会触发内存/浮点异常的直线寄存器片段进入 VM，原生调用、异常作用域、处理器和 epilogue 保持原位；日志分别统计 `full VM functions` 和 `native EH fragments`。链式展开、GS/TLS 操作数、AH/BH/CH/DH、LOCK/原子操作、setjmp/longjmp 和任意切栈仍不支持。

测试运行器（`Tests/RunTests.ps1`）会让 fixture 自报告各函数 RVA，逐个做 bridge 差分（含循环、分支、移位、VM 内存访问、MOVZX/MOVSX/MOVSXD、NEG/NOT、SETcc、Group1 内存+立即数、累加器短形式），并通过 `lift-raw` 对 34 组手工汇编字节做确定性解码差分（XCHG、PUSH imm、SETcc、ADC/SBB 进位链、旋转等），验证栈参数传递，并确认 CPUID 和 LOCK 操作得到明确拒绝。

`VmRegression.exe` 将 164640 组整数操作数宽度用例与原生 CPU 对照，验证边界读取、六参数调用、XMM 返回和 C++ 异常展开。`loader_tls_and_qt` 显式虚拟化 `LoaderCallWithStack`、`LoaderSimd`、`LoaderExceptionFragment` 和 `LoaderSehFragment`，要求实际 VM 入口标记，并检查变异后的栈参数、线程/重入、SIMD、C++ catch 和 SEH 结果。桥接日志在绑定 payload TLS 前初始化，避免依赖被替换的 CRT 静态初始化 epoch。

`protected_function_vm_bridge` 端到端验证 protect-function 产物中的 trampoline 确实调用了 VM2；`protected_multi_vm_bridge` 验证一条命令虚拟化两个函数后两个 trampoline 都进入 VM2 且结果正确；`protect_all_virtualization` 验证全量虚拟化管线；`mutation_and_watermark` 验证变异差分与水印往返；`licensing_and_compression` 验证签名卡密签发、各保护命令、旁挂优先级、旧卡/错误卡拒绝、公钥元数据和压缩往返；`LicenseRegression.exe` 覆盖逐位篡改、时间边界、输入校验及 DPAPI 密钥生命周期。测试需要访问当前 Windows 用户的 DPAPI 状态。


## SIMD 覆盖与 Qt 性能复测

已支持常用 SSE/SSE2：打包/标量移动，PS/PD/SS/SD 加减乘除、MIN/MAX/SQRT，逻辑运算、COMI/UCOMI、类型转换，以及打包整数加减、比较、低位乘法、unpack 和 shuffle。桥接保存 XMM0–XMM15 与 MXCSR；标量内存访问严格按 4/8 字节进行。目前仍是 SSE/SSE2 子集，AVX/AVX2/AVX-512 尚未覆盖。

SIMD 原生 CPU 对照共 85632 项，覆盖四种舍入模式、DAZ/FTZ、NaN payload、标志位和边界访存；另测 SIMD 镜像往返、异常片段返回地址认证和不安全片段拒绝。`Tests/QtPerformance.ps1` 测 31 个 Qt timer 回调，每个回调调用同一个显式保护函数 2000 次，并核对校验和；可用 `-BaselineExe` 指定旧保护版本。共享机器的耗时只记录，不设固定速度通过线。

`Tests/WindowResponsiveness.ps1` 测新启动程序窗口线程的 WM_NULL 响应，未覆盖登录后业务。完整应用仍需结合实际操作复测，高频界面/渲染函数进入 VM 后仍有执行开销。
