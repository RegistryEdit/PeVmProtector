# 卡密命名、签发与迁移

卡密系统对外统一采用用途命名，不在卡密前缀、命令或文档文件名中附加版本号。旧的带数字前缀、旧共享密钥参数和旧 wrapper 元数据均不再支持，没有兼容开关。已有旧版 EXE 内含旧加载器，必须重新构建并分发新版 EXE，才能应用新规则。

## 统一命名规则

| 对象 | 名称 / 规则 |
| --- | --- |
| 卡密文本 | `PEVM-LICENSE.<Base64>` |
| 公钥文本 | `PEVM-PUBLIC.<Base64>` |
| 私钥文本 | `PEVM-PRIVATE.<Base64>` |
| 产品保护凭据 | `PEVM-BUILDKEY.<Base64>`，保存为 `.buildkey`，仅保留在构建端 |
| 卡密文件 | `<名称>.license` |
| 公钥 / 私钥文件 | `<名称>.pub` / `<名称>.private` |
| 环境变量 | `PEVM_LICENSE` |
| 命令 | `license-<操作>` |
| 使用说明 | `Docs/Licensing.md` |

所有卡密命令使用同一前缀：

| 命令 | 用途 |
| --- | --- |
| `license-keygen` | 生成签发密钥对 |
| `license-export-public` | 从私钥导出公钥 |
| `license-export-build-key` | 导出由签发方签名、当前用户 DPAPI 加密的产品保护密钥 |
| `license-machine-id` | 获取机器码 |
| `license-issue` | 签发卡密 |
| `license-verify` | 验证卡密 |

内部载荷仍保留数值版本字段，用于识别二进制结构；它不参与对外命名。v2 和 v3 使用各自固定的签名域；机器 / 产品摘要的域参数保持不变，已经采集的 64 位机器码仍可使用。

## 首次配置

### GUI 操作

启动 `bin\Release\PeVmProtectorGui.exe`，进入“卡密签发与验证”：

1. 在“签发私钥”和“验证公钥”旁点击“新建路径”，选取尚不存在的 `.private` / `.pub` 文件，再点击“生成密钥对”。已有密钥使用“选择已有”；仅有私钥时可选一个新公钥路径并点击“从私钥导出公钥”。
2. 填写产品 ID 和客户设备的 64 位十六进制机器码。“获取本机机器码”读取运行 GUI 的这台设备，给客户签发时需粘贴客户机器码。
3. 设置有效天数（默认 30，0 为永久）。卡密文件路径留空则仅显示文本供复制；填写新路径会同时保存文件。点击“签发卡密”后，下方显示卡密正文、ID、产品和 UTC 到期时间。
4. 验证时选择已有卡密文件、公钥和对应产品 ID，点击“验证卡密文件”；机器码留空会验证本机。
5. 在“产品保护密钥”选择新的 `.buildkey` 路径，填写产品 ID，点击“导出产品保护密钥”。再点击“用于程序保护”，将公钥、产品 ID、保护密钥和卡密开关带入“保护选项”，回到相应页面构建。新建卡密保护必须提供匹配的保护密钥；缺失时拒绝构建。
6. 将卡密文本交给客户；客户首次启动受保护 EXE 时在原生弹窗中粘贴，验证成功后自动记住。也可将卡密文件分发为 `<受保护EXE完整文件名>.license`，放在 EXE 同目录。GUI 的签发操作不会自动安装客户卡密。

界面与 CLI 使用同一套签发和验签实现。已有密钥/卡密文件不会被覆盖。签发私钥不传给保护命令；卡密正文显示在专用结果框，可复制，不混入公共运行日志。

### 命令行配置

以下命令在项目根目录的 PowerShell 中执行。示例产品 ID 为 `my-product`，区分大小写；实际使用时固定同一个产品 ID。

```powershell
$Pevm = '.\bin\Release\PeVm.exe'
New-Item -ItemType Directory -Path .\license-keys
& $Pevm license-keygen .\license-keys\issuer.private .\license-keys\issuer.pub
```

`issuer.private` 用当前 Windows 用户的 DPAPI 保护，保留在签发端。`issuer.pub` 可以交给构建端。生成密钥、导出公钥、写入卡密文件都拒绝覆盖已有文件；应使用新路径或先妥善归档旧文件。

仅复制 `.private` 文件不保证可以在另一个用户或系统上解密。备份方案应包含 Windows 用户的 DPAPI 恢复条件，并实际演练恢复；丢失私钥或其解密条件后，需要换钥、重建 EXE、重新签发。恢复公钥时可执行：

```powershell
& $Pevm license-export-public .\license-keys\issuer.private .\license-keys\recovered.pub
```

## 签发与验证

先在客户设备运行新版工具，获得 **64 位十六进制机器码**：

```powershell
.\PeVm.exe license-machine-id
```

机器码来自 Windows MachineGuid 和系统卷序列号的域分离 SHA-256 摘要。重装系统或更换系统卷可能改变机器码；采集失败会报错。旧 8 位机器码无法转换为新机器码，必须重新采集。

在签发机填入客户返回的机器码：

```powershell
$Machine = '替换为客户的64位十六进制机器码'
& $Pevm license-issue .\license-keys\issuer.private 30 "--machine=$Machine" --product=my-product --output=customer.license
& $Pevm license-verify .\license-keys\issuer.pub .\customer.license --product=my-product "--machine=$Machine"
```

`days` 默认 30，接受十进制整数 `0..36500`，其中 `0` 为永久。签发必须显式提供机器码和产品 ID；验证省略 `--machine` 时使用验证机自身的机器码。输出文件只含卡密文本，可直接安装为旁挂文件；不传 `--output` 时，终端先打印卡密，再打印卡密 ID、产品和 UTC 到期时间。

## 构建与安装

```powershell
& $Pevm license-export-build-key .\license-keys\issuer.private .\license-keys\product.buildkey --product=my-product
& $Pevm wrap app.exe app.protected.exe 'build password' --license --license-public-key=.\license-keys\issuer.pub --license-product=my-product --license-build-key=.\license-keys\product.buildkey
# 客户启动时可在弹窗中输入卡密；以下旁挂安装方式可选。
Copy-Item .\customer.license .\app.protected.exe.license
```

`protect-function`、`protect-functions` 和 `protect-all` 接受相同的卡密参数。启用卡密时，公钥、产品 ID 和 `--license-build-key` 缺一即报错。所有新建卡密保护都启用卡密绑定解密模式，包括 VM 实例数为 0 或没有可虚拟化函数的封装。保护凭据必须匹配签发公钥和产品 ID，并可由构建用户解开 DPAPI；输入无效时不会生成输出。GUI 必须选择同一保护凭据；打包/解包不使用卡密设置。

新版卡密载荷为 v3，包含由签发私钥通过 HMAC-SHA256 派生的产品解密密钥，全部字段由 ECDSA 签名。同一签发密钥和产品的解密密钥保持稳定，设备、有效期和卡密 ID 仍各自签名。构建凭据中也包含此密钥，但它经过签发方签名并由 DPAPI 加密；不包含签发私钥。凭据与私钥都不能发给客户，且需要保护签发/构建 Windows 账户的访问。

加强模式的 wrapper footer 为 v3，使用随机 nonce 和 AES-256-GCM 加密构建口令。整个嵌入镜像及 footer 作为附加认证数据，包含运行时代码、载荷、VM 程序、公钥、产品和卡密开关。运行时需要新版卡密中的产品密钥才能解密；修改元数据或尝试降级格式也会失败。EXE 中不嵌入产品解密密钥。`inspect` 显示 `AES-256-GCM (license-held key)`，可确认启用了此模式。

`wrap`、`protect-function`、`protect-functions` 和 `protect-all` 自动清理发布 wrapper 加载器中的 CodeView/PDB 引用及路径字节、COFF 符号和字符串表、VC_FEATURE/POGO 等明确属于调试用途的信息。保留扩展 DLL 特征记录（Type 20）、REPRO（Type 16）和未知类型，以及导入、导出、TLS、异常表和重定位目录；节、RVA 和文件布局保持不变。元数据范围非法或与必要运行数据重叠时拒绝构建，不通过擦除代码勉强生成输出。此步骤只处理加载器 carrier，原始应用 payload 的字节与语义保持原有处理方式。

构建仍可生成内部调试用 PDB，但发布包应排除加载器及应用 PDB、符号文件和内部构建日志。构建 ID、默认 VM 种子和 footer nonce 使用 `BCryptGenRandom` 的系统随机源，不再从时间戳推导；显式指定 VM 种子仍受支持，不保证完整 EXE 逐字节复现。

受保护 EXE 启动时按顺序验证 `PEVM_LICENSE`、同目录的 `<完整EXE文件名>.license`、当前 Windows 用户的 DPAPI 卡密缓存。每个来源都独立验签和检查产品、机器码、签发时间及到期时间；较高优先级来源无效时继续尝试下一个来源。全部不可用时显示 Windows 原生卡密弹窗。取消会退出，不执行载荷。

弹窗采用浅色布局、独立提示区和蓝色“验证并启动”按钮，支持中英文与 DPI 缩放。点击“复制机器码”可直接发送给签发方，按钮会短暂显示“已复制”；“粘贴卡密”替换整条卡密，`Ctrl+V` 按选区粘贴，`Ctrl+A` 全选。卡密默认遮蔽，可勾选显示；空输入时禁用启动按钮，验证失败会标出输入框并选中内容，便于重新输入。`Tab` 切换控件，在输入框按 `Enter` 验证，`Esc` 取消。剪贴板占用、非文字、非 ASCII 或超长输入都有提示，失败粘贴保留原输入。

新版弹窗仍只依赖 Windows 系统组件。它内置于 `PeVmStub.exe`，已有受保护 EXE 需要重新构建后才能应用更新。

弹窗中成功验证的卡密会按公钥、产品和 EXE 完整路径区分，并用当前用户 DPAPI 加密后保存在 `%LOCALAPPDATA%\PeVmProtector\LicenseCache`。后续启动仍会重新验签并检查有效期；卡密过期或缓存损坏时会再次显示弹窗。卡密不会在缓存文件中以明文存储；复制到其他用户、产品、签发公钥或 EXE 路径的缓存均不可用。无法写缓存时本次启动仍会继续，并提示用户下次可能需要重新输入。

如部署环境需要免弹窗，也可设置 `PEVM_LICENSE` 或旁挂文件。卡密文本读取上限为 4096 字节，允许首尾 ASCII 空白，拒绝内部空白、额外前后缀和非规范 Base64。`PEVM_TEST_NO_DIALOG=1` 只供自动化测试关闭 UI 提示，不会跳过任何许可证验证。

在客户机器上，也可临时通过环境变量运行：

```powershell
$env:PEVM_LICENSE = (Get-Content .\customer.license -Raw).Trim()
.\app.protected.exe
Remove-Item Env:PEVM_LICENSE
```

弹窗不依赖 Qt/QFluent DLL。语言随 Windows 界面语言选择中文或英文，输入默认隐藏，可切换显示；机器码框支持选中复制。缓存只在弹窗验证成功后保存，环境变量和旁挂来源不会自动写入缓存。移动或重命名 EXE、切换 Windows 用户或更换产品/公钥后需要重新输入。要清除记住的卡密，可删除当前用户 `LicenseCache` 目录中的缓存文件（会清除该目录下各受保护程序的记忆），并移除相应环境变量/旁挂卡密；原始签发文件不受影响。

**这轮加固必须重新构建 EXE**。已有 v3 卡密和对应 `.buildkey` 可继续使用；原 v2 卡密仍可由 `license-verify` 验签，也仍能在已经分发的旧模式 EXE 中使用，其签名协议未变。新工具不再生成旧启动校验模式。v2 卡密没有产品解密密钥，必须按客户剩余有效期重新签发 v3 卡密。升级前保留原 EXE、卡密和密钥，而不是重新给予固定天数。

## 旧卡迁移顺序

1. 生成并备份新签发密钥，为产品固定产品 ID。
2. 从每台客户设备采集新版 64 位机器码。
3. 根据现有授权记录确定剩余授权天数或永久权益，使用 `license-issue` 重新签发。旧卡文本不能转换成新卡，旧共享密钥不能充当新私钥。
4. 用新公钥和产品 ID 重新构建所有需要卡密的 EXE，随新版 EXE 发放对应的新卡密。
5. 移除客户环境变量中残留的旧卡，替换旁挂文件，在客户机器上验证新版 EXE。

迁移不会自动修改已分发的旧 EXE，也不会自动撤销其旧卡。工作区没有客户授权台账；测试产生的卡密仅是回归夹具，不代表客户卡密已批量重新签发。

## 格式与边界

卡密使用 Windows CNG ECDSA P-256 / SHA-256。v3 的签名消息为协议域 `PeVmProtector-License-v3` 加上载荷前 164 字节，完整载荷为 228 字节。v2 的 196 字节载荷和原 132 字节签名内容仅用于兼容旧模式。域参数定义见 `Src/Libs/License/PeVmLicense.cpp`：

| 字段 | 字节数 |
| --- | ---: |
| 版本 3（小端 uint32） | 4 |
| 随机卡密 ID | 16 |
| 公钥 SHA-256 指纹 | 32 |
| 产品 ID 摘要 | 32 |
| 机器码摘要 | 32 |
| 签发 FILETIME（小端 uint64） | 8 |
| 到期 FILETIME（小端 uint64；0 表示永久） | 8 |
| 产品解密密钥（v3） | 32 |
| ECDSA 签名 r\|s（大端整数） | 64 |

公钥文件 `PEVM-PUBLIC.` 包含 72 字节 CNG 公钥 blob；私钥文件 `PEVM-PRIVATE.` 包含经 DPAPI 加密的私钥 blob。wrapper 的 `.vmp2` 元数据升级为版本 5，嵌入公钥和产品摘要，不包含签发私钥。`.pvm` 容器仍为版本 5。

加载器在启动、解密边界和载荷映射后检查授权。运行期间每 30 秒重新验签、检查机器和有效期，VM 入口和后台 watchdog 共用授权调度；watchdog 启动失败时拒绝启动 Release wrapper，线程在进程生命周期内持续检查，后台发现异常时直接以非零退出码终止进程。会话中的签名载荷由当前进程的 `CryptProtectMemory` 保护，临时明文和 SHA/HMAC 密钥派生状态在使用后清理。复核时间以最近一次成功检查的 UTC 和单调计时为锚，检测向前校时后回拨；调度时间、密文长度或会话状态异常时失败，失败状态不能通过重试恢复。

原生加载器代码另有独立的 1 秒复核调度。v3 卡密 wrapper 先完成整个磁盘嵌入镜像的 AES-GCM 认证，再从该磁盘镜像重建加载器可执行节的预期字节，并按实际加载地址应用 DIR64/ASLR 重定位；首次基准不会信任当前 RAM。摘要与范围清单存放在只读 manifest 页，启动和载荷准备边界强制复核，VM 入口与 watchdog 共用周期调度。检查同时验证代码字节、可执行页的映像归属及只读执行权限、manifest 只读属性；不匹配或调度状态异常会锁存失败并退出，恢复原字节后重试不会清除失败。1 秒是检查调度间隔，不是实时检测保证；该基准覆盖 wrapper 加载器代码，不将应用自身的合法运行期代码变化当作同一基准。

分析工具检查在启动、解包后和进入载荷前强制执行，运行期间由 watchdog 按独立的 2 秒调度周期扫描。VM 入口只无锁读取 atomic 失败锁存，不获取分析检查互斥锁或枚举进程/窗口，避免在载荷 TLS/DllMain 回调中新增扫描。进程名按大小写不敏感的精确可执行文件 basename 匹配，排除受保护程序自身 PID；`x64dbgClass` 等强窗口类直接匹配，Qt、Windows Forms、AWT 和 Delphi 框架窗口类须与锚定品牌标题组合匹配。标题接受纯品牌、可选 `v` 前缀的数字版本、以 `:` 或 ` - ` 分隔的描述，以及末尾 ` - <品牌>` / ` - <品牌 版本>`。隐藏顶层窗口也参与检查，沿用原 `FindWindow` 的可见性语义。`Detected` 和 `Unavailable` 均锁存失败并停止受保护进程；缺少 API、扫描不完整或调度状态异常不会放行。

这是一项严格的工具身份策略：已知分析器即使在分析其他程序也会触发。普通浏览器和 AI 应用名称不列为规则；工具改名、窗口伪装或修改检查器仍可绕过部分匹配，无法可靠归因到 AI 分析，2 秒检查间隔也不是实时保证。已有 wrapper 必须从原始 PE 重新构建才能应用这些规则；仅替换旁挂卡密不会更新加载器。

成功验证后，最高已见 UTC 按公钥、产品和机器保存到当前用户 `%LOCALAPPDATA%\PeVmProtector\LicenseClock`，采用 DPAPI 认证、独占文件锁、Flush 和原子替换。该记录独立于卡密 ID、EXE 路径和卡密缓存；续卡、改名或清除卡密缓存不会重置它。启动和周期复核使用系统时间、单调时间与持久最高时间中的最大值，小幅回拨不会延长有效期，超过 5 分钟的回拨会拒绝运行。无效/过期卡不能推进记录；记录损坏、无法读写或锁超时也拒绝运行。错误校时后应先恢复正确系统时间；损坏记录需由维护人员核对授权和正确时间后恢复，程序不会自动删除重置。首次有效启动需要可写的当前 Windows 用户配置目录。

本实现仍为离线保护。持久记录能检测保留记录时的跨启动回拨，但不是服务端可信时间源；同一 Windows 用户可主动解封重封 DPAPI 数据，删除记录、切换用户或恢复整机快照也仍是边界。设备摘要可被拥有本机权限的人模拟。v3 卡密包含稳定产品密钥，获得同一产品任意历史 v3 卡密的专业攻击者仍可能提取密钥并修改本地校验；本地加密与反调试增加成本，不是服务端权限控制的替代品。不同产品或签发密钥使用不同解密密钥，需要独立隔离时应使用不同产品 ID 或密钥；需要可信时间、及时吊销和抵抗本机完整控制时，应把关键权益放到服务端并使用短时签名租约。

剥离符号线索、独立构建随机性和原生代码复核旨在提高 AI 辅助定位与补丁验证的成本。运行时无法可靠判断分析者是否使用 AI；完全控制客户端并同时修改检查器和基准仍是本地保护的边界。结构与篡改回归不等同于经过 AI 自动破解评测，也不承诺无法破解。本轮功能必须重新构建并分发 EXE 才能生效，已有有效 v3 卡密和对应 `.buildkey` 可继续使用。

## 回归验证

```powershell
& 'D:/Visual Studio/MSBuild/Current/Bin/MSBuild.exe' PeVmProtector.slnx /p:Configuration=Release /p:Platform=x64 /p:TrackFileAccess=false /m /v:minimal /nologo
.\bin\Release\PeRegression.exe
.\bin\Release\LicenseRegression.exe .\bin\Release\TestArtifacts
.\bin\Release\LicenseRuntime.exe .\bin\Release\TestArtifacts
powershell -NoProfile -ExecutionPolicy Bypass -File .\Tests\RunTests.ps1 -Configuration Release
```

测试需能访问当前 Windows 用户 DPAPI 和交互桌面。回归覆盖签发与重新加载、逐位篡改、到期/时钟边界、错误产品/设备/公钥、旧数字前缀拒绝、v2 验签兼容及新构建拒绝、文件覆盖保护、输入长度与编码、各来源回退，以及真实 wrapper 启动与 VM bridge 执行。卡密构建还验证缺少保护凭据拒绝且无输出、AES-GCM 认证、策略/格式降级拒绝、产品凭据在成功 DPAPI 解封后被篡改仍被验签拒绝，以及 EXE 不包含产品密钥或明文构建口令。`LicenseRuntime.exe` 验证持久时间推进、前进后回拨、小幅回拨、无效卡不推进记录、并发锁、异常记录、硬链接拒绝、复核调度异常及到期失败锁存；时钟测试使用隔离记录与模拟时间，不修改系统时钟。它直接操作原生窗口验证中英文、输入重试、取消及 DPAPI 缓存，保存 `dialog-en.bmp` 和 `dialog-zh.bmp` 到独立测试目录；真实 wrapper 回归还覆盖首次激活、再次免输入、损坏缓存恢复和缓存写入失败。自动输入只在测试程序中实现，生产加载器没有自动填卡接口。每次测试使用独立目录和新生成的测试密钥。

发布信息与原生代码回归包括 PE32/64 的调试数据和 COFF 字符串实际擦除、Type 20/REPRO/未知记录保留、布局不变与非法范围拒绝，以及磁盘基准、DIR64/ASLR、代码字节和页权限修改的检查。真实 wrapper 启动回归用于确认清理后的加载器仍能验卡、解密和执行载荷。

分析工具回归覆盖进程/窗口身份规则、API 失败与句柄释放，以及调用线程 `GetLastError` 保留。六个临时 fixture 集成场景分别验证启动时已知进程、改名后的强窗口类、Qt 品牌标题、普通浏览器/文档负例，以及启动后的进程与窗口检测；fixture 只创建并清理测试自身的进程和隐藏窗口。
