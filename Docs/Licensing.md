# 卡密命名、签发与迁移

卡密系统对外统一采用用途命名，不在卡密前缀、命令或文档文件名中附加版本号。旧的带数字前缀、旧共享密钥参数和旧 wrapper 元数据均不再支持，没有兼容开关。已有旧版 EXE 内含旧加载器，必须重新构建并分发新版 EXE，才能应用新规则。

## 统一命名规则

| 对象 | 名称 / 规则 |
| --- | --- |
| 卡密文本 | `PEVM-LICENSE.<Base64>` |
| 公钥文本 | `PEVM-PUBLIC.<Base64>` |
| 私钥文本 | `PEVM-PRIVATE.<Base64>` |
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
| `license-machine-id` | 获取机器码 |
| `license-issue` | 签发卡密 |
| `license-verify` | 验证卡密 |

内部载荷仍保留数值版本字段，用于拒绝无法识别的二进制结构；它不参与对外命名。签名和机器 / 产品摘要的内部域参数保持固定，本次命名调整不改变已经采集的 64 位机器码。

## 首次配置

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
& $Pevm wrap app.exe app.protected.exe 'build password' --license --license-public-key=.\license-keys\issuer.pub --license-product=my-product
Copy-Item .\customer.license .\app.protected.exe.license
```

`protect-function`、`protect-functions` 和 `protect-all` 接受相同的三个卡密参数。启用卡密时，公钥和产品 ID 缺一即报错。GUI 顶部提供共享的卡密开关、公钥文件选择器和产品 ID 输入框，对封装及函数虚拟化生效；打包/解包不使用卡密设置。

运行时先读取 `PEVM_LICENSE` 环境变量。仅当变量**不存在**时，才读取 EXE 同目录的 `<完整EXE文件名>.license`。空值、无效值、超长值或非 ASCII 环境值不会回退到旁挂文件。卡密/密钥文本读取上限为 4096 字节，允许首尾空白，拒绝内部空白、额外前后缀和非规范 Base64。

在客户机器上，也可临时通过环境变量运行：

```powershell
$env:PEVM_LICENSE = (Get-Content .\customer.license -Raw).Trim()
.\app.protected.exe
Remove-Item Env:PEVM_LICENSE
```

## 旧卡迁移顺序

1. 生成并备份新签发密钥，为产品固定产品 ID。
2. 从每台客户设备采集新版 64 位机器码。
3. 根据现有授权记录确定剩余授权天数或永久权益，使用 `license-issue` 重新签发。旧卡文本不能转换成新卡，旧共享密钥不能充当新私钥。
4. 用新公钥和产品 ID 重新构建所有需要卡密的 EXE，随新版 EXE 发放对应的新卡密。
5. 移除客户环境变量中残留的旧卡，替换旁挂文件，在客户机器上验证新版 EXE。

迁移不会自动修改已分发的旧 EXE，也不会自动撤销其旧卡。工作区没有客户授权台账；测试产生的卡密仅是回归夹具，不代表客户卡密已批量重新签发。

## 格式与边界

卡密使用 Windows CNG ECDSA P-256 / SHA-256，签名消息为固定协议域加上载荷前 132 字节。`PEVM-LICENSE.` 后为 196 字节载荷的规范 Base64；域参数定义见 `Src/Libs/License/PeVmLicense.cpp`：

| 字段 | 字节数 |
| --- | ---: |
| 版本 2（小端 uint32） | 4 |
| 随机卡密 ID | 16 |
| 公钥 SHA-256 指纹 | 32 |
| 产品 ID 摘要 | 32 |
| 机器码摘要 | 32 |
| 签发 FILETIME（小端 uint64） | 8 |
| 到期 FILETIME（小端 uint64；0 表示永久） | 8 |
| ECDSA 签名 r\|s（大端整数） | 64 |

公钥文件 `PEVM-PUBLIC.` 包含 72 字节 CNG 公钥 blob；私钥文件 `PEVM-PRIVATE.` 包含经 DPAPI 加密的私钥 blob。wrapper 的 `.vmp2` 元数据升级为版本 5，嵌入公钥和产品摘要，不包含签发私钥。`.pvm` 容器仍为版本 5。

加载器在启动时验签并检查产品、机器、签发/到期时间；到期时刻即失效。允许系统时间比签发时间早最多 5 分钟。不包含在线时间源、持久化防回拨状态或在线吊销服务，不能阻止任意离线时钟回拨，也不会在已启动进程内定时重新验证。设备摘要不是不可伪造的硬件身份；客户端本地校验仍受二进制修改风险影响。

## 回归验证

```powershell
& 'D:/Visual Studio/MSBuild/Current/Bin/MSBuild.exe' PeVmProtector.slnx /p:Configuration=Release /p:Platform=x64 /p:TrackFileAccess=false /m /v:minimal /nologo
.\bin\Release\LicenseRegression.exe .\bin\Release\TestArtifacts
powershell -NoProfile -ExecutionPolicy Bypass -File .\Tests\RunTests.ps1 -Configuration Release
```

测试需能访问当前 Windows 用户 DPAPI。回归覆盖签发与重新加载、逐位篡改、到期/时钟边界、错误产品/设备/公钥、旧格式拒绝、文件覆盖保护、输入长度与编码、环境变量优先级，以及真实 wrapper 启动与 VM bridge 执行。每次测试使用独立目录和新生成的测试密钥。
