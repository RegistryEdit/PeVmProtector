# VM protection

VM 保护采用共享编解码器 `Src/Libs/Container/VmImageCodec.cpp`，CLI 与 loader 使用同一实现。默认启用整段认证、独立函数种子和严格执行边界检查，无需新增命令参数。

## 镜像认证

磁盘布局依次为：

| 区域 | 大小 | 说明 |
| --- | --- | --- |
| Header | 32 字节 | magic、内部格式号、函数数量、种子、干扰区长度、保留字段 |
| 函数入口表 | 每项 16 字节 | 函数 RVA、指令起始索引、数量、保留字段 |
| 加密指令表 | 每项 20 字节 | XTEA-CTR 加密后的 IR 记录 |
| 干扰区 | 0 或 128 字节 | 由现有 `--anti-disasm` 开关决定 |
| 认证标签 | 32 字节 | HMAC-SHA256，覆盖前面所有区域 |

内部格式号为 4，原有 `.vmp3` 节名保持不变。功能、命令及新增文件使用统一名称，不增加带版本后缀的公共入口。旧 VM 镜像不走兼容降级；已生成的可执行文件仍携带原来的 loader，需要重新保护原始 PE 才会获得本次加强。CLI 与 loader 应使用同一次构建的产物。

派生以构建口令作为 HMAC 密钥，以用途域、内部格式号、构建种子和 32 字节 handler profile 作为消息。加密、认证、函数种子使用不同用途域；函数种子再绑定函数 RVA。HMAC 使用完整 32 字节标签和恒定时间比较。

加载顺序为：最小长度/格式检查 → 整段认证 → 表结构检查 → 解密 → IR 解码 → 所有函数编译成功 → 发布桥接表。范围必须连续、不重叠，无空函数、重复入口或未归属指令；保留字段必须为零，额外尾部和截断数据均拒绝。临时指令表和派生密钥通过作用域析构清零。

## 运行时检查

- 整段校验绑定密文、opcode/register 映射、handler 变体、指令边界、逐指令标签及对应数量。
- 逐指令损坏检测标签扩展为 64 位。
- 执行前验证边界严格递增且在缓冲区内，寄存器映射为有效排列，opcode 无重复，handler 变体在允许范围内。
- 每条指令的编码长度必须与 opcode 一致，操作数读取不能越过该条指令末尾；跳转和返回继续执行 CFI 检查。
- `EntryAddress` 位于指令列表中间时，编译器生成入口跳转，确保从指定位置开始执行。
- 不可变编译缓存及每次调用独立的寄存器、内存、栈、flags、fuel 继续保留。

## 基本块重排与滚动解码

块入口包括函数入口、所有直接跳转/调用目标和控制流指令之后的继续执行位置。编译器为不再物理相邻的顺序执行边补充跳转；CALL 的返回位置会执行连接指令，继续走原来的逻辑后继。没有合法后继的尾部路径生成 `TRAP`，避免顺序落入重排后的其他块。块数量少时，随机排列可能保留原顺序。

滚动状态在每条指令开始时重置，随后随 opcode 和操作数字节更新。因此循环回边、分支汇合、递归返回及并发调用不需要共享可变的解码状态。解释器逐字节解码，不创建完整的明文字节码副本；编译器和 loader 原有的 lifted IR 仍然存在。该层用于混淆，不能代替镜像的 HMAC 认证。

重排发生在 VM 编译阶段，磁盘认证镜像仍存放原有 IR 记录，本次沿用内部格式号 4。使用新 CLI 与 loader 重新生成保护产物即可启用。生成的入口/继续执行跳转和陷阱都占用 VM fuel，限制按实际 VM 指令数计数。

构建时通过 `GetCompilationStats` 获取与 loader 相同种子下的实际编译统计，并逐函数输出：

- `blocks`：提升后识别的 VM 基本块数量。
- `relocated`：物理排列位置与逻辑排列不同的块数量。
- `link instructions`：为入口和顺序执行边补充的跳转数量。
- `bytecode instructions` / `encrypted bytes`：最终 VM 指令数与编码字节数。

运行时轻量校验属于损坏检测，不是密码学 MAC。加载器仍保留 lifted IR 和原有摘要检查；拥有进程控制权的分析者可以观察或修改运行状态。本次加强没有改变 x64 指令支持范围、桥接 ABI 或指令表加密算法。

## 验证

```powershell
& 'D:/Visual Studio/MSBuild/Current/Bin/MSBuild.exe' PeVmProtector.slnx /p:Configuration=Release /p:Platform=x64 /p:TrackFileAccess=false /m /v:minimal /nologo
& .\bin\Release\VmRegression.exe
& .\bin\Release\PeVm.exe vm2-self-test
powershell -NoProfile -ExecutionPolicy Bypass -File Tests/RunTests.ps1 -Configuration Release
& .\bin\Release\VmRegression.exe --benchmark
```

验证包括 RFC 4231 的 HMAC-SHA256 标准向量、单个镜像每一位篡改、所有截断长度、错误口令/profile、重新认证后的畸形结构/IR、多函数种子区分、非首条入口，以及映射和边界损坏。镜像拒绝用例共 5,808 个；运行时自测共 39 个篡改/布局场景及 6 个滚动解码检查。原有 4,000 次并发调用和 4,608 个变异差分用例继续通过。

控制流测试独立计算原生预期结果，共 9,536 个结果/边界用例，覆盖全部 16 种条件跳转、求和循环、嵌套 CALL/RET、跳入指令段中间、尾部未跳转路径及尾部 CALL 返回。64 个种子产生 23 种不同的循环执行布局；比较内容为 VIP 路径，排除了仅 opcode 编码变化造成的假差异。构建统计与解码后重新编译的统计也做了对应检查。

同机 Release 基准中，4 条 IR 的缓存调用从加强前的约 265 ns 增至 287 ns，每次重新编译约 2,516 ns，缓存约快 8.8 倍。固定 16 次迭代的求和循环约 2.76 微秒，含 4 个块、3 个重排块、2 条连接指令、57 字节编码数据。数据为每组 20,000 次调用、5 组中位数，不代表整程序性能。

构建日志默认列出 `VM authentication`、`VM key separation`、`VM runtime checks`、`VM code layout`、`VM decoding` 和逐函数编译统计。日志不包含构建口令、派生密钥或函数种子。
