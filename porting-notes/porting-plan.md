# SyringeEx → SyringeIH 移植工作方案

> 依据：`porting-notes/syringeex-22commits.md`（22 个 commit 逐条分析）
> 与 `porting-notes/syringeih-feature-map.md`（SyringeIH 现状地图）
> 目标：把 SyringeEx（Phobos-developers/SyringeEx，HEAD=535056d）相对 Ares-Developers/Syringe:master
> （基线=597dc4b）领先的 22 个 commit 所引入的全部功能，按部就班移植到工作区 Syringe0721 的 SyringeIH 项目。

---

## 一、目标澄清

- 两个仓库同源自 Ares-Developers/Syringe:master（基线 597dc4b，2017~2024 年历史）。
- SyringeEx 在基线之上有 22 个 commit（2025-06-22 ~ 2026-06-20），全部功能都要进 SyringeIH。
- SyringeIH 的历史在 0.2 之前已丢失（67 个 commit 自 2025-01-16 起），且双方各自独立演化、代码差异大
  （SyringeIH 增加了 daemon/pipe/dump/符号/相对钩子/SyringeExDll 等自有体系），
  **不能整体 merge，必须逐功能移植**。
- 判定标准：以 SyringeEx HEAD 的最终代码语义为准（中间版本如"按空格切分 flags"的缺陷以最终版为准）。

## 二、22 个 commit 完成的功能（第一步结论，已确认）

| 功能项 | commit | SyringeIH 现状 | 移植动作 |
|---|---|---|---|
| ① `-i=<dll>` 注入白名单（可重复；出现时只注入指定 DLL） | 3b21a21、bda61b9 | 缺失（仅有 `-Ext=` 扩展包、目录扫描） | 移植（接入 `Setting::UpdateSetting` 风格） |
| ② 多线程安全返回地址：`FS:[0x14]`（TIB）代替共享区 ReturnEIP | fa55bcc | 已用"栈上临时槽"天然线程安全，但该槽在恢复后 ESP 可变时失效 | 与③⑦合并重写 trampoline |
| ③ 钩子内修改 ESP（17 字节 POPAD 副本，ESP 最后恢复） | 3e36626 | 缺失（POPAD 丢弃保存的 ESP） | 移植 |
| ④ 新命令行格式 `CommandLineToArgvW`+`--args=` | bda61b9 | 自有解析器（引号 exe + 尾部参数）已覆盖场景 | **不移植整段**，只吸收 `-i=`/新 flag；后经用户决定补上 `--args=`（取最后一个、展开拼接到游戏参数最前，可出现在 exe 前后；另加引号感知 flags 切词） |
| ⑤ detach 生命周期：`--detach/--nodetach/--nowait`，默认附加直到目标退出 | 764beda、8d797f8、982517f | 有 `DetachAfterInjection`（detach 后立即退出），缺"detach 但等待退出" | 部分移植：补 nowait 语义 + 等待句柄逻辑 |
| ⑥ 可选握手 `--handshakes`（SyringeEx 默认关闭） | 39fc085 | 已有 `EnableHandshakeCheck`（默认 true，flag/JSON 可关） | **不需要移植**，保留 IH 默认值；后经用户决定改为默认 false（与 SyringeEx / 上游 0.7.3 对齐） |
| ⑦ 零标志保留（CMP/JE 提到 POPFD 之前，两条路径各自恢复） | ba05ddb | **实际缺失**：`CMP ss:[ESP-2Ch],0` 在 POPFD 之后，破坏恢复的 ZF | 移植 |
| ⑧ Feature Flags SDK：`include/Syringe.h` 的 `SyringeFeatures::{ESPModification,ZFPreservation,ReladdrInstructionFixup}` 导出 bool + 注入时写 true | 4e43375、54be1c3 | 缺失 | 移植（头文件几乎原样 + 协商机制适配 IH 加载状态机） |
| ⑨ Zydis 相对指令修复：vendored Zydis5/Zycore-C1.5.2 + `RebuildInstructions` 两趟算法 + 内存上界×3 + 17 个单测 | 54be1c3 | 有自有相对钩子体系（模块基址+偏移，无反汇编器；覆盖长度靠声明） | **移植（最重一项）** |
| ⑩ RIP_EVENT/EXIT_PROCESS break 前必须 `ContinueDebugEvent`（否则挂死） | b26b56a、982517f | **同病**：两个分支都是 break 前未 Continue（SyringeDebugger.cpp:1696-1704） | 移植（两行） |

**不移植**（工程/品牌类）：许可与 README（18addbd）、构建脚本/VSCode（7423bc2）、改名与版本号体系
（c192550/42aa2e1/43993e0/535056d）、纯格式化（cec977f/3147902）、CI（10a1fd3）。
SyringeIH 保留自己的品牌、版本号与构建配置。

## 三、分阶段执行

### 阶段 1：低风险快速项（可独立提交）
1. **⑩ 调试循环修复**：`EXIT_PROCESS_DEBUG_EVENT` 与 `RIP_EVENT` 分支 break 前补 `ContinueDebugEvent`。
2. **① `-i=` 白名单**：`Setting.cpp` 解析 `-i=<dll>` 累积到 `IncludeDLLs` 列表；`FindDLLsLoop`
   若列表非空则只扫描列表内 DLL（保留握手/段检查）。
3. **⑤ detach 语义**：`--detach` 映射 `DetachAfterInjection=true`；新增 `WaitForProcessExit`
   （默认 true）；detach 路径把 `CloseHandle(pInfo.hProcess)` 移到 `DebugActiveProcessStop` 之后，
   需要等待时 `WaitForSingleObject(pInfo.hProcess)`；`--nowait` → `WaitForProcessExit=false`。
4. **Log fflush**（随 ⑤ 一起）。

### 阶段 2：hook trampoline 重写（②③⑦ 合并）【形状已确认：照搬 SyringeEx】
以 SyringeIH 现有 40 字节 `hook_code_call` 改造为 SyringeEx HEAD 同款布局（下游 DLL 全部只用单参数
`REGISTERS* R`，2-dword 形状对它们无感；IH 的栈槽/SUB ESP,4 形状废弃）：
```
PUSHAD,PUSHFD / PUSH HookAddr / PUSH ESP / CALL (rel@+0x09)
ADD ESP,8
MOV fs:[0x14],EAX            ← ② TIB 每线程返回地址
CMP fs:[0x14],0 / JZ proceed ← ⑦ CMP 在恢复之前，不破坏 ZF
jmp 路径: POPFD + 17B 副本 → JMP fs:[0x14]   ← ③ ESP 可由 hook 修改、最后恢复
proceed:  POPFD + 17B 副本 → 被覆盖指令 + E9 跳回
```
- 完全对齐 SyringeEx 字节码（便于日后对拍）；回调参数 `(REGISTERS* R, HookAddress)`，`R->origin`=HookAddress。
- 同步更新 `SyringeExDll/Export.cpp` 的 `ExportOffsets{40,16}` → `{80,16}`（GetExportData 契约）。
- 所有尺寸引用确认走 `sizeof(hook_code_call)`（`Handle_ApplyHook` 的 sz、`RemoteDatabase`
  预分配/`AddrHiddenHeader` 布局）。
- ⑧ 的 `ESPModification`/`ZFPreservation` 在此阶段成为真实能力。

### 阶段 3：Feature Flags SDK（⑧）
- 新增 `include/Syringe.h`（近原样移植；REGISTERS 布局与 SyringeIH 一致：R 指向 HookAddress 槽，
  `origin/flags` + EDI..EAX 逆序）。
- `SyringeDebugger.h`：`FeatureFlagNames[]` 三个符号；`FeatureFlagEntry`/`v_FeatureFlags`。
- 协商机制适配 SyringeIH 的 `Handle_BreakPoint` 加载状态机：hook 函数地址全部解析完后，
  对每个唯一 hook DLL × 每个 flag 名，复用 `LoadLibraryFunc` 桩在目标进程内 GetProcAddress，
  单步取回地址后 `PatchMem(addr, TRUE)`；全部完成后回到入口点。
- 依赖阶段 2 完成（否则 ESPModification/ZFPreservation 名不副实）。

### 阶段 4：Zydis 相对指令修复（⑨，最重）
1. 从 SyringeEx 复制 `external/`（Zydis 5.0.0 + Zycore-C 1.5.2，MIT）+ `external/Zydis.vcxproj`。
2. `Syringe.sln` 增 Zydis 工程（与 Tests，见下）；`Debugger.vcxproj` 增 include 路径、
   `ZYDIS_STATIC_BUILD;ZYCORE_STATIC_BUILD`、ProjectReference。
   - **风险**：IH Release 是 `v141_xp`（XP 兼容目标）。先尝试 Zydis 用同工具集编译（C99 应可过）；
     若编译器不兼容则 Zydis 工程单独用 v143 静态库，主工程不变（链接兼容性需实测）。
3. 移植 `RebuildInstructions`/`ResolveRelativeOperands` 两趟算法（`#ifdef SYRINGE_TESTING` 暴露）。
4. 集成点：`Handle_ApplyHook` 中被覆盖字节改为 `ReadMem` → `RebuildInstructions(originalAddr→newAddr)`
   → 写入；分配上界 `overridden*3`；`PatchMem` 写实际大小。
   - 与 IH 自有相对钩子（模块基址+偏移解析）**不冲突**：解析阶段照旧，仅在写入 trampoline 时做重编码。
5. 移植 `Tests.vcxproj` + `tests/RebuildInstructionsTests.cpp`（17 用例）并本地跑通。
6. `ReladdrInstructionFixup` flag 生效。

### 阶段 5：收尾
- 构建验证：Debug/Release × Win32（主程序），SyringeExDll（Win32/x64）不受影响；
  Release 若保持 v141_xp 则单独验证 Zydis 编译。
- 冒烟：真实注入一个带 hook 的 DLL（含条件跳转 hook、改 ESP hook）验证行为。
- README/文档：新增 flag 与 Feature Flags 章节（SyringeIH 风格）。

## 四、已确认的决策点（用户拍板，2026-07）

1. **trampoline 形状**：照搬 SyringeEx 2-dword 形状（下游 DLL 回调全部只用单参数 `REGISTERS* R`，不受影响）。
2. **Zydis**：完整移植，含 Tests 工程与 17 个单测。
3. **握手默认值**：保留 IH 现状（`EnableHandshakeCheck` 默认 true）。→ **后续调整（2026-07）**：改为默认 **false**，与 SyringeEx / 上游 0.7.3 对齐（`--handshakes` / `-EnableHandshakeCheck=true` / JSON 可显式开启）。
4. **Release 工具集**：升级 v143（与 SyringeEx 一致，放弃 XP 目标；WindowsTargetPlatformVersion 需同步处理）。

### 血缘补充（用户更正）

- 血缘链客观存在：`597dc4b`（Ares master）→ SyringeIH 首个 commit → SyringeIH 0.1 → SyringeIH 0.2 首个 commit，
  中间历史丢失而已。故 SyringeIH 基线 = Ares master 时代代码，22 个 commit 均为 IH 所无。
- 钩子字节码三代：Ares=共享区固定槽（`MOV ds:ReturnEIP`）；SyringeEx=TIB `FS:[0x14]`；
  **SyringeIH=栈上临时槽（`ss:[ESP-8]`/`[ESP-2Ch]`，第三种变体，非旧布局）**。
  移植②③⑦合并重写时统一到 SyringeEx 布局（FS:[0x14] + POPAD 副本 + CMP 前置），
  原因：IH 栈槽在回调修改 ESP 后寻址失效；且 IH 现状 CMP 在 POPFD 之后会破坏恢复的 ZF。

### 基线安排（用户指令，2026-07）

- **功能修改基准 = `deb0447`（Final 0.3 Release）**：master 已回退到 deb0447。
- 最近两个 commit（`a869176` replace LoadLibraryA with ExA、`e513f37` remove ExA log）
  已停放在侧分支 **`syringeih-last2-exa`**（指向 e513f37），暂不参与移植，日后按需挑回。

### 构建环境修正记录（v143 升级附带，用户确认可手动修 Debug）

- `Debugger.vcxproj`：`WindowsTargetPlatformVersion` 7.0 → 10.0；Release `v141_xp` → `v143`；
  删除 Release 已废弃的 `<MinimalRebuild>`；Debug 链接补 `shlwapi.lib`（PathMatchSpecA/PathFindFileNameA）。
- `SyringeExDll.vcxproj`：`cJSON.c` 设 `PrecompiledHeader=NotUsing`（原 Debug/全部 x64 配置对 .c 启用了 pch.h → C1010）。
- 源码卫生修复（v143 暴露的既有 bug）：`PortableExecutable.h:102` 去掉类内 `PortableExecutable::` 限定名（C4596）；
  `HookAnalyzer.h` 补 `#include <string>`；`ExtJson.cpp` 的 `DetachArrayItem` 补 `return`（C4716）。
- **编码规范**：项目为 MultiByte 编译，被编辑的 GBK/UTF-8 源文件必须保持 UTF-8 BOM（编辑工具会剥 BOM，
  每次编辑后需用 pwsh 补回，否则 C2001/C4819 爆炸）。已在以下文件统一补 BOM：
  Setting.cpp/.h、SyringeDebugger.cpp/.h、RemoteDatabase.cpp/.h、HookAnalyzer.h、PortableExecutable.h、
  SyringeExDll/Export.cpp、tests/RebuildInstructionsTests.cpp。

## 五、实施进度（持续更新）

- ✅ 阶段 1：⑩ EXIT_PROCESS/RIP_EVENT break 前 ContinueDebugEvent；① `-i=` 白名单（UpdateSetting + FindDLLsLoop 过滤）；
  ⑤ detach/nowait（`WaitForProcessExit` + `--detach/--nodetach/--nowait/--handshakes` 别名 + detach 后等待并记录退出码）；
  握手跳过路径对齐 SyringeEx（nullopt → `.syexe00` CanHostDLL 回退）。Debug/Release 双绿。
- ✅ 阶段 2：trampoline 重写为 SyringeEx HEAD 同款 73 字节（`FS:[0x14]` + 17B POPAD 副本 + CMP 前置双路径恢复）；
  `ExportOffsets{40,16}→{73,9}`；删 `AllocData::ReturnEIP`；`wtf_call` 死槽改 `std::fill_n` NOP；
  `RemoteDatabase.h` 增 `HookCodeCallSize=73` + static_assert。Debug/Release 双绿。
- ✅ 阶段 3：`include/Syringe.h` SDK 头（3 个 feature flag）；`Handle_BreakPoint` 中新增特性协商阶段
  （唯一 hook DLL × flag，LoadLibraryFunc 桩 + 单步，目标内 PatchMem 写 true）。Debug/Release 双绿。
- ✅ 阶段 4：vendored Zydis/Zycore + `external/Zydis.vcxproj`；sln 加 Zydis/Tests 工程；主工程 include/宏/ProjectReference、
  移除 StdCall 调用约定；`ResolveRelativeOperands` + `RebuildInstructions` 移植进 SyringeDebugger.cpp；
  `Handle_ApplyHook` 集成（overridden×3 上界、ReadMem→重建→写入、实际大小 PatchMem）；
  RemoteDatabase 远程分配 ×3；`Tests.vcxproj`（IH 完整源码闭包适配）。
  验证：Debug/Release 双绿，**Tests.exe 94/94 通过**。
- ✅ 阶段 5：README 已更新（新 flag + Feature Flags + 构建说明）。
  **IHTEST 冒烟通过**：与旧二进制对照实验定位并修复了一个集成缺陷——
  移植时漏掉 SyringeEx 的 `p_code += sizeof(hook_jmp_back)`，导致 E9 跳回指令未写入远程
  trampoline（fall-through 钩子滑进零填充区崩溃，转储字节实锤，+BF 偏移吻合）。
  修复后 75 秒时 gamemd/Syringe 存活、日志零异常、组件全部加载成功（用户确认）。
  - 期间曾按"指令中间钩子"假设加过 leadIn 防护，经用户更正（IH 的 hookaddr/length 均对齐指令边界）
    后移除，恢复 SyringeEx 原始语义。
  - 保留 `-RemoteDatabaseDump=true` 时的 trampoline 字节转储（调试辅助，默认关闭）。

### 测试环境注意（重要）

- 本会话的 DSH 沙箱写限制会**被子进程继承**：直接启动的 Syringe/gamemd 写不了 IHTEST 的日志与数据，
  冒烟测试必须用升级权限（danger-full-access）运行，否则结果失真（曾误判为回归）。
- IHTEST 备份：`Syringe.exe.bak-porting`（原 7/15 旧版）、`Syringe.exe.new-porting`（中间含缺陷版，可删）。
- IHTEST 扩展组合：`\Patches`（当前活动）、`Patches - New`（Phobos46_3_31 等）、`Patches - Old`；
  默认加载策略=根目录+\Patches；`RunAres-reshade.bat/全屏启动.bat` 走独立的 Syringe-reshade.exe，与本次移植无关。
