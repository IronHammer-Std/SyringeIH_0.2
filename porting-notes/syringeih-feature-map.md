# SyringeIH 0.3 Release — 现状架构与功能地图（供 SyringeEx 移植参考）

> 分析对象：`C:\WORK\PROJ\RAINITOOL\Syringe0721`（SyringeIH，基于 Ares-Developers/Syringe 演化）
> 版本：`Version.h` → `"SyringeIH 0.3 Release"`（VMAJOR 0 / VMINOR 3 / VRELEASE 0 / VBUILD 99）
> 行号引用基于当前工作区文件；含 GBK 中文注释的文件（ExtJson.h、ExtFunc.cpp、res.rc 等）用 grep/GBK 解码读取。

---

## Q1. 命令行参数解析（Main.cpp / Support.h）

**入口**：`WinMain`（`Main.cpp:92-99`）→ `Run(lpCmdLine)`（`Main.cpp:9-90`）。

**解析**：`get_command_line`（`Support.h:40-93`）：
- 语法：`Syringe.exe "<可执行文件路径>" <程序参数...>`
- 第一个 `"` 之前的部分按空格拆成 **flags**（`flaglist`，`Support.h:51-56`），引号内是可执行文件，其后是传给目标程序的参数（`Support.h:64-76`）。
- 若 `OverwriteStartParams && !DefaultExecName.empty() && !DefaultCmdLine.empty()`，完全忽略命令行，改用配置（`Support.h:58-62`）。
- 无引号包裹时回退 `DefaultExecName`，否则抛 `invalid_command_arguments` 弹用法框（`Main.cpp:75-86`）。

**flag 语法**（`Setting.cpp:351-400`，`UpdateSetting`）——全部是布尔开关或扩展包名，**不支持 `-i=<dll>` 之类参数**：
- `-<设置名>=true|false`（`UpdateBoolImpl` 宏，`Setting.cpp:357-371`），可用的名字：
  - `-LongStackDump=` `-EnableHandshakeCheck=` `-DetachAfterInjection=` `-CheckInsignificantException=` `-CheckBreakpoint=` `-OnlyShowStackFrame=` `-InfiniteWaitForDebug=` `-ExceptionReportAlwaysFull=` `-RemoteDatabaseDump=` `-GenerateINJ=` `-AnalyzeCPPException=` `-OverwriteStartParams=` `-ShowHookConflictPopup=` `-AutoTerminate=` `-LogDaemonInteraction=`（`Setting.cpp:378-392`）
- `-Ext=<扩展包名>`（`Setting.cpp:372-377`，`remove_prefix(5)` 后写入 `DefaultExtPack`）
- 其余前缀一律记为"未知选项"（`Setting.cpp:393-396`）。

> 移植要点：SyringeEx 若新增 flag，必须扩展 `UpdateSetting` 的宏链；语法风格为 `-Name=true/false`。

---

## Q2. Hook 注入机制（SyringeDebugger.cpp）

### 总体流程
1. `DebugProcess`（`SyringeDebugger.cpp:169-186`）：`CreateProcess(..., DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED)` 以调试器身份挂起创建目标。
2. `RetrieveInfo`（`1756-1832`）：解析目标 EXE 的 PE——入口点、KERNEL32.DLL 导入表里 `LoadLibraryA`/`GetProcAddress` 的 IAT 槽地址、文件大小与 CRC32。
3. `Run`（`1548-1743`）：在目标进程 `VirtualAllocEx` 分配 `AllocData`（`SyringeDebugger.h:204-212`，含 `LoadLibraryFunc[0x40]` 机器码桩），对入口点下 INT3 断点 `SetBP`（`1612`），`ResumeThread` 进入 `WaitForDebugEvent` 循环（`1622-1729`）。
4. `Handle_BreakPoint`（`1133-1368`）——整个载入/寻址状态机：
   - 反复把 EIP 指向 `LoadLibraryFunc` 桩并置 TF 单步（`0x100`），桩执行 `LoadLibraryExA + GetProcAddress`（桩代码 `1567-1589`；`LoadLibraryExA` 地址由 IAT 中 LoadLibraryA 值 + 两函数本机地址差求得，`1083-1094`），结果写回 `GetData()->ProcAddress`。
   - 顺序：预加载 FindDLLs 发现的所有 DLL（`1161-1183`）→ 加载 `SyringeEx.dll`（`1185-1200`）→ 逐个解析 `v_AllHooks` 中 hook 的 proc_address（`1278-1311`）→ EIP 回入口点。
5. `Handle_ApplyHook`（`294-463`）写钩子（见下）。

### 钩子代码构造（数据布局）
`hook_code_call[40]`（`SyringeDebugger.cpp:263-277`）——每钩一份 40 字节 trampoline 片段：

```cpp
0x60, 0x9C,                       // PUSHAD, PUSHFD
0x68, _INIT×4,                    // PUSH HookAddress（patch 于 +0x03）
0x83, 0xEC, 0x04,                 // SUB ESP, 4          —— 返回值槽
0x8D, 0x44, 0x24, 0x04,           // LEA EAX, [ESP+4]    —— &返回值槽
0x50,                             // PUSH EAX
0xE8, _INIT×4,                    // CALL ProcAddress    （rel32 patch 于 +0x10，目标为 +0x14）
0x83, 0xC4, 0x0C,                 // ADD ESP, 0Ch
0x89, 0x44, 0x24, 0xF8,           // MOV ss:[ESP-8], EAX —— 保存返回值
0x9D, 0x61,                       // POPFD, POPAD
0x83, 0x7C, 0x24, 0xD4, 0x00,     // CMP ss:[ESP-2Ch], 0
0x74, 0x04,                       // JZ .proceed
0xFF, 0x64, 0x24, 0xD4,           // JMP ss:[ESP-2Ch]
```

- **钩子函数约定**：`void* Hook(void* hookAddr, void** returnValue)`；返回非 0 → `JMP` 到返回值（即"吃掉原函数"）；返回 0 → 继续执行被覆盖的原始指令（`HookAnalyzer.cpp:136` 注释也印证"覆盖长度 num_overridden"）。
- 片段依次拼接后跟：被覆盖的原始指令字节（`overridden`，`410-414`）+ 5 字节 `E9 rel32` 跳回原地址+5（`hook_jmp_back`，`291`、`416-421`）；原地址处写 5 字节 `E9 rel32` 跳到 caller 代码（`444-459`）。
- 目标地址：优先使用 `RemoteDatabase::CreateData` 预分配的远程钩子内存（`Database.GetMem` → `AddrHiddenHeader`，`337-349`；分配见 `RemoteDatabase.cpp:642-659`），否则临时 `AllocMem`（`353-354`）。
- 相对偏移：`RelativeOffset(from,to)=to-from`（`219-225`），CALL/JMP 的 rel32 全部按实际落地地址修正（`369-371`、`390-392`、`417-421`、`444-447`）。

### DS / FS 处理（多线程）
- **主程序 hook 代码不使用 DS/FS/TEB**：全库搜 `0x14`/`FS:`/`DS:`——`SyringeDebugger.cpp` 中 `+0x14` 只是 `hook_code_call` 里 CALL 指令 rel32 的写入偏移（`370`、`391`），不是 `FS:[0x14]`。
- `FS:[0x30]`（PEB）只出现在 **SyringeExDll** 里用于遍历模块链表（`SyringeExDll/dllmain.cpp:45`、`RemoteDatabase.cpp:794` 的 `ModuleListHeader`）。
- `hook_code_call` 用 `MOV ss:[ESP-8]`/`JMP ss:[ESP-2Ch]`——基于**栈的槽位**（ss 默认段），**没有每线程数据**；旧注释版（`233-261`）曾用全局 `MOV ds:ReturnEIP`（`GetData()->ReturnEIP`，共享静态数据）存返回值——新版已改为栈上槽。**多线程安全性仅靠 PUSHAD/POPAD + 栈局部槽**，无 TLS。

---

## Q3. 是否支持修改 ESP

- **hook 注入本身不修改返回时的 ESP**：`hook_code_call` 中 `SUB ESP,4 / ADD ESP,0Ch / POPFD / POPAD` 严格平衡（`263-277`）。
- 但 **`FinalizeErrorThread`**（`1514-1545`）在 `AutoTerminate` 模式下**直接改写出错线程的 ESP/EBP/EIP**：分配 0x10000 新栈 → `context.Esp = newEsp`（`1524-1527`）→ `context.Eip = InfiniteLoop`，把出错线程送入死循环（`1542-1544`；失败退路 `1531` 页对齐改 ESP）。这是异常善后逻辑，非注入机制。
- 栈转储读取用 `context.Esp`（`993-995`）。

---

## Q4. 零标志（ZF）保留

**保留**。`hook_code_call` 在调用钩子前 `PUSHFD`（0x9C）、返回前 `POPFD`（0x9D）完整保存/恢复 EFLAGS（`SyringeDebugger.cpp:265`、`273`）。关键点：
- POPFD 恢复全部标志后，后续 `CMP ss:[ESP-2Ch],0 / JZ / JMP` 只是临时改变标志；**最终回到原代码时 EFlags 就是 POPFD 恢复的值（= 调用前）**，ZF 等标志不被破坏。
- 已注释的旧版（`236-246`）同样 `PUSHFD/POPFD`。
- 全库无 `sahf/lahf/pushfq/popfd` 之外的相关操作。

---

## Q5. 握手（Handshake）

**流程**（`SyringeDebugger::Handshake`，`2386-2424`；调用点 `1990-2001`）：
1. `FindDLLsLoop` 检查候选 DLL 导出表：无 `SyringeHandshake` → `HasHandshake=false` 跳过（`1936`）；有 `SyringeForceLoad` → 强制加载（`1937`）。
2. 若 `EnableHandshakeCheck && HasHandshake`：在 **Syringe 自身进程空间** `LoadLibrary(lib)` 并 `GetProcAddress("SyringeHandshake")`，以 `SYRINGEHANDSHAKEFUNC`（`HRESULT __cdecl(SyringeHandshakeInfo*)`，`SyringeDebugger.h:303`）调用。
3. `SyringeHandshakeInfo`（`SyringeDebugger.h:291-301`）：`cbSize / num_hooks / checksum / exeFilesize / exeTimestamp / exeCRC / cchMessage(0x100) / Message`。
4. 返回 `S_OK` → 载入该 DLL；其他 HRESULT → 拒绝载入，除非 DLL 带 `.syexe00` 段且 `CanHostDLL`（`1998-2000`、`2255-2282`）匹配当前 EXE 名。

**可关闭**：`-EnableHandshakeCheck=false`（`Setting.cpp`）或 `Syringe.json` 的 `EnableHandshakeCheck:false`。
**默认值已改为 false**（原为 true，`Setting.cpp` 默认值；后经用户决定与上游 0.7.3 / SyringeEx 对齐，
默认关闭握手检查；`--handshakes` / `-EnableHandshakeCheck=true` / JSON 可显式开启）。

---

## Q6. detach / 守护行为（生命周期）

- **默认不 detach、不退场**：注入完成（`EverythingIsOK=true`，`1339`）后 Syringe 一直留在调试循环，`WaitForDebugEvent(INFINITE)`（`1624`）直到目标进程退出（`EXIT_PROCESS_DEBUG_EVENT`，`1696-1700`）→ `DebugActiveProcessStop + SymCleanup + CloseHandle`（`1731-1734`）→ 记录退出码结束。
- **可选 detach**：`DetachAfterInjection`（默认 false）为真时，注入完成后在单步事件中置 `PrepareForDetach`（`1414-1417`），循环尾部执行 `DebugSetProcessKillOnExit(FALSE)` → `DebugActiveProcessStop` → Syringe 退出、注入代码保留（`1708-1717`）。
- **InfiniteWaitForDebug**（默认 false）：遇到异常时弹 MessageBox 等待人工放行（`1063-1069`）。
- **"daemon"**：指**目标进程内守护线程 ↔ Syringe 的命名管道交互**，不是 Syringe 自身变成后台进程（`RemoteDatabase::InitializeDaemon → StartDaemonMonitor → EnterDaemonLoop`，`RemoteDatabase.cpp:264-341`）：管道名 `\\.\pipe\SyringeDaemonPipe_%08X`（按目标 PID，`346`、`364`），Syringe（调试器进程内线程）为服务端，消息为 JSON-RPC（`ProcessReceivedMessage`，`469-540`；命令表 `DbgCmdServer.cpp:16-47`）。
- 守护循环结束 → `PreTerminateFromDaemon/TerminateFromDaemon` 标志 → 主循环在 `AutoTerminate` 时 `TerminateProcess` 目标（`1719-1728`）。
- **AutoTerminate**（默认 false）：异常后 `FinalizeErrorThread` 把出错线程送入 `InfiniteLoop` 死循环（`1490-1493`、`1514-1545`）。

---

## Q7. 额外 DLL 加载（SyringeEx.dll 等）

**SyringeEx.dll 双加载**：
1. 目标进程内：`Handle_BreakPoint` 经 `LoadLibraryFunc` 桩加载（`1185-1200`，`SyringeExPath` 由 `FindDLLsLoop` 记录并跳过，`1919-1926`）；其 `DLL_PROCESS_ATTACH` 用 PEB 模块链表（`fs:[0x30]`）遍历模块，经共享内存 `SYRINGE<DirHash><PID>`（`dllmain.cpp:99-170`）回填各 DLL 基址、写 `NullOutput/InfiniteLoop` 函数地址与 `DllRecordAddr/Count`。
2. Syringe 自身进程内：`LoadLibraryA(SyringeExPath)`（`1203-1213`）以读取共享内存回填结果（`LibBase/LibAddr`，`1216-1254`）。

**其他 DLL**：**不能通过命令行指定**。发现机制（`FindDLLs`，`2034-2089`）：
- 默认策略：EXE 同目录 `*.dll` + `\Patches\*.dll`（`2047-2063`）。
- 或 `Syringe.json` 的 `ExtensionPacks` + `DefaultExtensionPack`（`2064-2082`，含 Include/Exclude 通配与 `LoadAllMatchedFiles`，`ExtPack.cpp`）。
- 候选 DLL 须含 `.syhks00`/`.hphks00` 段（`ParseHooksSection`，`2284-2369`）或配套 `<dll>.inj`（`ParseInjFileHooks`，`2204-2253`）才会被加载。

---

## Q8. 相对钩子支持

**已具备，且是 IH 扩展**（原版 Ares Syringe 无此能力）：
- 数据载体：`Hook::RelativeLib`（`HookAnalyzer.h:49`）、扩展钩子声明 `hookaltdecl::RelativeLibPtr`（`SyringeDebugger.h:272-279`）、`HookBuffer::hookExt` 按 `RelativeLib` 分组（`SyringeDebugger.h:223-239`）、`BreakpointRel` 容器（`SyringeDebugger.h:182`）。
- 来源：`.hphks00` 段（`ParseHooksSection`，`2341-2353`）；DLL 配套 `<dll>.json` 的 `RelativeHooks` 数组 `[RelativeLib, Addr, Proc, Len, Priority?, SubPriority?]`（`ExtFunc.cpp:99-128`）。
- 解析/修复：SyringeEx 注入后得到各模块基址 → `RemoteDatabase::GenerateAbsAddrList`（`RemoteDatabase.cpp:752-778`）为相对地址生成绝对地址 → `Handle_BreakPoint` 把 `BreakpointRel` 的钩子按 `模块基址 + 偏移` 并入 `Breakpoints`（`SyringeDebugger.cpp:1256-1275`），之后按绝对地址统一写钩子。
- 相对修正：写钩子时 CALL/JMP 的 rel32 一律经 `RelativeOffset(落地地址+指令长, 目标)` 计算（`369-371`、`390-392`、`417-421`、`444-447`）。
- **无反汇编器**：全库搜 `Zydis`/`disasm`/`Decode` **无任何结果**。覆盖长度完全信任 DLL 声明（`num_overridden`）；冲突检测仅按"地址+长度"区间重叠判断（`HookAnalyzer::HasHookConflict`，`HookAnalyzer.cpp:61-115`）。

---

## Q9. RIP_EVENT

- 调试循环对 `RIP_EVENT`（事件码 9，注释见 `1639`）**直接 `break`**（`1701-1704`）：视为目标已不可继续，结束调试会话 → 走统一退出路径 `DebugActiveProcessStop + SymCleanup + CloseHandle`（`1731-1734`），`exit_code` 保持 `-1`（0xFFFFFFFF）。
- **没有**专门恢复/上报逻辑（不调用 `HandleException`）。

---

## Q10. SDK 头 / 特性协商

**SyringeExDll 导出**（`SyringeExDll/Export.cpp`，全部 `extern "C" __stdcall`）：
- `UpdateJson(const char* Name, const char* Json)`（26-32）
- `GetJson(const char* Name) -> JsonObject`（34-39）
- `GetExportData() -> int`（41-44）——返回 `ExportOffsets{CodeSize=40, CallOfs=16}` 的地址，与主程序 `hook_code_call` 布局（`40` 字节、CALL 偏移 `0x10`）硬编码对应（`Export.cpp:15-24`）
- `SetBackUp(int Addr, int Size)`（46-57）/ `RestoreBackUp(int Addr)`（59-71）——备份/恢复目标内存
- 另有非导出函数 `Output`/`InfiniteLoop`/`Initialize`（`dllmain.cpp:11-22, 172-175`）

**特性协商**：**没有 feature-flag 协商 API**（搜 `feature`/`SYRINGE_` 无结果）。存在的协商/版本机制：
- `SyringeHandshake`（Q5）——是否加载某 DLL 的决定，非特性协商。
- `GetExportData` 返回代码布局参数（目前主程序并未调用它，硬编码 40/16）。
- `DaemonData` 中的 `EnableDaemon / ProcessReport / NewPipeFormat`（`RemoteDatabase.h:42-54`）——目标内守护线程与 Syringe 的**协议协商**（由被注入代码设置标志，控制管道行为/帧格式）。
- 管道命令 `HelpAccess -Info Basic`（`DbgCmdServer.cpp:228-247`）返回 `LibraryName/Version/LowestSupportedVersion/Description`——版本协商雏形。

**公共头**：**无独立 SDK 头**。握手结构 `SyringeHandshakeInfo`/`SYRINGEHANDSHAKEFUNC` 定义在 `SyringeDebugger.h:291-303`（未导出为独立 include）；`SyringeExDll` 通过**复制声明**共享内存布局（`framework.h:8-50` 的 `SharedMemHeader/RemoteMapper` 与主程序 `SyringeDebugger.h:21-71` 重复定义），而非共享头。DLL 项目直接复用主工程源码 `..\cJSON.c`、`..\ExtJson.cpp`（`SyringeExDll.vcxproj:157-165`）。

---

## Q11. 设置系统（Setting.cpp / Setting.h）

- 主配置：**JSON 文件 `Syringe.json`**（`ReadSetting`，`Setting.cpp:102-325`），自封装 cJSON（`ExtJson.h` 的 `JsonFile/JsonObject`），支持 UTF-8 / UTF-16LE / UTF-16BE BOM（`38-78`）。
- **设置项**（`Setting.h:25-55`）：
  - `HookAnalysis`（bool 或 `{ByLibrary, ByAddress, Format, LibraryRange[地址区间], LibraryRange[库名列表]}`；`Format` = `"Text"`（默认）或 `"NDJSON"`，控制 `HookAnalysis.log` 输出格式，2026-07 新增）
  - `DefaultExecutableName` / `DefaultCommandLine`
  - `IgnoreInvalidHookLibs`（数组）
  - `LongStackDump` `EnableHandshakeCheck` `DetachAfterInjection` `CheckInsignificantException` `CheckBreakpoint` `OnlyShowStackFrame` `InfiniteWaitForDebug` `ExceptionReportAlwaysFull` `RemoteDatabaseDump` `GenerateINJ` `AnalyzeCPPException` `OverwriteStartParams` `ShowHookConflictPopup` `AutoTerminate` `LogDaemonInteraction`（全部 bool）
  - `ExtensionPacks`（对象）/ `DefaultExtensionPack`（字符串，可为 `"NONE"`）
  - `DisableHooks` / `EnableHooks`（`{Lib, Proc}` 集合，`ReadHookIdxSet`）
- 命令行 `-X=true/false` 覆盖同名项（Q1）。
- **每 DLL 配套 JSON** `<dll>.json`（`LibExtData::ReadFromFile`，`ExtFunc.cpp:65-186`）：`DisableHooks`、`RelativeHooks`（数组）、`MemoryCopyRange`（`[Start, End, Name, OffsetFixes...]`）、`Setting`（可并入全局 `Syringe.json` 的 `Setting.<DllName>`）。

---

## Q12. 版本与构建

- **版本**：`Version.h:3-14` — `VMAJOR 0 / VMINOR 3 / VRELEASE 0 / VBUILD 99`，`CUSTOM_VERSION_STR "0.3 Release"` → `VersionString = "SyringeIH 0.3 Release"`；`res.rc` VS_VERSION_INFO 用宏自动生成（Company "Patrick Dinklage(Original) IronHammer Std(Modified)"）。
- **Debugger.vcxproj**（主程序，**仅 Win32**）：
  - `Release|Win32`：`PlatformToolset v141_xp`（:22），`CharacterSet MultiByte`，`LanguageStandard stdcpplatest`（:129），`RuntimeTypeInfo false`，`TargetMachine MachineX86`（:143），`WindowsTargetPlatformVersion 7.0`（:17）。
  - `Debug|Win32`：`PlatformToolset v143`（:29），`LanguageStandard stdcpplatest`（:81），MultiByte。
- **SyringeExDll.vcxproj**：4 配置（Win32+x64），全部 `PlatformToolset v143`；`Release|Win32` `LanguageStandard stdcpp20`（:111）且 `TargetName SyringeEx`（:78）；Unicode；复用 `..\cJSON.c`、`..\ExtJson.cpp`。
- **Syringe.sln**：两个工程 —— `"Syringe"`（`Debugger.vcxproj`，仅 Win32 映射）与 `"SyringeExDll"`（`SyringeExDll\SyringeExDll.vcxproj`，Win32+x64）。主程序在 x64 溶液配置下 ActiveCfg 映射回 Win32。

---

## 相对 Ares 原版新增的架构（总结）

1. **守护线程 + 命名管道 JSON-RPC 命令服务器**：`RemoteDatabase` 的 daemon 循环（`RemoteDatabase.cpp:242-341`、`429-540`）、`DbgCmdServer.cpp` 命令表（GetVersion / GetAccessStr / AnalyzeAddr / FlushDumpInfo / GetExceptionStr / HelpAccess / HasCommand / LogLine，另有十余个注释掉的调试命令）、`PipeRecord` 新旧消息帧格式（`PipeRecord.cpp`）。
2. **远程数据库（RemoteDatabase）**：运行前把 EXE/DLL/钩子/地址/内存拷贝打包为二进制流写入目标进程（`RemoteDataHeader/ExeRemoteData/LibRemoteData/AddrRemoteData/HookRemoteData/DaemonData`，`RemoteDatabase.h:20-137`），提供地址注解（`AnalyzeDBAddr/AnalyzeHookAddr`）、内存拷贝（`MemoryCopyRange` → `CopyAndPush`）、`RemoteData.dmp` 转储（`RemoteDatabaseDump`）。
3. **符号系统**：DbgHelp 加载 PDB（`LoadSymbolsForDLL`，`636-734`）+ 自写 MAP 解析（`SymMap.cpp`），异常栈转储带符号/源码行注解（`Handle_StackDump`，`903-1074`；`ProcessedDumpInfoHandler` 延迟填充地址描述）。
4. **钩子体系扩展**：相对钩子（Q8）、优先级/次优先级排序（`2119-2126`）、冲突检测（`HookAnalyzer.cpp:61-115`）、`.hphks00` 扩展段、INJ 生成（`GenerateINJ`，`117-145`）、钩子分析报告 `HookAnalysis.log`（`21-57`）、全局/局部 DisableHooks/EnableHooks（`2127-2128`、`ExtFunc.cpp`）。
5. **异常/善后增强**：C++ 异常（`0xE06D7363`）、.NET CLR 通知、Ctrl+C/Ctrl+Break、`AutoTerminate`+`InfiniteLoop` 死循环托管出错线程（`FinalizeErrorThread`）、意外断点处理（`CheckBreakpoint`）。
6. **扩展加载策略**：`ExtensionPacks`/`DefaultExtensionPack`（`ExtPack.h/.cpp`）、`SyringeForceLoad`/`CanHostDLL`（`.syexe00` 段）宿主过滤。
7. **共享内存模块枚举**：`RemoteMapper` + `SharedMemHeader/SharedMemRecord`（`SyringeDebugger.h:21-71` 与 `SyringeExDll/framework.h:8-50` 双份定义），SyringeEx 经 PEB 遍历模块回填基址。

---

## 与"移植 SyringeEx 22 个 commit"最相关的现状结论（速查）

| 功能 | SyringeIH 现状 |
|---|---|
| 命令行 flag 机制 | 部分具备（仅 `-Name=true/false` + `-Ext=`；**无 `-i=<dll>` 类语法**） |
| hook 注入/布局（PUSHAD/PUSHFD + 返回值槽） | 已具备（40 字节布局，与 SyringeExDll `ExportOffsets(40,16)` 硬编码对应） |
| 多线程（FS/TLS） | 缺失（无 TEB/TLS 处理，靠 PUSHAD/POPAD + 栈槽） |
| ESP 修改 | 部分（hook 不改；`FinalizeErrorThread` 异常善后时改写） |
| ZF/标志保留 | 已具备（PUSHFD/POPFD） |
| 握手 | 已具备（可开关） |
| detach/生命周期 | 已具备（`DetachAfterInjection`，默认等待目标退出） |
| SyringeEx.dll 加载 | 已具备（目标内+Syringe 内双加载） |
| 相对钩子 | 已具备（但**无反汇编器**，覆盖长度靠声明） |
| RIP_EVENT | 缺失精细处理（仅 break 退出调试） |
| SDK 头 / feature 协商 | 缺失（无独立 SDK 头、无 feature-flag 协商；仅 Handshake/GetExportData/管道命令版本信息） |
| 设置系统 | 已具备（Syringe.json + 每 DLL JSON + 命令行覆盖） |
| 构建 | 主程序 v141_xp/v143 + stdcpplatest，仅 Win32；DLL v143 + stdcpp20，Win32/x64 |
