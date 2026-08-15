# SyringeEx 22 个 commit 深度分析报告（597dc4b..HEAD）

> 仓库：`C:\WORK\ECProj\SyringeEx-Base`（Phobos-developers/SyringeEx）
> 基线：Ares-Developers/Syringe master 末代 commit `597dc4b`
> 范围：`597dc4b..HEAD` 共 22 个 commit（2025-06-22 ~ 2026-06-20）
> 用途：作为把 SyringeEx 改动移植到另一分支的根据。本报告基于逐 commit `git show` 与 HEAD 工作区关键文件核对。
>
> **网络验证（2026-07，git ls-remote via openssl 后端）**：
> - `Ares-Developers/Syringe:master` = `597dc4b2f48ffb510368e59cbf1d9e5c2be622e3` ✓（与本地推断的分界一致）
> - `Phobos-developers/SyringeEx:master` = `535056d326d850274856b4c5b1a403853d9a4857` ✓（= 本地 HEAD，无新增 commit）
> - 本地 `git rev-list --count 597dc4b..HEAD` = **22** ✓ → "This branch is 22 commits ahead" 属实，清单即全部后加功能。

---

## 一、总览表（按时间顺序 旧→新）

| # | SHA（短） | 标题 | 性质分类 |
|---|-----------|------|----------|
| 1 | 18addbd | Leave only LGPL license and adjust the readme for proper credits | 文档/许可 |
| 2 | 7423bc2 | Add VSCode support and build scripts, use v143 toolset and C++20 and adjust output slightly | 构建/工程配置 |
| 3 | 3b21a21 | Add an ability to specify DLLs to load via `[-i=<some.dll>]` flag (#10) | 功能 |
| 4 | fa55bcc | Support hooking multithreaded code by using FS:[0x14] instead of DS (#11) | 功能（核心机制） |
| 5 | c192550 | Update name and version | 版本号/品牌 |
| 6 | 42aa2e1 | Fix res.rc | 构建修复 |
| 7 | 3e36626 | Support changing ESP in hook code (#12) | 功能（stub 字节码） |
| 8 | cec977f | Format all files using spaces and VS style (#14) | 纯格式化 |
| 9 | bda61b9 | Change command line format (#15) | 功能（CLI 重构） |
| 10 | 764beda | Make Syringe detach itself after hooks are injected, and wait for the process to exit (#16) | 功能 |
| 11 | 39fc085 | Make handshakes optional | 功能（flag） |
| 12 | 3147902 | Restore formatting of the opcodes array | 纯格式化 |
| 13 | ba05ddb | Preserve zero flag after hook execution | 功能（stub 字节码） |
| 14 | 4e43375 | Feature flags (#17) | 功能（SDK/API） |
| 15 | 54be1c3 | Relative instruction fixup (#19) | 功能（核心）+ 第三方库 + 构建 + 测试 |
| 16 | 10a1fd3 | Add GitHub CI | CI 基础设施 |
| 17 | 982517f | fix `--nodetach` | bug 修复（一行） |
| 18 | 8d797f8 | make `--nodetach` default, introduce `--detach` | 功能（默认值翻转） |
| 19 | 43993e0 | increment version, adjust copyroght year | 版本号 |
| 20 | 7c8d0cb | adjust readme for `--detach/--nodetach` behavior | 文档 |
| 21 | b26b56a | Fix a hang on `RIP_EVENT` (#24) | bug 修复（一行） |
| 22 | 535056d | Increment version | 版本号 |

---

## 二、逐 commit 分析

### 1. 18addbd — Leave only LGPL license and adjust the readme for proper credits

- 【标题】只保留 LGPL 许可并调整 README 以正确署名
- 【性质】文档/许可（无功能改动）
- 【改动文件与规模】2 文件：`README.md` +9、`license.txt` -17（删除）
- 【功能细节】
  - 删除 `license.txt`（原 Syringe 的 CC BY-NC-SA 3.0 许可全文，含"禁止商用、需署名"条款），只保留根目录 `LICENSE`（LGPLv3）。
  - README 增加项目简介、分隔线，并明确致谢："The original codebase ('Syringe') ... created by Patrick 'pd' Dinklage, based in part on code written by Jan Newger. It was then maintained and worked on by Ares contributors."，保留原讨论帖链接（renegadeprojects 论坛）。
- 【对移植的意义】许可与署名规范化；移植时保留 LGPLv3 与原作者致谢即可，无代码影响。

### 2. 7423bc2 — Add VSCode support and build scripts, use v143 toolset and C++20 and adjust output slightly

- 【标题】增加 VSCode 支持与构建脚本，改用 v143 工具集与 C++20，并微调输出
- 【性质】构建/工程配置
- 【改动文件与规模】14 文件 +179/-16：新增 `.gitignore`、`.vscode/tasks.json`、`.vsconfig`、`scripts/{build,build_debug,build_release,clean,run_msbuild,run_vsdevcmd,editorconfig-checker}.bat` 及两个二进制工具 `scripts/vswhere.exe`、`scripts/ec-windows-386.exe`；修改 `Debugger.vcxproj`（-28 处）、`Syringe.exe.manifest`（1 行）。
- 【功能细节】
  - vcxproj：`PlatformToolset` 从 `v141_xp`（Release）/`v141`（Debug）→ `v143`（VS2022）；`LanguageStandard` `stdcpplatest` → `stdcpp20`；删除 `<MinimalRebuild>`；所有输出产物由 `Debugger.*` 改名 `Syringe.*`（PCH：`.\Debug\Syringe.pch`、PDB、TLB、BSC），Debug 输出 `.\Debug\Syringe.exe`、Release `.\Release\Syringe.exe`。
  - 构建脚本体系：`run_vsdevcmd.bat` 用 vswhere.exe 定位 VS 并进入 Developer Command Prompt；`run_msbuild.bat` 调用 msbuild；`build.bat <config>` 通用构建（`msbuild /m /property:Configuration=%1 Syringe.sln`）；`build_debug.bat` / `build_release.bat` / `clean.bat` 包装；`editorconfig-checker.bat` 用 ec 工具检查格式。
  - manifest 注释 Windows 10 → Windows 10/11。
- 【对移植的意义】移植目标工程需对齐 v143 + C++20；若目标分支用别的工具链需调整。

### 3. 3b21a21 — Add an ability to specify DLLs to load via `[-i=<some.dll>]` flag (#10)

- 【标题】通过 `[-i=<some.dll>]` flag 指定要加载的 DLL
- 【性质】功能（注入白名单）
- 【改动文件与规模】3 文件 +73/-49：`Main.cpp`、`SyringeDebugger.cpp`（FindDLLs 重写）、`SyringeDebugger.h`。
- 【功能细节】
  - 当时 CLI 语法（注意是旧格式，含引号 exe）：`Syringe.exe [-i=<injectedfile.dll> ...] "<exe name>" <arguments>`。
  - `SyringeDebugger.h`：
    - 新常量 `static constexpr std::string_view INCLUDE_FLAG = "-i=";`
    - 构造函数签名变为 `SyringeDebugger(std::string_view filename, std::string_view flags = "")`。
    - flags 解析：`std::views::split(flags, " "sv)` 按空格切分；每个 token 用 `flagView.find(INCLUDE_FLAG)` 找到 `-i=` 位置，其后部分作为 DLL 名加入新成员 `std::vector<std::string> dlls{}`；**未知 flag 只打日志跳过、不退出**；若 `dlls` 为空则默认 `dlls.emplace_back("*.dll")`（保持原"扫目录"行为）。
  - `SyringeDebugger.cpp::FindDLLs()`：外层从固定 `FindFile("*.dll")` 改为 `for (const auto& dll : dlls)` 对每个模式 `FindFile(dll.c_str())`；新增日志 "Searching for DLLs matching ..."、"DLL load was prevented: ..."；保留 catch(...) 静默跳过解析失败 DLL。
  - `Main.cpp`：删除"flags 非空即抛 invalid_command_arguments"的人工限制；`SyringeDebugger Debugger{ command.executable, command.flags };`；用法错误框更新为 `Syringe.exe [-i=<injectedfile.dll> ...] "<exe name>" <arguments>`。
- 【对移植的意义】注入白名单机制；**注意该版是按空格切分整串 flags**（DLL 路径含空格会错），此缺陷在 commit 9（bda61b9）改为 argv 数组后消除——移植时直接用最终版。

### 4. fa55bcc — Support hooking multithreaded code by using FS:[0x14] instead of DS (#11)

- 【标题】用 FS:[0x14] 取代 DS 以支持钩子多线程代码
- 【性质】功能（核心 hook 机制）
- 【改动文件与规模】2 文件：`SyringeDebugger.cpp`（~+40）、`SyringeDebugger.h`（-1 行）。
- 【功能细节】
  - 原实现把 hook 返回地址存在注入进程共享数据区字段 `AllocData::ReturnEIP`（`MOV ds:ReturnEIP, EAX`、`CMP ds:ReturnEIP, 0`、`JMP ds:ReturnEIP`，A3/83 3D/FF 25 无段前缀默认 DS）。多线程下多线程同时命中 hook 会互相覆盖该字段 → 串线程。
  - 改为 x86 每线程 TIB 字段：所有引用换用 **FS 段前缀（0x64）** + **偏移 0x14**：
    - `0x64, 0xA3, 0x14, 0x00, 0x00, 0x00` = `MOV fs:[0x14], EAX`
    - `0x64, 0x83, 0x3D, 0x14, 0x00, 0x00, 0x00, 0x00` = `CMP DWORD PTR fs:[0x14], 0`
    - `0x64, 0xFF, 0x25, 0x14, 0x00, 0x00, 0x00` = `JMP DWORD PTR fs:[0x14]`
  - 常量 0x14 是 TIB（Thread Information Block）中的 "arbitrary user pointer"（FS:[0x14]），每线程独立，注释引用 Raymond Chen 博文与 nynaeve 文章佐证可用性。
  - `SyringeDebugger.h`：从 `AllocData` 删除 `void* ReturnEIP;`（缓冲区少 4 字节）。
  - 注释："return 0 hooks are chained, so this structure may repeat"（同一地址多个 hook 时 stub 可重复，靠 fs:[0x14] 非零跳转链式进入下一个）。
- 【对移植的意义】多线程安全 hook 的根基，hook 约定（JMP fs:[0x14] 进入 hook 函数、hook 结束后跳回 proceed）必须与 DLL 侧一致。

### 5. c192550 — Update name and version

- 【标题】更新名称与版本
- 【性质】版本号/品牌
- 【改动文件与规模】3 文件：`Main.cpp`、`res.rc`、`resource.h`。
- 【功能细节】
  - `Main.cpp`：`VersionString` 由 `"Syringe 0.7.2.0"` → `"SyringeEx " SYRINGEEX_VER_TEXT ", based on Syringe 0.7.2.0"`；`#include "resource.h"`。
  - `resource.h` 新增版本宏体系：
    - `SYRINGEEX_VER_EPOCH 0`、`SYRINGEEX_VER_MAJOR 1`、`SYRINGEEX_VER_MINOR 0`、`SYRINGEEX_VER_PATCH 0`
    - `SYRINGEEX_VER` = `0, 1, 0, 0`（逗号形式，供 VERSIONINFO 的 FILEVERSION/PRODUCTVERSION）
    - `STRINGIFY_HELPER(x)` / `STRINGIFY(x)` 两级字符串化
    - `SYRINGEEX_VER_TEXT` = `"0.1.0.0"`
  - `res.rc`：FILEVERSION/PRODUCTVERSION 改用 `SYRINGEEX_VER`；CompanyName "Phobos Developers"；FileDescription "SyringeEx Main Executable"；InternalName "SyringeEx"；LegalCopyright 追加 "; Copyright © 2025 Phobos Developers"；**误删 `#include "windows.h"`**（由下一 commit 修复）。
- 【对移植的意义】版本宏集中管理：以后改版本只动 `resource.h` 四个宏。

### 6. 42aa2e1 — Fix res.rc

- 【标题】修复 res.rc
- 【性质】构建修复
- 【改动文件与规模】`res.rc` 2 行。
- 【功能细节】恢复 `#include "windows.h"`（c192550 误删，rc 编译必需）；顺带修正版权符号的编码写法。
- 【对移植的意义】构建可用性，随 c192550 一起移植。

### 7. 3e36626 — Support changing ESP in hook code (#12)

- 【标题】支持在 hook 代码中修改 ESP
- 【性质】功能（stub 字节码）
- 【改动文件与规模】`SyringeDebugger.cpp` 单处替换。
- 【功能细节】
  - 把 `0x61`（POPAD）替换为手工 POPAD 副本（17 字节 10 条指令），ESP 最后恢复：
    ```
    0x5F             POP EDI
    0x5E             POP ESI
    0x5D             POP EBP
    0x5B             POP EBX        ; EBX 暂存 PUSHAD 时保存的 ESP
    0x8B 0x44 0x24 0x0C  MOV EAX, [ESP + 0xC]   ; 恢复 EAX（PUSHAD 顺序中最后压入的槽位）
    0x89 0x5C 0x24 0x0C  MOV [ESP + 0xC], EBX   ; 把暂存 ESP 写入 EAX 槽位，供最后的 POP ESP 使用
    0x5B             POP EBX
    0x5A             POP EDX
    0x59             POP ECX
    0x5C             POP ESP        ; 最后恢复 ESP，避免提前改写栈指针导致后续 POP 错位
    ```
  - 原因：硬件 POPAD 弹出 ESP 后，剩余寄存器从"新 ESP"处继续弹出；若 hook 代码修改过 ESP（栈深度不同），POPAD 会从错误位置弹寄存器而崩。副本保证其它寄存器全部先恢复、ESP 最后恢复（EBX 暂存、经 [ESP+0xC] 槽位搬运）。
  - 提交信息注明第二点优化：用 MOV 对替代 XCHG（XCHG 隐含内存锁，更慢）。
  - 配合 ESPModification feature flag 语义："modify the stack pointer (ESP) across hooks to be able to exit on addresses with a different stack depth than the hook entry point"。
- 【对移植的意义】任何会改 ESP 的 hook 都依赖此 stub；寄存器保存/恢复顺序必须严格保持。

### 8. cec977f — Format all files using spaces and VS style (#14)

- 【标题】用空格与 VS 风格格式化所有文件
- 【性质】纯格式化
- 【改动文件与规模】12 文件 +1753/-1528：CRC32.cpp/h、FindFile.h、Handle.h、Log.cpp/h、Main.cpp、PortableExecutable.cpp/h、Support.h、SyringeDebugger.cpp/h。
- 【功能细节】tab 缩进改空格（4 空格）；花括号改 Allman 风格（`{` 独立成行）；运算符写法规范化（`operator ++`→`operator++`、`operator ->`→`operator->`、`operator *`→`operator*`）。已用 `git diff -w` 验证：忽略空白后残留差异全部是"大括号换行、运算符 token 间距"这类纯风格变化，**无任何功能改动**。
- 【对移植的意义】格式化基线；移植时无需关心（除非目标分支想统一风格）。

### 9. bda61b9 — Change command line format (#15)

- 【标题】改变命令行格式
- 【性质】功能（CLI 重构，决定最终解析骨架）
- 【改动文件与规模】4 文件：`Main.cpp`、`README.md`、`Support.h`、`SyringeDebugger.h`。
- 【功能细节】
  - **最终 CLI 语法**：`Syringe.exe <exe name> [-i=<injectedfile.dll> ...] [--args="<arguments>"]`
    - 第一个不以 `-` 开头的参数 = 要启动的 exe；
    - `--args="..."` = 传给目标程序的参数（`-i=` 与 `--args=` 可出现在 exe 之后任意顺序）；
    - 其余参数全部视为 Syringe 自身参数（进入 `syringe_arguments`）。
  - `Main.cpp`：新增 `GetArguments()`——`CommandLineToArgvW(GetCommandLineW(), &argc)` 取宽 argv，`WideCharToMultiByte(CP_UTF8, ...)` 逐项转 UTF-8，去掉 argv[0]（Syringe 自身路径）；`WinMain` 不再用 `lpCmdLine`（UNREFERENCED），改为 `Run(GetArguments())`。
  - `Support.h`：`get_command_line(std::string_view)` → `parse_command_line(const std::vector<std::string>&)`：
    - 常量 `static constexpr std::string_view ARGS_FLAG = "--args=";`
    - 遍历 argv：`!exe_found && !arg.starts_with("-")` → executable_name；`arg.starts_with(ARGS_FLAG)` → 剥掉前缀存 game_arguments；其余 push 进 syringe_arguments；无 exe → `throw invalid_command_arguments{}`。
    - 新增 `printable(const std::vector<std::string>&)`（thread_local 缓冲拼接，用于日志）。
  - `SyringeDebugger` 构造器改为 `(std::string_view filename, std::vector<std::string> flags = {})`，直接遍历 argv（不再按空格切分——**修复 DLL 路径含空格会被切断的缺陷**），`-i=` 提取逻辑不变。
  - `README.md`：完整 CLI 章节（见下）。
- 【对移植的意义】这是所有后续 flag（`--detach` 等）挂载的解析骨架，直接移植最终版。

### 10. 764beda — Make Syringe detach itself after hooks are injected, and wait for the process to exit (#16)

- 【标题】注入完 hook 后让 Syringe 自我 detach，并等待进程退出
- 【性质】功能
- 【改动文件与规模】4 文件：`Log.cpp`（+1）、`README.md`（+27）、`SyringeDebugger.cpp`（~+40）、`SyringeDebugger.h`（+13）。
- 【功能细节】
  - 新 flag 常量（`SyringeDebugger.h`）：`NODETACH_FLAG = "--nodetach"`、`NOWAIT_FLAG = "--nowait"`；新成员 `bool bDetachWhenDone{ true }`、`bool bWaitForProcessEnd{ true }`。
  - 新成员 `HANDLE workingHandle{ nullptr }`：`CREATE_PROCESS_DEBUG_EVENT` 时置为 `dbgEvent.u.CreateProcessInfo.hProcess`；`PatchMem`/`ReadMem`/`AllocMem` 全部改用 `workingHandle` 替代 `pInfo.hProcess`（detach 后仍可安全操作）；`DebugProcess` 启动时也先记录 `workingHandle = pInfo.hProcess`。
  - `Run()` 调试循环重构：
    - `EXIT_PROCESS_DEBUG_EVENT`：记录 `exit_code` 后 break；
    - 每轮 `ContinueDebugEvent` 之后判断 `if (bDetachWhenDone && bHooksCreated && wasSingleStep)` → 日志 "Hooks placed, detaching debugger." → `DebugActiveProcessStop(dbgEvent.dwProcessId)`（失败打日志）→ break。`wasSingleStep` 在 EXCEPTION_DEBUG_EVENT 且异常码为 `EXCEPTION_SINGLE_STEP` 时置位（即刚写完所有 hook stub 后的单步事件 = 全部 hook 已就位的信号）。
    - 循环外：`workingHandle = nullptr`；若 `bWaitForProcessEnd`：`WaitForSingleObject(pInfo.hProcess, INFINITE)` + `GetExitCodeProcess`；最后 `CloseHandle(pInfo.hProcess)`。
  - `Log.cpp`：`WriteLine` 末尾加 `fflush(File)`（detach 后日志即时可见）。
  - `README.md`：新增 "Debugger Detach and Process Lifetime" 章节：默认 detach；`--nodetach` 保持附加；`--nowait` 不等待目标进程退出。
- 【对移植的意义】detach = `DebugActiveProcessStop` + 手工等待句柄；**detach 时机判定（bHooksCreated && 单步事件）** 是移植要点。注意此 commit 后默认仍是"附加 + 等待"（bDetachWhenDone 默认 true），到 commit 18 才翻转。

### 11. 39fc085 — Make handshakes optional

- 【标题】让握手变为可选
- 【性质】功能（flag）
- 【改动文件与规模】2 文件：`SyringeDebugger.cpp`（+6）、`SyringeDebugger.h`（+5）。
- 【功能细节】
  - 新 flag：`HANDSHAKES_FLAG = "--handshakes"`；`bool bHandshakes{ false }`（**默认关闭**，显式传 `--handshakes` 才开启）。
  - `Handshake()` 开头：`if (!bHandshakes) { 日志 "Skipping handshake for DLL: %s"; return ret; }`——返回空 optional（nullopt）。
  - FindDLLs 中空 optional 的语义：既不阻止也不放行，落入 else-if 分支检查 `.syexe00`（`CanHostDLL`）。
  - 背景（README）：闭源版 Syringe 的握手会拒绝 Ares 在 Steam 版 Yuri's Revenge 上加载；SyringeEx 已重实现相关能力，故默认跳过握手。
- 【对移植的意义】握手开关；注意"空 optional → 回退 CanHostDLL"的控制流。

### 12. 3147902 — Restore formatting of the opcodes array

- 【标题】恢复 opcodes 数组的紧凑格式
- 【性质】纯格式化
- 【改动文件与规模】`SyringeDebugger.cpp` 单处（11+/46-）。
- 【功能细节】把 cec977f 展开成"每字节一行"的 opcodes 数组压回"每条指令一行"（如 `0x60, 0x9C, // PUSHAD, PUSHFD`）。已核对：字节序列完全一致，**无功能改动**。
- 【对移植的意义】无。

### 13. ba05ddb — Preserve zero flag after hook execution

- 【标题】hook 执行后保留零标志（ZF）
- 【性质】功能（stub 字节码）
- 【改动文件与规模】`SyringeDebugger.cpp` 单处。
- 【功能细节】
  - 把 POPFD + POPAD 副本提取为宏 `POPFD_POPAD`。
  - **关键重排**：旧顺序是 `POPFD → POPAD → CMP fs:[0x14],0 → JE → JMP fs:[0x14]`——CMP 会污染 ZF（ZF = "fs:[0x14]==0" 的结果），导致 hook 函数进入时标志位被破坏（无法安全 hook 条件跳转指令）。
  - 新顺序（code_call 数组）：
    ```
    0x60, 0x9C,                  ; PUSHAD, PUSHFD
    0x68, x4,                    ; PUSH HookAddress（hook 原始地址）
    0x54,                        ; PUSH ESP（注释：(final REGISTERS* argument)）
    0xE8, x4,                    ; CALL ProcAddress
    0x83, 0xC4, 0x08,            ; ADD ESP, 8
    0x64, 0xA3, 0x14,0,0,0,      ; MOV fs:[0x14], EAX（EAX=解析出的 hook 函数地址）
    0x64, 0x83, 0x3D, 0x14,0,0,0, 0x00,  ; CMP DWORD PTR fs:[0x14], 0
    0x74, 0x18,                  ; JE proceed（跳过 0x18=24 字节）
    ; jmp_to_address:
    POPFD_POPAD,                 ; 恢复标志+寄存器（含 ESP 支持）
    0x64, 0xFF, 0x25, 0x14,0,0,0, ; JMP DWORD PTR fs:[0x14]（进入 hook 函数）
    ; proceed:
    POPFD_POPAD,                 ; 恢复标志+寄存器
    ; 此处写入被覆盖的原指令（重建后）与 jmp_back
    ```
  - 两条路径（进 hook / 继续原代码）各自独立完成 POPFD+POPAD，均保留 hook 入口处的完整标志（含 ZF）。
- 【对移植的意义】允许 hook 条件跳转指令（Jcc 依赖 ZF）；对应 `ZFPreservation` feature flag。

### 14. 4e43375 — Feature flags (#17)

- 【标题】Feature flags（能力协商 API）
- 【性质】功能（SDK 头 + 协商机制）
- 【改动文件与规模】4 文件 +488：`include/Syringe.h`（新文件 +337）、`SyringeDebugger.cpp`（+92）、`SyringeDebugger.h`（+16）、`README.md`（+43）。
- 【功能细节】
  - **`include/Syringe.h`（新增 SDK 头，DLL 侧使用）**：
    - 寄存器封装：`LimitedRegister`（32 位 DWORD 容器 + Get16/Get8、模板 Get/Set）、`ExtendedRegister`（8 位高/低字节访问 Get8Hi/Get8Lo/Set8Hi/Set8Lo）、`StackRegister`（lea/At 栈指针访问）。
    - 宏 `REG_SHORTCUTS(reg)`、`REG_SHORTCUTS_X(r)`、`REG_SHORTCUTS_HL(r)`、`REG_SHORTCUTS_XHL(r)`。
    - `class REGISTERS`：`DWORD origin; DWORD flags;` + 8 个寄存器成员（_EDI/_ESI/_EBP/_ESP 为 StackRegister）；方法 `Origin()`、`EFLAGS()` get/set、`EAX()/EBX()/...` 快捷访问（含 16/8 位变体）、`Stack<T>(offset)`/`Stack16/Stack8`、`Base<T>(offset)`、`lea_Stack/ref_Stack`。**指针作为参数传给 EXPORT 函数**。
    - 宏：`EXPORT`（`extern "C" __declspec(dllexport) DWORD __cdecl`）、`EXPORT_FUNC(name)`。
    - 握手：`struct SyringeHandshakeInfo`（cbSize/num_hooks/checksum/exeFilesize/exeTimestamp/exeCRC/cchMessage/Message）、`SYRINGE_HANDSHAKE(pInfo)`。
    - `#if SYR_VER == 2`：`hookdecl`/`hostdecl`（`__declspec(align(16))`、pack(16)）、`.syhks00`/`.syexe00` 段声明、`declhook(hook, funcname, size)`/`declhost(exename, checksum)` 宏；`#ifndef declhook` 提供空宏兜底；`DEFINE_HOOK(hook, funcname, size)`（声明+函数开头）、`DEFINE_HOOK_AGAIN(...)`。
    - **Feature flags 定义（最终命名，注意不是 SYRINGE_HAS_* 前缀）**：
      ```cpp
      namespace SyringeFeatures
      {
          extern "C" __declspec(dllexport) inline bool ESPModification = false;
          extern "C" __declspec(dllexport) inline bool ZFPreservation = false;
      }
      ```
      `extern "C"` + `__declspec(dllexport)` + `inline`（替代最初尝试的 `__declspec(selectany)`，因不编译）导出符号，默认 false——**旧版 Syringe 不识别的符号保持 false**，实现向后兼容。
  - **`SyringeDebugger.h`**：`static constexpr std::string_view FeatureFlagNames[] = { "ESPModification", "ZFPreservation" };`；`struct FeatureFlagEntry { char lib[MaxNameLength]; char symbol[MaxNameLength]; };`；`v_FeatureFlags`、`loop_FeatureFlags`、`bool bFeaturesSet{ false }`。
  - **`SyringeDebugger.cpp`（协商机制）**：
    - `FindDLLs()` 末尾：对 `v_AllHooks` 中每个**唯一 DLL** × 每个 flag 名生成 `FeatureFlagEntry`（`strncpy_s` 拷贝 lib/symbol）。
    - `HandleException`：DLL 加载循环（LoadLibraryFunc 逐条解析 hook 函数地址）完成后，若 `v_FeatureFlags` 非空，先进入"设 flag"阶段：把 `LibName`/`ProcName` 写入共享数据区，`context.Eip = &GetData()->LoadLibraryFunc`（注入进程内执行 LoadLibrary+GetProcAddress 的小代码），单步执行；下一次单步断点处理里 `ReadMem(&GetData()->ProcAddress, &flagAddr, 4)` 得到目标进程内该导出符号地址，`PatchMem(flagAddr, &trueVal, 1)` 写 1（true），日志记录；循环直至全部条目完成，然后 `bFeaturesSet = true; context.Eip = pcEntryPoint` 继续目标进程入口。
  - **`README.md`**：Feature Flags API 章节——原理（DLL 加载后 Syringe 解析导出布尔符号并置 true）、示例代码（`if (SyringeFeatures::ZFPreservation)`）、当前 flag 列表、添加新 feature 的三步流程（1. Syringe.h 加 bool；2. SyringeDebugger.h 的 FeatureFlagNames[] 加符号名；3. README 文档）。
- 【对移植的意义】**移植时注意实际宏/符号名**：协商符号是 `SyringeFeatures::ESPModification` / `ZFPreservation` / `ReladdrInstructionFixup`（C 链接导出的布尔变量），并非任务提示的 `SYRINGE_HAS_*` 宏——以实际代码为准。

### 15. 54be1c3 — Relative instruction fixup (#19)（重点中的重点）

- 【标题】相对指令修复（相对寻址指令的搬迁重编码）
- 【性质】功能（核心）+ 引入第三方库 + 构建 + 测试
- 【改动文件与规模】107 文件 +152686/-14。其中约 15.2 万行是 vendored 的 **Zydis 5.0.0** 与 **Zycore-C 1.5.2**（MIT 许可）源码，真正逻辑改动：`SyringeDebugger.cpp` 275 行、`SyringeDebugger.h` 16 行、`include/Syringe.h` 1 行、`README.md` 5 行、`.gitignore` 3 行、`Debugger.vcxproj` 17 行、`Syringe.sln` 29 行、`Tests.vcxproj`（新 78 行）、`tests/RebuildInstructionsTests.cpp`（新 644 行）、`external/Zydis.vcxproj`（新 189 行）。
- 【引入的库与结构】
  - `external/include/Zydis/...`（Decoder/DecoderTypes/Encoder/Formatter/Utils/Register 等头）、`external/include/Zycore/...`（基础库头）、`external/src/Zydis/*.c`（含 Generated/DecoderTables.inc 等大表）、`external/src/Zycore/*.c`；`external/Zydis.vcxproj` 把 Zydis+Zycore 编成静态库（项目 GUID `{B2C3D4E5-2345-6789-ABCD-EF2345678901}`）。
  - `Syringe.sln`：`VisualStudioVersion` 15.0 → 18.5（VS 2026）；新增 `Tests`（`{A1B2C3D4-1234-5678-9ABC-DEF012345678}`）与 `Zydis` 两个工程（仅 Win32 平台映射）。
  - `Debugger.vcxproj`：`AdditionalIncludeDirectories` 加 `$(ProjectDir)external\include`；预定义加 `ZYDIS_STATIC_BUILD;ZYCORE_STATIC_BUILD`；删除 `<CallingConvention>StdCall</CallingConvention>`；Link 加 `AdditionalLibraryDirectories`；新增 ProjectReference → Zydis.vcxproj。
  - `Tests.vcxproj`（新，仅 Release|Win32 控制台应用）：编译 `tests\RebuildInstructionsTests.cpp` + `SyringeDebugger.cpp` + `Log.cpp` + `CRC32.cpp` + `PortableExecutable.cpp`，预定义含 `SYRINGE_TESTING`（见下），输出 `tests\bin\Tests.exe`，引用 Zydis 工程。
- 【SyringeDebugger.h 改动】
  - `#pragma warning(push, 0)` 包裹引入 `<Zydis/Decoder.h>`、`<Zydis/DecoderTypes.h>`、`<Zydis/Encoder.h>`、`<Zydis/Utils.h>`。
  - 新增静态方法：`static std::vector<BYTE> RebuildInstructions(BYTE const* bytes, size_t size, DWORD originalAddr, DWORD newAddr);`，用 `#ifdef SYRINGE_TESTING public/private` 包裹使其在测试构建中可被直接调用。
  - `FeatureFlagNames[]` 追加 `"ReladdrInstructionFixup"`。
- 【include/Syringe.h】`SyringeFeatures` 追加 `ReladdrInstructionFixup = false`。
- 【SyringeDebugger.cpp 275 行核心逻辑】
  - 新增 `ResolveRelativeOperands(ZydisEncoderRequest&, ZydisDecodedInstruction const&, ZydisDecodedOperand const*, ZyanU64 srcAddr)`：对 encoder request 中 IMMEDIATE 与 MEMORY 类型操作数用 `ZydisCalcAbsoluteAddress` 解出绝对地址写回（imm.u / mem.displacement）。
  - 新增 `RebuildInstructions(bytes, size, originalAddr, newAddr)` 两趟算法：
    - **Pass 1（解码+分类）**：`ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32)`，`ZydisDecoderDecodeFull` 逐条解码；对带 `ZYDIS_ATTRIB_IS_RELATIVE` 的指令：仅 `COND_BR / UNCOND_BR / CALL` 类别且 mnemonic 不是 LOOP/LOOPE/LOOPNE/JCXZ/JECXZ/JRCXZ（这些只有 rel8 无 near 形式）才认为"有 near 形式"；用 `ZydisCalcAbsoluteAddress` 解析目标，若落在 `[originalAddr, originalAddr+size)` 内则标记 `intraPrologue`（分支指向被搬迁代码内部）并记录 `targetSrcOffset`（无 near 形式的 intra 目标打警告日志）；用 `ZydisEncoderDecodedInstructionToEncoderRequest` 生成请求并缓存，`ResolveRelativeOperands` 绝对化，再强制 `branch_type = ZYDIS_BRANCH_TYPE_NEAR`、`branch_width = ZYDIS_BRANCH_WIDTH_32`（输出大小确定：Jcc near = 6 字节 `0F 8x rel32`，JMP/CALL = 5 字节 `E9/E8 rel32`）；解码失败 → 记录 `tailOffset`，剩余字节原样拷贝 + 警告日志（"faulty return 0 hook"）。
    - **Pass 2（重编码输出）**：非相对指令原样字节拷贝；相对指令用缓存请求 `ZydisEncoderEncodeInstructionAbsolute(&req, encoded, &len, dstAddr)`（按新地址编码 rel）；`intraPrologue` 时把立即数目标改写为目标指令在输出缓冲中的新绝对地址（在 `infos` 中按 `srcOffset` 查目标、替换 `newAddr + 目标输出偏移`），保证跳到**搬迁后**的指令而非原地址；编码失败则原样拷贝 + 日志。
  - `HandleException` 创建 hook 代码块处：
    - 先 `ReadMem(it.first, original_bytes.data(), overridden)` 读出被覆盖的原始字节（不再直接写进输出）；
    - 分配上界从 `count*sizeof(code_call) + sizeof(jmp_back) + overridden` 改为 `count*sizeof(code_call) + sizeof(jmp_back) + overridden*3`（重编码可能膨胀：短分支→near）；
    - 把"原样拷贝 overridden 字节"替换为 `RebuildInstructions(original_bytes.data(), overridden, originalAddr, newAddr)`，其中 `originalAddr = it.first`、`newAddr = base + (p_code - code.data())`；拷贝实际 `rebuilt.size()`；
    - jmp_back 后 `p_code += sizeof(jmp_back)`；最后 `PatchMem(base, code.data(), actual_sz)` 只写实际大小。
  - **解决什么问题**：hook 覆盖点（prologue）内的指令若含相对转移（Jcc/JMP/CALL），被简单拷贝到远处 trampoline（`AllocMem` 分配的 caller code 区）后，rel8 短跳距离不够、rel32 位移指向旧地址 → 崩溃/错误跳转。现在用 Zydis 解码 → 绝对目标 → 按新地址 near 重编码，trampoline 内行为与原地一致；intra-prologue 目标重映射到搬迁后位置。
- 【tests/RebuildInstructionsTests.cpp（644 行，自研微型 harness：TEST_CASE/CHECK 宏 + 静态注册表，main 返回失败数）】17 个用例：
  1. `non_relative_copied_verbatim`：`83 C4 08 85 C0` 原样拷贝、长度不变；
  2. `short_jnz_relocated`：`75 14` @0x005DBA4E 搬到 0x10000000 → near JNZ（6 字节），目标仍 0x005DBA64；
  3. `short_jmp_relocated`：`EB 10` → 5 字节 near JMP，目标不变；
  4. `near_call_relocated`：`E8 FB 0F 00 00` 保持 5 字节，目标不变；
  5. `near_jmp_relocated`：同上；
  6. `mixed_instructions_with_jnz`：**真实 bug 复现**——`83 C4 08 85 C0 75 14` @0x005DBA49，前 5 字节原样、JNZ 重编码、目标 0x005DBA64；
  7. `short_jnz_stays_short_when_close`（后被 12 号用例推翻语义：现在总是 near）；
  8. `near_jnz_relocated`：`0F 85 FA 0F 00 00` → 6 字节、目标不变；
  9. `multiple_relative_instructions`：CALL+JNZ+JMP 连排各自保目标；
  10. `empty_input` / 11. `single_nop`：边界；
  12. `short_backward_jmp`：`EB F0` 负位移 → near、目标不变；
  13. `various_short_jcc`：JZ/JNZ/JB/JNB/JBE/JNBE/JL/JNL/JLE/JNLE 全系列；
  14. `intra_prologue_je_forward`：JE 目标指向 prologue 内指令 → 必须指向搬迁后的地址，**绝不允许指向原地址**；
  15. `intra_prologue_jmp_backward`：JMP 回 prologue 开头 → 指向 newAddr+0；
  16. `mixed_intra_and_external`：外部 CALL 保持原目标 + intra JE 重映射；
  17. `loop_external_target` / `loop_intra_prologue_does_not_corrupt_offsets` / `jecxz_intra_prologue_not_remapped`：LOOP/JECXZ 无 near 形式，不得标记 intraPrologue、不得破坏后续偏移表；
  18. `short_jnz_forced_near`：即使搬迁很近也强制 near 6 字节。
- 【README】License 章节注明 vendored Zydis 5.0.0 / Zycore-C 1.5.2 为 MIT；Feature Flags 列表追加 `ReladdrInstructionFixup`。
- 【.gitignore】追加 `tests/obj/**`、`tests/bin/**`、`external/lib/**`。
- 【对移植的意义】**整个 fork 最重的移植点**：需要 (a) 搬入 vendored Zydis/Zycore 源码与 Zydis.vcxproj 工程；(b) sln/vcxproj 加工程引用与 ZYDIS_STATIC_BUILD 宏；(c) 移植 RebuildInstructions 两趟算法与 HandleException 调用点（注意内存上界 overridden*3、actual_sz 写入）；(d) 移植 Tests 工程与测试（SYRINGE_TESTING 宏暴露静态方法）。

### 16. 10a1fd3 — Add GitHub CI

- 【标题】添加 GitHub CI
- 【性质】CI 基础设施
- 【改动文件与规模】4 文件 +177：`.github/actions/build/action.yml`、`.github/workflows/{nightly-build,pr-nightly-comment,release-build}.yml`。
- 【功能细节】
  - `build/action.yml`：composite action；`microsoft/setup-msbuild@v2`（vs-version `[17.0,)`）；`msbuild /m /p:Configuration=<cfg> /p:Platform=Win32 /v:q Syringe.sln`（注：Any CPU 平台无 Build.0 条目，必须显式 Win32）；可选 `run-tests` 跑 `tests\bin\Tests.exe`（非零即失败）；可选上传 artifact（LICENSE + `<config>/Syringe.exe` + `.pdb`）。
  - `nightly-build.yml`：push master/main/develop + 任意 PR 触发；windows-2022；Debug/Release 矩阵（fail-fast: false）；Release 跑测试；artifact 名 `Syringe-<config>-<sha>`。
  - `pr-nightly-comment.yml`：`workflow_run` completed 后，经 GitHub API 反查 PR 号，给 PR 发 nightly.link 下载评论（upsert 机制，标记 `<!-- bot: nightly-link -->`）。
  - `release-build.yml`：release published 触发；Release 构建 + 跑测试；7z 打包 `LICENSE` + `Release/Syringe.exe` 上传。
- 【对移植的意义】可直接复用为模板。

### 17. 982517f — fix `--nodetach`

- 【标题】修复 `--nodetach`
- 【性质】bug 修复（一行）
- 【改动文件与规模】`SyringeDebugger.cpp` +1 行。
- 【功能细节】`Run()` 中 `EXIT_PROCESS_DEBUG_EVENT` 分支：`exit_code = dbgEvent.u.ExitProcess.dwExitCode;` 之后、`break;` 之前补一行 `ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, continueStatus);`。原因：nodetach 模式下进程退出事件不继续（ContinueDebugEvent），调试器挂在 WaitForDebugEvent 上永不返回。
- 【对移植的意义】调试事件在 break 前必须 ContinueDebugEvent。

### 18. 8d797f8 — make `--nodetach` default, introduce `--detach`

- 【标题】让 `--nodetach` 成为默认，引入 `--detach`
- 【性质】功能（默认行为翻转）
- 【改动文件与规模】`SyringeDebugger.h` 2 处。
- 【功能细节】
  - 新常量 `DETACH_FLAG = "--detach"`（置 `bDetachWhenDone = true`）；
  - `bool bDetachWhenDone{ true }` → `bool bDetachWhenDone{ false }`（默认不 detach）；
  - `--nodetach` 保留（显式置 false，兼容旧命令行）。
- 【对移植的意义】最终默认语义：附加调试器直到目标进程退出；`--detach` 才提前脱离。

### 19. 43993e0 — increment version, adjust copyroght year

- 【标题】递增版本号、调整版权年份
- 【性质】版本号
- 【改动文件与规模】2 文件各 1 处：`resource.h`、`res.rc`。
- 【功能细节】`SYRINGEEX_VER_PATCH` 0→1（版本 0.1.0.0 → 0.1.0.1）；LegalCopyright 年份 "2025" → "2025-2026 Phobos Developers"。
- 【对移植的意义】版本宏修改点示例。

### 20. 7c8d0cb — adjust readme for `--detach/--nodetach` behavior

- 【标题】按 `--detach/--nodetach` 行为调整 README
- 【性质】文档
- 【改动文件与规模】`README.md` 单节。
- 【功能细节】**最终 CLI 语义（README 权威描述）**：
  - 默认：Syringe 保持调试器附加，目标进程退出后 Syringe 退出；
  - `--detach`：全部 hook 放完后自动 detach，目标进程继续运行；
  - `--nodetach`：保持附加（默认行为，为兼容保留）；
  - `--nowait`：detach 后（或附加时目标进程退出后）立即退出，不等待；
  - 示例：`syringe.exe game.exe` / `syringe.exe game.exe --detach` / `syringe.exe game.exe --detach --nowait`。
- 【对移植的意义】移植后 README 的目标形态。

### 21. b26b56a — Fix a hang on `RIP_EVENT` (#24)

- 【标题】修复 `RIP_EVENT` 上的挂起
- 【性质】bug 修复（一行）
- 【改动文件与规模】`SyringeDebugger.cpp` +1 行。
- 【功能细节】`Run()` 中 `else if (dbgEvent.dwDebugEventCode == RIP_EVENT)` 分支在 `break;` 前补 `ContinueDebugEvent(...)`。RIP_EVENT 是 Windows 调试器接口事件（System Error / "debugger does not handle this"），本代码将其视为终止调试循环的出口；不 Continue 会导致挂起（与 982517f 同类问题）。
- 【对移植的意义】同 982517f：break 前必须 ContinueDebugEvent。

### 22. 535056d — Increment version

- 【标题】递增版本号
- 【性质】版本号
- 【改动文件与规模】`resource.h` 1 行。
- 【功能细节】`SYRINGEEX_VER_PATCH` 1→2。**最终版本 0.1.0.2**（SyringeEx，基于 Syringe 0.7.2.0）。
- 【对移植的意义】最终版本号。

---

## 三、可移植功能清单（22 个 commit 归并为 10 项）

| # | 功能项 | 涉及 commit | 关键文件 | 核心事实 |
|---|--------|-------------|----------|----------|
| ① | `-i=` 额外 DLL 加载（注入白名单） | 3（3b21a21）、9（bda61b9 改进） | Main.cpp、SyringeDebugger.h（INCLUDE_FLAG）、SyringeDebugger.cpp（FindDLLs） | flag 语法 `-i=<dllname.dll>`，可重复；出现时只注入列出的 DLL，缺省 `*.dll` 全目录扫描；未知 flag 跳过并记日志；最终版基于 argv 数组解析（无空格切断问题） |
| ② | FS:[0x14] 多线程 hook 返回机制 | 4（fa55bcc） | SyringeDebugger.cpp（code_call 字节码）、SyringeDebugger.h（删 AllocData::ReturnEIP） | 返回地址从共享区字段改为 TIB 每线程字段：`MOV/CMP/JMP fs:[0x14]`（0x64 FS 前缀 + 0x14 TIB arbitrary user pointer）；多线程安全 |
| ③ | 钩子内改 ESP（POPAD 副本） | 7（3e36626） | SyringeDebugger.cpp | 硬件 POPAD 换成 17 字节手工副本，EAX 从 [ESP+0xC] 恢复、旧 ESP 经 EBX 暂存搬入槽位、ESP 最后 POP；hook 可改栈深度退出 |
| ④ | 新命令行格式 | 9（bda61b9） | Main.cpp（GetArguments）、Support.h（parse_command_line/ARGS_FLAG）、SyringeDebugger.h | 最终语法 `Syringe.exe <exe name> [-i=<dll> ...] [--args="<args>"]`；CommandLineToArgvW+UTF-8；第一个非 `-` 参数为 exe；`--args=` 剥前缀作游戏参数；其余进 syringe_arguments |
| ⑤ | detach 默认行为（`--detach/--nodetach/--nowait`） | 10（764beda）、17（982517f）、18（8d797f8）、20（7c8d0cb） | SyringeDebugger.cpp（Run 循环、workingHandle、DebugActiveProcessStop）、SyringeDebugger.h（bDetachWhenDone/bWaitForProcessEnd）、README | 默认附加直到目标进程退出；`--detach` 钩子放完（bHooksCreated && 单步事件）后 DebugActiveProcessStop；`--nodetach` 保持附加（兼容）；`--nowait` 不等退出；Log 加 fflush；EXIT_PROCESS/RIP_EVENT break 前必须 ContinueDebugEvent |
| ⑥ | 可选握手（`--handshakes`） | 11（39fc085） | SyringeDebugger.cpp（Handshake）、SyringeDebugger.h（HANDSHAKES_FLAG、bHandshakes） | 默认跳过握手（返回空 optional → 回退 .syexe00 CanHostDLL 检查）；显式 `--handshakes` 开启 |
| ⑦ | 零标志保留 | 13（ba05ddb） | SyringeDebugger.cpp（POPFD_POPAD 宏、code_call 重排） | CMP fs:[0x14],0 与 JE 提前到 POPFD 之前；进 hook 与 proceed 两条路径各自 POPFD+POPAD；hook 入口标志（含 ZF）完整 |
| ⑧ | Feature flags SDK 头 | 14（4e43375）、15（54be1c3 追加 1 个） | include/Syringe.h（SyringeFeatures 命名空间）、SyringeDebugger.h（FeatureFlagNames[]/FeatureFlagEntry/v_FeatureFlags/bFeaturesSet）、SyringeDebugger.cpp（LoadLibraryFunc 逐条设 true）、README | 符号为 `extern "C" __declspec(dllexport) inline bool`（**非 SYRINGE_HAS_* 宏**）：`ESPModification`、`ZFPreservation`、`ReladdrInstructionFixup`，默认 false；机制=加载 DLL→GetProcAddress 导出符号→目标进程内写 1 字节 1 |
| ⑨ | Zydis 相对指令修复 | 15（54be1c3） | SyringeDebugger.cpp（RebuildInstructions/ResolveRelativeOperands + HandleException 调用点）、SyringeDebugger.h（Zydis 头、SYRINGE_TESTING）、external/（vendored Zydis 5.0.0+Zycore-C 1.5.2）、Syringe.sln/Debugger.vcxproj/Tests.vcxproj、tests/RebuildInstructionsTests.cpp | 被覆盖指令含相对转移时原样拷贝会跳错/崩溃；Zydis 解码→绝对目标→强制 near→按新地址 ZydisEncoderEncodeInstructionAbsolute 重编码；intra-prologue 目标重映射到搬迁后地址；内存上界 overridden*3；17 个单测 |
| ⑩ | RIP_EVENT 挂起修复 | 21（b26b56a） | SyringeDebugger.cpp | RIP_EVENT 分支 break 前补 ContinueDebugEvent，否则 WaitForDebugEvent 挂死 |

---

## 四、附注

- **版本轨迹**：0.1.0.0（c192550）→ 0.1.0.1（43993e0）→ **0.1.0.2（535056d，HEAD）**。
- **最终 CLI 全集**：`-i=<dll>`、`--args="<game args>"`、`--detach`、`--nodetach`、`--nowait`、`--handshakes`（常量见 SyringeDebugger.h：INCLUDE_FLAG / ARGS_FLAG（Support.h）/ DETACH_FLAG / NODETACH_FLAG / NOWAIT_FLAG / HANDSHAKES_FLAG）。
- **最终 FeatureFlagNames[]**（SyringeDebugger.h）：`ESPModification`、`ZFPreservation`、`ReladdrInstructionFixup`。
- **未改动/保持上游的部分**：PE 解析（PortableExecutable）、inj 文件解析（ParseInjFileHooks）、.syhks00/.syexe00 段解析、CRC32、CanHostDLL 逻辑、Syringe.h 中 SYR_VER==2 的 declhook/declhost 体系（沿用上游）。
- 本分析基于 `git show <sha>` 与 HEAD 工作区核对；未修改仓库任何文件。
