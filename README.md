# SyringeIH

SyringeIH —— 基于 Ares-Developers/Syringe 演化的 DLL 注入与运行时钩子加载器。
本仓库已并入 SyringeEx（Phobos-developers/SyringeEx）相对 Ares/Syringe master 的 22 个 commit 所引入的功能。

## 命令行用法

语法（沿用 SyringeIH 原有格式）：

```
Syringe.exe [-Name=true|false ...] [-Ext=扩展包名] [-i=<dll> ...] [--args="<游戏参数>"] "<exe name>" <游戏参数>
```

SyringeIH 原有 flag 保持不变（`-LongStackDump=`、`-EnableHandshakeCheck=`、`-DetachAfterInjection=`、
`-AutoTerminate=` 等，全部也可在 Syringe.json 中配置）。

flags 段支持**引号感知切词**：引号紧贴值书写（如 `-SnapshotFileName="my log.txt"`）时，
引号内的空格属于参数值、合并为单个 flag，引号本身被剔除；exe 的起始引号以"token 开头位置的 `"`"
判定，flag 值内的引号不会误判为 exe 边界。未闭合引号会吞到段尾。注意：整体加引号的 flag
（`"-SnapshotFileName=my log.txt"`）仍会被视为 exe 位置，请用 `-X="值"` 写法。

- **`--args="<游戏参数>"`**：移植自 SyringeEx。可放在 exe 的**前面或后面**；出现多个时取
  **最后一个**；引号内文本被展开，拼接在游戏参数**最前面**（`--args=` 内容在前 +
  引号后尾巴在后，空格分隔），`--args="..."` 片段本身不再传给游戏。
  裸形式 `--args=xxx`（无引号）取到下一个空白为止；`--args` 不带 `=` 不识别。

### 移植自 SyringeEx 的新增项

- **`-i=<dll>`（可重复）**：注入白名单。出现时只注入列出的 DLL（按文件名或路径、大小写不敏感匹配；
  `SyringeEx.dll` 始终载入）；不出现时按默认策略扫描目录（含 `\Patches\` 与扩展包）。
- **`--detach` / `--nodetach`**：别名，等价于 `-DetachAfterInjection=true / false`。
  注入完成后分离调试器，目标进程继续运行；`--nodetach`（默认）保持附加直到目标退出。
- **`--nowait`**：等价于 `-WaitForProcessExit=false`。分离后不等待目标进程退出，Syringe 立即结束。
  默认（无 `--nowait`）在分离后等待目标进程退出并记录退出码。
- **`--handshakes`**：别名，等价于 `-EnableHandshakeCheck=true`。握手检查默认**关闭**
  （2022 年起废弃的特性，与上游 0.7.3 / SyringeEx 对齐）；可用此 flag、`-EnableHandshakeCheck=true`
  或 Syringe.json 的 `EnableHandshakeCheck` 显式开启。
- 另新增 JSON 设置项 **`WaitForProcessExit`**（默认 true）。

## 快照模式

### 快照模式的命令行

**`--snapshot`**：快照广播模式（等价于 `-StackSnapshot=true`；Syringe.json 中 `"StackSnapshot": true` 亦可触发）。
  此模式下 Syringe 不启动游戏、不走注入流程：枚举本机所有运行中的 SyringeIH，按身份映射
  （`Local\SyringeIH.Snapshot.{pid}`，内含 Magic/协议版本/软件版本/GamePid + 请求载荷区）三段验证——
  是 SyringeIH、协议版本受支持（协议只增不减，当前 1 为兼容起点，更早版本放弃）——之后向每个
  目标进程写入本轮请求载荷并 `DebugBreakProcess` 请求一次全线程栈快照，结果由各目标 SyringeIH
  写入自己的 `syringe.log`，广播器把打断数量/版本/PID 等汇总写入独立的 `syringe_snapshot.log`
  （不接触同目录 syringe 的 `syringe.log`），随后退出（成功返回 0）。
  请求载荷为序列化 JSON 对象（携带影响快照呈现形式的配置；上限 4096 字节，超限截断；
  每次广播覆写、按目标定向）。首个载荷参数：
  - **`SnapshotFileName`**：Syringe.json 参数（默认 `""`，可用 `-SnapshotFileName=xxx` 覆盖）；
    广播时原样复述进载荷；接收方非空时，**本次快照的全程内容**（摘要/request/process/thread/TEXT
    各段）输出到该文件而非 `syringe.log`（syringe.log 句柄保持打开，结束后恢复，不截断）。
    ⚠ Windows PowerShell 5.1 传参会把 `-X=值.扩展名` 在点号前拆开（`snap_manual.log` 变成
    `snap_manual .log`）。Syringe 已在 flag 解析层自动拼回（日志可见"命令行参数修复"），
    一般无需处理；若遇到异常可给整个 flag 加引号或改用 `--%` / cmd /c（pwsh 7+ 无此问题）。
- 随包提供 **`一键快照.bat`**（与 `Syringe.exe` 同目录，GBK 编码）：双击即广播一轮快照；
  文件内注释说明了换成 `--snapshot -SnapshotFileName=xxx.log` 的效果。

### 快照 / 异常报告格式（skill 接口）v1

目标 SyringeIH 会在自己的 `syringe.log` 中输出结构化报告段（`format = syringeih.report.v1`），
供下游 skill / AI agent 解析。栈转储文本**不结构化**（外部 DLL 可在其中夹带任意注释，
如 IHInspector 行、钩子信息），因此报告 = 结构化 JSON 段（固定字段契约）+ 原样文本转储段。

### 标记语法（标记行与 JSON 行不带时间戳，独占一行）

```
@@SyringeIH:JSON:BEGIN:process:{seq}@@      @@SyringeIH:JSON:END:process:{seq}@@
@@SyringeIH:JSON:BEGIN:request:{seq}@@      @@SyringeIH:JSON:END:request:{seq}@@
@@SyringeIH:JSON:BEGIN:thread:{tid}@@       @@SyringeIH:JSON:END:thread:{tid}@@
@@SyringeIH:TEXT:BEGIN:thread:{tid}@@       @@SyringeIH:TEXT:END:thread:{tid}@@
```

识别正则：`^@@SyringeIH:(JSON|TEXT):(BEGIN|END):(process|request|thread):(\d+)@@$`。
BEGIN/END 标记之间的、以 `{` 开头的行即 JSON；`TEXT` 段内为原样栈转储（含夹带，不解析）。
`seq` 为快照/异常共用的事件序号，同一事件的所有段共享同一 seq；线程按 TID 升序、
模块按基址升序输出。

### 段 Schema（字段集固定，缺数据填 `null`；地址为 `"0x%08X"` 字符串，计数/字节为数字）

- **request 段**（可选，仅快照；有请求载荷时出现）：`format/type/group/seq` 恒有（`type:"request"`），
  载荷本体嵌套在 `payload` 对象内——广播器写入的序列化 JSON（携带影响快照呈现形式的配置），
  经接收端净化重序列化为单行，与快照同 `seq`。
- **process 段**（每次快照一个，`group:"snapshot"`）：`format/type/group/seq/epoch_ms/time/trigger`、
  `syringe{pid,version,protocol}`、`pid/main_tid/exe/path/image_base/image_size/exe_timestamp/crc`、
  `uptime_ms/cpu{user_ms,kernel_ms}/memory{working_set,pagefile,peak_working_set}`、
  `handle_count/thread_count/module_count`、`phase{hooks_created,everything_ok}`、
  `modules[{name,path,base,size}]`（`main_tid` = 主线程 TID，即进程初始线程）。
- **thread 段**（快照=每线程一个 `group:"snapshot"`；异常=仅出错线程一个 `group:"exception"`）：
  `format/type/group/seq/tid`、`main`（bool，是否主线程——主线程 = CREATE_PROCESS 调试事件报告的初始线程）、
  `name`（0x406D1388 命名机制登记的线程名；未命名时填
  `"来自 {模块} 的线程"`）、`source`（线程来源 = 入口点经 AnalyzeAddr 解析出的模块名，
  无法解析时为 null）、`start{addr,module,offset}`（线程起始地址，来自
  `CREATE_THREAD_DEBUG_EVENT.lpStartAddress`）、`context{eax..edi,eip,esp,ebp,eflags}`
  （仅寄存器指针，**栈信息不进 JSON**）；异常段另附 `exception{code,addr,flags,params[],
  access,fault_addr}`（access/fault_addr 仅访问违例时出现）。
  文本转储中，线程 ID 之后同样标注显示名（如 `线程 ID = 48908（来自 ntdll.dll 的线程，主线程）：`）。

### skill 提取规则

```
grep '@@SyringeIH:.*BEGIN' syringe.log             # 编目（全部段）
某线程 JSON = BEGIN/END 间以 { 开头的行；线程文本附件 = TEXT:BEGIN/END 之间的所有行
```

## Feature Flags（特性协商）

SDK 头：`include/Syringe.h`（供被注入 DLL 使用；REGISTERS 布局、握手结构、`DEFINE_HOOK`/`declhook`
等与 SyringeIH 注入协议一致）。

注入时，Syringe 会把下列导出布尔在被注入的 DLL 中置为 true（DLL 侧默认 false，旧版 Syringe 不会触碰）：

```cpp
#include <Syringe.h>

namespace SyringeFeatures
{
    // 支持在 hook 回调中修改 ESP（以不同栈深度退出）
    extern "C" __declspec(dllexport) inline bool ESPModification = false;
    // hook 执行后保留零标志（ZF），可安全钩住条件跳转指令
    extern "C" __declspec(dllexport) inline bool ZFPreservation = false;
    // 被覆盖字节中的相对寻址指令（Jcc/JMP/CALL）经 Zydis 重编码修正（相对指令修复）
    extern "C" __declspec(dllexport) inline bool ReladdrInstructionFixup = false;
}
```

DLL 内用法示例：

```cpp
#include <Syringe.h>
if (SyringeFeatures::ZFPreservation) {
    // 该 Syringe 版本保留零标志
} else {
    // 回退或拒绝加载
}
```

## 构建

- 解决方案 `Syringe.sln`：`Syringe`（主程序，Win32）、`SyringeExDll`、`Zydis`（vendored 静态库）、
  `NametestTarget` / `NametestStdTarget`（线程命名/快照载荷集成测试用的被调试程序，输出到 `tests\bin\`）、
  `Tests`（单测 + 端到端集成测试，Release 构建，运行 `tests\bin\Tests.exe`；端到端用例会在
  `tests\bin` 内跑完整调试会话，自动从 `Release\` 复制 `SyringeEx.dll`，资产缺失时跳过）。
- 工具集 v143、Windows SDK 10.0；主程序 Release/Debug 均为 v143。
- vendored 第三方：Zydis 5.0.0 与 Zycore-C 1.5.2（MIT，见 `external/`）。
