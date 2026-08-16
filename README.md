# Syringe0721

SyringeIH —— 基于 Ares-Developers/Syringe 演化的 DLL 注入与运行时钩子加载器（版本线 0.3.x）。
本仓库已并入 SyringeEx（Phobos-developers/SyringeEx）相对 Ares/Syringe master 的 22 个 commit 所引入的功能。

## 命令行用法

语法（沿用 SyringeIH 原有格式）：

```
Syringe.exe [-Name=true|false ...] [-Ext=扩展包名] [-i=<dll> ...] "<exe name>" <游戏参数>
```

SyringeIH 原有 flag 保持不变（`-LongStackDump=`、`-EnableHandshakeCheck=`、`-DetachAfterInjection=`、
`-AutoTerminate=` 等，全部也可在 Syringe.json 中配置）。

### 移植自 SyringeEx 的新增项

- **`-i=<dll>`（可重复）**：注入白名单。出现时只注入列出的 DLL（按文件名或路径、大小写不敏感匹配；
  `SyringeEx.dll` 始终载入）；不出现时按默认策略扫描目录（含 `\Patches\` 与扩展包）。
- **`--detach` / `--nodetach`**：别名，等价于 `-DetachAfterInjection=true / false`。
  注入完成后分离调试器，目标进程继续运行；`--nodetach`（默认）保持附加直到目标退出。
- **`--nowait`**：等价于 `-WaitForProcessExit=false`。分离后不等待目标进程退出，Syringe 立即结束。
  默认（无 `--nowait`）在分离后等待目标进程退出并记录退出码。
- **`--handshakes`**：别名，等价于 `-EnableHandshakeCheck=true`（SyringeIH 默认即开启握手检查）。
- **`--snapshot`**：快照广播模式（等价于 `-StackSnapshot=true`；Syringe.json 中 `"StackSnapshot": true` 亦可触发）。
  此模式下 Syringe 不启动游戏、不走注入流程：枚举本机所有运行中的 SyringeIH，按身份映射
  （`Local\SyringeIH.Snapshot.{pid}`，内含 Magic/协议版本/软件版本/GamePid）三段验证——是 SyringeIH、
  协议版本受支持（协议只增不减，当前 1 为兼容起点，更早版本放弃）——之后向每个目标进程
  `DebugBreakProcess` 请求一次全线程栈快照，结果由各目标 SyringeIH 写入自己的 `syringe.log`，
  广播器把打断数量/版本/PID 等汇总写入独立的 `syringe_snapshot.log`（不接触同目录 syringe 的
  `syringe.log`），随后退出（成功返回 0）。
- 另新增 JSON 设置项 **`WaitForProcessExit`**（默认 true）。

## 快照 / 异常报告格式（skill 接口）v1

目标 SyringeIH 会在自己的 `syringe.log` 中输出结构化报告段（`format = syringeih.report.v1`），
供下游 skill / AI agent 解析。栈转储文本**不结构化**（外部 DLL 可在其中夹带任意注释，
如 IHInspector 行、钩子信息），因此报告 = 结构化 JSON 段（固定字段契约）+ 原样文本转储段。

### 标记语法（标记行与 JSON 行不带时间戳，独占一行）

```
@@SyringeIH:JSON:BEGIN:process:{seq}@@      @@SyringeIH:JSON:END:process:{seq}@@
@@SyringeIH:JSON:BEGIN:thread:{tid}@@       @@SyringeIH:JSON:END:thread:{tid}@@
@@SyringeIH:TEXT:BEGIN:thread:{tid}@@       @@SyringeIH:TEXT:END:thread:{tid}@@
```

识别正则：`^@@SyringeIH:(JSON|TEXT):(BEGIN|END):(process|thread):(\d+)@@$`。
BEGIN/END 标记之间的、以 `{` 开头的行即 JSON；`TEXT` 段内为原样栈转储（含夹带，不解析）。
`seq` 为快照/异常共用的事件序号，同一事件的所有段共享同一 seq；线程按 TID 升序、
模块按基址升序输出。

### 段 Schema（字段集固定，缺数据填 `null`；地址为 `"0x%08X"` 字符串，计数/字节为数字）

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
  `Tests`（`RebuildInstructions` 单测，Release 构建，运行 `tests\bin\Tests.exe`）。
- 工具集 v143、Windows SDK 10.0；主程序 Release/Debug 均为 v143。
- vendored 第三方：Zydis 5.0.0 与 Zycore-C 1.5.2（MIT，见 `external/`）。
