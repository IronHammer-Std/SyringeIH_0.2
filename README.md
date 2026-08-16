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
- 另新增 JSON 设置项 **`WaitForProcessExit`**（默认 true）。

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
