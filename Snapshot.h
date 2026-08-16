#pragma once
#define WIN32_LEAN_AND_MEAN

#include <string>
#include <string_view>

#include <Windows.h>

#include "Version.h"

// ============ 快照广播协议（SyringeIH 专用） ============
// 身份对象：命名文件映射 L"Local\\SyringeIH.Snapshot.{syringePid}"
// 内容：SnapshotIdentity
//   Magic            —— 固定值，识别“SyringeIH 快照协议家族”
//   ProtocolVersion  —— 协议版本，只增不减；1 = 兼容起点（更早版本没有映射，直接放弃）
//   SoftwareVersion  —— Syringe 软件版本（十进制打包），供广播器记录
//   GamePid          —— 被调试进程 PID，广播器的打断目标
// 广播器验证链：映射存在（是 SyringeIH）→ Magic 正确 → 协议版本受支持 → 才 DebugBreakProcess(GamePid)
#define SNAPSHOT_MAGIC             0x53595248u                             // 'SYRH'
#define SNAPSHOT_PROTOCOL_VERSION  1u
#define SNAPSHOT_SOFTWARE_VERSION  (VMAJOR * 1000000 + VMINOR * 10000 + VRELEASE * 100 + VBUILD)

struct SnapshotIdentity
{
	DWORD Magic;
	DWORD ProtocolVersion;
	DWORD SoftwareVersion;
	DWORD GamePid;
};

inline std::wstring SnapshotMappingName(DWORD const syringePid)
{
	return L"Local\\SyringeIH.Snapshot." + std::to_wstring(syringePid);
}

// 调试侧（接收端）：发布 / 撤销身份映射
bool SnapshotRegister(DWORD gamePid);
void SnapshotUnregister();

struct SnapshotScopeGuard
{
	explicit SnapshotScopeGuard(DWORD const gamePid)
	{
		SnapshotRegister(gamePid);
	}

	~SnapshotScopeGuard()
	{
		SnapshotUnregister();
	}

	SnapshotScopeGuard(SnapshotScopeGuard const&) = delete;
	SnapshotScopeGuard& operator=(SnapshotScopeGuard const&) = delete;
};

// 广播侧：一轮广播，返回进程退出码（0 = 成功）
DWORD SnapshotBroadcast();

// Main 的日志文件选择：在解析 flags/JSON 之前做轻量预扫描
// （误判由 Main 在最终配置确定后的权威切换兜底）
bool CommandLineRequestsSnapshot(std::string_view arguments);
bool JsonFileRequestsSnapshot();
char const* SelectLogFile(std::string_view arguments);
