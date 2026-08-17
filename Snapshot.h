#pragma once
#define WIN32_LEAN_AND_MEAN

#include <string>
#include <string_view>
#include <vector>

#include <Windows.h>

#include "Version.h"

// ============ 快照广播协议（SyringeIH 专用） ============
// 身份对象：命名文件映射 L"Local\\SyringeIH.Snapshot.{syringePid}"
// 内容：SnapshotIdentity
//   Magic            —— 固定值，识别“SyringeIH 快照协议家族”
//   ProtocolVersion  —— 协议版本，只增不减；1 = 兼容起点
//   SoftwareVersion  —— Syringe 软件版本（十进制打包），供广播器记录
//   GamePid          —— 被调试进程 PID，广播器的打断目标
//   PayloadLen       —— 载荷字节数；0 = 无载荷。作为“提交标志”最后写入
//   Payload          —— UTF-8 载荷（序列化 JSON 对象），携带影响快照呈现形式的配置
//
// 载荷语义：
//   - 生命周期：每次广播（触发快照）覆写一次；接收端在 Handle_Snapshot 时读取当前值；
//   - 按目标定向：载荷写在每个目标各自的映射里，天然支持不同目标不同载荷；
//   - 写序：先写 Payload 字节，最后写 PayloadLen（接收端以 PayloadLen!=0 判定提交完成）。
// 广播器验证链：映射存在（是 SyringeIH）→ Magic 正确 → 协议版本受支持 →
// 写入载荷 → 才 DebugBreakProcess(GamePid)
#define SNAPSHOT_MAGIC             0x53595248u                             // 'SYRH'
#define SNAPSHOT_PROTOCOL_VERSION  1u
#define SNAPSHOT_SOFTWARE_VERSION  (VMAJOR * 1000000 + VMINOR * 10000 + VRELEASE * 100 + VBUILD)
#define SNAPSHOT_PAYLOAD_MAX       4096u                                   // 载荷字节上限（超限截断）

struct SnapshotIdentity
{
	DWORD Magic;
	DWORD ProtocolVersion;
	DWORD SoftwareVersion;
	DWORD GamePid;
	DWORD PayloadLen;
	char  Payload[SNAPSHOT_PAYLOAD_MAX];
};

inline std::wstring SnapshotMappingName(DWORD const syringePid)
{
	return L"Local\\SyringeIH.Snapshot." + std::to_wstring(syringePid);
}

// 调试侧（接收端）：发布 / 撤销身份映射
bool SnapshotRegister(DWORD gamePid);
void SnapshotUnregister();

// 接收端：读取自己映射里的当前载荷（PayloadLen == 0 → 空串）
std::string SnapshotReadPayload();

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

// 广播侧：向指定目标（syringePid 的映射）覆写载荷；返回是否成功。
// 超限截断到 SNAPSHOT_PAYLOAD_MAX；空串写入 PayloadLen = 0（清除旧载荷）。
bool SnapshotWritePayload(DWORD syringePid, std::string_view payload);

// 广播侧：一轮广播，返回进程退出码（0 = 成功）。
// payload：本轮请求载荷（序列化 JSON）；当前所有目标写入同一载荷，
// 按目标定向的载荷提供方式后续接入（写入发生在每个目标的映射上，机制已支持）。
DWORD SnapshotBroadcast(std::string_view payload);

// 报告编目：以无时间戳直写输出一个 JSON 段（BEGIN 标记行 / JSON 行 / END 标记行）
// type: "process" | "thread" | "request"；key: 十进制串（进程/请求段用 seq、线程段用 tid）
void WriteReportSegment(char const* type, char const* key, char const* jsonText);

// 线程来源过滤（渲染配置）：sourceModule 为线程来源模块名（basename，如 "game.exe"；
// 空串 = 来源未知）。include/exclude 为拆分后的模块名数组（Syringe.json 的数组形式
// 与命令行逗号分隔串解析后均归一到此）。
// 规则：命中 exclude → 过滤；否则 include 非空且未命中 → 过滤；其余保留。
// 来源未知：include 模式下被过滤（fail-closed），纯 exclude 模式下保留。
// 匹配：模块名整体比较、不区分大小写。
bool SnapshotThreadFiltered(
	std::string_view sourceModule,
	std::vector<std::string> const& include,
	std::vector<std::string> const& exclude);

// 把逗号分隔的模块名列表切成模式串（剔除空白与空项）；命令行解析与请求段回显共用
std::vector<std::string> SnapshotSplitModuleList(std::string_view list);

// Main 的日志文件选择：在解析 flags/JSON 之前做轻量预扫描
// （误判由 Main 在最终配置确定后的权威切换兜底）
bool CommandLineRequestsSnapshot(std::string_view arguments);
bool JsonFileRequestsSnapshot();
char const* SelectLogFile(std::string_view arguments);
