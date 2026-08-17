#include "Snapshot.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <cwchar>

#include <tlhelp32.h>

#include "Log.h"
#include "Setting.h" // GetStringFromFile

namespace
{
	HANDLE SnapshotMappingHandle{};
	void* SnapshotMappingView{};
}

bool SnapshotRegister(DWORD const gamePid)
{
	SnapshotUnregister();

	auto const name = SnapshotMappingName(GetCurrentProcessId());
	auto const mapping = CreateFileMappingW(
		INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE,
		0, sizeof(SnapshotIdentity), name.c_str());
	if(!mapping)
	{
		Log::WriteLine(__FUNCTION__ ": 创建快照身份映射失败，GetLastError() = %u。", GetLastError());
		return false;
	}

	auto const view = MapViewOfFile(mapping, FILE_MAP_WRITE, 0, 0, sizeof(SnapshotIdentity));
	if(!view)
	{
		Log::WriteLine(__FUNCTION__ ": 映射快照身份视图失败，GetLastError() = %u。", GetLastError());
		CloseHandle(mapping);
		return false;
	}

	SnapshotIdentity identity{};
	identity.Magic = SNAPSHOT_MAGIC;
	identity.ProtocolVersion = SNAPSHOT_PROTOCOL_VERSION;
	identity.SoftwareVersion = SNAPSHOT_SOFTWARE_VERSION;
	identity.GamePid = gamePid;
	std::memcpy(view, &identity, sizeof(identity));

	SnapshotMappingHandle = mapping;
	SnapshotMappingView = view;

	Log::WriteLine(
		__FUNCTION__ ": 已发布快照身份（SyringePID=%u, GamePid=%u, 协议=%u, 版本=%u）。",
		GetCurrentProcessId(), gamePid, identity.ProtocolVersion, identity.SoftwareVersion);
	return true;
}

void SnapshotUnregister()
{
	if(SnapshotMappingView)
	{
		UnmapViewOfFile(SnapshotMappingView);
		SnapshotMappingView = nullptr;
	}
	if(SnapshotMappingHandle)
	{
		CloseHandle(SnapshotMappingHandle);
		SnapshotMappingHandle = nullptr;
	}
}

std::string SnapshotReadPayload()
{
	if(!SnapshotMappingView) return {};

	auto const* const identity = static_cast<SnapshotIdentity const*>(SnapshotMappingView);
	auto const len = identity->PayloadLen;
	if(len == 0 || len > SNAPSHOT_PAYLOAD_MAX) return {};

	return std::string(identity->Payload, len);
}

bool SnapshotWritePayload(DWORD const syringePid, std::string_view const payload)
{
	auto const mapping = OpenFileMappingW(
		FILE_MAP_WRITE, FALSE, SnapshotMappingName(syringePid).c_str());
	if(!mapping)
	{
		Log::WriteLine(__FUNCTION__ ": 打开目标 %u 的载荷映射失败，GetLastError() = %u。", syringePid, GetLastError());
		return false;
	}

	auto const view = MapViewOfFile(mapping, FILE_MAP_WRITE, 0, 0, sizeof(SnapshotIdentity));
	if(!view)
	{
		Log::WriteLine(__FUNCTION__ ": 映射目标 %u 的载荷视图失败，GetLastError() = %u。", syringePid, GetLastError());
		CloseHandle(mapping);
		return false;
	}

	auto* const identity = static_cast<SnapshotIdentity*>(view);

	// 先写载荷字节，最后写 PayloadLen（提交标志）
	auto const len = (std::min)(payload.size(), size_t(SNAPSHOT_PAYLOAD_MAX));
	if(len)
	{
		std::memcpy(identity->Payload, payload.data(), len);
	}
	identity->PayloadLen = static_cast<DWORD>(len);

	UnmapViewOfFile(view);
	CloseHandle(mapping);
	return true;
}

bool CommandLineRequestsSnapshot(std::string_view const arguments)
{
	// 与 UpdateSetting 的真实语义对齐：--snapshot 或 -StackSnapshot=true
	// （预扫描大小写不敏感；误判由 Main 在最终配置确定后的权威切换兜底）
	auto const icontains = [](std::string_view const hay, std::string_view const needle)
	{
		if(needle.size() > hay.size()) return false;
		for(size_t i = 0; i + needle.size() <= hay.size(); ++i)
		{
			bool match = true;
			for(size_t j = 0; j < needle.size(); ++j)
			{
				if(std::toupper(static_cast<unsigned char>(hay[i + j])) !=
					std::toupper(static_cast<unsigned char>(needle[j])))
				{
					match = false;
					break;
				}
			}
			if(match) return true;
		}
		return false;
	};

	return icontains(arguments, "--snapshot") ||
		icontains(arguments, "-StackSnapshot=true");
}

bool JsonFileRequestsSnapshot()
{
	auto const text = GetStringFromFile("Syringe.json");
	if(text.empty()) return false;

	// 轻量原文扫描：找 "StackSnapshot" 键，其 ':' 后第一个非空白词是 true 即视为开启
	size_t pos = 0;
	while((pos = text.find("\"StackSnapshot\"", pos)) != std::string::npos)
	{
		auto const colon = text.find(':', pos + 14);
		if(colon == std::string::npos) return false;

		size_t i = colon + 1;
		while(i < text.size() &&
			(text[i] == ' ' || text[i] == '\t' || text[i] == '\r' || text[i] == '\n'))
		{
			++i;
		}
		if(text.compare(i, 4, "true") == 0) return true;
		pos = colon + 1;
	}
	return false;
}

char const* SelectLogFile(std::string_view const arguments)
{
	return (CommandLineRequestsSnapshot(arguments) || JsonFileRequestsSnapshot())
		? "syringe_snapshot.log"
		: "syringe.log";
}

void WriteReportSegment(char const* const type, char const* const key, char const* const jsonText)
{
	auto const begin = "@@SyringeIH:JSON:BEGIN:" + std::string(type) + ":" + key + "@@";
	auto const end = "@@SyringeIH:JSON:END:" + std::string(type) + ":" + key + "@@";
	Log::WriteRaw(begin.c_str());
	Log::WriteRaw(jsonText);
	Log::WriteRaw(end.c_str());
}

std::vector<std::string> SnapshotSplitModuleList(std::string_view const list)
{
	std::vector<std::string> ret;
	size_t begin = 0;
	while(begin <= list.size())
	{
		auto const end = list.find(',', begin);
		auto item = list.substr(begin,
			end == std::string_view::npos ? std::string_view::npos : end - begin);
		while(!item.empty() &&
			(item.front() == ' ' || item.front() == '\t' || item.front() == '\r' || item.front() == '\n'))
		{
			item.remove_prefix(1);
		}
		while(!item.empty() &&
			(item.back() == ' ' || item.back() == '\t' || item.back() == '\r' || item.back() == '\n'))
		{
			item.remove_suffix(1);
		}
		if(!item.empty()) ret.emplace_back(item);
		if(end == std::string_view::npos) break;
		begin = end + 1;
	}
	return ret;
}

bool SnapshotThreadFiltered(
	std::string_view const sourceModule,
	std::string_view const includeList,
	std::string_view const excludeList)
{
	if(sourceModule.empty()) return !includeList.empty(); // 来源未知：白名单下过滤，纯黑名单下保留

	auto const matches = [](std::string_view const source, std::string_view const list)
	{
		for(auto const& pattern : SnapshotSplitModuleList(list))
		{
			if(source.size() == pattern.size() &&
				_strnicmp(source.data(), pattern.data(), source.size()) == 0)
			{
				return true;
			}
		}
		return false;
	};

	if(matches(sourceModule, excludeList)) return true;              // exclude 命中 → 过滤
	if(!includeList.empty() && !matches(sourceModule, includeList)) return true; // 白名单未命中 → 过滤
	return false;
}

DWORD SnapshotBroadcast(std::string_view const payload)
{
	Log::WriteLine(__FUNCTION__ ": 正在枚举 Syringe 进程……");
	if(!payload.empty())
	{
		Log::WriteLine(__FUNCTION__ ": 本轮请求载荷 %u 字节（超限将截断至 %u）。",
			(unsigned)payload.size(), SNAPSHOT_PAYLOAD_MAX);
	}

	auto const hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if(hSnapshot == INVALID_HANDLE_VALUE)
	{
		Log::WriteLine(__FUNCTION__ ": 枚举进程失败，GetLastError() = %u。", GetLastError());
		return 1;
	}

	DWORD interrupted = 0;
	DWORD skipped = 0;
	DWORD failed = 0;
	auto const ownPid = GetCurrentProcessId();

	PROCESSENTRY32W entry{ sizeof(entry) };
	if(Process32FirstW(hSnapshot, &entry))
	{
		do
		{
			if(entry.th32ProcessID == ownPid) continue;
			if(_wcsicmp(entry.szExeFile, L"syringe.exe") != 0) continue;

			auto const syringePid = entry.th32ProcessID;
			Log::WriteLine(__FUNCTION__ ": 发现 syringe.exe（PID %u），正在验证……", syringePid);

			// 验证 1/2：存在身份映射（是 SyringeIH 且支持快照协议）
			auto const mapping = OpenFileMappingW(
				FILE_MAP_READ, FALSE, SnapshotMappingName(syringePid).c_str());
			if(!mapping)
			{
				++skipped;
				Log::WriteLine(__FUNCTION__ ":   PID %u 未发布快照身份（非 SyringeIH 或更早版本），跳过。", syringePid);
				continue;
			}

			SnapshotIdentity identity{};
			auto const view = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, sizeof(SnapshotIdentity));
			auto const mapped = view != nullptr;
			if(mapped)
			{
				identity = *static_cast<SnapshotIdentity const*>(view);
				UnmapViewOfFile(view);
			}
			CloseHandle(mapping);

			if(!mapped)
			{
				++failed;
				Log::WriteLine(__FUNCTION__ ":   PID %u 读取快照身份失败。", syringePid);
				continue;
			}

			if(identity.Magic != SNAPSHOT_MAGIC)
			{
				++skipped;
				Log::WriteLine(__FUNCTION__ ":   PID %u 身份 Magic 不符（0x%08X），跳过。", syringePid, identity.Magic);
				continue;
			}

			if(identity.ProtocolVersion < 1 || identity.ProtocolVersion > SNAPSHOT_PROTOCOL_VERSION)
			{
				++skipped;
				Log::WriteLine(__FUNCTION__ ":   PID %u 协议版本 %u 不受支持（本版本支持 1~%u），跳过。",
					syringePid, identity.ProtocolVersion, SNAPSHOT_PROTOCOL_VERSION);
				continue;
			}

			if(!identity.GamePid)
			{
				++skipped;
				Log::WriteLine(__FUNCTION__ ":   PID %u 尚未初始化目标进程，跳过。", syringePid);
				continue;
			}

			// 验证 3 通过：写入本轮载荷（每个目标各自的映射，天然支持按目标定向），
			// 写入失败降级为无载荷打断，不中断广播
			SnapshotWritePayload(syringePid, payload);

			auto const hGame = OpenProcess(
				PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
				PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
				FALSE, identity.GamePid);
			if(!hGame)
			{
				++failed;
				Log::WriteLine(__FUNCTION__ ":   PID %u 打开目标进程 %u 失败，GetLastError() = %u。",
					syringePid, identity.GamePid, GetLastError());
				continue;
			}

			BOOL const ok = DebugBreakProcess(hGame);
			CloseHandle(hGame);

			if(ok)
			{
				++interrupted;
				Log::WriteLine(__FUNCTION__ ":   已打断：SyringePID=%u 版本=%u 协议=%u GamePID=%u 载荷=%u 字节。",
					syringePid, identity.SoftwareVersion, identity.ProtocolVersion, identity.GamePid,
					(unsigned)payload.size());
			}
			else
			{
				++failed;
				Log::WriteLine(__FUNCTION__ ":   PID %u 打断失败，GetLastError() = %u。", syringePid, GetLastError());
			}
		} while(Process32NextW(hSnapshot, &entry));
	}

	CloseHandle(hSnapshot);

	Log::WriteLine(__FUNCTION__ ": 广播完成：打断 %u 个，跳过 %u 个，失败 %u 个。", interrupted, skipped, failed);
	return 0;
}
