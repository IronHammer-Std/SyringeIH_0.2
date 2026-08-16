#pragma once
#include <variant>
#include <string>
#include <Windows.h>
#include <vector>
#include "Log.h"

struct ProcessedDumpInfoEntry_String
{
	std::string Info;
};

struct ProcessedDumpInfoEntry_Addr
{
	DWORD Address;
	std::string Prefix;
	std::string Processed;
};

using ProcessedDumpInfoEntry = std::variant<ProcessedDumpInfoEntry_String, ProcessedDumpInfoEntry_Addr>;

struct ProcessedDumpInfoHandler
{
	std::vector<ProcessedDumpInfoEntry> Entries;

	// 报告编目：Flush 时若有内容，则在输出前后加
	// @@SyringeIH:TEXT:BEGIN:{Tag}@@ / @@SyringeIH:TEXT:END:{Tag}@@
	// 标记行；空则什么都不输出。默认空 Tag = 行为与旧版完全一致。
	std::string Tag;

public:
	void AddString()
	{
		Entries.emplace_back(ProcessedDumpInfoEntry_String{ "" });
	}

	void AddString(const std::string& Info)
	{
		Entries.emplace_back(ProcessedDumpInfoEntry_String{ Info });
	}

	void AddAddr(DWORD Address, const std::string& Prefix)
	{
		Entries.emplace_back(ProcessedDumpInfoEntry_Addr{ Address, Prefix, "" });
	}

	void AddString(char const* pFormat, ...);

	void Flush();

	void Fillin(const std::vector<std::string> DescStr);

	void Clear();

	std::wstring CollectAddrToJsonArray();
};