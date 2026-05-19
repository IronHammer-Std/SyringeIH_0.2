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

	std::wstring CollectAddrToJsonArray();
};