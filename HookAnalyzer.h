#pragma once

#include<vector>
#include<unordered_map>

const std::string AnalyzerDelim = "\\*^*\\";

struct HookAnalyzeData
{
	std::string Lib;
	std::string Proc;
	int Addr;
	int Len;

	int Priority;
	std::string SubPriority;
	std::string RelLib;
};

class HookAnalyzer
{
private:
	std::unordered_map<std::string, std::vector<HookAnalyzeData>> ByLibName;
	std::unordered_map<std::string, std::vector<HookAnalyzeData>> ByLibNameEx;
public:
	std::unordered_map<std::string, HookAnalyzeData> HookMap;
	std::unordered_map<int, std::vector<HookAnalyzeData>> ByAddress;
	std::unordered_map<std::string, HookAnalyzeData> HookMapEx;
	std::unordered_map<int, std::vector<HookAnalyzeData>> ByAddressEx;

	void Add(HookAnalyzeData&&);
	void AddEx(HookAnalyzeData&&);
	bool Report();
	bool GenerateINJ();
	bool HasHookConflict();
};

static constexpr size_t MaxNameLength = 0x100u;

struct Hook
{
	char lib[MaxNameLength];
	char proc[MaxNameLength];
	void* proc_address;

	size_t num_overridden;
	int Priority;
	char SubPriority[MaxNameLength];
	char RelativeLib[MaxNameLength];
};