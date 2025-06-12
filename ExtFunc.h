#pragma once
#include <string>
#include <string_view>
#include <set>
#include <vector>
#include "HookAnalyzer.h"


struct HookIdx
{
	std::string Lib;
	std::string Proc;
};
bool operator<(const HookIdx& A, const HookIdx& B);

class JsonObject;

bool ReadHookIdxSet(std::set<HookIdx>& Set, JsonObject Obj);

void LogIdxSet(const std::set<HookIdx>& Set,const std::string_view Name);

class DisableHookIdxSet
{
private:
	std::set<HookIdx> IdxSet;
public:
	inline std::set<HookIdx>& Get() { return IdxSet; }
	bool Disabled(const HookIdx& Idx);
	void Enable(const std::set<HookIdx>& Set);
	void Disable(const std::set<HookIdx>& Set);
};

struct MemCopyInfo
{
	int Start;
	int End;
	std::string Name;
	std::vector<int> OffsetFixes;
};


class LibExtData
{
private:
	std::set<HookIdx> DiasbleHooks;
	std::vector<MemCopyInfo> MemCopyRange;
	std::vector<Hook> Hooks;
	
	bool OK;
	std::string SettingText;
	
public:
	std::wstring ModuleName;
	unsigned BaseAddr;
	std::wstring PDBPath;
	uintmax_t PDBSize;
	bool PDBExists;
	bool MAPExists;
	std::wstring MAPPath;

	bool Available() { return OK; }
	void ReadFromFile(std::string_view FileName,std::string_view DllName);
	void PushDiasbleHooks(DisableHookIdxSet& Set);
	inline std::vector<MemCopyInfo>& GetMemCopy() { return MemCopyRange; }
	inline std::vector<Hook>& GetHooks() { return Hooks; }
	inline std::string& GetSetting() { return SettingText; }
	inline void SetPDBPath(const std::wstring& str, size_t _PDBSize)
	{
		PDBPath = str;
		PDBExists = !str.empty();
		PDBSize = _PDBSize;
	}
	inline void SetMAPPath(const std::wstring& str)
	{
		MAPPath = str;
		MAPExists = !str.empty();
	}
};
