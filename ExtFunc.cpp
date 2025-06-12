#include "ExtFunc.h"
#include "ExtJson.h"
#include "Log.h"
#include "Setting.h"
#include "SyringeDebugger.h"

bool operator<(const HookIdx& A, const HookIdx& B)
{
	if (A.Lib != B.Lib)
	{
		return A.Lib < B.Lib;
	}
	else
	{
		return A.Proc < B.Proc;
	}
}

const std::string& ExecutableDirectoryPath();

bool ReadHookIdxSet(std::set<HookIdx>& Set, JsonObject Obj)
{
	if (!Obj.Available())return false;
	for (auto& p : Obj.GetMapObject())
	{
		if (p.second.Available())
			for (auto& q : p.second.GetArrayString())
			{
				Set.insert({ ExecutableDirectoryPath() + "\\" + p.first, q});
				Set.insert({ ExecutableDirectoryPath() + "\\Patches\\" + p.first, q });
			}
		else return false;
	}
	return true;
}

void LogIdxSet(const std::set<HookIdx>& Set, const std::string_view Name)
{
	Log::WriteLine("钩子组 %s ：", Name.data());
	for (const auto& p : Set)
	{
		Log::WriteLine("库 \"%s\"， 函数  \"%s\"", p.Lib.c_str(), p.Proc.c_str());
	}
}

bool DisableHookIdxSet::Disabled(const HookIdx& Idx)
{
	return IdxSet.count(Idx) != 0;
}
void DisableHookIdxSet::Enable(const std::set<HookIdx>& Set)
{
	for (auto& p : Set)
	{
		if (IdxSet.count(p))IdxSet.erase(p);
	}
}
void DisableHookIdxSet::Disable(const std::set<HookIdx>& Set)
{
	for (auto& p : Set)
	{
		if (!IdxSet.count(p))IdxSet.insert(p);
	}
}

void LibExtData::ReadFromFile(std::string_view FileName, std::string_view DllName)
{
	OK = false;
	auto Str = GetStringFromFile(FileName.data());
	if (Str.empty())
	{
		//Log::WriteLine(" 此DLL不存在配套的 .json 文件。");
		return;
	}
	else Log::WriteLine(" 此DLL存在配套的 .json 文件。");


	JsonFile File;
	auto ErrorStr = File.ParseChecked(Str);
	if (!File.Available())
	{
		Log::WriteLine("载入 %s 失败：非法的 JSON 文件", FileName.data());
		Log::WriteLine("将不使用此配置。");
		if (!ErrorStr.empty())
		{
			Log::WriteLine("错误信息：\"\n%s\"", ErrorStr.c_str());
			MessageBoxA(
				nullptr, (std::string(DllName) + "的配套JSON文件非法。详见Syringe.log。").c_str(),
				VersionString, MB_OK | MB_ICONINFORMATION);
		}
		return;
	}
	auto Obj = File.GetObj();
	auto SObj = Obj.GetObjectItem("DisableHooks");
	if (SObj.Available() && SObj.IsTypeObject())
	{
		ReadHookIdxSet(DiasbleHooks, SObj);
		LogIdxSet(DiasbleHooks, FileName.data() + std::string("::DiasbleHooks"));
	}
	SObj = Obj.GetObjectItem("RelativeHooks");
	if (SObj.Available() && SObj.IsTypeArray())
	{
		auto Arr = SObj.GetArrayObject();
		Hooks.reserve(Arr.size());
		for (auto& obj : Arr)
		{
			auto arr = obj.GetArrayString();
			if (arr.size() >= 4)
			{
				Hooks.emplace_back();
				auto& h = Hooks.back();
				strncpy(h.RelativeLib, arr[0].c_str(), MaxNameLength);
				strncpy(h.lib, DllName.data(), MaxNameLength);
				strncpy(h.proc, arr[2].c_str(), MaxNameLength);
				sscanf(arr[3].c_str(), "%d", &h.num_overridden);
				sscanf(arr[1].c_str(), "%X", &h.proc_address);
				if (arr.size() >= 5)
				{
					sscanf(arr[4].c_str(), "%d", &h.Priority);
				}
				if (arr.size() >= 6)
				{
					strncpy(h.SubPriority, arr[5].c_str(), MaxNameLength);
				}
			}
		}
	}
	SObj = Obj.GetObjectItem("MemoryCopyRange");
	if (SObj.Available() && SObj.IsTypeArray())
	{
		auto Arr = SObj.GetArrayObject();
		MemCopyRange.reserve(Arr.size());
		for (auto& obj : Arr)
		{
			if (obj.Available() && obj.IsTypeArray())
			{
				auto arr = obj.GetArrayString();
				if (arr.size() >= 3)
				{
					MemCopyRange.emplace_back();
					auto& rg = MemCopyRange.back();
					rg.Name = arr[2];
					sscanf(arr[0].c_str(), "%X", &rg.Start);
					sscanf(arr[1].c_str(), "%X", &rg.End);
					if (arr.size() > 3)
					{
						rg.OffsetFixes.resize(arr.size() - 3);
						for (size_t i = 3; i < arr.size(); i++)
						{
							sscanf(arr[i].c_str(), "%X", &rg.OffsetFixes[i - 3]);
						}
					}
				}
			}
			else
			{
				Log::WriteLine(__FUNCTION__ " : 无法识别的Json条目 \"%s\" 。", obj.GetText().c_str());
			}
		}
	}



	SObj = Obj.GetObjectItem("Setting");
	if (SObj.Available())
	{
		if (Setting.Available())
		{
			auto SO = Setting.GetObj();
			auto SS = SO.GetObjectItem("Setting");
			if (SS.Available())
			{
				auto SD = SS.GetObjectItem(DllName.data());
				if (SD.Available())
				{
					SObj.Merge(SD);
				}
			}
		}
		SettingText = SObj.GetText();
	}
	else SettingText = "";

	OK = true;
}
void LibExtData::PushDiasbleHooks(DisableHookIdxSet& Set)
{
	Set.Disable(DiasbleHooks);
}




