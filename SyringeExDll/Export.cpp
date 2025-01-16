
#include "..\ExtJson.h"
#include <unordered_map>
#include <Windows.h>

struct BackupData
{
	std::vector<char> Data;
	bool Restored{ false };
};

std::unordered_map<std::string, JsonFile> Files;
std::unordered_map<int, BackupData> Ptr;

struct ExportOffsets
{
	int CodeSize;
	int CallOfs;
	int Reserved[6];
}Ofs
{
	40,//FOR RESHADE //38,
	16 //FOR RESHADE //9
};

extern "C" void __declspec(dllexport) __stdcall UpdateJson(const char* Name, const char* Json)
{
	if (!Name || !Json)return;
	auto it = Files.find(Name);
	if (it != Files.end())return;
	Files[Name].Parse(Json);
}

extern "C" JsonObject __declspec(dllexport) __stdcall GetJson(const char* Name)
{
	auto it = Files.find(Name);
	if (it == Files.end())return NullJsonObject;
	return it->second.GetObj();
}

extern "C" int __declspec(dllexport) __stdcall GetExportData(void)
{
	return int(&Ofs);
}

extern "C" void __declspec(dllexport) __stdcall SetBackUp(int Addr, int Size)
{
	DWORD OldProtect;
	VirtualProtect((LPVOID)Addr, Size, PAGE_EXECUTE_READWRITE, &OldProtect);
	auto& v = Ptr[Addr];
	if (!v.Restored && !v.Data.empty())return;
	v.Restored = false;
	v.Data.clear();
	v.Data.resize(Size);
	memcpy(v.Data.data(), (LPVOID)Addr, Size);
	VirtualProtect((LPVOID)Addr, Size, OldProtect, &OldProtect);
}

extern "C" void __declspec(dllexport) __stdcall RestoreBackUp(int Addr)
{
	auto it = Ptr.find(Addr);
	if (it == Ptr.end())return;
	if (it->second.Data.empty())return;
	auto Size = it->second.Data.size();
	DWORD OldProtect;
	VirtualProtect((LPVOID)Addr, Size, PAGE_EXECUTE_READWRITE, &OldProtect);
	memcpy((LPVOID)Addr, it->second.Data.data(), Size);
	VirtualProtect((LPVOID)Addr, Size, OldProtect, &OldProtect);
	//it->second.Data.clear();
	it->second.Restored = true;
}


