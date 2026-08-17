#include "HookAnalyzer.h"
#include "Handle.h"
#include "Setting.h"
#include <filesystem>
#include <cstring>
#include "Log.h"

void PrintTimeStampToFile(const FileHandle& File);

// ============ NDJSON（HookAnalysis.Format = "NDJSON"）输出辅助 ============

// JSON 字符串转义输出（入参须为 UTF-8；含两端引号）
static void PrintJsonEscaped(FILE* File, std::string const& utf8)
{
	fputc('"', File);
	for (auto c : utf8)
	{
		switch (c)
		{
		case '"': fputs("\\\"", File); break;
		case '\\': fputs("\\\\", File); break;
		case '\n': fputs("\\n", File); break;
		case '\r': fputs("\\r", File); break;
		case '\t': fputs("\\t", File); break;
		default:
			if ((unsigned char)c < 0x20)
				fprintf(File, "\\u%04X", (unsigned char)c);
			else
				fputc(c, File);
			break;
		}
	}
	fputc('"', File);
}

// ACP(代码页 936) → UTF-8：NDJSON 规范要求 UTF-8（库名/路径可能含中文）
static std::string ACPtoUTF8(std::string const& s)
{
	if (s.empty()) return s;
	auto const wlen = MultiByteToWideChar(CP_ACP, 0, s.c_str(), (int)s.size(), nullptr, 0);
	std::wstring w(wlen, L'\0');
	MultiByteToWideChar(CP_ACP, 0, s.c_str(), (int)s.size(), w.data(), wlen);
	auto const ulen = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), wlen, nullptr, 0, nullptr, nullptr);
	std::string u(ulen, '\0');
	WideCharToMultiByte(CP_UTF8, 0, w.c_str(), wlen, u.data(), ulen, nullptr, nullptr);
	return u;
}

// 单条钩子记录输出为一行 JSON（section 标明所属分组：ByAddress / ByLibrary）
static void PrintHookNDJSON(FILE* File, char const* section, HookAnalyzeData const& v)
{
	fprintf(File, "{\"section\":\"%s\",\"addr\":%d,\"proc\":", section, v.Addr);
	PrintJsonEscaped(File, ACPtoUTF8(v.Proc));
	fputs(",\"rel_lib\":", File);
	PrintJsonEscaped(File, ACPtoUTF8(v.RelLib));
	fputs(",\"lib\":", File);
	PrintJsonEscaped(File, ACPtoUTF8(v.Lib));
	fprintf(File, ",\"len\":%d,\"priority\":%d,\"sub_priority\":", v.Len, v.Priority);
	PrintJsonEscaped(File, ACPtoUTF8(v.SubPriority));
	fputs("}\n", File);
}

void HookAnalyzer::Add(HookAnalyzeData&& Data)
{
	ByLibName[Data.Lib].push_back(Data);
	HookMap[Data.Lib + AnalyzerDelim + Data.Proc] = Data;
	ByAddress[Data.Addr].push_back(std::move(Data));
}
void HookAnalyzer::AddEx(HookAnalyzeData&& Data)
{
	HookMapEx[Data.Lib + AnalyzerDelim + Data.Proc] = Data;
	ByLibNameEx[Data.Lib].push_back(Data);
	ByAddressEx[Data.RelLib][Data.Addr].push_back(std::move(Data));
}
bool HookAnalyzer::Report()
{
	FileHandle File = FileHandle(fopen("HookAnalysis.log", "w"));
	if (!File)return false;
	bool const NDJSON = _stricmp(HookAnalysisFormat.c_str(), "NDJSON") == 0;
	if (NDJSON)
	{
		fprintf(File, "{\"event\":\"start\",\"version\":\"%s\"}\n", VersionString);
	}
	else
	{
		fprintf(File, "%s 将分析获取到的钩子。\n", VersionString);
	}
	if (ShowHookAnalysis_ByAddr)
	{
		if (NDJSON)
		{
			for (auto& p : ByAddress)
			{
				for (auto const& v : p.second)
				{
					PrintHookNDJSON(File, "ByAddress", v);
				}
			}
		}
		else
		{
			fputs("========================\n", File);
			fputs("按照钩子位置分析：（每个地址处按照钩子执行序）\n", File);
			for (auto& p : ByAddress)
			{
				fprintf(File, "在 %08X ：\n", p.first);
				for (auto v : p.second)
				{
					fprintf(File, "钩子\"%s，相对于\"%s\"，来自\"%s\"，长度%d，优先级 %d，次优先级 \"%s\"\n", v.Proc.c_str(), v.RelLib.c_str(), v.Lib.c_str(), v.Len, v.Priority, v.SubPriority.c_str());
				}
			}
		}
	}
	
	if (ShowHookAnalysis_ByLib)
	{
		if (NDJSON)
		{
			for (auto& p : ByLibName)
			{
				for (auto const& v : p.second)
				{
					PrintHookNDJSON(File, "ByLibrary", v);
				}
			}
		}
		else
		{
			fputs("========================\n", File);
			fputs("按照钩子来源分析：\n", File);
			for (auto& p : ByLibName)
			{
				fprintf(File, "正在分析 DLL ：\"%s\" ……\n", p.first.c_str());
				for (auto v : p.second)
				{
					fprintf(File, "钩子\"%s\"，相对于\"%s\"，位于%08X，长度%d，优先级 %d，次优先级 \"%s\"\n", v.Proc.c_str(), v.RelLib.c_str(), v.Addr, v.Len, v.Priority, v.SubPriority.c_str());
				}
			}
		}
	}
	
	if (NDJSON)
	{
		fputs("{\"event\":\"end\"}\n", File);
	}
	else
	{
		fputs("========================\n", File);
		fprintf(File, "%s 分析完毕。\n", VersionString);
	}
	return true;
}

const std::string& ExecutableDirectoryPath();

bool HookAnalyzer::HasHookConflict()
{
	//check if there are conflicting hooks
	bool Conflict = false;
	for (auto& [lib, byaddr] : ByAddressEx)
	{
		std::vector<std::vector<HookAnalyzeData>*> SortedHooks;
		for (auto& p : byaddr)
			SortedHooks.push_back(&p.second);
		std::sort(SortedHooks.begin(), SortedHooks.end(), [](const auto& lhs, const auto& rhs) -> bool
			{
				return lhs->front().Addr < rhs->front().Addr;
			});
		for (size_t i = 0; i < SortedHooks.size() - 1; i++)
		{
			auto Addr1 = SortedHooks[i]->front().Addr;
			auto Addr2 = SortedHooks[i + 1]->front().Addr;
			auto Len1 = std::max_element(SortedHooks[i]->begin(), SortedHooks[i]->end(), [](const auto& lhs, const auto& rhs) -> bool
				{
					return lhs.Len < rhs.Len;
				})->Len;
			Len1 = std::max(Len1, 5);//a JMP is 5 bytes
			if (Addr1 + Len1 > Addr2)
			{
				Log::WriteLine("检测到钩子冲突：");
				for (auto& h : *SortedHooks[i])
					Log::WriteLine("钩子\"%s\"，来自\"%s\"，相对于\"%s\"，位于%08X，长度%d，优先级 %d，次优先级 \"%s\"",
						h.Proc.c_str(),
						h.Lib.c_str(),
						h.RelLib.c_str(),
						h.Addr,
						h.Len,
						h.Priority,
						h.SubPriority.c_str());
				for (auto& h : *SortedHooks[i + 1])
					Log::WriteLine("钩子\"%s\"，来自\"%s\"，相对于\"%s\"，位于%08X，长度%d，优先级 %d，次优先级 \"%s\"",
						h.Proc.c_str(),
						h.Lib.c_str(),
						h.RelLib.c_str(),
						h.Addr,
						h.Len,
						h.Priority,
						h.SubPriority.c_str());
				if (!Conflict && ShowHookConflictPopup)
				{
					wchar_t ErrorStr[1000];
					swprintf_s(ErrorStr, 1000, L"检测到位于 0x%08X 和 0x%08X 的钩子冲突，详见 Syringe.log 。", Addr1, Addr2);
					MessageBoxW(NULL, ErrorStr, VersionLString, MB_OK | MB_ICONERROR);
				}
				Conflict = true;
			}
		}
	}
	return Conflict;
}

bool HookAnalyzer::GenerateINJ()
{
	//Log::WriteLine(ExecutableDirectoryPath().c_str());
	auto path = ExecutableDirectoryPath() + "\\INJ";
	auto pp = CreateDirectoryA(path.c_str(), NULL);
	if (pp || GetLastError() == ERROR_ALREADY_EXISTS)
	{
		//Log::WriteLine((path + "\\").c_str());
		for (auto& p : ByLibNameEx)
		{
			//Log::WriteLine((path + "\\" + p.first).c_str());
			FileHandle File = FileHandle(fopen((path+"\\"+p.first+".inj").c_str(), "w"));
			if (!File)return false;
			for (auto& h : p.second)
			{
				if (!h.RelLib.empty())
					fputs(";Relative Hook Found ,failed to Generate", File);
				else if (!h.SubPriority.empty())
					fprintf(File, "%X=%s,%X,%d,%s\n", h.Addr, h.Proc.c_str(), h.Len, h.Priority, h.SubPriority.c_str());
				else if (h.Priority == 100000)
					fprintf(File, "%X=%s,%X\n", h.Addr, h.Proc.c_str(), h.Len);
				else
					fprintf(File, "%X=%s,%X,%d\n", h.Addr, h.Proc.c_str(), h.Len, h.Priority);
			}
		}
		return true;
	}
	return false;
}