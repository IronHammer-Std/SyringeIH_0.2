#include <Windows.h>
#include <string>
#include <vector>
#include <fstream>
#include <algorithm>
#include <sstream>
#include <set>
#include <DbgHelp.h>
#include <map>
#include "Log.h"
#include "ExtFunc.h"
#include "SymMap.h"

struct MapSymbol {
    DWORD segment;
    DWORD offset;
    std::wstring name;
    DWORD64 address;
};

struct Segment {
	DWORD segment;
	DWORD offset;
	DWORD length;
};

namespace ModuleMap
{
    void AddSymbol(DWORD moduleBase, DWORD Size, const MapSymbol& Symbol);
}

std::string UnicodetoANSI(const std::wstring& Unicode);

std::string Trim(const std::string& str) {
	auto start = str.find_first_not_of(" \t");
	auto end = str.find_last_not_of(" \t");
	return (start == std::string::npos || end == std::string::npos) ? "" : str.substr(start, end - start + 1);
}

std::wstring Trim(const std::wstring& str) {
	auto start = str.find_first_not_of(L" \t");
	auto end = str.find_last_not_of(L" \t");
	return (start == std::wstring::npos || end == std::wstring::npos) ? L"" : str.substr(start, end - start + 1);
}

std::vector<MapSymbol> ParseMapFile(const std::wstring& mapFilePath) {
    std::vector<MapSymbol> symbols;
    std::vector<Segment> segments;
    std::vector<DWORD> segbase;
    std::set<DWORD> usedseg;

	Log::WriteLine("Parsing MAP file: %s",  UnicodetoANSI(mapFilePath).c_str());

    std::wifstream file(mapFilePath);

    if (!file.is_open()) {
        return symbols;
    }
    std::wstring line;
    bool inPublicsSection = false;

    while (std::getline(file, line)) {

        //Log::WriteLine("%s", UnicodetoANSI(line).c_str());

        // 跳过空行和注释行
        if (line.empty() || line.find(L";") == 0) {
            continue;
        }

        // 检查是否进入公共符号段
        if (line.find(L"Publics by Value") != std::wstring::npos) {

            DWORD LastBase = 0x1000;
            for (auto& seg : segments)
            {
                segbase.push_back(LastBase);
                //Log::WriteLine("SEGMENT BASE: %08X", LastBase);
                LastBase += seg.length;
                LastBase = (LastBase + 0xFFF) & 0xFFFFF000;
            }


            inPublicsSection = true;
            std::getline(file, line); // 跳过标题行
            continue;
        }

        // 处理符号行
        if (inPublicsSection) {
            // 格式示例: 0001:00000000       _main
            std::wistringstream iss(line);
            std::wstring segmentOffset, name;

            if (iss >> segmentOffset) {
                // 解析段:偏移格式
				name = Trim(iss.str().substr(segmentOffset.length() + 1));
                size_t colonPos = segmentOffset.find(L':');
                if (colonPos != std::string::npos) {
                    try {
                        //Log::WriteLine("SEGMENT : \"%s\" OFFSET : \"%s\" NAME : \"%s\"", 
                        //    UnicodetoANSI(segmentOffset.substr(0, colonPos)).c_str(), 
                        //    UnicodetoANSI(segmentOffset.substr(colonPos + 1)).c_str(),
                        //    UnicodetoANSI(name).c_str());

                        if (name._Starts_with(L"loc_"))continue;
                        if (name._Starts_with(L"locret_"))continue; 

                        MapSymbol sym;
                        sym.segment = std::stoul(segmentOffset.substr(0, colonPos), 0, 16);
                        usedseg.insert(sym.segment);
                        sym.offset = std::stoul(segmentOffset.substr(colonPos + 1), 0, 16);
                        sym.name = name;
                        DWORD base = segbase[std::min(usedseg.size(), segbase.size()) - 1];
						sym.address = base + sym.offset; // 假设段基址为 0x10000
                        symbols.push_back(sym);
                        
                    }
                    catch (...) {
                        //Log::WriteLine("Exception!");
                    }
                }
            }
        }
        else {
            std::wistringstream iss(line);
            std::wstring segmentOffset, length;
            if (iss >> segmentOffset >> length) 
            {
                length.pop_back();//'H' at back
                size_t colonPos = segmentOffset.find(L':');
                if (colonPos != std::string::npos) {
                    try {
                        DWORD segment = std::stoul(segmentOffset.substr(0, colonPos), 0, 16);
                        DWORD offset = std::stoul(segmentOffset.substr(colonPos + 1), 0, 16);
                        DWORD len = std::stoul(length, 0, 16);
                        segments.emplace_back();
                        segments.back().length = len;
						segments.back().segment = segment;
						segments.back().offset = offset;
						//Log::WriteLine("SEGMENT : %04X OFFSET : %08X LENGTH : %08X", segment, offset, len);
                    }
                    catch (...) {
                    }
                }
            }
        }
    }

    return symbols;
}

/*

// 增强的 MAP 文件解析
std::vector<MapSymbol> ParseMapFileEnhanced(const std::wstring& mapFilePath) {
    std::vector<MapSymbol> symbols;
    std::ifstream file(mapFilePath);

    if (!file) return symbols;

    std::string line;
    enum ParseState { NONE, SEGMENTS, PUBLICS, STATICS };
    ParseState state = NONE;

    while (std::getline(file, line)) {
        // 标准化行（移除多余空格）
        line.erase(std::remove(line.begin(), line.end(), '\r'), line.end());
        std::string trimmed = Trim(line);

        if (trimmed.empty()) continue;

        // 检测段
        if (trimmed.find("Start  Length") == 0) {
            state = SEGMENTS;
            continue;
        }
        else if (trimmed.find("Address         Publics by Value") == 0) {
            state = PUBLICS;
            continue;
        }
        else if (trimmed.find("Static symbols") == 0) {
            state = STATICS;
            continue;
        }

        // 处理不同段
        switch (state) {
        case SEGMENTS:
            ParseSegmentLine(trimmed);
            break;
        case PUBLICS:
        case STATICS:
            ParseSymbolLine(trimmed, symbols);
            break;
        default:
            break;
        }
    }

    return symbols;
}

*/

void AddSymbolsInBatch(HANDLE hProcess, DWORD64 moduleBase,
    const std::vector<MapSymbol>& symbols) 
{
    for (const auto& sym : symbols) 
    {
		SymAddSymbolW(hProcess, moduleBase, sym.name.c_str(), moduleBase + sym.address, 0, 0);
    }
}

void AddSymbolFromMapFile(HANDLE hProcess, DWORD64 moduleBase, DWORD Size, const std::wstring& fileName, const std::string& exeName)
{
    auto symbols = ParseMapFile(fileName);
    if (symbols.empty()) {
        return;
    }

    DWORD64 modBase = SymLoadModuleExW(
        hProcess,
        NULL,
        nullptr,
        nullptr,
        moduleBase,
        Size,        // 自动确定大小
        nullptr,   // 不需要额外数据
        SLMFLAG_VIRTUAL
    );
    if (!modBase)
    {
        Log::WriteLine(__FUNCTION__ ": SymGetModuleInfoW64 获取模块信息失败，错误码 %d", GetLastError());
        //return false;
    }

    IMAGEHLP_MODULEW64 hlp;
    hlp.SizeOfStruct = sizeof(hlp);
    if (!SymGetModuleInfoW64(hProcess, moduleBase, &hlp))
    {
        Log::WriteLine(__FUNCTION__ ": SymGetModuleInfoW64 获取模块信息失败，错误码 %d", GetLastError());
        //return false;
    }
    else
    {
        //output infor hlp
        /*
        Log::WriteLine(__FUNCTION__": hlp.BaseOfImage = %016llX", hlp.BaseOfImage);
        Log::WriteLine(__FUNCTION__": hlp.ImageSize = %u", hlp.ImageSize);
        Log::WriteLine(__FUNCTION__": hlp.TimeDateStamp = %u", hlp.TimeDateStamp);
        Log::WriteLine(__FUNCTION__": hlp.CheckSum = %u", hlp.CheckSum);
        Log::WriteLine(__FUNCTION__": hlp.ModuleName = %s", UnicodetoANSI(hlp.ModuleName).c_str());
        Log::WriteLine(__FUNCTION__": hlp.ImageName = %s", UnicodetoANSI(hlp.ImageName).c_str());
        Log::WriteLine(__FUNCTION__": hlp.LoadedImageName = %s", UnicodetoANSI(hlp.LoadedImageName).c_str());
        Log::WriteLine(__FUNCTION__": hlp.TypeInfo = %s", hlp.TypeInfo ? "true" : "false");
        Log::WriteLine(__FUNCTION__": hlp.SymType = %d", hlp.SymType);
        Log::WriteLine(__FUNCTION__": hlp.NumSyms = %u", hlp.NumSyms);
        Log::WriteLine(__FUNCTION__": hlp.Publics  = %s", hlp.Publics ? "true" : "false");
        Log::WriteLine(__FUNCTION__": hlp.LineNumbers  = %s", hlp.LineNumbers ? "true" : "false");
        */
    }


    Log::WriteLine(__FUNCTION__ ": moduleBase = %08X", modBase);
    Log::WriteLine(__FUNCTION__ ": symbolCount = %u", symbols.size());
    for (const auto& sym : symbols) {
        DWORD64 address = moduleBase + sym.address;
        //Log::WriteLine(__FUNCTION__ ": Addr=%08X Name=\"%s\"", (DWORD)address, UnicodetoANSI(sym.name).c_str());
        //SymAddSymbolW(hProcess, moduleBase, sym.name.c_str(), address, 0, 0);
        ModuleMap::AddSymbol((DWORD)moduleBase, Size, sym);
    }

    /*
    
    SymEnumSymbolsW(hProcess, moduleBase, L"*",
        [](PSYMBOL_INFOW sym, ULONG sz, PVOID)
        {
            Log::WriteLine(__FUNCTION__": Address = %016llX", sym->Address);
            Log::WriteLine(__FUNCTION__": Name = %s", UnicodetoANSI(sym->Name).c_str());
            Log::WriteLine(__FUNCTION__": Flags = %08X", sym->Flags);
            Log::WriteLine(__FUNCTION__": Size = %u", sz);
            return TRUE;
        },
        nullptr
    );
    */
    ModuleMap::AddBaseName(moduleBase, exeName);

    Log::WriteLine(__FUNCTION__ ": \"%s\" 已在 %08X 处加载MAP符号。", exeName.c_str(), moduleBase);
}




namespace ModuleMap
{
    std::map<DWORD, DWORD> Contained_Base;
    std::map<DWORD, std::string> BaseName;

    std::map<DWORD, std::wstring> Symbols;

    void AddBaseName(DWORD moduleBase, const std::string& Basename)
    {
		BaseName[moduleBase] = Basename;
    }

    void AddSymbol(DWORD moduleBase, DWORD Size, const MapSymbol& Symbol)
    {
        Contained_Base[moduleBase] = Size;
        Symbols[(DWORD)Symbol.address + moduleBase] = Symbol.name;
    }

    bool HasSymbol(DWORD Address)
    {
        auto it = Contained_Base.upper_bound(Address);
        if (it == Contained_Base.begin())
            return false;
        --it;
        DWORD moduleBase = it->first;
        DWORD moduleSize = it->second;
        return (Address >= moduleBase) && (Address < (moduleBase + moduleSize));
    }

    const std::string& GetLibName(DWORD Address)
    {
        static const std::string s = "";
        auto it = Contained_Base.upper_bound(Address);
        if (it == Contained_Base.begin())
            return s;
        --it;
        DWORD moduleBase = it->first;
        DWORD moduleSize = it->second;
        if ((Address >= moduleBase) && (Address < (moduleBase + moduleSize)))return BaseName[moduleBase];
        else return s;
    }

    // 获取最接近的符号及其偏移量
    std::pair<DWORD, std::wstring> GetSymbol(DWORD Address)
    {
        // 查找第一个大于Address的符号
        auto it = Symbols.upper_bound(Address);

        // 如果没有小于等于Address的符号
        if (it == Symbols.begin())
            return { 0, L"" }; // 返回空值

        // 回退到前一个符号（小于等于Address的最大符号）
        --it;

        DWORD symbolAddress = it->first;
        DWORD offset = Address - symbolAddress;

        return { offset, it->second };
    }
}