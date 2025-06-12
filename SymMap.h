#pragma once
#include <Windows.h>
#include <utility>
#include <string>

void AddSymbolFromMapFile(HANDLE hProcess, DWORD64 moduleBase, DWORD Size, const std::wstring& fileName);

namespace ModuleMap
{
    bool HasSymbol(DWORD Address);

    std::pair<DWORD, std::wstring> GetSymbol(DWORD Address);
    const std::string& GetLibName(DWORD Address);
    void AddBaseName(DWORD moduleBase, const std::string& Basename);
}