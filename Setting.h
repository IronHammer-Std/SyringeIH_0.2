#pragma once
#include <string>
#include <vector>
#include "ExtFunc.h"
#include "ExtPack.h"

class JsonFile;


struct BytePointerArray
{
	int N;
	uint8_t* Data;
};


void ReadSetting();
void UpdateSetting(const std::vector<std::string_view>& Flags);
std::string GetStringFromFile(const char* FileName);
bool InLibList(std::string_view Lib);
bool InAddrList(int Addr);

extern bool ShowHookAnalysis;
extern bool ShowHookAnalysis_ByLib;
extern bool ShowHookAnalysis_ByAddr;
extern std::vector<int> AddrRestriction;
extern std::vector<std::string> LibRestriction;
extern JsonFile Setting;

extern bool RunningYR;
extern bool RemoteDatabaseDump;
extern bool InfiniteWaitForDebug;
extern bool ExceptionReportAlwaysFull;
extern bool LongStackDump;
extern bool OnlyShowStackFrame;
extern bool EnableHandshakeCheck;
extern bool DetachAfterInjection;
extern bool GenerateINJ;
extern bool CheckInsignificantException;
extern bool AnalyzeCPPException;

extern std::set<HookIdx> GlobalDisableHooks;
extern std::set<HookIdx> GlobalEnableHooks;

extern std::unordered_map<std::string, ExtensionPack> ExtPacks;
extern std::string DefaultExtPack;

extern std::string DefaultExecName;
extern std::string DefaultCmdLine;

constexpr auto const VersionString = "SyringeIH 0.3b2";
constexpr auto const VersionLString = L"SyringeIH 0.3b2";
const int VMajor = 0;
const int VMinor = 3;
const int VRelease = 0;
const int VBuild = 2;
