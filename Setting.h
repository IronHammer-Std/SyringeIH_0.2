#pragma once
#include <string>
#include <vector>
#include <unordered_set>
#include "ExtFunc.h"
#include "ExtPack.h"
#include "Handle.h"

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
// 钩子分析报告输出格式（Syringe.json 的 HookAnalysis.Format，默认 "Text"；可选 "NDJSON"）
extern std::string HookAnalysisFormat;
extern std::vector<int> AddrRestriction;
extern std::vector<std::string> LibRestriction;
extern JsonFile Setting;

extern bool RemoteDatabaseDump;
extern bool InfiniteWaitForDebug;
extern bool ExceptionReportAlwaysFull;
extern bool LongStackDump;
extern bool OnlyShowStackFrame;
extern bool EnableHandshakeCheck;
extern bool DetachAfterInjection;
extern bool GenerateINJ;
extern bool CheckInsignificantException;
extern bool CheckBreakpoint;
extern bool AnalyzeCPPException;
extern bool OverwriteStartParams;
extern bool ShowHookConflictPopup;
extern bool AutoTerminate;
extern bool LogDaemonInteraction;
extern bool WaitForProcessExit;
extern bool StackSnapshot;
extern bool UseSyringeExCommandLine;
extern std::vector<std::string> IncludeDLLs;
extern std::set<HookIdx> GlobalDisableHooks;
extern std::set<HookIdx> GlobalEnableHooks;
extern std::unordered_set<std::string, UpperHash, UpperEqualPred> IgnoreInvalidHookLibs;

extern std::unordered_map<std::string, ExtensionPack> ExtPacks;
extern std::string DefaultExtPack;

extern std::string DefaultExecName;
extern std::string DefaultCmdLine;

// 快照输出文件名：Syringe.json 参数（默认 ""），可用 -SnapshotFileName= 覆盖；
// 广播时原样复述进载荷；接收方非空时把本次快照全程内容输出到该文件
extern std::string SnapshotFileName;

// 快照线程来源过滤（模块名数组，basename、不区分大小写）：
// SnapshotThreadFilter 非空即白名单（只输出来源命中列表的线程）；
// SnapshotThreadExclude 命中即跳过（exclude 优先）。两键皆空 = 不过滤。
// 内部统一存为拆分后的模块名数组：Syringe.json 用数组形式；
// 命令行保持逗号分隔串（-SnapshotThreadFilter=a,b），解析时立即拆分。
// 广播载荷同样以数组形式携带，逐目标生效。
extern std::vector<std::string> SnapshotThreadFilter;
extern std::vector<std::string> SnapshotThreadExclude;



#include "Version.h"