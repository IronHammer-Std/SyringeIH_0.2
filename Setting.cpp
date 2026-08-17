#include "Setting.h"
#include "ExtJson.h"
#include "Handle.h"
#include "Support.h"
#include "Log.h"

bool ShowHookAnalysis = false;
std::string DefaultExecName;
std::string DefaultCmdLine;
std::string SnapshotFileName;
bool ShowHookAnalysis_ByLib = false;
bool ShowHookAnalysis_ByAddr = false;
std::vector<int> AddrRestriction;
std::vector<std::string> LibRestriction;
bool RemoteDatabaseDump = false;
bool InfiniteWaitForDebug = false;
bool ExceptionReportAlwaysFull = false;
bool LongStackDump = false;
bool OnlyShowStackFrame = false;
bool EnableHandshakeCheck = false; // 握手检查默认关闭（2022 年起废弃的特性，与上游 0.7.3 / SyringeEx 对齐）；--handshakes、-EnableHandshakeCheck=true 或 Syringe.json 可显式开启
bool DetachAfterInjection = false;
bool GenerateINJ = false;
bool CheckInsignificantException = false;
bool CheckBreakpoint = false;
bool AnalyzeCPPException = true;
bool OverwriteStartParams = false;
bool ShowHookConflictPopup = false;
bool LogDaemonInteraction = false;
bool AutoTerminate = false;
bool WaitForProcessExit = true;
bool StackSnapshot = false;
bool UseSyringeExCommandLine = false; // 命令行解析风格：false=IH 风格（引号 exe + 尾部参数）；true=SyringeEx 风格（首个非 '-' token 为 exe，flag 任意位置，游戏参数仅来自 --args=）
std::vector<std::string> IncludeDLLs;

std::unordered_map<std::string, ExtensionPack> ExtPacks;
std::string DefaultExtPack;

std::set<HookIdx> GlobalDisableHooks;
std::set<HookIdx> GlobalEnableHooks;
std::unordered_set<std::string, UpperHash, UpperEqualPred> IgnoreInvalidHookLibs;


std::string GetStringFromFile(const char* FileName)
{
    FileHandle File(fopen(FileName, "r"));
    if (!File)return "";
    fseek(File, 0, SEEK_END);
    auto Pos = ftell(File);
    char* FileStr;
    FileStr = new char[Pos + 50];
    if (FileStr == nullptr)return "";
    fseek(File, 0, SEEK_SET);
    fread(FileStr, 1, Pos, File);
    FileStr[Pos] = 0;

    //std::string LoadStr = FileStr;
	// skip BOM
	std::string LoadStr;
    std::string UnicodetoUTF8(const std::wstring& Unicode);
	if (Pos >= 3 && (unsigned char)FileStr[0] == 0xEF && (unsigned char)FileStr[1] == 0xBB && (unsigned char)FileStr[2] == 0xBF)
	{
		LoadStr = std::string(FileStr + 3, Pos - 3);
	}
    else if (Pos >= 2 && (unsigned char)FileStr[0] == 0xFF && (unsigned char)FileStr[1] == 0xFE)
    {
		LoadStr = UnicodetoUTF8(std::wstring((wchar_t*)(FileStr + 2), (Pos - 2) / 2));
	}
	else if (Pos >= 2 && (unsigned char)FileStr[0] == 0xFE && (unsigned char)FileStr[1] == 0xFF)
	{
		//手动反转
        std::wstring TempWStr((wchar_t*)(FileStr + 2), (Pos - 2) / 2);
		for (auto& ch : TempWStr)
            ch = (ch >> 8) | (ch << 8);
		LoadStr = UnicodetoUTF8(TempWStr);
    }
	else
	{
        LoadStr = FileStr;
	}

    delete[]FileStr;
    return LoadStr;
}

bool InLibList(std::string_view Lib)
{
    if (LibRestriction.empty())return true;
    for (auto& s : LibRestriction)
    {
        if (Lib == s)return true;
    }
    return false;
}

bool InAddrList(int Addr)
{
    if (AddrRestriction.empty())return true;
    for (size_t i = 0; i < AddrRestriction.size() >> 1; i++)
    {
        if (AddrRestriction[i << 1] < Addr &&
            Addr < AddrRestriction[i << 1 | 1])return true;
    }
    return false;
}

JsonFile Setting;
void ReadSetting()
{
    Log::WriteLine("正在从 Syringe.json 中载入配置……");
    auto Str = GetStringFromFile("Syringe.json");
    if (Str.empty())
    {
        Log::WriteLine("载入 Syringe.json 失败：无法读取配置文件。");
        Log::WriteLine("回退到默认配置。");
        return;
    }
    auto ErrorStr = Setting.ParseChecked(Str, "【出错位置】");
    if (!Setting.Available())
    {
        Log::WriteLine("载入 Syringe.json 失败：非法的 JSON 文件");
        Log::WriteLine("回退到默认配置。");
        if (!ErrorStr.empty())
        {
            Log::WriteLine("错误信息：\"\n%s\"", ErrorStr.c_str());
            MessageBoxA(
                nullptr, "Syringe.json有错误。详见Syringe.log。\n\n",
                VersionString, MB_OK | MB_ICONINFORMATION);
        }
        return;
    }

    auto Obj = Setting.GetObj();  
    auto SObj = Obj.GetObjectItem("HookAnalysis");
    if (SObj.Available())
    {
        if (SObj.IsTypeBool())
        {
            ShowHookAnalysis = SObj.GetBool();
            Log::WriteLine("HookAnalysis = %s", CStrBoolImpl(ShowHookAnalysis, StrBoolType::Str_true_false));
            ShowHookAnalysis_ByLib = ShowHookAnalysis;
            ShowHookAnalysis_ByAddr = ShowHookAnalysis;
        }
        else if (SObj.IsTypeObject())
        {
            auto TObj = SObj.GetObjectItem("ByLibrary");
            if (TObj.Available() && TObj.IsTypeBool())
            {
                ShowHookAnalysis_ByLib = TObj.GetBool();
            }
            TObj = SObj.GetObjectItem("ByAddress");
            if (TObj.Available() && TObj.IsTypeBool())
            {
                ShowHookAnalysis_ByAddr = TObj.GetBool();
            }
            ShowHookAnalysis = ShowHookAnalysis_ByLib || ShowHookAnalysis_ByAddr;
            Log::WriteLine("HookAnalysis = %s", CStrBoolImpl(ShowHookAnalysis, StrBoolType::Str_true_false));
            Log::WriteLine("\tByLibrary = %s", CStrBoolImpl(ShowHookAnalysis_ByLib, StrBoolType::Str_true_false));
            Log::WriteLine("\tByAddress = %s", CStrBoolImpl(ShowHookAnalysis_ByAddr, StrBoolType::Str_true_false));
            TObj = SObj.GetObjectItem("LibraryRange");
            Log::WriteLine("\tAddressRange : ");
            if (TObj.Available() && TObj.IsTypeArray())
            {
                for (auto& obj : TObj.GetArrayObject())
                {
                    if (obj.Available() && obj.IsTypeArray())
                    {
                        auto arr = obj.GetArrayString();
                        if (arr.size() >= 2)
                        {
                            auto sz = AddrRestriction.size();
                            AddrRestriction.resize(AddrRestriction.size() + 2);
                            sscanf(arr[0].c_str(), "%X", &AddrRestriction[sz]);
                            sscanf(arr[1].c_str(), "%X", &AddrRestriction[sz + 1]);
                            Log::WriteLine("\t\t%08X ~ %08X", AddrRestriction[sz], AddrRestriction[sz + 1]);
                        }
                    }
                }
            }
            Log::WriteLine("\tLibraryRange : ");
            TObj = SObj.GetObjectItem("LibraryRange");
            if (TObj.Available() && TObj.IsTypeArray())
            {
                LibRestriction = std::move(TObj.GetArrayString());
                for (auto& s : LibRestriction)
                {
                    Log::WriteLine("\t\t%s", s.c_str());
                }
            }
        }
    }
    SObj = Obj.GetObjectItem("DefaultExecutableName");
    if (SObj.Available() && SObj.IsTypeString())
    {
        DefaultExecName = SObj.GetString();
        Log::WriteLine("DefaultExecutableName = \"%s\"", DefaultExecName.c_str());
    }
    SObj = Obj.GetObjectItem("DefaultCommandLine");
    if (SObj.Available() && SObj.IsTypeString())
    {
        DefaultCmdLine = SObj.GetString();
        Log::WriteLine("DefaultCommandLine = \"%s\"", DefaultCmdLine.c_str());
    }
    SObj = Obj.GetObjectItem("SnapshotFileName");
    if (SObj.Available() && SObj.IsTypeString())
    {
        SnapshotFileName = SObj.GetString();
        Log::WriteLine("SnapshotFileName = \"%s\"", SnapshotFileName.c_str());
    }
    SObj = Obj.GetObjectItem("IgnoreInvalidHookLibs");
    if (SObj.Available() && SObj.IsTypeArray())
    {
		auto arr = SObj.GetArrayString();
		IgnoreInvalidHookLibs.insert(arr.begin(), arr.end());
		Log::WriteLine("IgnoreInvalidHookLibs : ");
        for (auto& s : IgnoreInvalidHookLibs)
            Log::WriteLine("\t%s", s.c_str());
    }
    SObj = Obj.GetObjectItem("LongStackDump");
    if (SObj.Available() && SObj.IsTypeBool())
    {
        LongStackDump = SObj.GetBool();
        Log::WriteLine("LongStackDump = %s", CStrBoolImpl(LongStackDump, StrBoolType::Str_true_false));
    }
    SObj = Obj.GetObjectItem("EnableHandshakeCheck");
    if (SObj.Available() && SObj.IsTypeBool())
    {
        EnableHandshakeCheck = SObj.GetBool();
        Log::WriteLine("EnableHandshakeCheck = %s", CStrBoolImpl(EnableHandshakeCheck, StrBoolType::Str_true_false));
    }
    SObj = Obj.GetObjectItem("DetachAfterInjection");
    if (SObj.Available() && SObj.IsTypeBool())
    {
        DetachAfterInjection = SObj.GetBool();
        Log::WriteLine("DetachAfterInjection = %s", CStrBoolImpl(DetachAfterInjection, StrBoolType::Str_true_false));
    }
    SObj = Obj.GetObjectItem("CheckInsignificantException");
    if (SObj.Available() && SObj.IsTypeBool())
    {
        CheckInsignificantException = SObj.GetBool();
        Log::WriteLine("CheckInsignificantException = %s", CStrBoolImpl(CheckInsignificantException, StrBoolType::Str_true_false));
    }
	SObj = Obj.GetObjectItem("CheckBreakpoint");
	if (SObj.Available() && SObj.IsTypeBool())
	{
		CheckBreakpoint = SObj.GetBool();
		Log::WriteLine("CheckBreakpoint = %s", CStrBoolImpl(CheckBreakpoint, StrBoolType::Str_true_false));
	}
    SObj = Obj.GetObjectItem("OnlyShowStackFrame");
    if (SObj.Available() && SObj.IsTypeBool())
    {
        OnlyShowStackFrame = SObj.GetBool();
        Log::WriteLine("OnlyShowStackFrame = %s", CStrBoolImpl(OnlyShowStackFrame, StrBoolType::Str_true_false));
    }
    SObj = Obj.GetObjectItem("InfiniteWaitForDebug");
    if (SObj.Available() && SObj.IsTypeBool())
    {
        InfiniteWaitForDebug = SObj.GetBool();
        Log::WriteLine("InfiniteWaitForDebug = %s", CStrBoolImpl(InfiniteWaitForDebug, StrBoolType::Str_true_false));
    }
    SObj = Obj.GetObjectItem("ExceptionReportAlwaysFull");
    if (SObj.Available() && SObj.IsTypeBool())
    {
        ExceptionReportAlwaysFull = SObj.GetBool();
        Log::WriteLine("ExceptionReportAlwaysFull = %s", CStrBoolImpl(ExceptionReportAlwaysFull, StrBoolType::Str_true_false));
    }
    SObj = Obj.GetObjectItem("RemoteDatabaseDump");
    if (SObj.Available() && SObj.IsTypeBool())
    {
        RemoteDatabaseDump = SObj.GetBool();
        Log::WriteLine("RemoteDatabaseDump = %s", CStrBoolImpl(RemoteDatabaseDump, StrBoolType::Str_true_false));
    }
    SObj = Obj.GetObjectItem("GenerateINJ");
    if (SObj.Available() && SObj.IsTypeBool())
    {
        GenerateINJ = SObj.GetBool();
        Log::WriteLine("GenerateINJ = %s", CStrBoolImpl(GenerateINJ, StrBoolType::Str_true_false));
    }
    SObj = Obj.GetObjectItem("AnalyzeCPPException");
    if (SObj.Available() && SObj.IsTypeBool())
    {
        AnalyzeCPPException = SObj.GetBool();
        Log::WriteLine("AnalyzeCPPException = %s", CStrBoolImpl(AnalyzeCPPException, StrBoolType::Str_true_false));
    }
    SObj = Obj.GetObjectItem("OverwriteStartParams");
    if (SObj.Available() && SObj.IsTypeBool())
    {
        OverwriteStartParams = SObj.GetBool();
        Log::WriteLine("OverwriteStartParams = %s", CStrBoolImpl(OverwriteStartParams, StrBoolType::Str_true_false));
    }
    SObj = Obj.GetObjectItem("ShowHookConflictPopup");
    if (SObj.Available() && SObj.IsTypeBool())
    {
        ShowHookConflictPopup = SObj.GetBool();
        Log::WriteLine("ShowHookConflictPopup = %s", CStrBoolImpl(ShowHookConflictPopup, StrBoolType::Str_true_false));
    }
	SObj = Obj.GetObjectItem("AutoTerminate");
    if (SObj.Available() && SObj.IsTypeBool())
    {
        AutoTerminate = SObj.GetBool();
		Log::WriteLine("AutoTerminate = %s", CStrBoolImpl(AutoTerminate, StrBoolType::Str_true_false));
    }
	SObj = Obj.GetObjectItem("LogDaemonInteraction");
    if (SObj.Available() && SObj.IsTypeBool())
    {
        LogDaemonInteraction = SObj.GetBool();
        Log::WriteLine("LogDaemonInteraction = %s", CStrBoolImpl(LogDaemonInteraction, StrBoolType::Str_true_false));
	}
    SObj = Obj.GetObjectItem("WaitForProcessExit");
    if (SObj.Available() && SObj.IsTypeBool())
    {
        WaitForProcessExit = SObj.GetBool();
        Log::WriteLine("WaitForProcessExit = %s", CStrBoolImpl(WaitForProcessExit, StrBoolType::Str_true_false));
    }
    SObj = Obj.GetObjectItem("StackSnapshot");
    if (SObj.Available() && SObj.IsTypeBool())
    {
        StackSnapshot = SObj.GetBool();
        Log::WriteLine("StackSnapshot = %s", CStrBoolImpl(StackSnapshot, StrBoolType::Str_true_false));
    }
    SObj = Obj.GetObjectItem("UseSyringeExCommandLine");
    if (SObj.Available() && SObj.IsTypeBool())
    {
        UseSyringeExCommandLine = SObj.GetBool();
        Log::WriteLine("UseSyringeExCommandLine = %s", CStrBoolImpl(UseSyringeExCommandLine, StrBoolType::Str_true_false));
    }
    SObj = Obj.GetObjectItem("ExtensionPacks");
    if (SObj.Available() && SObj.IsTypeObject())
    {
        for (auto& [name, obj] : SObj.GetMapObject())
        {
            Log::WriteLine("正在载入扩展配置 \"%s\"", name.c_str());
            ExtPacks[name].LoadFromJson(obj);
        }
    }
    SObj = Obj.GetObjectItem("DefaultExtensionPack");
    if (SObj.Available() && SObj.IsTypeString())
    {
        DefaultExtPack = SObj.GetString();
        Log::WriteLine("DefaultExtPack = \"%s\"", DefaultExtPack.c_str());
    }
    SObj = Obj.GetObjectItem("DisableHooks");
    if (SObj.Available() && SObj.IsTypeObject())
    {
        ReadHookIdxSet(GlobalDisableHooks, SObj);
        //LogIdxSet(GlobalDisableHooks, "GlobalDisableHooks");
    }
    SObj = Obj.GetObjectItem("EnableHooks");
    if (SObj.Available() && SObj.IsTypeObject())
    {
        ReadHookIdxSet(GlobalEnableHooks, SObj);
        //LogIdxSet(GlobalEnableHooks, "GlobalEnableHooks");
    }
    Log::WriteLine("成功载入配置。");
}
/*

HookAnalysis
DefaultExecutableName
DefaultCommandLine
//IsRunningYR

LongStackDump
EnableHandshakeCheck
DetachAfterInjection
CheckInsignificantException
CheckBreakpoint
OnlyShowStackFrame
InfiniteWaitForDebug
ExceptionReportAlwaysFull
RemoteDatabaseDump
GenerateINJ

ExtensionPacks
DefaultExtensionPack
DisableHooks
EnableHooks

*/

void UpdateSetting(const std::vector<std::string_view>& Flags)
{
    Log::WriteLine("正在从命令行更新配置……");
    for (size_t i = 0; i < Flags.size(); i++)
    {
        auto v = Flags[i];
        std::string mergedValue;
        // Windows PowerShell 5.1 传参修复：它会把 "-X=值.扩展名" 拆成
        // "-X=值" 与 ".扩展名" 两个 token（点号前插入空格）。
        // 若本 token 是 "-X=值" 形式且其后紧跟以 '.' 开头的 token，则循环拼回。
        while (i + 1 < Flags.size() && Flags[i + 1].size() > 1 && Flags[i + 1][0] == '.'
            && v.size() > 1 && v[0] == '-' && v.find('=') != std::string_view::npos && v.back() != '=')
        {
            auto const& next = Flags[i + 1];
            mergedValue.assign(v);
            mergedValue.append(next);
            Log::WriteLine("命令行参数修复：\"%.*s\" + \"%.*s\" → \"%s\"（Windows PowerShell 传参拆分）",
                printable(v), printable(next), mergedValue.c_str());
            v = mergedValue;
            ++i;
        }
#define UpdateBoolImpl(f)\
else if (v._Starts_with("-" #f "="))\
{\
    v.remove_prefix(sizeof(#f) + 1);\
    if (v == "true")\
    {\
        f = true;\
        Log::WriteLine( #f " = true");\
    }\
    else if (v == "false")\
    {\
        f = false;\
        Log::WriteLine( #f " = false");\
    }\
}
        if (v._Starts_with("-Ext="))
        {
            v.remove_prefix(5);
            DefaultExtPack = v;
            Log::WriteLine("更改扩展配置 \"%.*s\"", printable(v));
        }
        else if (v._Starts_with("-i="))
        {
            v.remove_prefix(3);
            IncludeDLLs.emplace_back(v);
            Log::WriteLine("加入注入白名单 DLL \"%.*s\"", printable(v));
        }
        else if (v._Starts_with("-SnapshotFileName="))
        {
            v.remove_prefix(18);
            SnapshotFileName = v;
            Log::WriteLine("SnapshotFileName = \"%.*s\"", printable(v));
        }
        else if (v == "--detach")
        {
            DetachAfterInjection = true;
            Log::WriteLine("DetachAfterInjection = true (--detach)");
        }
        else if (v == "--nodetach")
        {
            DetachAfterInjection = false;
            Log::WriteLine("DetachAfterInjection = false (--nodetach)");
        }
        else if (v == "--nowait")
        {
            WaitForProcessExit = false;
            Log::WriteLine("WaitForProcessExit = false (--nowait)");
        }
        else if (v == "--handshakes")
        {
            EnableHandshakeCheck = true;
            Log::WriteLine("EnableHandshakeCheck = true (--handshakes)");
        }
        else if (v == "--snapshot")
        {
            StackSnapshot = true;
            Log::WriteLine("StackSnapshot = true (--snapshot)");
        }
        else if (v._Starts_with("-UseSyringeExCommandLine"))
        {
            // 命令行不允许设置解析风格开关（避免"鸡生蛋"：风格未定无法解析命令行）；
            // 仅 Syringe.json 的 UseSyringeExCommandLine 可配置。
            Log::WriteLine("命令行不允许设置 UseSyringeExCommandLine（仅 Syringe.json 可配置），忽略 \"%.*s\"", printable(v));
        }
        UpdateBoolImpl(LongStackDump)
        UpdateBoolImpl(EnableHandshakeCheck)
        UpdateBoolImpl(DetachAfterInjection)
        UpdateBoolImpl(CheckInsignificantException)
        UpdateBoolImpl(CheckBreakpoint)
        UpdateBoolImpl(OnlyShowStackFrame)
        UpdateBoolImpl(InfiniteWaitForDebug)
        UpdateBoolImpl(ExceptionReportAlwaysFull)
        UpdateBoolImpl(RemoteDatabaseDump)
        UpdateBoolImpl(GenerateINJ)
        UpdateBoolImpl(AnalyzeCPPException)
		UpdateBoolImpl(OverwriteStartParams)
        UpdateBoolImpl(ShowHookConflictPopup)
		UpdateBoolImpl(AutoTerminate)
		UpdateBoolImpl(LogDaemonInteraction)
		UpdateBoolImpl(WaitForProcessExit)
		UpdateBoolImpl(StackSnapshot)
        else
        {
            Log::WriteLine("未知选项 \"%.*s\"", printable(v));
        }
#undef UpdateBoolImpl
    }
    Log::WriteLine("更新配置完成。");
}