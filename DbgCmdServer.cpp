#include "DbgCmdServer.h"
#include <string>


using DebugCommandMethodFunction = DebugCommandReturnType(*)(SyringeDebugger* Dbg, JsonObject Arguments);

DebugCommandReturnType ProcessDebugCommand_GetVersion(SyringeDebugger* Dbg, JsonObject Arguments);
DebugCommandReturnType ProcessDebugCommand_GetAccessStr(SyringeDebugger* Dbg, JsonObject Arguments);
DebugCommandReturnType ProcessDebugCommand_AnalyzeAddr(SyringeDebugger* Dbg, JsonObject Arguments);
DebugCommandReturnType ProcessDebugCommand_FlushDumpInfo(SyringeDebugger* Dbg, JsonObject Arguments);
DebugCommandReturnType ProcessDebugCommand_GetExceptionStr(SyringeDebugger* Dbg, JsonObject Arguments);
DebugCommandReturnType ProcessDebugCommand_HelpAccess(SyringeDebugger* Dbg, JsonObject Arguments);
DebugCommandReturnType ProcessDebugCommand_HasCommand(SyringeDebugger* Dbg, JsonObject Arguments);

std::unordered_map<std::string, DebugCommandMethodFunction> DebugCommandMethodMap
{
	{"GetVersion", ProcessDebugCommand_GetVersion},
	{"GetAccessStr", ProcessDebugCommand_GetAccessStr},
	{"AnalyzeAddr", ProcessDebugCommand_AnalyzeAddr},
	{"FlushDumpInfo", ProcessDebugCommand_FlushDumpInfo},
	{"GetExceptionStr", ProcessDebugCommand_GetExceptionStr},
	{"HelpAccess", ProcessDebugCommand_HelpAccess},
	{"HasCommand", ProcessDebugCommand_HasCommand},
	// {"ListModules", ProcessDebugCommand_ListModules},
	// {"ReadMemory", ProcessDebugCommand_ReadMemory},
	// {"WriteMemory", ProcessDebugCommand_WriteMemory},
	// {"SetBreakpoint", ProcessDebugCommand_SetBreakpoint},
	// {"RemoveBreakpoint", ProcessDebugCommand_RemoveBreakpoint},
	// {"ListBreakpoints", ProcessDebugCommand_ListBreakpoints},
	// {"DumpStack", ProcessDebugCommand_DumpStack},
	// {"ContinueExecution", ProcessDebugCommand_ContinueExecution},
	// {"PauseExecution", ProcessDebugCommand_PauseExecution},
	// {"StepOver", ProcessDebugCommand_StepOver},
	// {"StepInto", ProcessDebugCommand_StepInto},
	// {"StepOut", ProcessDebugCommand_StepOut},
	// {"EvaluateExpression", ProcessDebugCommand_EvaluateExpression},
	// {"GetRegisters", ProcessDebugCommand_GetRegisters},
	// {"SetRegisters", ProcessDebugCommand_SetRegisters},
	// {"ListThreads", ProcessDebugCommand_ListThreads},
	// {"SwitchThread", ProcessDebugCommand_SwitchThread},
	// {"GetProcessInfo", ProcessDebugCommand_GetProcessInfo},
	// {"LoadExtension", ProcessDebugCommand_LoadExtension},
	// {"UnloadExtension", ProcessDebugCommand_UnloadExtension},
	// {"ListExtensions", ProcessDebugCommand_ListExtensions}
};
std::unordered_map<std::string, std::string> DebugCommandHelpMap
{
	{"GetVersion", (const char*)
u8R"(获取Syringe调试器的版本信息。
参数：无
返回值：包含版本号和构建日期的JSON对象
)"},{"GetAccessStr", (const char*)
u8R"(获取指定内存地址的访问权限描述字符串。
参数：
- Address: 要查询的内存地址（整数）
返回值：包含访问权限描述字符串的JSON对象
)"},{"AnalyzeAddr", (const char*)
u8R"(分析指定的内存地址，获取所在的模块来源和偏移量。
参数：
- Address: 要分析的内存地址（整数）
返回值：包含Source（来源描述字符串）和Offset（偏移量整数）的JSON对象
)"},{"FlushDumpInfo", (const char*)
u8R"(注意：此命令服务于地址注解功能，不应该从控制台直接调用。
填充并刷新当前的Dump信息。
参数：包含额外转储数据的字符串数组（可选）
返回值：Null
)"},{"GetExceptionStr", (const char*)
u8R"(获取指定异常代码的描述字符串。
参数：
- ExceptionCode: 异常代码（整数）
返回值：包含异常描述字符串的JSON对象
)"},{"HelpAccess", (const char*)
u8R"(注意：此命令服务于Help指令，不应该从控制台直接调用。
获取调试命令的帮助说明或库的元数据信息。
参数（提供其一）：
- Command: 要获取帮助的命令名称（字符串）
- Info: 查询特定信息（"Basic" / "Setting" / "Hooks"）
返回值：取决于请求参数的JSON对象或字符串
)"},{"HasCommand", (const char*)
u8R"(检查当前调试器是否支持执行某个特定命令。
参数：
- Command: 要检查的命令名称（字符串）
返回值：表示是否包含该命令的布尔值
)"},
};

std::string ANSItoUTF8(const std::string& ANSI);
std::string UnicodetoUTF8(const std::wstring& Unicode);

std::string FormatMessageU8(DWORD ErrorValue)
{
	wchar_t Buffer[1024];
	DWORD Result = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, ErrorValue, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), Buffer, 1024, NULL);
	if (Result == 0)
	{
		return "Unknown error";
	}
	return UnicodetoUTF8(Buffer);
}
std::pair<std::string, LONG> FormatError(DWORD ErrorValue)
{
	return std::make_pair(FormatMessageU8(ErrorValue), (LONG)ErrorValue);
}

DebugCommandReturnType
ProcessDebugCommand(
	SyringeDebugger* Dbg, 
	const std::string& Method, 
	JsonObject Arguments)
{
	((void)Dbg);

	auto It = DebugCommandMethodMap.find(Method);
	if (It != DebugCommandMethodMap.end())
	{
		return It->second(Dbg, Arguments);
	}
	else
	{
		return FormatError(ERROR_INVALID_FUNCTION);
	}
}

DebugCommandReturnType ProcessDebugCommand_GetVersion(SyringeDebugger* Dbg, JsonObject Arguments)
{
	((void)Dbg);
	((void)Arguments);
	JsonFile F;
	auto Obj = F.GetObj();
	Obj.AddString("Version", VersionString);
	Obj.AddString("BuildDate", __DATE__ " " __TIME__);
	return F;
}

DebugCommandReturnType ProcessDebugCommand_GetAccessStr(SyringeDebugger* Dbg, JsonObject Arguments)
{
	std::string GetAccessStr(HANDLE hProc, LPCVOID Ptr);
	std::string S;
	if (Arguments.Available() && Arguments.HasItem("Address"))
	{
		auto Address = Arguments.ItemInt("Address");
		S = GetAccessStr(Dbg->pInfo.hProcess, (LPCVOID)Address);
	}
	JsonFile F;
	auto Obj = F.GetObj();
	Obj.SetString(ANSItoUTF8(S));
	return F;
}

DebugCommandReturnType ProcessDebugCommand_GetExceptionStr(SyringeDebugger* Dbg, JsonObject Arguments)
{
	((void)Dbg);
	std::string GetExcStr(int Exc);
	std::string S;
	if (Arguments.Available() && Arguments.HasItem("ExceptionCode"))
	{
		auto ExceptionCode = Arguments.ItemInt("ExceptionCode");
		S = GetExcStr(ExceptionCode);
	}
	JsonFile F;
	auto Obj = F.GetObj();
	Obj.SetString(ANSItoUTF8(S));
	return F;
}

DebugCommandReturnType ProcessDebugCommand_AnalyzeAddr(SyringeDebugger* Dbg, JsonObject Arguments)
{
	std::string S;
	DWORD Addr = 0;
	if (Arguments.Available() && Arguments.HasItem("Address"))
	{
		auto Address = Arguments.ItemInt("Address");
		std::tie(Addr, S) = Dbg->AnalyzeAddr((DWORD)Address);
	}
	JsonFile F;
	auto Obj = F.GetObj();
	Obj.AddString("Source", ANSItoUTF8(S));
	Obj.AddInt("Offset", Addr);
	return F;
}

DebugCommandReturnType ProcessDebugCommand_FlushDumpInfo(SyringeDebugger* Dbg, JsonObject Arguments)
{
	((void)Dbg);
	auto& Handler = InfoHandlerToFlush.front();
	if (Arguments.Available() && Arguments.IsTypeArray())
	{
		Handler.Fillin(Arguments.GetArrayString());
	}
	Handler.Flush();
	InfoHandlerToFlush.pop();
	JsonFile F;
	F.GetObj().SetNull();
	return F;
}

DebugCommandReturnType ProcessDebugCommand_HelpAccess(SyringeDebugger* Dbg, JsonObject Arguments)
{
	//Help for commands above
	//from DebugCommandHelpMap
	//Syntax : 
	//  Syringe.HelpAccess
	//  Syringe.HelpAccess -Command xxx [-Version vvv]
	//  Syringe.HelpAccess -Info ooo (ooo = Basic/Setting/Hooks)
	//Version temporarily unused, for future use of different help versions

	((void)Dbg);
	auto oCommand = Arguments.GetObjectItem("Command");
	auto oInfo = Arguments.GetObjectItem("Info");
	JsonFile F;
	auto Obj = F.GetObj();
	if (oCommand.Available() && oCommand.IsTypeString())
	{
		auto CmdName = oCommand.GetString();
		if(DebugCommandHelpMap.count(CmdName))
		{
			Obj.SetString(DebugCommandHelpMap[CmdName]);
		}
		else
		{
			return FormatError(ERROR_INVALID_INDEX);
		}
		return F;
	}
	else if (oInfo.Available() && oInfo.IsTypeString())
	{
		auto InfoType = oInfo.GetString();
		if (InfoType == "Basic")
		{
			//-LibraryName : <string>
			//-Version : <int>
			//-LowestSupportedVersion : <int>
			//-Description : <string>
			//-Dependencies : <Array>
			const char* LibraryName = "Syringe";
			int Version = 1000000 * VMAJOR + 10000 * VMINOR + 100 * VRELEASE + VBUILD;
			int LSV = 0;
			Obj.AddString("LibraryName", LibraryName);
			Obj.AddInt("Version", Version);
			Obj.AddInt("LowestSupportedVersion", LSV);
			Obj.AddString("Description", VersionString);
			Obj.AddObjectItem("Dependencies", JsonObject(cJSON_CreateArray()), false);
			return F;
		}
		else if (InfoType == "Setting")
		{
			extern JsonFile Setting;
			return Setting.Duplicate(true);
		}
		else if (InfoType == "Hooks")
		{
			cJSON* HooksArray = cJSON_CreateArray();
			return JsonFile(HooksArray);
		}
		else
		{
			return FormatError(ERROR_INVALID_INDEX);
		}
	}
	else
	{
		return FormatError(ERROR_BAD_ARGUMENTS);
	}
}

DebugCommandReturnType ProcessDebugCommand_HasCommand(SyringeDebugger* Dbg, JsonObject Arguments)
{
	((void)Dbg);
	JsonFile F;
	auto oCommand = Arguments.GetObjectItem("Command");
	if (oCommand.Available() && oCommand.IsTypeString())
	{
		auto CmdName = oCommand.GetString();
		F.GetObj().SetBool(DebugCommandMethodMap.count(CmdName) > 0);
	}
	else
	{
		return FormatError(ERROR_BAD_ARGUMENTS);
	}
	return F;
}


std::queue<ProcessedDumpInfoHandler> InfoHandlerToFlush;

void FlushRestDumpInfo()
{
	while (!InfoHandlerToFlush.empty())
	{
		InfoHandlerToFlush.front().Flush();
		InfoHandlerToFlush.pop();
	}
}