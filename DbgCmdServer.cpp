#include "DbgCmdServer.h"
#include <string>


using DebugCommandMethodFunction = DebugCommandReturnType(*)(SyringeDebugger* Dbg, JsonObject Arguments);

DebugCommandReturnType ProcessDebugCommand_GetVersion(SyringeDebugger* Dbg, JsonObject Arguments);
DebugCommandReturnType ProcessDebugCommand_GetAccessStr(SyringeDebugger* Dbg, JsonObject Arguments);
DebugCommandReturnType ProcessDebugCommand_AnalyzeAddr(SyringeDebugger* Dbg, JsonObject Arguments);
DebugCommandReturnType ProcessDebugCommand_FlushDumpInfo(SyringeDebugger* Dbg, JsonObject Arguments);
DebugCommandReturnType ProcessDebugCommand_GetExceptionStr(SyringeDebugger* Dbg, JsonObject Arguments);
DebugCommandReturnType ProcessDebugCommand_HelpAccess(SyringeDebugger* Dbg, JsonObject Arguments);

std::unordered_map<std::string, DebugCommandMethodFunction> DebugCommandMethodMap
{
	{"GetVersion", ProcessDebugCommand_GetVersion},
	{"GetAccessStr", ProcessDebugCommand_GetAccessStr},
	{"AnalyzeAddr", ProcessDebugCommand_AnalyzeAddr},
	{"FlushDumpInfo", ProcessDebugCommand_FlushDumpInfo},
	{"GetExceptionStr", ProcessDebugCommand_GetExceptionStr},
	{"HelpAccess", ProcessDebugCommand_HelpAccess},
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
	{"", (const char*)u8""}
};

std::string ANSItoUTF8(const std::string& ANSI);

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
		JsonFile F;
		auto Obj = F.GetObj();
		Obj.AddObjectItem("-Arguments-", Arguments, true);
		Obj.AddString("-Method-", Method);
		return F;
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
			Obj.SetNull();
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
			Obj.SetNull();
			return F;
		}
	}
	else
	{
		Obj.SetNull();
		return F;
	}
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