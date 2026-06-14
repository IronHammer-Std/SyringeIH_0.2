#include "DbgCmdServer.h"



using DebugCommandMethodFunction = DebugCommandReturnType(*)(SyringeDebugger* Dbg, JsonObject Arguments);

DebugCommandReturnType ProcessDebugCommand_GetVersion(SyringeDebugger* Dbg, JsonObject Arguments);
DebugCommandReturnType ProcessDebugCommand_GetAccessStr(SyringeDebugger* Dbg, JsonObject Arguments);
DebugCommandReturnType ProcessDebugCommand_AnalyzeAddr(SyringeDebugger* Dbg, JsonObject Arguments);
DebugCommandReturnType ProcessDebugCommand_FlushDumpInfo(SyringeDebugger* Dbg, JsonObject Arguments);

std::unordered_map<std::string, DebugCommandMethodFunction> DebugCommandMethodMap
{
	{"GetVersion", ProcessDebugCommand_GetVersion},
	{"GetAccessStr", ProcessDebugCommand_GetAccessStr},
	{"AnalyzeAddr", ProcessDebugCommand_AnalyzeAddr},
	{"FlushDumpInfo", ProcessDebugCommand_FlushDumpInfo}
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

std::queue<ProcessedDumpInfoHandler> InfoHandlerToFlush;

void FlushRestDumpInfo()
{
	while (!InfoHandlerToFlush.empty())
	{
		InfoHandlerToFlush.front().Flush();
		InfoHandlerToFlush.pop();
	}
}