#include "DbgCmdServer.h"



using DebugCommandMethodFunction = DebugCommandReturnType(*)(SyringeDebugger* Dbg, JsonObject Arguments);

DebugCommandReturnType ProcessDebugCommand_GetVersion(SyringeDebugger* Dbg, JsonObject Arguments);

std::unordered_map<std::string, DebugCommandMethodFunction> DebugCommandMethodMap
{
	{"GetVersion", ProcessDebugCommand_GetVersion},
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