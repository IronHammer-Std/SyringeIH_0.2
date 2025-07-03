#include "DbgCmdServer.h"

std::variant<JsonFile, std::pair<std::string, LONG> > 
ProcessDebugCommand(
	SyringeDebugger* Dbg, 
	const std::string& Method, 
	JsonObject Arguments)
{
	((void)Dbg);
	JsonFile F;
	auto Obj = F.GetObj();
	Obj.AddObjectItem("-Arguments-", Arguments, true);
	Obj.AddString("-Method-", Method);
	return F;
}