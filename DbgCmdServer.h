#pragma once

#include "ExtJson.h"
#include "SyringeDebugger.h"
#include <string>
#include <variant>
#include <queue>

using DebugCommandReturnType = std::variant<JsonFile, std::pair<std::string, LONG> >;
DebugCommandReturnType ProcessDebugCommand(SyringeDebugger* Dbg, const std::string& Method, JsonObject Arguments);

extern std::queue<ProcessedDumpInfoHandler> InfoHandlerToFlush;