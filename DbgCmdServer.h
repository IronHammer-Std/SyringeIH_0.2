#pragma once

#include "ExtJson.h"
#include "SyringeDebugger.h"
#include <string>
#include <variant>

using DebugCommandReturnType = std::variant<JsonFile, std::pair<std::string, LONG> >;
DebugCommandReturnType ProcessDebugCommand(SyringeDebugger* Dbg, const std::string& Method, JsonObject Arguments);

