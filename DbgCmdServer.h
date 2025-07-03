#pragma once

#include "ExtJson.h"
#include "SyringeDebugger.h"
#include <string>
#include <variant>

std::variant<JsonFile, std::pair<std::string,LONG> > ProcessDebugCommand(SyringeDebugger* Dbg, const std::string& Method, JsonObject Arguments);

