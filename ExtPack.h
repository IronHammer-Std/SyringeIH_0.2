#pragma once
#include <string>
#include <string_view>
#include <vector>
#include "ExtJson.h"

class ExtensionDir
{
public:
	std::string Path;//UTF8
	std::vector<std::string> IncludeName;//UTF8
	std::vector<std::string> ExcludeName;//UTF8
	bool LoadAllMatchedFiles{ false };
	void LoadFromJson(JsonObject Obj);
	bool MatchName(const char* Name);
};

class ExtensionPack
{
public:
	std::vector<ExtensionDir> Directories;
	void LoadFromJson(JsonObject Obj);
};