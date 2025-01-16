#include "ExtPack.h"
#include <shlwapi.h>

void ExtensionDir::LoadFromJson(JsonObject Obj)
{
	if (Obj.Available() && Obj.IsTypeObject())
	{
		auto s = Obj.GetObjectItem("Path");
		if (s.Available() && s.IsTypeString())Path = s.GetString();
		s = Obj.GetObjectItem("Includes");
		if (s.Available() && s.IsTypeArray())IncludeName = s.GetArrayString();
		s = Obj.GetObjectItem("Excludes");
		if (s.Available() && s.IsTypeArray())ExcludeName = s.GetArrayString();
		s = Obj.GetObjectItem("LoadAllMatchedFiles");
		if (s.Available() && s.IsTypeBool())LoadAllMatchedFiles = s.GetBool();
	}
}

bool ExtensionDir::MatchName(const char* Name)
{
	for (auto& str : ExcludeName)
		if (PathMatchSpecA(Name, str.c_str()))
			return false;
	for (auto& str : IncludeName)
		if (PathMatchSpecA(Name, str.c_str()))
			return true;
	return IncludeName.empty();
}

void ExtensionPack::LoadFromJson(JsonObject Obj)
{
	if (Obj.Available() && Obj.IsTypeArray())
	{
		auto Arr = Obj.GetArrayObject();
		Directories.reserve(Arr.size());
		for (auto obj : Obj.GetArrayObject())
		{
			Directories.emplace_back();
			Directories.back().LoadFromJson(obj);
		}
	}
}

