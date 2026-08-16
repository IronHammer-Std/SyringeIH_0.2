// 线程命名（0x406D1388）端到端自动化测试。
// 在 Tests.exe 进程内跑完整 SyringeDebugger 调试会话，验证：
//   - 命名线程名进入 syringe 日志（"线程 N 命名为 \"CrashWorker\""）；
//   - 异常报告 thread JSON 段携带 "name":"CrashWorker" 与 group=exception；
//   - 异常文本转储头部为 "异常线程ID = N（CrashWorker）"。
#include "TestHarness.h"

#include "SyringeDebugger.h"
#include "Log.h"
#include "cJSON.h"

#include <windows.h>
#include <shlwapi.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace
{
	bool GetTestDirs(std::string& exeDir, std::string& releaseDir)
	{
		char exePath[MAX_PATH];
		if(!GetModuleFileNameA(nullptr, exePath, MAX_PATH)) return false;
		exeDir = exePath;
		auto const slash = exeDir.find_last_of("\\/");
		if(slash == std::string::npos) return false;
		exeDir.resize(slash);
		// tests\bin → 仓库根\Release
		releaseDir = exeDir + "\\..\\..\\Release";
		return true;
	}

	std::vector<std::string> ReadJsonSegments(char const* logPath)
	{
		std::vector<std::string> ret;
		FILE* f = fopen(logPath, "rb");
		if(!f) return ret;
		char line[8192];
		bool inJson = false;
		while(fgets(line, sizeof(line), f))
		{
			if(strstr(line, "@@SyringeIH:JSON:BEGIN")) { inJson = true; continue; }
			if(strstr(line, "@@SyringeIH:JSON:END"))   { inJson = false; continue; }
			if(inJson && line[0] == '{')
			{
				std::string s(line);
				while(!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
				ret.push_back(std::move(s));
			}
		}
		fclose(f);
		return ret;
	}

	std::string ReadWholeLog(char const* logPath)
	{
		std::string ret;
		FILE* f = fopen(logPath, "rb");
		if(!f) return ret;
		char buf[8192];
		size_t n;
		while((n = fread(buf, 1, sizeof(buf), f)) > 0) ret.append(buf, n);
		fclose(f);
		return ret;
	}

	// 跑一次"命名→崩溃→报告"场景并断言
	void RunNamingScenario(char const* targetExe)
	{
		std::string exeDir, releaseDir;
		if(!GetTestDirs(exeDir, releaseDir))
		{
			printf("  SKIP: 无法定位测试资产目录\n");
			return;
		}

		auto const targetPath = exeDir + "\\" + targetExe;
		if(!PathFileExistsA(targetPath.c_str()))
		{
			printf("  SKIP: 缺少 %s（先构建 Nametest* 工程）\n", targetExe);
			return;
		}

		// 注入资产按 ExecutableDirectoryPath() 查找：复制 SyringeEx.dll 到 Tests.exe 同目录
		auto const srcDll = releaseDir + "\\SyringeEx.dll";
		auto const dstDll = exeDir + "\\SyringeEx.dll";
		if(!PathFileExistsA(srcDll.c_str()))
		{
			printf("  SKIP: 缺少 SyringeEx.dll（%s）\n", srcDll.c_str());
			return;
		}
		CopyFileA(srcDll.c_str(), dstDll.c_str(), FALSE);

		char oldCwd[MAX_PATH];
		GetCurrentDirectoryA(MAX_PATH, oldCwd);
		SetCurrentDirectoryA(exeDir.c_str());
		Log::Open("tests_syringe.log");

		try
		{
			SyringeDebugger Debugger{ targetPath };
			Debugger.FindDLLs();
			Debugger.Run("");
		}
		catch(...)
		{
			printf("  SKIP: 调试会话异常退出（环境不完整？）\n");
		}

		// 等守护线程（如有）收尾（连接超时约 2s）后落盘
		Sleep(3500);
		Log::Flush();
		Log::Close();

		auto const logText = ReadWholeLog("tests_syringe.log");
		CHECK(logText.find("命名为 \"CrashWorker\"") != std::string::npos);

		bool exceptionJsonSeen = false;
		bool nameInJson = false;
		for(auto const& seg : ReadJsonSegments("tests_syringe.log"))
		{
			auto* const obj = cJSON_Parse(seg.c_str());
			if(!obj) continue;
			auto* const type = cJSON_GetObjectItem(obj, "type");
			auto* const group = cJSON_GetObjectItem(obj, "group");
			auto* const name = cJSON_GetObjectItem(obj, "name");
			if(group && group->valuestring && strcmp(group->valuestring, "exception") == 0)
				exceptionJsonSeen = true;
			if(type && type->valuestring && strcmp(type->valuestring, "thread") == 0 &&
				name && name->valuestring && strcmp(name->valuestring, "CrashWorker") == 0)
				nameInJson = true;
			cJSON_Delete(obj);
		}
		CHECK(exceptionJsonSeen);
		CHECK(nameInJson);
		CHECK(logText.find("异常线程ID = ") != std::string::npos);
		CHECK(logText.find("（CrashWorker）") != std::string::npos);

		DeleteFileA("tests_syringe.log");
		SetCurrentDirectoryA(oldCwd);
	}
}

TEST_CASE(threadname_hybrid_layout)
{
	RunNamingScenario("nametest.exe");
}

TEST_CASE(threadname_msvc_canonical_layout)
{
	RunNamingScenario("nametest_std.exe");
}
