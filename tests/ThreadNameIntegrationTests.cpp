// 线程命名（0x406D1388）与快照请求载荷的端到端自动化测试。
// 在 Tests.exe 进程内跑完整 SyringeDebugger 调试会话，验证：
//   - 命名线程名进入 syringe 日志（"线程 N 命名为 \"CrashWorker\""）；
//   - 异常报告 thread JSON 段携带 "name":"CrashWorker" 与 group=exception；
//   - 异常文本转储头部为 "异常线程ID = N（CrashWorker）"；
//   - 广播载荷经身份映射写入 → 快照输出 request 段（统一契约包装）。
#include "TestHarness.h"

#include "SyringeDebugger.h"
#include "Log.h"
#include "Snapshot.h"
#include "Setting.h"
#include "Support.h"
#include "cJSON.h"

#include <windows.h>
#include <shlwapi.h>

#include <cstdio>
#include <cstring>
#include <direct.h>
#include <string>
#include <thread>
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
	// expectMain：崩溃线程是否应为进程主线程（CREATE_PROCESS 事件的初始线程）
	void RunNamingScenario(char const* targetExe, bool const expectMain)
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
		bool mainFlag = false;
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
			{
				nameInJson = true;
				auto* const main = cJSON_GetObjectItem(obj, "main");
				if(main && main->type == cJSON_True) mainFlag = true;
			}
			cJSON_Delete(obj);
		}
		CHECK(exceptionJsonSeen);
		CHECK(nameInJson);
		CHECK(logText.find("异常线程ID = ") != std::string::npos);
		if(expectMain)
		{
			CHECK(mainFlag);
			CHECK(logText.find("（CrashWorker，主线程）") != std::string::npos);
		}
		else
		{
			CHECK(!mainFlag);
			CHECK(logText.find("（CrashWorker）") != std::string::npos);
		}

		DeleteFileA("tests_syringe.log");
		SetCurrentDirectoryA(oldCwd);
	}

	// 载荷端到端：在 nametest.exe 的 5s SEH 保活窗口内，从会话内写入载荷并打断，
	// 断言快照输出 request 段（统一契约包装）与文本摘要
	void RunPayloadScenario()
	{
		std::string exeDir, releaseDir;
		if(!GetTestDirs(exeDir, releaseDir))
		{
			printf("  SKIP: 无法定位测试资产目录\n");
			return;
		}

		auto const targetPath = exeDir + "\\nametest.exe";
		if(!PathFileExistsA(targetPath.c_str()))
		{
			printf("  SKIP: 缺少 nametest.exe（先构建 Nametest* 工程）\n");
			return;
		}
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

		auto const payload = std::string("{\"tool\":\"tests\",\"mode\":\"verify\",\"n\":42}");

		try
		{
			SyringeDebugger Debugger{ targetPath };
			Debugger.FindDLLs();

			// 会话内辅助线程：写入载荷 → 打断 → 稍后终止目标让 Run 返回
			std::thread breaker([&]()
			{
				Sleep(2500);
				SnapshotWritePayload(GetCurrentProcessId(), payload);
				DebugBreakProcess(Debugger.pInfo.hProcess);
				Sleep(2000);
				TerminateProcess(Debugger.pInfo.hProcess, 0);
			});

			Debugger.Run("");
			breaker.join();
		}
		catch(...)
		{
			printf("  SKIP: 调试会话异常退出（环境不完整？）\n");
		}

		Sleep(3500);
		Log::Flush();
		Log::Close();

		auto const logText = ReadWholeLog("tests_syringe.log");
		CHECK(logText.find("收到快照请求") != std::string::npos);
		CHECK(logText.find("快照载荷：") != std::string::npos);

		bool requestSeen = false;
		bool payloadKeySeen = false;
		for(auto const& seg : ReadJsonSegments("tests_syringe.log"))
		{
			auto* const obj = cJSON_Parse(seg.c_str());
			if(!obj) continue;
			auto* const type = cJSON_GetObjectItem(obj, "type");
			if(type && type->valuestring && strcmp(type->valuestring, "request") == 0)
			{
				requestSeen = true;
				auto* const payloadObj = cJSON_GetObjectItem(obj, "payload");
				if(payloadObj)
				{
					auto* const tool = cJSON_GetObjectItem(payloadObj, "tool");
					if(tool && tool->valuestring && strcmp(tool->valuestring, "tests") == 0)
						payloadKeySeen = true;
				}
			}
			cJSON_Delete(obj);
		}
		CHECK(requestSeen);
		CHECK(payloadKeySeen);

		DeleteFileA("tests_syringe.log");
		SetCurrentDirectoryA(oldCwd);
	}

	// SnapshotFileName 重定向端到端：载荷指定输出文件后，本次快照全程内容
	// 应写入该文件（syringe.log 只保留异常报告等非快照内容）
	void RunRedirectScenario()
	{
		std::string exeDir, releaseDir;
		if(!GetTestDirs(exeDir, releaseDir))
		{
			printf("  SKIP: 无法定位测试资产目录\n");
			return;
		}

		auto const targetPath = exeDir + "\\nametest.exe";
		if(!PathFileExistsA(targetPath.c_str()))
		{
			printf("  SKIP: 缺少 nametest.exe（先构建 Nametest* 工程）\n");
			return;
		}
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
		DeleteFileA("snapshot_redirect_test.log");

		auto const payload = std::string(
			"{\"tool\":\"tests\",\"SnapshotFileName\":\"snapshot_redirect_test.log\"}");

		try
		{
			SyringeDebugger Debugger{ targetPath };
			Debugger.FindDLLs();

			std::thread breaker([&]()
			{
				Sleep(2500);
				SnapshotWritePayload(GetCurrentProcessId(), payload);
				DebugBreakProcess(Debugger.pInfo.hProcess);
				Sleep(2000);
				TerminateProcess(Debugger.pInfo.hProcess, 0);
			});

			Debugger.Run("");
			breaker.join();
		}
		catch(...)
		{
			printf("  SKIP: 调试会话异常退出（环境不完整？）\n");
		}

		Sleep(3500);
		Log::Flush();
		Log::Close();

		auto const mainLog = ReadWholeLog("tests_syringe.log");
		auto const redirectLog = ReadWholeLog("snapshot_redirect_test.log");

		// 重定向文件：本次快照全程内容在此
		CHECK(redirectLog.find("收到快照请求") != std::string::npos);
		CHECK(redirectLog.find("本次快照输出重定向至") != std::string::npos);
		CHECK(redirectLog.find("快照载荷：") != std::string::npos);
		CHECK(redirectLog.find("@@SyringeIH:JSON:BEGIN:request:") != std::string::npos);
		CHECK(redirectLog.find("@@SyringeIH:JSON:BEGIN:process:") != std::string::npos);
		CHECK(redirectLog.find("栈快照输出完成") != std::string::npos);

		// request 段的 payload 原样复述了 SnapshotFileName
		bool fileRelayed = false;
		for(auto const& seg : ReadJsonSegments("snapshot_redirect_test.log"))
		{
			auto* const obj = cJSON_Parse(seg.c_str());
			if(!obj) continue;
			auto* const type = cJSON_GetObjectItem(obj, "type");
			if(type && type->valuestring && strcmp(type->valuestring, "request") == 0)
			{
				auto* const p = cJSON_GetObjectItem(obj, "payload");
				if(p)
				{
					auto* const f = cJSON_GetObjectItem(p, "SnapshotFileName");
					if(f && f->valuestring &&
						strcmp(f->valuestring, "snapshot_redirect_test.log") == 0)
						fileRelayed = true;
				}
			}
			cJSON_Delete(obj);
		}
		CHECK(fileRelayed);

		// 主日志：无任何快照内容（异常报告照旧在 syringe.log）
		CHECK(mainLog.find("收到快照请求") == std::string::npos);
		CHECK(mainLog.find("快照 #") == std::string::npos);
		CHECK(mainLog.find("@@SyringeIH:JSON:BEGIN:process:") == std::string::npos);
		CHECK(mainLog.find("异常线程ID = ") != std::string::npos);

		DeleteFileA("tests_syringe.log");
		DeleteFileA("snapshot_redirect_test.log");
		SetCurrentDirectoryA(oldCwd);
	}

	// 线程来源过滤端到端：载荷携带 SnapshotThreadFilter 时，只有来源命中白名单的
	// 线程才输出 thread 段与 TEXT 段（process 段与异常报告不受影响）。
	// mode "miss"：白名单未命中任何线程 → 0 个 snapshot thread 段，摘要含“已过滤”；
	// mode "hit" ：白名单 = nametest.exe → 主线程保留，source 均为 nametest.exe。
	void RunFilterScenario(char const* mode)
	{
		std::string exeDir, releaseDir;
		if(!GetTestDirs(exeDir, releaseDir))
		{
			printf("  SKIP: 无法定位测试资产目录\n");
			return;
		}

		auto const targetPath = exeDir + "\\nametest.exe";
		if(!PathFileExistsA(targetPath.c_str()))
		{
			printf("  SKIP: 缺少 nametest.exe（先构建 Nametest* 工程）\n");
			return;
		}
		auto const srcDll = releaseDir + "\\SyringeEx.dll";
		auto const dstDll = exeDir + "\\SyringeEx.dll";
		if(!PathFileExistsA(srcDll.c_str()))
		{
			printf("  SKIP: 缺少 SyringeEx.dll（%s）\n", srcDll.c_str());
			return;
		}
		CopyFileA(srcDll.c_str(), dstDll.c_str(), FALSE);

		auto const filter = strcmp(mode, "miss") == 0
			? std::string("__no_such_module__.dll")
			: std::string("nametest.exe");
		// 载荷内统一为模块名数组形式（与内部存储一致）
		auto const payload =
			std::string("{\"tool\":\"tests\",\"SnapshotThreadFilter\":[\"") + filter + "\"]}";

		char oldCwd[MAX_PATH];
		GetCurrentDirectoryA(MAX_PATH, oldCwd);
		SetCurrentDirectoryA(exeDir.c_str());
		Log::Open("tests_syringe.log");

		try
		{
			SyringeDebugger Debugger{ targetPath };
			Debugger.FindDLLs();

			std::thread breaker([&]()
			{
				Sleep(2500);
				SnapshotWritePayload(GetCurrentProcessId(), payload);
				DebugBreakProcess(Debugger.pInfo.hProcess);
				Sleep(2000);
				TerminateProcess(Debugger.pInfo.hProcess, 0);
			});

			Debugger.Run("");
			breaker.join();
		}
		catch(...)
		{
			printf("  SKIP: 调试会话异常退出（环境不完整？）\n");
		}

		Sleep(3500);
		Log::Flush();
		Log::Close();

		auto const logText = ReadWholeLog("tests_syringe.log");
		CHECK(logText.find("收到快照请求") != std::string::npos);
		CHECK(logText.find("线程来源过滤：") != std::string::npos);

		size_t snapshotThreadSegments = 0;
		bool allSourcesMatch = true;
		bool filterEchoSeen = false;
		for(auto const& seg : ReadJsonSegments("tests_syringe.log"))
		{
			auto* const obj = cJSON_Parse(seg.c_str());
			if(!obj) continue;
			auto* const type = cJSON_GetObjectItem(obj, "type");
			auto* const group = cJSON_GetObjectItem(obj, "group");
			if(type && type->valuestring && strcmp(type->valuestring, "thread") == 0 &&
				group && group->valuestring && strcmp(group->valuestring, "snapshot") == 0)
			{
				++snapshotThreadSegments;
				auto* const src = cJSON_GetObjectItem(obj, "source");
				if(!src || !src->valuestring || _stricmp(src->valuestring, "nametest.exe") != 0)
					allSourcesMatch = false;
			}
			if(type && type->valuestring && strcmp(type->valuestring, "request") == 0)
			{
				auto* const flt = cJSON_GetObjectItem(obj, "filter");
				if(flt)
				{
					auto* const inc = cJSON_GetObjectItem(flt, "include");
					if(inc && inc->type == cJSON_Array && cJSON_GetArraySize(inc) >= 1)
					{
						auto* const first = cJSON_GetArrayItem(inc, 0);
						if(first && first->valuestring && strcmp(first->valuestring, filter.c_str()) == 0)
							filterEchoSeen = true;
					}
				}
			}
			cJSON_Delete(obj);
		}

		if(strcmp(mode, "miss") == 0)
		{
			CHECK(snapshotThreadSegments == 0);
			CHECK(logText.find("0 线程（已过滤 ") != std::string::npos);
		}
		else
		{
			// 白名单 = nametest.exe：至少主线程保留；每个输出的 thread 段 source 均为 nametest.exe。
			// 注：调试会话中可能有 SyringeEx.dll 的常驻线程等来源，被白名单过滤是预期行为，
			// 因此这里不断言“无过滤”，而是校验摘要行“快照 #N：M 线程”的 M 与实际段数一致。
			// （“：”是多字节字符，不能用字节偏移切分，用 sscanf 直接解析数字）
			CHECK(snapshotThreadSegments >= 1);
			CHECK(allSourcesMatch);
			unsigned parsedCount = 0;
			auto const pos = logText.find("快照 #");
			if(pos != std::string::npos &&
				sscanf(logText.c_str() + pos, "快照 #%*u：%u", &parsedCount) == 1)
			{
				CHECK(parsedCount == snapshotThreadSegments);
			}
		}
		CHECK(filterEchoSeen);

		DeleteFileA("tests_syringe.log");
		SetCurrentDirectoryA(oldCwd);
	}
}

// 载荷映射单元往返：注册 → 写入 → 读取 → 超限截断 → 空载荷清除
TEST_CASE(snapshot_payload_roundtrip)
{
	CHECK(SnapshotRegister(1234));
	auto const payload = std::string("{\"tool\":\"tests\",\"n\":1}");
	CHECK(SnapshotWritePayload(GetCurrentProcessId(), payload));
	CHECK(SnapshotReadPayload() == payload);

	CHECK(SnapshotWritePayload(GetCurrentProcessId(), std::string(SNAPSHOT_PAYLOAD_MAX + 100, 'x')));
	CHECK(SnapshotReadPayload().size() == SNAPSHOT_PAYLOAD_MAX);

	CHECK(SnapshotWritePayload(GetCurrentProcessId(), ""));
	CHECK(SnapshotReadPayload().empty());

	SnapshotUnregister();
}

TEST_CASE(threadname_hybrid_layout)
{
	// nametest.exe 在主线程命名并崩溃 → 崩溃线程即主线程
	RunNamingScenario("nametest.exe", true);
}

TEST_CASE(threadname_msvc_canonical_layout)
{
	// nametest_std.exe 在工作线程命名并崩溃 → 崩溃线程非主线程
	RunNamingScenario("nametest_std.exe", false);
}

TEST_CASE(snapshot_payload_request_segment)
{
	RunPayloadScenario();
}

// SnapshotFileName 参数解析：命令行覆盖
TEST_CASE(setting_snapshot_filename_cli)
{
	auto const old = SnapshotFileName;
	std::vector<std::string_view> flags{ "-SnapshotFileName=snap_test.log" };
	UpdateSetting(flags);
	CHECK(SnapshotFileName == "snap_test.log");
	SnapshotFileName = old;
}

// SnapshotFileName 参数解析：Syringe.json（默认空串；缺键时保持原值）
TEST_CASE(setting_snapshot_filename_json)
{
	char cwd[MAX_PATH];
	_getcwd(cwd, MAX_PATH);

	char tmpDir[MAX_PATH];
	GetTempPathA(MAX_PATH, tmpDir);
	strcat_s(tmpDir, "syringe_setting_test");
	CreateDirectoryA(tmpDir, nullptr);
	SetCurrentDirectoryA(tmpDir);

	FILE* f = fopen("Syringe.json", "wb");
	if(f)
	{
		fputs("{\"SnapshotFileName\":\"from_json.log\"}", f);
		fclose(f);
	}

	auto const old = SnapshotFileName;
	SnapshotFileName = "";
	ReadSetting();
	CHECK(SnapshotFileName == "from_json.log");

	SetCurrentDirectoryA(cwd);
	SnapshotFileName = old;

	char jsonPath[MAX_PATH];
	strcpy_s(jsonPath, tmpDir);
	strcat_s(jsonPath, "\\Syringe.json");
	DeleteFileA(jsonPath);
	RemoveDirectoryA(tmpDir);
}

// SnapshotFileName 端到端：载荷重定向快照全程输出
TEST_CASE(snapshot_filename_redirect)
{
	RunRedirectScenario();
}

// Windows PowerShell 5.1 传参拆分修复："-X=值" + ".扩展名" 应被自动拼回
TEST_CASE(setting_ps51_split_repair)
{
	auto const old = SnapshotFileName;

	// 拆分场景：-SnapshotFileName=snap_manual + .log → snap_manual.log
	UpdateSetting({ "-SnapshotFileName=snap_manual", ".log" });
	CHECK(SnapshotFileName == "snap_manual.log");

	// 正常单 token 不受影响
	UpdateSetting({ "-SnapshotFileName=direct.log" });
	CHECK(SnapshotFileName == "direct.log");

	// 无 '=' 的 token 后跟 '.x' 不触发修复
	SnapshotFileName = old;
	UpdateSetting({ "foo", ".log" });
	CHECK(SnapshotFileName == old);

	SnapshotFileName = old;
}

// 线程来源过滤判定：纯函数语义（exclude 优先 / 白名单 / 未知来源 / 大小写）
TEST_CASE(snapshot_thread_filter_matcher)
{
	// 无过滤配置：全部保留（含来源未知）
	CHECK(!SnapshotThreadFiltered("game.exe", {}, {}));
	CHECK(!SnapshotThreadFiltered("", {}, {}));

	// exclude 命中 → 过滤；大小写不敏感
	CHECK(SnapshotThreadFiltered("game.exe", {}, {"game.exe"}));
	CHECK(SnapshotThreadFiltered("GAME.EXE", {}, {"game.exe"}));
	CHECK(!SnapshotThreadFiltered("other.dll", {}, {"game.exe"}));

	// include 非空即白名单：命中保留、未命中过滤
	CHECK(!SnapshotThreadFiltered("game.exe", {"game.exe", "SyringeEx.dll"}, {}));
	CHECK(!SnapshotThreadFiltered("syringeex.dll", {"game.exe", "SyringeEx.dll"}, {}));
	CHECK(SnapshotThreadFiltered("ntdll.dll", {"game.exe"}, {}));

	// 来源未知：include 下过滤（fail-closed），纯 exclude 下保留
	CHECK(SnapshotThreadFiltered("", {"game.exe"}, {}));
	CHECK(!SnapshotThreadFiltered("", {}, {"game.exe"}));

	// 匹配层为精确比较（大小写不敏感）；空白修剪只发生在解析层（SnapshotSplitModuleList）
	CHECK(SnapshotThreadFiltered("game.exe", {" game.exe "}, {}));
}

// 逗号分隔模块列表拆分：剔除空白与空项
TEST_CASE(snapshot_split_module_list)
{
	auto const v = SnapshotSplitModuleList(" game.exe , SyringeEx.dll,ntdll.dll ");
	CHECK(v.size() == 3);
	CHECK(v[0] == "game.exe");
	CHECK(v[1] == "SyringeEx.dll");
	CHECK(v[2] == "ntdll.dll");
	CHECK(SnapshotSplitModuleList("").empty());
	CHECK(SnapshotSplitModuleList(",,").empty());
}

// 线程来源过滤参数解析：命令行逗号分隔串，吃进来立即拆分为数组
TEST_CASE(setting_snapshot_thread_filter_cli)
{
	auto const oldF = SnapshotThreadFilter;
	auto const oldE = SnapshotThreadExclude;
	UpdateSetting({
		"-SnapshotThreadFilter=game.exe,SyringeEx.dll",
		"-SnapshotThreadExclude=ntdll.dll" });
	CHECK(SnapshotThreadFilter.size() == 2);
	CHECK(SnapshotThreadFilter[0] == "game.exe");
	CHECK(SnapshotThreadFilter[1] == "SyringeEx.dll");
	CHECK(SnapshotThreadExclude.size() == 1);
	CHECK(SnapshotThreadExclude[0] == "ntdll.dll");
	SnapshotThreadFilter = oldF;
	SnapshotThreadExclude = oldE;
}

// 线程来源过滤参数解析：Syringe.json
TEST_CASE(setting_snapshot_thread_filter_json)
{
	char cwd[MAX_PATH];
	_getcwd(cwd, MAX_PATH);

	char tmpDir[MAX_PATH];
	GetTempPathA(MAX_PATH, tmpDir);
	strcat_s(tmpDir, "syringe_setting_filter_test");
	CreateDirectoryA(tmpDir, nullptr);
	SetCurrentDirectoryA(tmpDir);

	FILE* f = fopen("Syringe.json", "wb");
	if(f)
	{
		fputs("{\"SnapshotThreadFilter\":[\"game.exe\",\"Phobos.dll\"],\"SnapshotThreadExclude\":[\"ntdll.dll\"]}", f);
		fclose(f);
	}

	auto const oldF = SnapshotThreadFilter;
	auto const oldE = SnapshotThreadExclude;
	SnapshotThreadFilter = {};
	SnapshotThreadExclude = {};
	ReadSetting();
	CHECK(SnapshotThreadFilter.size() == 2);
	CHECK(SnapshotThreadFilter[0] == "game.exe");
	CHECK(SnapshotThreadFilter[1] == "Phobos.dll");
	CHECK(SnapshotThreadExclude.size() == 1);
	CHECK(SnapshotThreadExclude[0] == "ntdll.dll");

	SetCurrentDirectoryA(cwd);
	SnapshotThreadFilter = oldF;
	SnapshotThreadExclude = oldE;

	char jsonPath[MAX_PATH];
	strcpy_s(jsonPath, tmpDir);
	strcat_s(jsonPath, "\\Syringe.json");
	DeleteFileA(jsonPath);
	RemoveDirectoryA(tmpDir);
}

// Windows PowerShell 5.1 拆分修复同样作用于过滤列表（.exe 位于列表中间）
TEST_CASE(setting_ps51_split_repair_filter)
{
	auto const oldF = SnapshotThreadFilter;
	// 拆分场景：-SnapshotThreadFilter=game + .exe,SyringeEx.dll → [game.exe, SyringeEx.dll]
	UpdateSetting({ "-SnapshotThreadFilter=game", ".exe,SyringeEx.dll" });
	CHECK(SnapshotThreadFilter.size() == 2);
	CHECK(SnapshotThreadFilter[0] == "game.exe");
	CHECK(SnapshotThreadFilter[1] == "SyringeEx.dll");
	SnapshotThreadFilter = oldF;
}

// 线程来源过滤端到端：白名单未命中任何线程 → 0 个 snapshot thread 段
TEST_CASE(snapshot_thread_filter_miss)
{
	RunFilterScenario("miss");
}

// 线程来源过滤端到端：白名单 = nametest.exe → 主线程保留且 source 为 nametest.exe
TEST_CASE(snapshot_thread_filter_hit)
{
	RunFilterScenario("hit");
}

// 引号感知切词：带空格的 flag 值合并为单 token，引号自身被剔除
TEST_CASE(splitview_quote_aware)
{
	auto const tokens = SplitView("-i=first -SnapshotFileName=\"my log.txt\" -Ext=pack");
	CHECK(tokens.size() == 3);
	CHECK(tokens[0] == "-i=first");
	CHECK(tokens[1] == "-SnapshotFileName=my log.txt");
	CHECK(tokens[2] == "-Ext=pack");
}

// 引号内连续空格保留；引号外连续空白不产生空 token；空引号对不产生 token
TEST_CASE(splitview_whitespace_and_empty_quotes)
{
	auto const tokens = SplitView("  -a=1   \"b c  d\"   \"\"   -e=2  ");
	CHECK(tokens.size() == 3);
	CHECK(tokens[0] == "-a=1");
	CHECK(tokens[1] == "b c  d");
	CHECK(tokens[2] == "-e=2");
}

// 未闭合引号一直吞到段尾
TEST_CASE(splitview_unclosed_quote)
{
	auto const tokens = SplitView("-SnapshotFileName=\"my log.txt");
	CHECK(tokens.size() == 1);
	CHECK(tokens[0] == "-SnapshotFileName=my log.txt");
}

// 引号感知切词 + UpdateSetting 端到端：带空格的文件名
TEST_CASE(setting_quoted_value_with_spaces)
{
	auto const old = SnapshotFileName;
	UpdateSetting(SplitView("-SnapshotFileName=\"my log.txt\""));
	CHECK(SnapshotFileName == "my log.txt");
	SnapshotFileName = old;
}

// FindExecutableQuote：flag 值内引号不算 exe 边界，token 开头的引号才算
TEST_CASE(find_executable_quote_boundary)
{
	CHECK(FindExecutableQuote("-SnapshotFileName=\"my log.txt\" \"gamemd.exe\"") == 31);
	CHECK(FindExecutableQuote("\"gamemd.exe\"") == 0);
	CHECK(FindExecutableQuote("--snapshot") == std::string_view::npos);
	CHECK(FindExecutableQuote("-i=x.dll \"gamemd.exe\" -CD") == 9);
	CHECK(FindExecutableQuote("-i=\"a b.dll\" -Ext=p \"gamemd.exe\"") == 20);
}

// 全链路：带空格 flag 值 + 引号 exe + 尾部参数
TEST_CASE(quoted_flag_full_command_line)
{
	auto const cmd = get_command_line("-SnapshotFileName=\"my log.txt\" \"gamemd.exe\" -CD");
	CHECK(cmd.executable == "gamemd.exe");
	CHECK(cmd.arguments == "-CD");
	CHECK(cmd.flaglist.size() == 1);
	CHECK(cmd.flaglist[0] == "-SnapshotFileName=my log.txt");
}

// --args= 提取：引号形式取引号内文本，整段从命令行移除
TEST_CASE(extract_args_flag_basic)
{
	std::string content;
	auto const cleaned = ExtractArgsFlag("-i=a --args=\"-CD -X\" \"gamemd.exe\" -Y", content);
	CHECK(content == "-CD -X");
	CHECK(cleaned == "-i=a  \"gamemd.exe\" -Y");
}

// --args= 前后都出现：取最后一个，两处都移除；裸形式（无引号）取到空白
TEST_CASE(extract_args_flag_last_wins)
{
	std::string content;
	auto const cleaned = ExtractArgsFlag("--args=\"-CD\" \"gamemd.exe\" -SPEEDCONTROL --args=-WIN", content);
	CHECK(content == "-WIN");
	CHECK(cleaned == " \"gamemd.exe\" -SPEEDCONTROL ");
}

// 边界：空内容、无 '=' 不识别、空输入、引号内形似文本不动
TEST_CASE(extract_args_flag_edges)
{
	std::string content;

	CHECK(ExtractArgsFlag("--args=\"\" \"gamemd.exe\"", content) == " \"gamemd.exe\"");
	CHECK(content.empty());

	CHECK(ExtractArgsFlag("--args \"gamemd.exe\"", content) == "--args \"gamemd.exe\"");
	CHECK(content.empty());

	CHECK(ExtractArgsFlag("", content).empty());
	CHECK(content.empty());

	// 引号保护：游戏参数里的 "--args=literal" 原样保留
	CHECK(ExtractArgsFlag("\"gamemd.exe\" \"--args=literal\"", content) == "\"gamemd.exe\" \"--args=literal\"");
	CHECK(content.empty());
}

// 全链路：--args 在 exe 前、后各出现一次，最后一个生效，展开拼到游戏参数最前
TEST_CASE(args_flag_full_command_line)
{
	std::string content;
	auto const cleaned = ExtractArgsFlag("--args=\"-CD\" \"gamemd.exe\" -SPEEDCONTROL --args=\"-WIN\"", content);
	CHECK(content == "-WIN");

	auto const cmd = get_command_line(cleaned);
	CHECK(cmd.executable == "gamemd.exe");
	CHECK(cmd.arguments == "-SPEEDCONTROL");

	// 与 Main.cpp 相同的合并规则：--args 内容在前 + 尾巴在后（空格分隔）
	std::string merged = content;
	if (!merged.empty() && !cmd.arguments.empty())
		merged += ' ';
	if (!cmd.arguments.empty())
		merged.append(cmd.arguments.data(), cmd.arguments.size());
	CHECK(merged == "-WIN -SPEEDCONTROL");
}

// trim：全空白串收缩为空串（--args 移除后尾巴只剩空白时不得残留空格）
TEST_CASE(trim_all_whitespace_empty)
{
	CHECK(trim("   ").empty());
	CHECK(trim("").empty());
	CHECK(trim(" a " ) == "a");
	CHECK(trim("a") == "a");
}

// 全链路：--args 移除后尾巴只剩空白 → 合并结果无多余空格
TEST_CASE(args_flag_whitespace_only_tail)
{
	std::string content;
	auto const cleaned = ExtractArgsFlag("--args=\"-WIN\" \"gamemd.exe\" --args=\"-OLD\"", content);
	CHECK(content == "-OLD");

	auto const cmd = get_command_line(cleaned);
	CHECK(cmd.executable == "gamemd.exe");
	CHECK(cmd.arguments.empty());

	std::string merged = content;
	if (!merged.empty() && !cmd.arguments.empty())
		merged += ' ';
	if (!cmd.arguments.empty())
		merged.append(cmd.arguments.data(), cmd.arguments.size());
	CHECK(merged == "-OLD");
}

// ============ UseSyringeExCommandLine（SyringeEx 风格命令行） ============

// SyringeEx 风格：全行分类（flag 任意位置；首个非 '-' token 为 exe；带空格引号 exe）
TEST_CASE(classify_syringeex_line)
{
	auto const parts = ClassifySyringeexLine("-i=a.dll gamemd.exe -CD -i=b.dll");
	CHECK(parts.executable == "gamemd.exe");
	CHECK(parts.flags.size() == 3);
	CHECK(parts.flags[0] == "-i=a.dll");
	CHECK(parts.flags[1] == "-CD");
	CHECK(parts.flags[2] == "-i=b.dll");

	auto const parts2 = ClassifySyringeexLine("\"C:\\game dir\\gamemd.exe\" -CD");
	CHECK(parts2.executable == "C:\\game dir\\gamemd.exe");
	CHECK(parts2.flags.size() == 1);
	CHECK(parts2.flags[0] == "-CD");

	auto const parts3 = ClassifySyringeexLine("--snapshot");
	CHECK(parts3.executable.empty());
	CHECK(parts3.flags.size() == 1);
	CHECK(parts3.flags[0] == "--snapshot");
}

// SyringeEx 风格解析：无 JSON 默认时，游戏参数仅来自 --args= 内容
TEST_CASE(resolve_syringeex_command_basic)
{
	auto const parts = ClassifySyringeexLine("gamemd.exe -i=x.dll");
	auto const resolved = ResolveSyringeexCommand(parts, "-CD");
	CHECK(resolved.executable == "gamemd.exe");
	CHECK(resolved.arguments == "-CD");
}

// OverwriteStartParams=true → JSON 默认覆盖命令行 exe（--args= 仍拼在前）
TEST_CASE(resolve_syringeex_command_overwrite)
{
	auto const oldOver = OverwriteStartParams;
	auto const oldExe = DefaultExecName;
	auto const oldCmd = DefaultCmdLine;
	OverwriteStartParams = true;
	DefaultExecName = "gamemd.exe";
	DefaultCmdLine = "-WIN";

	auto const parts = ClassifySyringeexLine("other.exe -i=x.dll");
	auto const resolved = ResolveSyringeexCommand(parts, "-CD");
	CHECK(resolved.executable == "gamemd.exe");
	CHECK(resolved.arguments == "-CD -WIN");

	OverwriteStartParams = oldOver;
	DefaultExecName = oldExe;
	DefaultCmdLine = oldCmd;
}

// 命令行无 exe 且无 JSON 默认 → 抛 invalid_command_arguments
TEST_CASE(resolve_syringeex_command_no_exe)
{
	auto const oldOver = OverwriteStartParams;
	auto const oldExe = DefaultExecName;
	OverwriteStartParams = false;
	DefaultExecName.clear();

	auto const parts = ClassifySyringeexLine("--snapshot");
	bool threw = false;
	try { auto const r = ResolveSyringeexCommand(parts, ""); (void)r; }
	catch (invalid_command_arguments const&) { threw = true; }
	CHECK(threw);

	OverwriteStartParams = oldOver;
	DefaultExecName = oldExe;
}

// 命令行无 exe 但 DefaultExecutableName 非空 → JSON 兜底（与 IH 风格一致）
TEST_CASE(resolve_syringeex_command_json_fallback)
{
	auto const oldOver = OverwriteStartParams;
	auto const oldExe = DefaultExecName;
	auto const oldCmd = DefaultCmdLine;
	OverwriteStartParams = false;
	DefaultExecName = "gamemd.exe";
	DefaultCmdLine = "-WIN";

	auto const parts = ClassifySyringeexLine("--snapshot");
	auto const resolved = ResolveSyringeexCommand(parts, "-CD");
	CHECK(resolved.executable == "gamemd.exe");
	CHECK(resolved.arguments == "-CD -WIN");

	OverwriteStartParams = oldOver;
	DefaultExecName = oldExe;
	DefaultCmdLine = oldCmd;
}

// 开关仅 Syringe.json 可配：命令行 -UseSyringeExCommandLine=... 被拒绝且不生效（双向）
TEST_CASE(setting_syringeex_mode_cli_rejected)
{
	auto const old = UseSyringeExCommandLine;
	UseSyringeExCommandLine = false;
	UpdateSetting({ "-UseSyringeExCommandLine=true" });
	CHECK(!UseSyringeExCommandLine);
	UseSyringeExCommandLine = true;
	UpdateSetting({ "-UseSyringeExCommandLine=false" });
	CHECK(UseSyringeExCommandLine);
	UseSyringeExCommandLine = old;
}

// 开关 JSON 读取：Syringe.json 的 UseSyringeExCommandLine
TEST_CASE(setting_syringeex_mode_json)
{
	char cwd[MAX_PATH];
	_getcwd(cwd, MAX_PATH);

	char tmpDir[MAX_PATH];
	GetTempPathA(MAX_PATH, tmpDir);
	strcat_s(tmpDir, "syringe_synex_mode_test");
	CreateDirectoryA(tmpDir, nullptr);
	SetCurrentDirectoryA(tmpDir);

	FILE* f = fopen("Syringe.json", "wb");
	if (f)
	{
		fputs("{\"UseSyringeExCommandLine\":true}", f);
		fclose(f);
	}

	auto const old = UseSyringeExCommandLine;
	UseSyringeExCommandLine = false;
	ReadSetting();
	CHECK(UseSyringeExCommandLine);

	SetCurrentDirectoryA(cwd);
	UseSyringeExCommandLine = old;

	char jsonPath[MAX_PATH];
	strcpy_s(jsonPath, tmpDir);
	strcat_s(jsonPath, "\\Syringe.json");
	DeleteFileA(jsonPath);
	RemoveDirectoryA(tmpDir);
}

// -i= 注入白名单通配模式匹配（SyringeEx 对齐；PathMatchSpecA 语义实测：* 跨 \、大小写不敏感、
// 空模式命中一切故显式跳过）
TEST_CASE(match_include_dlls_patterns)
{
	// basename 通配
	CHECK(MatchIncludeDLLs("Phobos.dll", "C:\\game\\Phobos.dll", "Phobos.dll", { "*.dll" }));
	CHECK(MatchIncludeDLLs("Phobos.dll", "C:\\game\\Phobos.dll", "Phobos.dll", { "Phobos*.dll" }));
	CHECK(MatchIncludeDLLs("Phobos.dll", "C:\\game\\Phobos.dll", "Phobos.dll", { "Phobos.dll" }));
	CHECK(MatchIncludeDLLs("A1.dll", "C:\\game\\A1.dll", "A1.dll", { "??.dll" }));
	CHECK(!MatchIncludeDLLs("ABC.dll", "C:\\game\\ABC.dll", "ABC.dll", { "??.dll" }));
	CHECK(!MatchIncludeDLLs("ARES.dll", "C:\\game\\ARES.dll", "ARES.dll", { "Phobos*.dll" }));
	CHECK(!MatchIncludeDLLs("X.dat", "C:\\game\\X.dat", "X.dat", { "*.dll" }));
	// 大小写不敏感
	CHECK(MatchIncludeDLLs("PHOBOS.DLL", "C:\\GAME\\PHOBOS.DLL", "phobos.dll", { "phobos*.dll" }));
	// 多模式并集
	CHECK(MatchIncludeDLLs("X.dll", "C:\\game\\X.dll", "X.dll", { "A.dll", "*.dll" }));
	CHECK(!MatchIncludeDLLs("X.dat", "C:\\game\\X.dat", "X.dat", { "A.dll", "*.dll" }));
	// 空列表 = 不过滤
	CHECK(MatchIncludeDLLs("X.dll", "C:\\game\\X.dll", "X.dll", {}));
	// 空模式串 = 永不命中（PathMatchSpecA 空模式命中一切，已显式跳过）
	CHECK(!MatchIncludeDLLs("X.dll", "C:\\game\\X.dll", "X.dll", { "" }));
	// 绝对路径精确模式（无通配即精确匹配）
	CHECK(MatchIncludeDLLs("X.dll", "C:\\game\\X.dll", "X.dll", { "C:\\game\\X.dll" }));
	// 目录成分模式 → exe 相对路径（basename 对 "Patches\\X.dll" 不命中）
	CHECK(MatchIncludeDLLs("X.dll", "C:\\game\\Patches\\X.dll", "Patches\\X.dll", { "Patches\\X.dll" }));
	CHECK(MatchIncludeDLLs("X.dll", "C:\\game\\Patches\\X.dll", "Patches\\X.dll", { "Patches\\*.dll" }));
	CHECK(!MatchIncludeDLLs("X.dll", "C:\\game\\Patches\\X.dll", "Patches\\X.dll", { "Patches\\Y.dll" }));
	// * 跨 \（整串级，实测）
	CHECK(MatchIncludeDLLs("X.dll", "C:\\game\\Patches\\X.dll", "Patches\\X.dll", { "*\\X.dll" }));
	// 带空格引号值（切词后单 token，空格为字面量）
	CHECK(MatchIncludeDLLs("my mod.dll", "C:\\game\\my mod.dll", "my mod.dll", { "my mod.dll" }));
	CHECK(!MatchIncludeDLLs("my mod.dll", "C:\\game\\my mod.dll", "my mod.dll", { "*.txt" }));
	// 根目录扫描（relPath 无目录成分）时，目录模式不误命中
	CHECK(!MatchIncludeDLLs("X.dll", "C:\\game\\X.dll", "X.dll", { "Patches\\X.dll" }));
}

// HookAnalysis.Format = "NDJSON"：报告按行输出合法 JSON（start/end 事件行 + 每条钩子一行）
TEST_CASE(hook_analysis_ndjson_format)
{
	char cwd[MAX_PATH];
	_getcwd(cwd, MAX_PATH);

	char tmpDir[MAX_PATH];
	GetTempPathA(MAX_PATH, tmpDir);
	strcat_s(tmpDir, "syringe_hookndjson_test");
	CreateDirectoryA(tmpDir, nullptr);
	SetCurrentDirectoryA(tmpDir);

	auto const oldFmt = HookAnalysisFormat;
	auto const oldByLib = ShowHookAnalysis_ByLib;
	auto const oldByAddr = ShowHookAnalysis_ByAddr;

	HookAnalyzer A;
	A.Add(HookAnalyzeData{ "C:\\game\\mod.dll", "TestHook", 0x401000, 5, 100000, "", "" });
	A.Add(HookAnalyzeData{ "C:\\game\\mod.dll", "OtherHook", 0x402000, 8, 50, "sub", "RelLib.dll" });

	HookAnalysisFormat = "NDJSON";
	ShowHookAnalysis_ByLib = true;
	ShowHookAnalysis_ByAddr = true;
	CHECK(A.Report());

	FILE* f = fopen("HookAnalysis.log", "rb");
	CHECK(f != nullptr);
	if (f)
	{
		int lineCount = 0;
		int dataCount = 0;
		int eventCount = 0;
		char line[4096];
		while (fgets(line, sizeof(line), f))
		{
			++lineCount;
			auto* const j = cJSON_Parse(line);
			CHECK(j != nullptr);
			if (j)
			{
				auto* const ev = cJSON_GetObjectItem(j, "event");
				if (ev && ev->type == cJSON_String)
				{
					++eventCount;
					CHECK(strcmp(ev->valuestring, "start") == 0 || strcmp(ev->valuestring, "end") == 0);
				}
				else
				{
					++dataCount;
					auto* const sec = cJSON_GetObjectItem(j, "section");
					CHECK(sec && sec->type == cJSON_String);
					auto* const addr = cJSON_GetObjectItem(j, "addr");
					CHECK(addr && addr->type == cJSON_Number);
					auto* const proc = cJSON_GetObjectItem(j, "proc");
					CHECK(proc && proc->type == cJSON_String);
					auto* const rel_lib = cJSON_GetObjectItem(j, "rel_lib");
					CHECK(rel_lib && rel_lib->type == cJSON_String);
					auto* const lib = cJSON_GetObjectItem(j, "lib");
					CHECK(lib && lib->type == cJSON_String);
					auto* const len = cJSON_GetObjectItem(j, "len");
					CHECK(len && len->type == cJSON_Number);
					auto* const prio = cJSON_GetObjectItem(j, "priority");
					CHECK(prio && prio->type == cJSON_Number);
					auto* const sub = cJSON_GetObjectItem(j, "sub_priority");
					CHECK(sub && sub->type == cJSON_String);
				}
				cJSON_Delete(j);
			}
		}
		fclose(f);
		CHECK(lineCount == 6); // start + 4 条钩子（ByAddress 2 + ByLibrary 2）+ end
		CHECK(eventCount == 2);
		CHECK(dataCount == 4);
	}

	HookAnalysisFormat = oldFmt;
	ShowHookAnalysis_ByLib = oldByLib;
	ShowHookAnalysis_ByAddr = oldByAddr;

	SetCurrentDirectoryA(cwd);
	char logPath[MAX_PATH];
	strcpy_s(logPath, tmpDir);
	strcat_s(logPath, "\\HookAnalysis.log");
	DeleteFileA(logPath);
	RemoveDirectoryA(tmpDir);
}
