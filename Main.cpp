#include "Log.h"
#include "SyringeDebugger.h"
#include "Support.h"
#include "Setting.h"
#include "Snapshot.h"
#include "cJSON.h"
#include <string>

#include <commctrl.h>

int Run(std::string_view const arguments) {

	InitCommonControls();

	// 预扫描选择日志文件：快照广播模式绝不接触 syringe.log
	// （_SH_DENYWR 下与同目录运行中的 syringe 互不破坏，且广播报告始终落盘）
	Log::Open(SelectLogFile(arguments));

	Log::WriteLine(VersionString);
	Log::WriteLine("===============");
	ReadSetting();
	Log::WriteLine();
	Log::WriteLine("WinMain: 命令行参数： \"%.*s\"", printable(arguments));

	auto failure = "可执行文件加载失败：";
	auto exit_code = ERROR_ERRORS_ENCOUNTERED;

	try
	{
		// --args= 提取（两种解析风格共用）：取最后一个、展开其内容拼到游戏参数最前面；
		// 片段无论出现在 exe 前还是后，都从命令行中移除。
		std::string ArgsFromFlag;
		auto const cleaned = ExtractArgsFlag(arguments, ArgsFromFlag);
		if (!ArgsFromFlag.empty())
		{
			Log::WriteLine("WinMain: 已提取 --args= 参数： \"%.*s\"", printable(ArgsFromFlag));
		}

		SyringeexLineParts syringeexParts;
		if (UseSyringeExCommandLine)
		{
			// SyringeEx 风格：全行 token 分类（首个非 '-' token 为 exe，其余全部是 flag）
			syringeexParts = ClassifySyringeexLine(cleaned);
			UpdateSetting(syringeexParts.flags);
		}
		else
		{
			// IH 风格：flags 只取 exe 起始引号之前（引号感知切词；
			// flag 值上紧贴的引号不算边界，由 FindExecutableQuote 判定）。
			auto const end_flags = FindExecutableQuote(cleaned);
			UpdateSetting(SplitView(trim(cleaned.substr(0, end_flags))));
		}

		// 权威兜底：预扫描可能误判（JSON 注释等），按最终配置切换日志文件
		auto const predictedSnapshot =
			CommandLineRequestsSnapshot(arguments) || JsonFileRequestsSnapshot();
		if(StackSnapshot != predictedSnapshot) {
			Log::Close();
			Log::Open(StackSnapshot ? "syringe_snapshot.log" : "syringe.log");
			Log::WriteLine("WinMain: 已按最终配置切换日志文件。");
		}

		// 快照广播模式：不启动游戏、不走注入流程，广播一圈打断后退出。
		// 顺序在 exe 解析之前：两种风格下 --snapshot 都可以不带 exe。
		if(StackSnapshot) {
			Log::WriteLine("WinMain: 快照广播模式（StackSnapshot=true），开始广播……");
			// 载荷：把本机设置原样复述进载荷（首个参数 SnapshotFileName；
			// 完整的载荷生成方式后续接入）
			std::string payload;
			if(!SnapshotFileName.empty()) {
				cJSON* const root = cJSON_CreateObject();
				cJSON_AddStringToObject(root, "SnapshotFileName", SnapshotFileName.c_str());
				char* const text = cJSON_PrintUnformatted(root);
				if(text) {
					payload = text;
					cJSON_Free(text);
				}
				cJSON_Delete(root);
			}
			auto const code = SnapshotBroadcast(payload);
			Log::WriteLine("WinMain: 广播结束，返回码 %u。", code);
			Log::Flush();
			return static_cast<int>(code);
		}

		// exe / 游戏参数解析（快照早退之后，此处分支可能因缺 exe 抛用法错误）
		std::string_view exe;
		std::string finalArguments;
		if (UseSyringeExCommandLine)
		{
			// SyringeEx 风格：exe 优先取命令行首个非 '-' token；OverwriteStartParams=true
			// 或命令行无 exe 时保留 Syringe.json 的 DefaultExecutableName/DefaultCommandLine
			// 语义（与 IH 风格一致）；游戏参数仅来自 --args= 内容。
			auto const resolved = ResolveSyringeexCommand(syringeexParts, ArgsFromFlag);
			exe = resolved.executable;
			finalArguments = std::move(resolved.arguments);
		}
		else
		{
			auto const command = get_command_line(cleaned);
			exe = command.executable;

			// 合并游戏参数：--args= 内容在前 + 引号后的尾巴在后（空格分隔）
			finalArguments = ArgsFromFlag;
			if (!finalArguments.empty() && !command.arguments.empty())
				finalArguments += ' ';
			if (!command.arguments.empty())
				finalArguments.append(command.arguments.data(), command.arguments.size());
		}

		Log::WriteLine("WinMain: 可执行文件为： \"%.*s\"", printable(exe));
		Log::WriteLine("WinMain: 程序启动参数为： \"%.*s\"", printable(finalArguments));

		/*
		* 限制尼玛呢 IHS 25/1/15
		* 
		if(!command.flags.empty()) {
			// artificial limitation
			throw invalid_command_arguments{};
		}
		*/

		Log::WriteLine(
			"WinMain: 开始载入可执行文件： \"%.*s\"……",
			printable(exe));
		Log::WriteLine();

		SyringeDebugger Debugger{ exe };
		failure = "无法运行可执行文件。";

		Log::WriteLine("WinMain: SyringeDebugger::FindDLLs();");
		Log::WriteLine();
		SetEnvironmentVariable("HERE_IS_SYRINGE", "1");
		Debugger.FindDLLs();
		SetEnvironmentVariable("HERE_IS_SYRINGE", NULL);

		Log::WriteLine(
			"WinMain: SyringeDebugger::Run(\"%.*s\");",
			printable(finalArguments));
		Log::WriteLine();

		Debugger.Run(finalArguments);
		Log::WriteLine("WinMain: SyringeDebugger::Run 完成运行。");
		Log::WriteLine("WinMain: 程序正常结束。");
		return ERROR_SUCCESS;
	}
	catch(lasterror const& e)
	{
		auto const message = replace(e.message, "%1", e.insert);
		Log::WriteLine("WinMain: %s (%d)", message.c_str(), e.error);

		auto const msg = std::string(failure) + "\n\n" + message;
		if(!e.SuppressPopup)MessageBoxA(nullptr, msg.c_str(), VersionString, MB_OK | MB_ICONERROR);

		exit_code = static_cast<long>(e.error);
	}
	catch(invalid_command_arguments const&)
	{
		MessageBoxA(
			nullptr, UseSyringeExCommandLine
				? "Syringe 不能直接运行.\n\n"
				  "使用方法（UseSyringeExCommandLine=true，SyringeEx 风格）:\n"
				  "Syringe.exe <exe name> [-i=<injectedfile.dll> ...] [--args=\"<arguments>\"]"
				: "Syringe 不能直接运行.\n\n"
				  "使用方法:\n在Syringe.json中设置DefaultExecutableName为可用值\n或通过命令行或BAT文件：\nSyringe.exe \"<exe name>\" <arguments>",
			VersionString, MB_OK | MB_ICONINFORMATION);

		Log::WriteLine(
			"WinMain: 启动参数缺少或错误！正在退出……");

		exit_code = ERROR_INVALID_PARAMETER;
	}

	Log::WriteLine("WinMain: 程序异常结束。");
	return static_cast<int>(exit_code);
}

int WINAPI WinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPSTR lpCmdLine, _In_ int nCmdShow)
{
	UNREFERENCED_PARAMETER(hInstance);
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(nCmdShow);

	return Run(lpCmdLine);
}
