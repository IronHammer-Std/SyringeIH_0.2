#include "Log.h"
#include "SyringeDebugger.h"
#include "Support.h"
#include "Setting.h"
#include <string>

#include <commctrl.h>

int Run(std::string_view const arguments) {

	InitCommonControls();

	Log::Open("syringe.log");

	Log::WriteLine(VersionString);
	Log::WriteLine("===============");
	ReadSetting();
	Log::WriteLine();
	Log::WriteLine("WinMain: 命令行参数： \"%.*s\"", printable(arguments));

	auto failure = "可执行文件加载失败：";
	auto exit_code = ERROR_ERRORS_ENCOUNTERED;

	try
	{
		auto const command = get_command_line(arguments);
		//Log::WriteLine("WinMain: 调用选项为： \"%.*s\"", printable(command.flags));
		UpdateSetting(command.flaglist);
		Log::WriteLine("WinMain: 可执行文件为： \"%.*s\"", printable(command.executable));
		Log::WriteLine("WinMain: 程序启动参数为： \"%.*s\"", printable(command.arguments));

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
			printable(command.executable));
		Log::WriteLine();

		SyringeDebugger Debugger{ command.executable };
		failure = "无法运行可执行文件。";

		Log::WriteLine("WinMain: SyringeDebugger::FindDLLs();");
		Log::WriteLine();
		SetEnvironmentVariable("HERE_IS_SYRINGE", "1");
		Debugger.FindDLLs();
		SetEnvironmentVariable("HERE_IS_SYRINGE", NULL);

		Log::WriteLine(
			"WinMain: SyringeDebugger::Run(\"%.*s\");",
			printable(command.arguments));
		Log::WriteLine();

		Debugger.Run(command.arguments);
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
			nullptr, "Syringe 不能直接运行.\n\n"
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
