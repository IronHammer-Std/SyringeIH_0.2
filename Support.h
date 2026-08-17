#pragma once
#include "Setting.h"

#define WIN32_LEAN_AND_MEAN
//      WIN32_FAT_AND_STUPID

#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

#include <Windows.h>
#include <shlwapi.h>

struct invalid_command_arguments : std::exception {};

inline auto trim(std::string_view string) noexcept {
	auto const first = string.find_first_not_of(' ');
	if(first != std::string_view::npos) {
		auto const last = string.find_last_not_of(' ');
		string = string.substr(first, last - first + 1);
	}
	else string = {}; // 全空白串收缩为空串
	return string;
}

// 提取 --args= 参数：把每个 "--args=..." 片段从原始命令行中移除，返回清理后的
// 命令行（thread_local 存储中的视图）；outContent 置为最后一个 --args= 的内容。
// - 引号形式 "--args=\"...\""：取引号内文本，连同开闭引号整段移除；
// - 裸形式 "--args=xxx"：取到下一个空白为止（片段本身移除，空白保留）；
// - "--args" 不带 '=' 不识别；
// - 仅在 token 开头匹配（行首或前一个字符为空白），引号内形似文本不受影响；
// - 未闭合引号内容吞到行尾。
inline std::string_view ExtractArgsFlag(std::string_view const arguments, std::string& outContent)
{
	static thread_local std::string Storage;

	outContent.clear();
	if (arguments.empty()) return arguments;

	Storage.clear();
	Storage.reserve(arguments.size());

	std::string_view constexpr FLAG = "--args=";
	size_t const len = arguments.size();
	size_t cur = 0;

	while (cur < len)
	{
		bool hit = false;
		if (arguments.compare(cur, FLAG.size(), FLAG) == 0)
		{
			bool const atTokenStart = cur == 0
				|| arguments[cur - 1] == ' ' || arguments[cur - 1] == '\t';
			if (atTokenStart)
			{
				size_t spanEnd = cur + FLAG.size();
				outContent.clear();
				if (spanEnd < len && arguments[spanEnd] == '"')
				{
					++spanEnd; // 跳过开引号
					auto const contentStart = spanEnd;
					while (spanEnd < len && arguments[spanEnd] != '"')
						++spanEnd;
					outContent.assign(arguments.substr(contentStart, spanEnd - contentStart));
					if (spanEnd < len) ++spanEnd; // 连同闭引号移除
				}
				else
				{
					auto const contentStart = spanEnd;
					while (spanEnd < len && arguments[spanEnd] != ' ' && arguments[spanEnd] != '\t')
						++spanEnd;
					outContent.assign(arguments.substr(contentStart, spanEnd - contentStart));
				}
				cur = spanEnd;
				hit = true;
			}
		}
		if (!hit)
		{
			Storage.push_back(arguments[cur]);
			++cur;
		}
	}
	return Storage;
}

// 找 exe 起始引号：第一个位于 token 开头的 '"'（行首，或前一个字符为空白）。
// 紧贴在 flag 值上的引号（如 -SnapshotFileName="my log.txt"）不算 exe 边界。
inline std::string_view::size_type FindExecutableQuote(std::string_view const arguments) noexcept
{
	for (std::string_view::size_type i = 0; i < arguments.size(); ++i)
	{
		if (arguments[i] == '"')
		{
			bool const atTokenStart = i == 0
				|| arguments[i - 1] == ' ' || arguments[i - 1] == '\t';
			if (atTokenStart)
				return i;
		}
	}
	return std::string_view::npos;
}

// 引号感知的 flags 切词：
// - 空格/制表符在引号外是分隔符；连续空白不产生空 token；
// - '"' 切换引号状态且自身被剔除（引号内容合并进同一 token）；
// - 引号内空格属于 token 内容（-SnapshotFileName="my log.txt" → 单 token）；
// - 未闭合引号一直吞到段尾。
// 返回的 string_view 指向 thread_local 存储，下一次调用本函数前保持有效。
inline std::vector<std::string_view> SplitView(std::string_view const Text)
{
	static thread_local std::string Storage;

	std::vector<std::string_view> ret;
	if (Text.empty()) return ret;

	Storage.clear();
	Storage.reserve(Text.size()); // 输出总长 ≤ 输入长，预分配后视图不会因扩容悬空

	size_t const len = Text.size();
	size_t cur = 0;
	bool inQuote = false;

	while (cur < len)
	{
		while (cur < len && !inQuote && (Text[cur] == ' ' || Text[cur] == '\t'))
			++cur;
		if (cur >= len) break;

		auto const tokStart = Storage.size();
		while (cur < len)
		{
			char const c = Text[cur];
			if (c == '"')
			{
				inQuote = !inQuote;
				++cur;
				continue;
			}
			if (!inQuote && (c == ' ' || c == '\t'))
				break;
			Storage.push_back(c);
			++cur;
		}
		if (Storage.size() > tokStart)
		{
			ret.push_back(std::string_view(Storage).substr(tokStart, Storage.size() - tokStart));
		}
	}
	return ret;
}


// -i= 注入白名单的模式匹配（SyringeEx 对齐，2026-07）：
// 每个 -i=<值> 视为通配模式（* / ?，大小写不敏感，PathMatchSpecA），依次对 DLL 的
// 文件名 / 绝对路径 / exe 相对路径 匹配，任一命中即放行；无通配符时即精确匹配
// （兼容原有字面语义）。空模式串永不命中（对齐 SyringeEx 的 FindFile("") 无结果；
// PathMatchSpecA 的空模式反而命中一切，故显式跳过）。patterns 为空 → 不过滤
// （目录扫描模型下等价 SyringeEx 缺省 "*.dll" 的语义）。
inline bool MatchIncludeDLLs(
	std::string const& filename,
	std::string const& absPath,
	std::string const& relPath,
	std::vector<std::string> const& patterns) noexcept
{
	if (patterns.empty()) return true;
	for (auto const& pat : patterns)
	{
		if (pat.empty()) continue;
		if (PathMatchSpecA(filename.c_str(), pat.c_str())
			|| PathMatchSpecA(absPath.c_str(), pat.c_str())
			|| (!relPath.empty() && PathMatchSpecA(relPath.c_str(), pat.c_str())))
		{
			return true;
		}
	}
	return false;
}

inline auto get_command_line(std::string_view arguments) {
	struct argument_set {
		std::string_view flags;
		std::vector<std::string_view> flaglist;
		std::string_view executable;
		std::string_view arguments;
	};

	try {
		argument_set ret;

		auto const end_flags = FindExecutableQuote(arguments);
		ret.flags = trim(arguments.substr(0, end_flags));
		if (!ret.flags.empty())
		{
			ret.flaglist = SplitView(ret.flags);
		}

		if (OverwriteStartParams && !DefaultExecName.empty() && !DefaultCmdLine.empty()) {
			ret.executable = DefaultExecName;
			ret.arguments = DefaultCmdLine;
			return ret;
		}

		if(end_flags != std::string_view::npos) {
			arguments.remove_prefix(end_flags + 1);

			auto const end_executable = arguments.find('"');
			if(end_executable != std::string_view::npos) {
				ret.executable = trim(arguments.substr(0, end_executable));
				arguments.remove_prefix(end_executable + 1);

				ret.arguments = trim(arguments);

				return ret;
			}
		}
		else if (!DefaultExecName.empty())
		{
			ret.executable = DefaultExecName;
			if (!DefaultCmdLine.empty())
			{
				ret.arguments = DefaultCmdLine;
				ret.arguments = trim(ret.arguments);
			}
			else ret.arguments = trim(arguments);
			return ret;
		}
	} catch(...) {
		// swallow everything, throw new one
	}

	throw invalid_command_arguments{};
}

// ============ SyringeEx 风格命令行（UseSyringeExCommandLine=true 时使用） ============

// 全行分类（不抛异常，供 UpdateSetting/快照早退在 exe 解析之前使用）：
// - 首个不以 '-' 开头的 token = executable（路径含空格时整体加引号，切词时引号被剔除）；
// - 其余 token 全部归入 flags（含 exe 之后的裸 token —— SyringeEx 语义：它们不是游戏参数）。
// 返回的 string_view 指向 SplitView 的 thread_local 存储，下次调用前有效。
struct SyringeexLineParts
{
	std::vector<std::string_view> flags;
	std::string_view executable; // 空 = 命令行未提供 exe
};

inline SyringeexLineParts ClassifySyringeexLine(std::string_view const cleaned)
{
	SyringeexLineParts ret;
	for (auto const& t : SplitView(trim(cleaned)))
	{
		if (ret.executable.empty() && !t.starts_with("-"))
			ret.executable = t;
		else
			ret.flags.push_back(t);
	}
	return ret;
}

// SyringeEx 风格 exe/args 解析（保留 IH 的 JSON 语义层）：
// 1) OverwriteStartParams=true 且 DefaultExecutableName/DefaultCommandLine 均非空
//    → 用 JSON 默认（命令行 exe 被忽略，flags 与 --args= 仍生效）；
// 2) 命令行有 exe → 用之；游戏参数仅来自 --args= 内容（argsFromFlag）；
// 3) 命令行无 exe 但 DefaultExecutableName 非空 → JSON 默认兜底；
// 4) 否则抛 invalid_command_arguments。
inline auto ResolveSyringeexCommand(
	SyringeexLineParts const& parts, std::string const& argsFromFlag)
{
	struct result
	{
		std::string_view executable;
		std::string arguments;
	};

	if (OverwriteStartParams && !DefaultExecName.empty() && !DefaultCmdLine.empty())
	{
		std::string args = argsFromFlag;
		if (!args.empty() && !DefaultCmdLine.empty()) args += ' ';
		args += DefaultCmdLine;
		return result{ DefaultExecName, std::move(args) };
	}

	if (!parts.executable.empty())
		return result{ parts.executable, argsFromFlag };

	if (!DefaultExecName.empty())
	{
		std::string args = argsFromFlag;
		if (!args.empty() && !DefaultCmdLine.empty()) args += ' ';
		args += DefaultCmdLine;
		return result{ DefaultExecName, std::move(args) };
	}

	throw invalid_command_arguments{};
}

inline std::string replace(
	std::string_view string, std::string_view const pattern,
	std::string_view const substitute)
{
	std::string ret;

	auto pos = 0u;
	while((pos = string.find(pattern)) != std::string::npos) {
		ret += string.substr(0, pos);
		string.remove_prefix(pos);

		if(string.size() > 1) {
			ret += substitute;
			string.remove_prefix(pattern.size());
		}
	}

	ret += string;
	return ret;
}

// returns something %.*s can format
inline auto printable(std::string_view const string) noexcept {
	return std::make_pair(string.size(), string.data());
}

inline auto GetFormatMessage(DWORD const error) {
	LocalAllocHandle handle;

	auto count = FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, error,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		reinterpret_cast<LPTSTR>(handle.set()), 0u, nullptr);

	auto const message = static_cast<LPCTSTR>(handle.get());
	while(count && isspace(static_cast<unsigned char>(message[count - 1]))) {
		--count;
	}

	return std::string(message, count);
}

struct lasterror : std::exception {
	lasterror(DWORD const error, bool Suppress = false)
		: error(error), SuppressPopup(Suppress)
	{ }

	lasterror(DWORD const error, std::string insert, bool Suppress = false)
		: error(error), insert(std::move(insert)), SuppressPopup(Suppress)
	{ }

	DWORD error{ 0 };
	std::string message{ GetFormatMessage(error) };
	std::string insert;
	bool SuppressPopup{ false };
};

[[noreturn]] inline void throw_lasterror(DWORD error_code, std::string insert, bool Suppress = false) {
	throw lasterror(error_code, std::move(insert), Suppress);
}

[[noreturn]] inline void throw_lasterror_or(
	DWORD alterative, std::string insert)
{
	auto const error_code = GetLastError();
	throw_lasterror(
		error_code ? error_code : alterative, std::move(insert));
}
