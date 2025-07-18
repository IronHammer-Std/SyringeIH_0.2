#pragma once
#include "Setting.h"

#define WIN32_LEAN_AND_MEAN
//      WIN32_FAT_AND_STUPID

#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

#include <Windows.h>

struct invalid_command_arguments : std::exception {};

inline auto trim(std::string_view string) noexcept {
	auto const first = string.find_first_not_of(' ');
	if(first != std::string_view::npos) {
		auto const last = string.find_last_not_of(' ');
		string = string.substr(first, last - first + 1);
	}
	return string;
}

inline std::vector<std::string_view> SplitView(const std::string_view Text)//ORIG
{
	if (Text.empty())return {};
	size_t cur = 0, crl;
	std::vector<std::string_view> ret;
	while ((crl = Text.find_first_of(' ', cur)) != Text.npos)
	{
		ret.push_back(trim(Text.substr(cur, crl - cur)));
		cur = crl + 1;
	}
	ret.push_back(trim(Text.substr(cur)));
	return ret;
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

		auto const end_flags = arguments.find('"');
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
