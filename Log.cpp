#include "Log.h"

#include <share.h>
#include <stdarg.h>
#include <stdio.h>
#include <time.h>
#include <chrono>

FileHandle Log::File;

namespace
{
	FileHandle SavedLogFile;
}

bool AlwaysFlush = true;

void PrintTimeStampToFile(const FileHandle& File)
{
	time_t raw;
	time(&raw);

	tm t;
	localtime_s(&t, &raw);
	auto now = std::chrono::system_clock::now();
	auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
	int imilli = (int)millis.count();
	fprintf(File, "[%02d:%02d:%02d:%03d] ", t.tm_hour, t.tm_min, t.tm_sec, imilli);
}

void Log::Open(char const* const pFilename) noexcept
{
	if(pFilename && *pFilename) {
		File = FileHandle(_fsopen(pFilename, "w", _SH_DENYWR));
	}
}

void Log::Flush() noexcept
{
	if(File) {
		fflush(File);
	}
}

void Log::Close() noexcept
{
	File.clear();
}

void Log::Redirect(char const* const pFilename) noexcept
{
	if(!File || !pFilename || !*pFilename) return;
	SavedLogFile = std::move(File); // 暂存原句柄（保持打开，不截断）
	File = FileHandle(_fsopen(pFilename, "w", _SH_DENYWR));
}

void Log::RedirectBack() noexcept
{
	if(!SavedLogFile) return;
	File.clear();                 // 关闭重定向文件
	File = std::move(SavedLogFile); // 恢复原句柄
}

void Log::WriteRaw(char const* const pText) noexcept
{
	if(File) {
		fputs(pText, File);
		fputc('\n', File);
		fflush(File);
	}
}

void Log::WriteTimestamp() noexcept
{
	if(File) {
		PrintTimeStampToFile(File);
	}
}

void Log::WriteLine() noexcept
{
	if(File) {
		WriteTimestamp();
		fputs("\n", File);
	}
}

void Log::WriteLine(char const* const pFormat, ...) noexcept
{
	if(File) {
		va_list args;
		va_start(args, pFormat);

		WriteTimestamp();
		vfprintf(File, pFormat, args);
		fputs("\n", File);

		va_end(args);
		if (AlwaysFlush)
		{
			fflush(File);
		}
	}
}
