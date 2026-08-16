#pragma once

#include "Handle.h"

class Log
{
private:
	static FileHandle File;

	static void WriteTimestamp() noexcept;

public:
	static void Open(char const* pFilename) noexcept;

	static void Close() noexcept;

	static void Flush() noexcept;

	// Raw line write without timestamp (report markers / JSON lines only)
	static void WriteRaw(char const* pText) noexcept;

	static void WriteLine() noexcept;
	static void WriteLine(char const* pFormat, ...) noexcept;
};
