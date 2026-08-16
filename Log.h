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

	// Temporarily redirect all log output to another file. The current handle
	// is stashed (kept open, never truncated); RedirectBack closes the temp
	// file and restores it.
	static void Redirect(char const* pFilename) noexcept;
	static void RedirectBack() noexcept;

	static void WriteLine() noexcept;
	static void WriteLine(char const* pFormat, ...) noexcept;
};
