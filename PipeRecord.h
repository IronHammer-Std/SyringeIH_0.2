#pragma once
#include <windows.h>
#include <vector>

struct DaemonPipeRecordHeader
{
	static constexpr DWORD HeaderMagic = 0x67676767;
	DWORD Magic;
	DWORD DataSize;
	DWORD Reserved[6];

	DaemonPipeRecordHeader(DWORD DataSize) :Magic(HeaderMagic), DataSize(DataSize)
	{
		memset(Reserved, 0, sizeof(Reserved));
	}
};

bool WritePipeRecordToFile(bool NewPipeFormat, HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten);
bool ReadPipeRecordFromFile(bool NewPipeFormat, HANDLE hFile, std::vector<BYTE>& Buffer, LPDWORD lpNumberOfBytesRead);