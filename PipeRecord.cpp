#include "PipeRecord.h"
#include "Log.h"

bool WritePipeRecordToFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten)
{
	DaemonPipeRecordHeader Header(nNumberOfBytesToWrite);
	DWORD dwWritten = 0;
	if (!WriteFile(hFile, &Header, sizeof(Header), &dwWritten, NULL))
	{
		if (lpNumberOfBytesWritten)*lpNumberOfBytesWritten = 0;
		return false;
	}

	if (!WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, &dwWritten, NULL))
	{
		if (lpNumberOfBytesWritten)*lpNumberOfBytesWritten = dwWritten;
		return false;
	}

	if (lpNumberOfBytesWritten)*lpNumberOfBytesWritten = dwWritten;
	return true;
}

bool ReadPipeRecordFromFile(HANDLE hFile, std::vector<BYTE>& Buffer, LPDWORD lpNumberOfBytesRead)
{
	DaemonPipeRecordHeader Header(0);
	memset(&Header, 0, sizeof(Header));
	DWORD dwRead = 0;
	if (!ReadFile(hFile, &Header, sizeof(Header), &dwRead, NULL))
	{
		if (lpNumberOfBytesRead)*lpNumberOfBytesRead = 0;
		return false;
	}
	if (dwRead != sizeof(Header) || Header.Magic != DaemonPipeRecordHeader::HeaderMagic)
	{
		if (lpNumberOfBytesRead)*lpNumberOfBytesRead = 0;
		return false;
	}

	Buffer.reserve(Header.DataSize + 1);
	Buffer.resize(Header.DataSize);
	if (!ReadFile(hFile, Buffer.data(), Header.DataSize, &dwRead, NULL))
	{
		if (lpNumberOfBytesRead)*lpNumberOfBytesRead = 0;
		return false;
	}

	if (lpNumberOfBytesRead)*lpNumberOfBytesRead = dwRead;
	return true;
}

bool WritePipeRecordToFile(bool NewPipeFormat, HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten)
{
	if (NewPipeFormat)
	{
		Log::WriteLine(__FUNCTION__ ": 使用新管道格式写入数据，大小 %u 字节。", nNumberOfBytesToWrite);
		return WritePipeRecordToFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten);
	}
	else
	{
		Log::WriteLine(__FUNCTION__ ": 使用旧管道格式写入数据，大小 %u 字节。", nNumberOfBytesToWrite);
		return WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, NULL);
	}
}

bool ReadPipeRecordFromFile(bool NewPipeFormat, HANDLE hFile, std::vector<BYTE>& Buffer, LPDWORD lpNumberOfBytesRead)
{
	const size_t PipeBufferSize = 32768;// 32KB
	if (NewPipeFormat)
	{
		Log::WriteLine(__FUNCTION__ ": 使用新管道格式读取数据。");
		return ReadPipeRecordFromFile(hFile, Buffer, lpNumberOfBytesRead);
	}
	else
	{
		Log::WriteLine(__FUNCTION__ ": 使用旧管道格式读取数据。");
		Buffer.resize(PipeBufferSize);
		DWORD dwRead = 0;
		if (!ReadFile(hFile, Buffer.data(), (DWORD)Buffer.size(), &dwRead, NULL))
		{
			if (lpNumberOfBytesRead)*lpNumberOfBytesRead = 0;
			return false;
		}
		if (lpNumberOfBytesRead)*lpNumberOfBytesRead = dwRead;
		return true;
	}
}