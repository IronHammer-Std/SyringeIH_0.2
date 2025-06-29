#pragma once

#include "Setting.h"
#include "Handle.h"
#include <vector>
#include <memory>
#include <unordered_map>
#include <string_view>

class SyringeDebugger;
class PortableExecutable;
class LibExtData;
struct MemCopyInfo;

DWORD QuickHashCStr(const char* str);
DWORD QuickHashCStrUpper(const char* str);

struct UpperHash
{
	inline size_t operator()(const std::string& s) const
	{
		return QuickHashCStrUpper(s.c_str());
	}
};

struct UpperEqualPred
{
	inline bool operator ()(const std::string& s1, const std::string& s2) const
	{
		return QuickHashCStrUpper(s1.c_str()) == QuickHashCStrUpper(s2.c_str());
	}
};

struct RemoteDataHeader
{
	int Size;
	int NLib;
	int NAddr;
	int NHook;
	int NMem;

	int ExeDataOffset;
	int LibDataListOffset;
	int AddrDataListOffset;
	int HookDataListOffset;
	int CopyMemListOffset;
	int dwReserved[20];

	int HookOpCodeSize;
	int JmpBackCodeSize;
};
static_assert(sizeof(RemoteDataHeader) == 128);

struct ExeRemoteData
{
	char SyringeVersionStr[256];
	BYTE VMajor;
	BYTE VMinor;
	BYTE VRelease;
	BYTE VBuild;
	
	char FileName[260];
	char AbsPath[260];
	DWORD BaseAddress;
	DWORD EntryPoint;

	int dwReserved[3];
};
struct LibRemoteData
{
	struct _Base
	{
		char* LibName;
		char* AbsPath;
		DWORD ID;//QuickHash of AbsPath

		char* JSONText;
		int dwReserved[4];
	}Base;

	std::string LibName;
	std::string AbsPath;
	std::string Json;
};
struct AddrRemoteData
{
	struct _Base
	{
		DWORD Addr;
		DWORD HookDataAddr;
		int OverriddenCount;
		int HookCount;
		int dwReserved[6];
		//DWORD FirstHookIndex;//VLA Header
	}Base;
	std::vector<DWORD> HookID;
	size_t HookDataSize;
	DWORD HookOpAddr;
	DWORD HookHeaderAddr;
};

struct AddrHiddenHeader
{
	DWORD ActiveHookCount;
	DWORD OpCodeAddress;
	DWORD OverriddenCount;
	DWORD dwReserved;
};

struct HookRemoteData
{
	struct _Base
	{
		char* ProcName;
		//char* LibName;
		DWORD HookID;
		DWORD LibID;
		DWORD HookAddress;
		size_t OverrideLength;
		int dwReserved[3];
	}Base;

	std::string ProcName;
	//std::string LibName;
};

struct MemCopyData
{
	char* Name;
	void* Addr;
};

class AddrAccumulator
{
private:
	size_t size{ 0 };
public:
	template<typename T>
	size_t Push(size_t ExtBytes)//返回写入的头偏移量
	{
		auto sz = size;
		size += sizeof(T)+ExtBytes;
		return sz;
	}

	size_t PushBytes(size_t Count)
	{
		auto sz = size;
		size += Count;
		return sz;
	}

	size_t PushAligned(size_t Count, size_t Align)
	{
		size = ((size / Align) + 1) * Align;
		return PushBytes(Count);
	}

	inline void Clear()
	{
		size = 0;
	}

	inline size_t Size()
	{
		return size;
	}
};

class TempByteStream
{
private:
	std::vector<BYTE> Buffer;
public:
	template<typename T>
	size_t Push(const T& Data, size_t ExtBytes)//返回写入的头偏移量
	{
		auto pData = (const BYTE*)&Data;
		auto sz = Buffer.size();
		Buffer.resize(sz + sizeof(T)+ ExtBytes);
		memcpy((void*)(Buffer.data() + sz), pData, sizeof(T) + ExtBytes);
		return sz;
	}

	size_t PushBytes(const BYTE* Data, size_t Count)//返回写入的头偏移量
	{
		auto sz = Buffer.size();
		Buffer.resize(sz + Count);
		memcpy((void*)(Buffer.data() + sz), Data, Count);
		return sz;
	}

	size_t PushZero(size_t Count)
	{
		auto sz = Buffer.size();
		Buffer.resize(sz + Count);
		return sz;
	}

	void Clear()
	{
		Buffer.clear();
	}

	const BYTE* Data() const;
	BYTE* Offset(int Ofs) const;
	size_t Size() const;
};

struct DoubleInteractData
{
	struct TransferData
	{
		DWORD PEB_Base;
		int dwReserved[15];
	}Transfer;
	DWORD FinalAddr;
	size_t FinalOffset;

	inline TransferData* RemotePtr()
	{
		return reinterpret_cast<TransferData*>(FinalAddr);
	}
};

struct CopyRange
{
	DWORD Begin;
	DWORD End;
	MemCopyInfo* ptr;
};

class RemoteDatabase
{
private:
	VirtualMemoryHandle Mem;
	TempByteStream Stm;
	AddrAccumulator HookStm;
	VirtualMemoryHandle HookMem;
	SyringeDebugger* Dbg;

	std::unique_ptr<ExeRemoteData> Exe;
	std::vector<LibRemoteData> Lib;
	std::vector<AddrRemoteData> Addr;
	std::vector<HookRemoteData> Hook;
	std::unordered_map<DWORD, std::string_view> StrList;
	std::unordered_map<DWORD, DWORD> OfsList;
	std::unordered_map<DWORD, DWORD> NegOfsList;
	std::unordered_map<std::string, DWORD> CopyList;
	std::vector<MemCopyInfo> CopyAll;
	std::unordered_map<std::string, CopyRange> CopyRangeList;
	std::unordered_map<DWORD, AddrRemoteData*> AddrList;

	DWORD RemoteDBStart, RemoteDBEnd;
	DoubleInteractData Interact;
public:
	inline AddrRemoteData* GetMem(DWORD HookAddr)
	{
		auto it = AddrList.find(HookAddr);
		if (it == AddrList.end())return nullptr;
		return it->second;
	}

	DoubleInteractData& GetDblInteractData()
	{
		return Interact;
	}

	inline void Init(SyringeDebugger* p)
	{
		Dbg = p;
	}

	template<typename T>
	size_t Push(const T& Data,size_t ExtBytes = 0)//返回写入的头偏移量
	{
		return Stm.Push(Data, ExtBytes);
	}

	inline size_t PushZero(size_t Count)
	{
		return Stm.PushZero(Count);
	}
	inline size_t PushBytes(const BYTE* Data, size_t Count)
	{
		return Stm.PushBytes(Data, Count);
	}

	template<typename T>
	T& Offset(int Ofs)
	{
		return *reinterpret_cast<T*>(Stm.Offset(Ofs));
	}


	void WriteToStream();
	void CreateData();
	void PushString();
	void ResetPointer(DWORD BaseAddr);
	void CreateLibData(LibExtData& Ext, const PortableExecutable& DLL, std::string_view cname, std::string_view abs);
	size_t CopyAndPush(DWORD Start, DWORD End);
	void CopyAndPush(const std::vector<MemCopyInfo>&);
	void CopyAndPushEnd();



	//RUNTIME
	void SendData();
	void Dump();

	inline bool InRange(DWORD RemoteAddr)
	{
		if (!RemoteDBStart)return false;
		if (!RemoteDBEnd)return false;
		return (RemoteDBStart <= RemoteAddr) && (RemoteAddr < RemoteDBEnd);
	}

	inline bool InHookRange(DWORD RemoteAddr)
	{
		if (!HookMem)return false;
		if (!HookStm.Size())return false;
		return ((DWORD)HookMem.get() <= RemoteAddr) && (RemoteAddr < (DWORD)HookMem.get()+ HookStm.Size());
	}

	MemCopyInfo* GetCopyMemName(DWORD RemoteAddr);
	std::pair<DWORD, std::string> AnalyzeDBAddr(DWORD RemoteAddr);
	std::pair<DWORD, std::string> AnalyzeHookAddr(DWORD RemoteAddr);
};


void RemoteBuf_Load(SyringeDebugger* Dbg, void* Addr, void* Buffer, size_t Size);

template<typename T>
class RemoteBuf
{
	SyringeDebugger* Dbg;
	void* Addr;
	T Buffer;
public:
	RemoteBuf() = delete;
	RemoteBuf(SyringeDebugger* pDbg) :Dbg(pDbg), Addr(nullptr), Buffer(){}
	RemoteBuf(SyringeDebugger* pDbg,T* Address) :Dbg(pDbg), Addr((void*)Address), Buffer() {}

	RemoteBuf& operator=(T* Ptr)
	{
		Addr = Ptr;
		return *this;
	}

	T& operator*()
	{
		RemoteBuf_Load(Dbg, Addr, &Buffer, sizeof(T));
		return Buffer;
	}
};

template<typename T>
class RemoteArrayBuf
{
	SyringeDebugger* Dbg;
	void* Addr;
	T* Buffer;
public:
	RemoteArrayBuf() = delete;
	RemoteArrayBuf(SyringeDebugger* pDbg) :Dbg(pDbg), Addr(nullptr), Buffer(nullptr) {}
	RemoteArrayBuf(SyringeDebugger* pDbg, T* Address) :Dbg(pDbg), Addr((void*)Address), Buffer(nullptr) {}

	RemoteArrayBuf& operator=(T* Ptr)
	{
		Addr = Ptr;
		return *this;
	}

	T* operator()(size_t N)
	{
		if (Buffer)delete[]Buffer;
		Buffer = new T(N);
		RemoteBuf_Load(Dbg, Addr, &Buffer, sizeof(T)*N);
		return Buffer;
	}

	T& operator[](size_t Idx)
	{
		return Buffer[Idx];
	}
};

template<typename T>
T& AnyOffset(void* ptr, size_t offset)
{
	return *((T*)(((char*)ptr) + offset));
}

template<typename T>
T* AnyOffsetPtr(void* ptr, size_t offset)
{
	return (T*)(((char*)ptr) + offset);
}

