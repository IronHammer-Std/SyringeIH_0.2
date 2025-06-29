#pragma once
#define WIN32_LEAN_AND_MEAN
//      WIN32_FAT_AND_STUPID

#include "CRC32.h"
#include "PortableExecutable.h"
#include "FindFile.h"
#include "HookAnalyzer.h"
#include "RemoteDatabase.h"

#include <cstring>
#include <iostream>
#include <map>
#include <set>
#include <optional>
#include <string_view>

#include <windows.h>

struct SharedMemHeader
{
	int TotalSize;
	int WritingComplete;
	int RecordCount;
	int RecordSize;

	DWORD DatabaseAddr;
	DWORD DllRecordAddr;
	int DllRecordCount;
	int ReservedPtr;
	int ReservedHandle;
	int Reserved[7];
};

struct SharedMemRecord
{
	wchar_t Name[256];
	DWORD BaseAddr;
	DWORD TargetHash;
	int Reserved[14];
};

class RemoteMapper
{
private:
	HANDLE hMap;
	LPBYTE View;
	size_t Size;
public:
	RemoteMapper();
	void Create(SharedMemHeader&, int RemoteMapSuffix, const std::string& Prefix);
	void Open(int RemoteMapSuffix, const std::string& Prefix);
	bool Available();
	inline LPBYTE GetView()
	{
		return View;
	}
	template<typename T>
	T* OffsetPtr(size_t Ofs)
	{
		if (GetView())return((T*)(GetView() + Ofs));
		else return nullptr;
	}
	inline SharedMemHeader* Header()
	{
		return OffsetPtr<SharedMemHeader>(0);
	}
	~RemoteMapper();
};

const std::string& ExecutableDirectoryPath();

class SyringeDebugger
{

	static constexpr BYTE INIT = 0x00;
	static constexpr BYTE INT3 = 0xCC; // trap to debugger interrupt opcode.
	static constexpr BYTE NOP = 0x90;

public:
	SyringeDebugger(std::string_view filename)
		: exe(filename)
	{
		RetrieveInfo();
	}

	// debugger
	void Run(std::string_view arguments);
	DWORD HandleException(DEBUG_EVENT const& dbgEvent);
	DWORD Handle_BreakPoint(DEBUG_EVENT const& dbgEvent);
	void Handle_StackDump(DEBUG_EVENT const& dbgEvent);
	void Handle_ApplyHook();
	void PreloadData();

	// breakpoints
	bool SetBP(void* address);
	void RemoveBP(LPVOID address, bool restoreOpcode);

	// memory
	VirtualMemoryHandle AllocMem(void* address, size_t size);
	bool PatchMem(void* address, void const* buffer, DWORD size);
	bool ReadMem(void const* address, void* buffer, DWORD size);

	// syringe
	void FindDLLs();


	// process info
	PROCESS_INFORMATION pInfo;

	// flags
	bool bEntryBP{ true };

	// Ext
	HookAnalyzer Analyzer;
	RemoteDatabase Database;
	DisableHookIdxSet IdxSet;
	std::unordered_map<std::string, LibExtData> LibExt;
	std::vector<std::string> DLLs;
	std::vector<std::string> DLLShort;
	bool FirstHook{ true };
	int LoadedCount{ 0 };
	char ExLoadingLib[300];
	RemoteMapper Mapper;
	std::unordered_map<std::string, DWORD> LibAddr;
	std::vector<SharedMemRecord>LibBase;
	int RemoteMapSuffix;
	std::pair<DWORD, std::string> AnalyzeAddr(DWORD);
	DWORD NullOutput;
	bool EverythingIsOK{ false };
	bool PrepareForDetach{ false };
	std::string SyringeExPath{ };


	void FindDLLsLoop(const FindFile& file, const std::string& Path, bool AlwaysLoad);

	void InitializeSymbols();
	void RetrieveInfo();
	void DebugProcess(std::string_view arguments);

	// helper Functions
	static DWORD __fastcall RelativeOffset(void const* from, void const* to);

	template<typename T>
	static void ApplyPatch(void* ptr, T&& data) noexcept
	{
		std::memcpy(ptr, &data, sizeof(data));
	}

	// thread info
	struct ThreadInfo
	{
		ThreadInfo() = default;

		ThreadInfo(HANDLE hThread) noexcept
			: Thread{hThread}
		{ }

		ThreadHandle Thread;
		LPVOID lastBP{ nullptr };
	};

	std::map<DWORD, ThreadInfo> Threads;

	struct BreakpointInfo
	{
		BYTE original_opcode{ 0x0u };
		std::vector<Hook> hooks;
		VirtualMemoryHandle p_caller_code;
	};

	std::map<void*, BreakpointInfo> Breakpoints;
	std::map<void*, BreakpointInfo> BreakpointRel;

	std::vector<Hook*> v_AllHooks;
	std::vector<Hook*>::iterator loop_LoadLibrary;

	// syringe
	std::string exe;
	void* pcEntryPoint{ nullptr };
	DWORD ExeImageBase{ 0u };
	void* pImLoadLibrary{ nullptr };
	void* pImGetProcAddress{ nullptr };
	VirtualMemoryHandle pAlloc;
	DWORD dwTimeStamp{ 0u };
	DWORD dwExeSize{ 0u };
	DWORD dwExeCRC{ 0u };

	bool bDLLsLoaded{ false };
	bool bHooksCreated{ false };

	bool bAVLogged{ false };

	// data addresses
	struct AllocData {
		static constexpr auto CodeSize = 0x40u;
		std::byte LoadLibraryFunc[CodeSize];
		void* ProcAddress;
		void* ReturnEIP;
		char LibName[MaxNameLength];
		char ProcName[MaxNameLength];
	};

	AllocData* GetData() const noexcept {
		return reinterpret_cast<AllocData*>(pAlloc.get());
	};

	struct HookBuffer {
		std::map<void*, std::vector<Hook>> hooks;
		std::map<void*, std::vector<Hook>> hookExt;
		CRC32 checksum;
		size_t count{ 0 };

		void add(void* const eip, Hook const& hook) {
			if (strlen(hook.RelativeLib))
			{
				auto& h = hookExt[eip];
				h.push_back(hook);
			}
			else
			{
				auto& h = hooks[eip];
				h.push_back(hook);
			}

			checksum.compute(&eip, sizeof(eip));
			checksum.compute(&hook.num_overridden, sizeof(hook.num_overridden));
			count++;
		}

		void add(
			void* const eip, std::string_view const filename,
			std::string_view const proc, size_t const num_overridden, int priority,std::string_view sub_priority, std::string_view Library)
		{
			Hook hook;
			hook.lib[filename.copy(hook.lib, std::size(hook.lib) - 1)] = '\0';
			hook.proc[proc.copy(hook.proc, std::size(hook.proc) - 1)] = '\0';
			hook.proc_address = nullptr;
			hook.num_overridden = num_overridden;
			hook.Priority = priority;
			hook.SubPriority[sub_priority.copy(hook.SubPriority, std::size(hook.SubPriority) - 1)] = '\0';
			hook.RelativeLib[Library.copy(hook.RelativeLib, std::size(hook.RelativeLib) - 1)] = '\0';
			add(eip, hook);
		}
	};

	bool ParseInjFileHooks(std::string_view lib, HookBuffer& hooks);
	bool CanHostDLL(PortableExecutable const& DLL, IMAGE_SECTION_HEADER const& hosts) const;
	bool ParseHooksSection(PortableExecutable & DLL, IMAGE_SECTION_HEADER const* hooks, HookBuffer& buffer);
	std::optional<bool> Handshake(char const* lib, int hooks, unsigned int crc);
};

// disable "structures padded due to alignment specifier"
#pragma warning(push)
#pragma warning(disable : 4324)
struct alignas(16) hookdecl {
	unsigned int hookAddr;
	unsigned int hookSize;
	DWORD hookNamePtr;
};

struct alignas(16) hookaltdecl {
	unsigned int hookAddr;
	unsigned int hookSize;
	DWORD hookNamePtr;
	int Priority;
	DWORD SubPriorityPtr;
};

struct alignas(16) hostdecl {
	unsigned int hostChecksum;
	DWORD hostNamePtr;
};

static_assert(sizeof(hookdecl) == 16);
static_assert(sizeof(hookaltdecl) == 32);
static_assert(sizeof(hostdecl) == 16);
#pragma warning(pop)

struct SyringeHandshakeInfo
{
	int cbSize;
	int num_hooks;
	unsigned int checksum;
	DWORD exeFilesize;
	DWORD exeTimestamp;
	unsigned int exeCRC;
	int cchMessage;
	char* Message;
};

using SYRINGEHANDSHAKEFUNC = HRESULT(__cdecl *)(SyringeHandshakeInfo*);
