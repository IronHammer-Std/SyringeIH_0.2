#include "SyringeDebugger.h"

#include "CRC32.h"
#include "FindFile.h"
#include "Handle.h"
#include "Log.h"
#include "Support.h"
#include "Setting.h"
#include "SymMap.h"

#include <algorithm>
#include <filesystem>
#include <array>
#include <fstream>
#include <memory>
#include <numeric>
#include <Psapi.h>
#include <DbgHelp.h>

using namespace std;
#define EXCEPTION_UNKNOWN_ERROR_1 0xE06D7363
#define STATUS_FAIL_FAST_EXCEPTION 0xC0000409

std::string UnicodetoANSI(const std::wstring& Unicode)
{
	int ANSIlen = WideCharToMultiByte(CP_ACP, 0, Unicode.c_str(), -1, 0, 0, 0, 0);// 获取UTF-8编码长度
	char* ANSI = new CHAR[ANSIlen + 4]{};
	WideCharToMultiByte(CP_ACP, 0, Unicode.c_str(), -1, ANSI, ANSIlen, 0, 0); //转换成UTF-8编码
	std::string ret = ANSI;
	delete[] ANSI;
	return ret;
}

std::string UnicodetoUTF8(const std::wstring& Unicode)
{
	int UTF8len = WideCharToMultiByte(CP_UTF8, 0, Unicode.c_str(), -1, 0, 0, 0, 0);// 获取UTF-8编码长度
	char* UTF8 = new CHAR[UTF8len + 4]{};
	WideCharToMultiByte(CP_UTF8, 0, Unicode.c_str(), -1, UTF8, UTF8len, 0, 0); //转换成UTF-8编码
	std::string ret = UTF8;
	delete[] UTF8;
	return ret;
}

// UTF-8字符集转换成Unicode
std::wstring UTF8toUnicode(const std::string& UTF8)
{
	int nLength = MultiByteToWideChar(CP_UTF8, 0, UTF8.c_str(), -1, NULL, NULL);   // 获取缓冲区长度，再分配内存
	WCHAR* tch = new WCHAR[nLength + 4]{};
	MultiByteToWideChar(CP_UTF8, 0, UTF8.c_str(), -1, tch, nLength);     // 将UTF-8转换成Unicode
	std::wstring ret = tch;
	delete[] tch;
	return ret;
}

// UTF-8字符集转换成ANSI
std::string UTF8toANSI(const std::string& MBCS)
{
	return UnicodetoANSI(UTF8toUnicode(MBCS));
}

std::pair<DWORD ,std::wstring>  ResolveFunctionSymbol(HANDLE hProcess, DWORD address);

std::pair<DWORD, std::string> SyringeDebugger::AnalyzeAddr(DWORD Addr)
{
	if (Database.InRange(Addr))
	{
		return Database.AnalyzeDBAddr(Addr);
	}
	if (Database.InHookRange(Addr))
	{
		return Database.AnalyzeHookAddr(Addr);
	}
	if (ModuleMap::HasSymbol(Addr))
	{
		auto sym = ModuleMap::GetSymbol(Addr);
		if (!sym.second.empty())return std::make_pair(sym.first, ModuleMap::GetLibName(Addr) + "!" + UnicodetoANSI(sym.second));
	}
	for (size_t i = 0; i < LibBase.size() - 1; i++)
	{
		if (LibBase[i].BaseAddr <= Addr && Addr < LibBase[i + 1].BaseAddr)
		{
			auto Ret = std::make_pair(Addr - LibBase[i].BaseAddr, std::move(UnicodetoANSI(LibBase[i].Name)));
			auto Res = ResolveFunctionSymbol(pInfo.hProcess, Addr);
			if (Res.second == L"[未知]" || Res.first == 0xFFFFFFFF)return Ret;
			else return std::make_pair(Res.first, UnicodetoANSI(LibBase[i].Name + std::wstring(L"!") + Res.second));
		}
	}
	if (LibBase.back().BaseAddr <= Addr)
	{
		auto Ret = std::make_pair(Addr - LibBase.back().BaseAddr, std::move(UnicodetoANSI(LibBase.back().Name)));
		auto Res = ResolveFunctionSymbol(pInfo.hProcess, Addr);
		if (Res.second == L"[未知]" || Res.first == 0xFFFFFFFF)return Ret;
		else return std::make_pair(Res.first, UnicodetoANSI(LibBase.back().Name + std::wstring(L"!") + Res.second));
	}
	return std::make_pair(Addr, "UNKNOWN");
}


const std::string& UniqueIDByPath()
{
	static std::string Result{};
	if (!Result.empty())return Result;
	auto id = QuickHashCStrUpper(ExecutableDirectoryPath().c_str());
	Result = std::to_string(id);
	return Result;
}

void RemoteMapper::Create(SharedMemHeader& rcd, int RemoteMapSuffix, const std::string& Prefix)
{
	if (!rcd.TotalSize)return;
	hMap = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, rcd.TotalSize, (Prefix + UniqueIDByPath() + std::to_string(RemoteMapSuffix)).c_str());
	//MessageBoxA(NULL,(Prefix + UniqueIDByPath() + std::to_string(RemoteMapSuffix)).c_str(), "Syringe Side", MB_OK);
	if (!hMap)return;
	View = (LPBYTE)MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, rcd.TotalSize);
	if (!View)return;
	memcpy(View, &rcd, sizeof(SharedMemHeader));
	Size = rcd.TotalSize;
}
void RemoteMapper::Open(int RemoteMapSuffix, const std::string& Prefix)
{
	hMap = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, (Prefix + UniqueIDByPath() + std::to_string(RemoteMapSuffix)).c_str());
	if (!hMap)return;
	View = (LPBYTE)MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SharedMemHeader));
	if (!View)return;
	auto pHeader = Header();
	Size = pHeader->TotalSize;
	UnmapViewOfFile(View);
	View = (LPBYTE)MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, Size);
	if (!View)Size = 0;
}
bool RemoteMapper::Available()
{
	return View != nullptr;
}
RemoteMapper::RemoteMapper() :hMap(NULL), View(nullptr), Size(0) {}
RemoteMapper::~RemoteMapper()
{
	if (View)UnmapViewOfFile(View);
	if (hMap)CloseHandle(hMap);
}

//bool SyringeReceive(char const* const lib);

void SyringeDebugger::DebugProcess(std::string_view const arguments)
{
	STARTUPINFO startupInfo{ sizeof(startupInfo) };

	SetEnvironmentVariable("_NO_DEBUG_HEAP", "1");

	auto command_line = '"' + exe + "\" ";
	command_line += arguments;

	if(CreateProcess(
		exe.c_str(), command_line.data(), nullptr, nullptr, false,
		DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED,
		nullptr, nullptr, &startupInfo, &pInfo) == FALSE)
	{
		//Log::WriteLine("ERROR_ERRORS_ENCOUNTERED A %s", exe.c_str());
		throw_lasterror_or(ERROR_ERRORS_ENCOUNTERED, exe);
	}
}

bool SyringeDebugger::PatchMem(void* address, void const* buffer, DWORD size)
{
	return (WriteProcessMemory(pInfo.hProcess, address, buffer, size, nullptr) != FALSE);
}

bool SyringeDebugger::ReadMem(void const* address, void* buffer, DWORD size)
{
	return (ReadProcessMemory(pInfo.hProcess, address, buffer, size, nullptr) != FALSE);
}

VirtualMemoryHandle SyringeDebugger::AllocMem(void* address, size_t size)
{
	if(VirtualMemoryHandle res{ pInfo.hProcess, address, size }) {
		return res;
	}
	//Log::WriteLine("ERROR_ERRORS_ENCOUNTERED B %s", exe.c_str());
	throw_lasterror_or(ERROR_ERRORS_ENCOUNTERED, exe);
}

bool SyringeDebugger::SetBP(void* address)
{
	// save overwritten code and set INT 3
	if(auto& opcode = Breakpoints[address].original_opcode; opcode == 0x00) {
		auto const buffer = INT3;
		ReadMem(address, &opcode, 1);
		return PatchMem(address, &buffer, 1);
	}

	return true;
}

DWORD __fastcall SyringeDebugger::RelativeOffset(void const* pFrom, void const* pTo)
{
	auto const from = reinterpret_cast<DWORD>(pFrom);
	auto const to = reinterpret_cast<DWORD>(pTo);

	return to - from;
}

const char ExLib[300] = "SyringeEx.dll";
const char ExProc[300] = "Initialize";

const BYTE _INIT = 0x00;
const BYTE _NOP = 0x90;

//FOR RESHADE
/*
BYTE const hook_code_call[38] =
{
	0x60, 0x9C, // PUSHAD, PUSHFD
	0x68, _INIT, _INIT, _INIT, _INIT, // PUSH HookAddress
	0x54, // PUSH ESP
	0xE8, _INIT, _INIT, _INIT, _INIT, // CALL ProcAddress
	0x83, 0xC4, 0x08, // ADD ESP, 8
	0xA3, _INIT, _INIT, _INIT, _INIT, // MOV ds:ReturnEIP, EAX
	0x9D, 0x61, // POPFD, POPAD
	0x83, 0x3D, _INIT, _INIT, _INIT, _INIT, 0x00, // CMP ds:ReturnEIP, 0
	0x74, 0x06, // JZ .proceed
	0xFF, 0x25, _INIT, _INIT, _INIT, _INIT, // JMP ds:ReturnEIP
};

BYTE const wtf_call[38] =
{
	_NOP, _NOP, // PUSHAD, PUSHFD
	_NOP, _NOP, _NOP, _NOP, _NOP, // PUSH HookAddress
	_NOP, // PUSH ESP
	_NOP, _NOP, _NOP, _NOP, _NOP, // CALL ProcAddress
	_NOP, _NOP, _NOP, // ADD ESP, 8
	_NOP, _NOP, _NOP, _NOP, _NOP, // MOV ds:ReturnEIP, EAX
	_NOP, _NOP, // POPFD, POPAD
	_NOP, _NOP, _NOP, _NOP, _NOP, _NOP, _NOP, // CMP ds:ReturnEIP, 0
	_NOP, _NOP, // JZ .proceed
	_NOP, _NOP, _NOP, _NOP, _NOP, _NOP, // JMP ds:ReturnEIP
};
*/

BYTE const hook_code_call[40] =
{
	0x60, 0x9C,                       // PUSHAD, PUSHFD
	0x68, _INIT, _INIT, _INIT, _INIT, // PUSH HookAddress
	0x83, 0xEC, 0x04,                 // SUB ESP, 4
	0x8D, 0x44, 0x24, 0x04,           // LEA EAX, [ESP + 4]
	0x50,                             // PUSH EAX
	0xE8, _INIT, _INIT, _INIT, _INIT, // CALL ProcAddress
	0x83, 0xC4, 0x0C,                 // ADD ESP, 0Ch
	0x89, 0x44, 0x24, 0xF8,           // MOV ss:[ESP - 8], EAX
	0x9D, 0x61,                       // POPFD, POPAD
	0x83, 0x7C, 0x24, 0xD4, 0x00,     // CMP ss:[ESP - 2Ch], 0
	0x74, 0x04,                       // JZ .proceed
	0xFF, 0x64, 0x24, 0xD4,           // JMP ss:[ESP - 2Ch]
};

BYTE const wtf_call[40] =
{
	_NOP, _NOP, _NOP, _NOP, _NOP,
	_NOP, _NOP, _NOP, _NOP, _NOP,
	_NOP, _NOP, _NOP, _NOP, _NOP,
	_NOP, _NOP, _NOP, _NOP, _NOP, 
	_NOP, _NOP, _NOP, _NOP, _NOP, 
	_NOP, _NOP, _NOP, _NOP, _NOP, 
	_NOP, _NOP, _NOP, _NOP, _NOP, 
	_NOP, _NOP, _NOP, _NOP, _NOP, 
};

BYTE const hook_jmp_back[5] = { 0xE9, _INIT, _INIT, _INIT, _INIT };
BYTE const hook_jmp[5] = { 0xE9, _INIT, _INIT, _INIT, _INIT };

void SyringeDebugger::Handle_ApplyHook()

{

	Log::WriteLine(__FUNCTION__ ": 开始启动DLL，并创建钩子。");

	std::vector<BYTE> code;

	for (auto& it : Breakpoints)
	{
		auto const p_original_code = static_cast<BYTE*>(it.first);

		//Log::WriteLine("将在 0x%08X 处插入钩子。", it.first);

		if (it.first == nullptr || it.first == pcEntryPoint)
		{
			continue;
		}

		auto const [count, overridden] = std::accumulate(
			it.second.hooks.cbegin(), it.second.hooks.cend(),
			std::make_pair(0u, 0u), [](auto acc, auto const& hook)
			{
				if (hook.proc_address) {
					if (acc.second < hook.num_overridden) {
						acc.second = hook.num_overridden;
					}
					acc.first++;
				}
				return acc;
			});

		if (!count)
		{
			continue;
		}

		auto const sz = it.second.hooks.size() * sizeof(hook_code_call)
			+ sizeof(hook_jmp_back) + overridden;

		code.resize(sz);
		auto p_code = code.data();

		auto pAddr = Database.GetMem((DWORD)p_original_code);
		BYTE* base;
		if (pAddr)
		{
			base = (BYTE*)pAddr->HookOpAddr;
			AddrHiddenHeader* pHidden = (AddrHiddenHeader*)(pAddr->HookHeaderAddr);
			//Log::WriteLine("Base at %X Header at %X", base,pHidden); 
			AddrHiddenHeader Hidden;
			Hidden.ActiveHookCount = count;
			Hidden.OpCodeAddress = pAddr->Base.HookDataAddr + count * sizeof(hook_code_call);
			Hidden.OverriddenCount = overridden;
			PatchMem(pHidden, &Hidden, sizeof(AddrHiddenHeader));
		}
		else
		{
			Log::WriteLine(__FUNCTION__ ":错误： %X 处的钩子无法获取到预分配的空间地址。", p_original_code);
			it.second.p_caller_code = AllocMem(nullptr, sz);
			base = it.second.p_caller_code.get();
		}

		// write caller code
		for (auto const& hook : it.second.hooks)
		{
			if (hook.proc_address)
			{
				ApplyPatch(p_code, hook_code_call); // code
				ApplyPatch(p_code + 0x03, it.first); // PUSH HookAddress

				//FOR RESHADE 
				//auto const rel = RelativeOffset(
				//	base + (p_code - code.data() + 0x0D), hook.proc_address);
				//ApplyPatch(p_code + 0x09, rel); // CALL
				auto const rel = RelativeOffset(
					base + (p_code - code.data() + 0x14), hook.proc_address);
				ApplyPatch(p_code + 0x10, rel); // CALL

				//FOR RESHADE
				//auto const pdReturnEIP = &GetData()->ReturnEIP;
				//ApplyPatch(p_code + 0x11, pdReturnEIP); // MOV
				//ApplyPatch(p_code + 0x19, pdReturnEIP); // CMP
				//ApplyPatch(p_code + 0x22, pdReturnEIP); // JMP ds:ReturnEIP

				p_code += sizeof(hook_code_call);
			}
			else if(NullOutput)
			{
				ApplyPatch(p_code, hook_code_call); // code
				ApplyPatch(p_code + 0x03, it.first); // PUSH HookAddress

				//FOR RESHADE
				//auto const rel = RelativeOffset(
				//	base + (p_code - code.data() + 0x0D), (const void*)NullOutput);
				//ApplyPatch(p_code + 0x09, rel); // CALL
				auto const rel = RelativeOffset(
					base + (p_code - code.data() + 0x14), (const void*)NullOutput);
				ApplyPatch(p_code + 0x10, rel); // CALL

				//FOR RESHADE
				//auto const pdReturnEIP = &GetData()->ReturnEIP;
				//ApplyPatch(p_code + 0x11, pdReturnEIP); // MOV
				//ApplyPatch(p_code + 0x19, pdReturnEIP); // CMP
				//ApplyPatch(p_code + 0x22, pdReturnEIP); // JMP ds:ReturnEIP

				p_code += sizeof(hook_code_call);
			}
			else
			{
				ApplyPatch(p_code, wtf_call);
				p_code += sizeof(hook_code_call);
			}
		}

		// write overridden bytes
		if (overridden)
		{
			ReadMem(it.first, p_code, overridden);
			p_code += overridden;
		}

		// write the jump back
		auto const rel = RelativeOffset(
			base + (p_code - code.data() + 0x05),
			static_cast<BYTE*>(it.first) + 0x05);
		ApplyPatch(p_code, hook_jmp_back);
		ApplyPatch(p_code + 0x01, rel);

		PatchMem(base, code.data(), code.size());

		// dump
		/*
		Log::WriteLine("Call dump for 0x%08X at 0x%08X:", it.first, base);

		code.resize(sz);
		ReadMem(it.second.p_caller_code, code.data(), sz);

		std::string dump_str{ "\t\t" };
		for(auto const& byte : code) {
			char buffer[0x10];
			sprintf(buffer, "%02X ", byte);
			dump_str += buffer;
		}

		Log::WriteLine(dump_str.c_str());
		Log::WriteLine();*/

		// patch original code

		auto const rel2 = RelativeOffset(p_original_code + 5, base);
		code.assign(std::max(overridden, sizeof(hook_jmp)), NOP);
		ApplyPatch(code.data(), hook_jmp);
		ApplyPatch(code.data() + 0x01, rel2);

		DWORD OldProtect;
		VirtualProtectEx(pInfo.hProcess, p_original_code, code.size(), PAGE_EXECUTE_READWRITE, &OldProtect);
		if (PatchMem(p_original_code, code.data(), code.size()))
		{
			//Log::WriteLine("在 0x%08X 处插入钩子入口。", p_original_code);
		}
		else
		{
			Log::WriteLine("无法在 0x%08X 处插入钩子入口。", p_original_code);
		}
		VirtualProtectEx(pInfo.hProcess, p_original_code, code.size(), OldProtect, &OldProtect);
	}
	Log::Flush();
	bHooksCreated = true;
}

const std::unordered_map<int, std::string> TmpMap
{
	{0x10,"仅执行"},
	{0x20,"读/执行"},
	{0x40,"读/写/执行"},
	{0x80,"写入时复制/执行"},
	{0x01,"不可访问"},
	{0x02,"只读"},
	{0x04,"读/写"},
	{0x08,"写入时复制"},
	{0x00,"未分配/已释放"},
};

const std::unordered_map<int, std::string> ExcMap
{{
EXCEPTION_ACCESS_VIOLATION,"程序试图越权访问某个地址。"}, {
EXCEPTION_ARRAY_BOUNDS_EXCEEDED,"边界检查发现了数组访问越界。"}, {
EXCEPTION_BREAKPOINT,"遇到断点。"}, {
EXCEPTION_DATATYPE_MISALIGNMENT,"程序尝试读写未对齐或错误对齐的数据。"}, {
EXCEPTION_FLT_DENORMAL_OPERAND,"浮点运算时，试图除以无法表示为标准浮点值的过小浮点数。"}, {
EXCEPTION_FLT_DIVIDE_BY_ZERO,"进行浮点数除法时试图除以0。"}, {
EXCEPTION_FLT_INEXACT_RESULT,"浮点运算的结果超越了可准确表示的范围。"}, {
EXCEPTION_FLT_INVALID_OPERATION,"未知的浮点运算错误。"}, {
EXCEPTION_FLT_OVERFLOW,"参与浮点运算的数指数过大。"}, {
EXCEPTION_FLT_STACK_CHECK,"浮点运算时，堆栈发生了上溢或下溢。"}, {
EXCEPTION_FLT_UNDERFLOW,"参与浮点运算的数指数过小。"}, {
EXCEPTION_ILLEGAL_INSTRUCTION,"程序尝试执行无效的指令或不存在的指令。"}, {
EXCEPTION_IN_PAGE_ERROR,"程序试图访问系统暂时无法加载的内存页面，如通过网络运行程序时网络连接断开等。"}, {
EXCEPTION_INT_DIVIDE_BY_ZERO,"进行整数除法时试图除以0。"}, {
EXCEPTION_INT_OVERFLOW,"整数运算的结果过大而上溢。"}, {
EXCEPTION_INVALID_DISPOSITION,"异常处理程序对异常的处置无效。使用高级语言的程序员不应遇到此异常。"}, {
EXCEPTION_NONCONTINUABLE_EXCEPTION,"程序试图在发生致命异常后继续运行。"}, {
EXCEPTION_PRIV_INSTRUCTION,"程序尝试执行其无权执行的指令。"}, {
EXCEPTION_SINGLE_STEP,"正在单步调试中，已执行一个指令。"}, {
EXCEPTION_STACK_OVERFLOW,"栈空间发生上溢。"}, {
STATUS_FAIL_FAST_EXCEPTION ,"快速失败机制要求程序立即退出。"}, {
EXCEPTION_UNKNOWN_ERROR_1 ,"抛出的C++异常不被捕获，可能由于缺少对应的catch块，或C++的运行时配置存在异常。"}
};
/*
沟槽的微软中文
const std::unordered_map<int, std::string> ExcMap
{
{EXCEPTION_ACCESS_VIOLATION,"线程尝试从虚拟地址读取或写入其没有相应访问权限的虚拟地址。"
}, {
EXCEPTION_ARRAY_BOUNDS_EXCEEDED,"线程尝试访问超出边界且基础硬件支持边界检查的数组元素。"
}, {
EXCEPTION_BREAKPOINT,"遇到断点。"
}, {
EXCEPTION_DATATYPE_MISALIGNMENT,"线程尝试读取或写入在不提供对齐的硬件上未对齐的数据。 例如，16 位值必须在 2 字节边界上对齐; 4 字节边界上的 32 位值等。"
}, {
EXCEPTION_FLT_DENORMAL_OPERAND,"浮点运算中的一个操作数是反常运算。 非规范值太小，无法表示为标准浮点值。"
}, {
EXCEPTION_FLT_DIVIDE_BY_ZERO,"线程尝试将浮点值除以 0 的浮点除数。"
}, {
EXCEPTION_FLT_INEXACT_RESULT,"浮点运算的结果不能完全表示为小数点。"
}, {
EXCEPTION_FLT_INVALID_OPERATION,"此异常表示此列表中未包含的任何浮点异常。"
}, {
EXCEPTION_FLT_OVERFLOW,"浮点运算的指数大于相应类型允许的量级。"
}, {
EXCEPTION_FLT_STACK_CHECK,"堆栈因浮点运算而溢出或下溢。"
}, {
EXCEPTION_FLT_UNDERFLOW,"浮点运算的指数小于相应类型允许的量级。"
}, {
EXCEPTION_ILLEGAL_INSTRUCTION,"线程尝试执行无效指令。"
}, {
EXCEPTION_IN_PAGE_ERROR,"线程尝试访问不存在的页面，但系统无法加载该页。 例如，如果在通过网络运行程序时网络连接断开，则可能会发生此异常。"
}, {
EXCEPTION_INT_DIVIDE_BY_ZERO,"线程尝试将整数值除以零的整数除数。"
}, {
EXCEPTION_INT_OVERFLOW,"整数运算的结果导致执行结果中最重要的位。"
}, {
EXCEPTION_INVALID_DISPOSITION,"异常处理程序向异常调度程序返回了无效处置。 使用高级语言（如 C）的程序员不应遇到此异常。"
}, {
EXCEPTION_NONCONTINUABLE_EXCEPTION,"线程尝试在发生不可连续的异常后继续执行。"
}, {
EXCEPTION_PRIV_INSTRUCTION,"线程尝试执行在当前计算机模式下不允许其操作的指令。"
}, {
EXCEPTION_SINGLE_STEP,"跟踪陷阱或其他单指令机制指示已执行一个指令。"
}, {
EXCEPTION_STACK_OVERFLOW,"线程占用了其堆栈。"
}, {
0xC0000409 ,"存在未捕获的快速异常。"}//STATUS_FAIL_FAST_EXCEPTION E06D7363
, {
EXCEPTION_UNKNOWN_ERROR_1 ,"某段代码抛出了一个异常，但没有人捕获它；也很可能是C++的运行时配置存在异常。"}
};
*/

std::string GetAccessStr(HANDLE hProc, LPCVOID Ptr)
{
	MEMORY_BASIC_INFORMATION BInfo;
	if (VirtualQueryEx(hProc, Ptr, &BInfo, sizeof(BInfo)))
	{
		auto it = TmpMap.find(BInfo.Protect);
		if (it == TmpMap.cend())
		{
			return "未知权限（请搜索“内存保护属性常量”以确定此值的含义）：" + std::to_string(BInfo.Protect);
		}
		else
		{
			return it->second;
		}
	}
	else return "获取失败";
}

bool IsExecutable(HANDLE hProc, LPCVOID Ptr)
{
	MEMORY_BASIC_INFORMATION BInfo;
	if (VirtualQueryEx(hProc, Ptr, &BInfo, sizeof(BInfo)))
	{
		if (BInfo.Protect == 0x10 || BInfo.Protect == 0x20 || BInfo.Protect == 0x40 || BInfo.Protect == 0x80)return true;
		else return false;
	}
	else return false;
}

std::string GetExcStr(int Exc)
{
	auto it = ExcMap.find(Exc);
	if (it == ExcMap.cend())
	{
		return "未知";
	}
	else
	{
		return it->second;
	}
}

bool LoadSymbolsForDLL(HANDLE hProcess, const std::wstring& dllName, const std::wstring& pdbPath, size_t Size, DWORD baseAddr, bool ForceLoad) 
{
	DWORD Orig = SymGetOptions();
	if (ForceLoad)SymSetOptions(Orig | SYMOPT_LOAD_ANYTHING);
	struct __Helper { DWORD Orig; bool ForceLoad;~__Helper() { if (ForceLoad)SymSetOptions(Orig); }}HLP{ Orig, ForceLoad };

	// 设置符号搜索路径
	if (!SymSetSearchPathW(hProcess, pdbPath.c_str())) 
	{
		Log::WriteLine(__FUNCTION__ ": SymSetSearchPath 设置失败，错误码 %d", GetLastError());
	}


	// 加载模块符号
	DWORD64 modBase = SymLoadModuleExW(
		hProcess,
		NULL,
		pdbPath.c_str(),
		dllName.c_str(),
		baseAddr,
		Size,        // 自动确定大小
		nullptr,   // 不需要额外数据
		0
	);

	IMAGEHLP_MODULEW64 hlp;
	hlp.SizeOfStruct = sizeof(hlp);
	if (!SymGetModuleInfoW64(hProcess, baseAddr, &hlp))
	{
		Log::WriteLine(__FUNCTION__ ": SymGetModuleInfoW64 获取模块信息失败，错误码 %d", GetLastError());
		//return false;
	}
	else
	{
		//output infor hlp
		Log::WriteLine(__FUNCTION__": hlp.BaseOfImage = %016llX", hlp.BaseOfImage);
		Log::WriteLine(__FUNCTION__": hlp.ImageSize = %u", hlp.ImageSize);
		Log::WriteLine(__FUNCTION__": hlp.TimeDateStamp = %u", hlp.TimeDateStamp);
		Log::WriteLine(__FUNCTION__": hlp.CheckSum = %u", hlp.CheckSum);
		Log::WriteLine(__FUNCTION__": hlp.ModuleName = %s", UnicodetoANSI(hlp.ModuleName).c_str());
		Log::WriteLine(__FUNCTION__": hlp.ImageName = %s", UnicodetoANSI(hlp.ImageName).c_str());
		Log::WriteLine(__FUNCTION__": hlp.LoadedImageName = %s", UnicodetoANSI(hlp.LoadedImageName).c_str());
		Log::WriteLine(__FUNCTION__": hlp.TypeInfo = %s", hlp.TypeInfo ? "true" : "false");
		Log::WriteLine(__FUNCTION__": hlp.SymType = %d", hlp.SymType);
		Log::WriteLine(__FUNCTION__": hlp.NumSyms = %u", hlp.NumSyms);
		Log::WriteLine(__FUNCTION__": hlp.Publics  = %s", hlp.Publics ? "true" : "false");
		Log::WriteLine(__FUNCTION__": hlp.LineNumbers  = %s", hlp.LineNumbers ? "true" : "false");
		
		/*
		SymEnumSymbolsW(hProcess, baseAddr, L"*",
			[](PSYMBOL_INFOW sym, ULONG sz, PVOID)
			{
				//Log::WriteLine(__FUNCTION__": Address = %016llX", sym->Address);
				//Log::WriteLine(__FUNCTION__": Name = %s", UnicodetoANSI(sym->Name).c_str());
				//Log::WriteLine(__FUNCTION__": Flags = %08X", sym->Flags);
				//Log::WriteLine(__FUNCTION__": Size = %u", sz);
				return TRUE; 
			},
			nullptr
		);
		*/
	}

	if (modBase == 0) {
		Log::WriteLine(__FUNCTION__ ": SymLoadModuleEx 失败, 错误码 %d", GetLastError());
		Log::WriteLine(__FUNCTION__ ": 加载PDB: \"%s\"", UnicodetoANSI(pdbPath).c_str());
		Log::WriteLine(__FUNCTION__ ": DLL: \"%s\"", UnicodetoANSI(dllName).c_str());
		Log::WriteLine(__FUNCTION__ ": 基址: %08X", baseAddr);
		Log::WriteLine(__FUNCTION__ ": 文件大小: %u", Size);
		// 尝试直接通过路径加载
		modBase = SymLoadModuleExW(
			hProcess,
			NULL,
			pdbPath.c_str(),
			dllName.c_str(),
			baseAddr,
			Size,
			nullptr,
			0
		);

		hlp.SizeOfStruct = sizeof(hlp);
		if (!SymGetModuleInfoW64(hProcess, baseAddr, &hlp))
		{
			Log::WriteLine(__FUNCTION__ ": SymGetModuleInfoW64 获取模块信息失败，错误码 %d", GetLastError());
			//return false;
		}

		if (modBase == 0) {
			Log::WriteLine(__FUNCTION__ ": DLL 载入符号失败, 错误码 %d", GetLastError());
			return false;
		}
	}

	Log::WriteLine(__FUNCTION__ ": \"%s\" 已在 %08X 处加载PDB符号。", UnicodetoANSI(dllName).c_str(), modBase);
	return true;
}

std::string GetFileName(const std::string& ss)//文件名
{
	using namespace std;
	auto p = ss.find_last_of('\\');
	return p == ss.npos ? ss : string(ss.begin() + min(p + 1, ss.length()), ss.end());
}

std::wstring GetFileName(const std::wstring& ss)//文件名
{
	using namespace std;
	auto p = ss.find_last_of('\\');
	return p == ss.npos ? ss : wstring(ss.begin() + min(p + 1, ss.length()), ss.end());
}

std::pair<DWORD, std::wstring>  ResolveFunctionSymbol(HANDLE hProcess, DWORD address) {
	
	
	
// 准备符号缓冲区
	SYMBOL_INFOW* pSymbol = (SYMBOL_INFOW*)malloc(sizeof(SYMBOL_INFOW) + MAX_SYM_NAME * sizeof(wchar_t));
	if (!pSymbol) return { 0, L"" };

	pSymbol->SizeOfStruct = sizeof(SYMBOL_INFOW);
	pSymbol->MaxNameLen = MAX_SYM_NAME;

	DWORD64 displacement = 0;

	// 尝试获取源文件信息
	IMAGEHLP_LINEW64 line;
	line.SizeOfStruct = sizeof(IMAGEHLP_LINEW64);
	DWORD lineDisplacement;
	bool HasLine = false;
	if (SymGetLineFromAddrW64(hProcess, address, &lineDisplacement, &line)) {
		HasLine = true;//return { DWORD(displacement), std::wstring(L"[源] ") + line.FileName + L":" + std::to_wstring(line.LineNumber) };
	}
	else {
		//Log::WriteLine(__FUNCTION__ ": SymGetLineFromAddrW64 获取源文件信息失败，错误码 %d", GetLastError());
	}


	if (SymFromAddrW(hProcess, address, &displacement, pSymbol)) {
		std::wstring result(pSymbol->Name);
		free(pSymbol);
		if (HasLine)
		{
			result += L'{';
			result += GetFileName(line.FileName);
			result += L"，行";
			result += std::to_wstring(line.LineNumber);
			result += L'}';
		}
		return { DWORD(displacement), result };
	}
	else {
		//Log::WriteLine(__FUNCTION__ ": SymFromAddrW 获取符号失败，错误码 %d", GetLastError());
	}

	free(pSymbol);

	if (HasLine)
	{
		return { DWORD(lineDisplacement), std::wstring(L"[源] ") + line.FileName + L":" + std::to_wstring(line.LineNumber) };
	}

	return { address, L"[未知]" };
}

const std::wstring& ExecutableDirectoryPathW();
void AddSymbolFromMapFile(HANDLE hProcess, DWORD64 moduleBase, DWORD Size, const std::wstring& fileName, const std::string& exeName);

bool g_symInitialized = false;

void SyringeDebugger::InitializeSymbols()
{
	if (g_symInitialized) return;
	SymSetOptions(SYMOPT_DEBUG | SYMOPT_UNDNAME | SYMOPT_LOAD_LINES);
	if (!SymInitialize(pInfo.hProcess, nullptr, FALSE)) 
	{
		Log::WriteLine(__FUNCTION__ ": 无法初始化符号引擎，错误代码: %d", GetLastError());
		return;
	}

	{
		std::filesystem::path Exe{ exe };
		Log::WriteLine(__FUNCTION__ ": Exe = %s", Exe.string().c_str());
		Log::WriteLine(__FUNCTION__ ": dwExeSize = %u", dwExeSize);
		Log::WriteLine(__FUNCTION__ ": ExeImageBase = %u", ExeImageBase);
		auto we = Exe.wstring();
		auto Map = we.substr(0, we.size() - 4) + L".map";
		auto Pdb = we.substr(0, we.size() - 4) + L".pdb";
		auto PdbPath = std::filesystem::path(Pdb);
		if (std::filesystem::exists(PdbPath))
		{
			LoadSymbolsForDLL(
				pInfo.hProcess,
				Exe.wstring(),
				PdbPath.wstring(),
				(size_t)std::filesystem::file_size(PdbPath),
				ExeImageBase,
				true
			);
		}
		else if (std::filesystem::exists(std::filesystem::path(Map)))
		{

			AddSymbolFromMapFile(
				pInfo.hProcess,
				ExeImageBase,
				dwExeSize,
				Map,
				GetFileName(exe)
			);
		}
	}
	
	

	/*
	LoadSymbolsForDLL(
		pInfo.hProcess,
		Exe.wstring(),
		Exe.wstring()+L".sym",
		(size_t)dwExeSize,
		ExeImageBase,
		true);*/


	//for(auto& [k,v]: LibAddr)
	//	Log::WriteLine("已加载库：%s 基址：0x%08X", k.c_str(), v);

	for (auto& [Name, Lib] : LibExt)
	{
		Log::WriteLine("Name = %s", Name.c_str());

		auto fn = GetFileName(Name);
		for (auto& c : fn)c = (char)toupper(c);

		if (Lib.PDBExists)
		{
			LoadSymbolsForDLL(
				pInfo.hProcess,
				Lib.ModuleName,
				Lib.PDBPath,
				(size_t)Lib.PDBSize,
				LibAddr[fn],
				false);
		}
		else if (Lib.MAPExists)
		{
			std::filesystem::path dllPath{ Name };
			AddSymbolFromMapFile(
				pInfo.hProcess,
				LibAddr[fn],
				(DWORD)std::filesystem::file_size(dllPath),
				Lib.MAPPath,
				GetFileName(Name)
			);
		}
	}

	

	
	
	g_symInitialized = true;
}

void SyringeDebugger::Handle_StackDump(DEBUG_EVENT const& dbgEvent)
{
	auto const exceptCode = dbgEvent.u.Exception.ExceptionRecord.ExceptionCode;
	auto const exceptAddr = dbgEvent.u.Exception.ExceptionRecord.ExceptionAddress;
	auto const AccessAddr = dbgEvent.u.Exception.ExceptionRecord.ExceptionInformation[1];

	InitializeSymbols();

	auto [Rel, Str] = AnalyzeAddr((DWORD)exceptAddr);
	Log::WriteLine(
		__FUNCTION__ ": 发生异常，代码: 0x%08X ", exceptCode);
	Log::WriteLine(
		"(可能原因：%s)", GetExcStr(exceptCode).c_str());
	Log::WriteLine(
		"地址： 0x%08X（%s+%X）[访问权限：%s]", 
		exceptAddr, Str.c_str(), Rel, GetAccessStr(pInfo.hProcess, exceptAddr).c_str());
	if (IsExecutable(pInfo.hProcess, (LPCVOID)exceptAddr))Log::WriteLine("发生异常的地址为可执行的代码。");
	else Log::WriteLine("发生异常的地址不是代码，可能为分配的内存。");
	if (ExceptionReportAlwaysFull || !bAVLogged)
	{
		//Log::WriteLine(__FUNCTION__ ": ACCESS VIOLATION at 0x%08X!", exceptAddr);
		auto const& threadInfo = Threads[dbgEvent.dwThreadId];
		HANDLE currentThread = threadInfo.Thread;

		char const* access = nullptr;
		switch (dbgEvent.u.Exception.ExceptionRecord.ExceptionInformation[0])
		{
		case 0: access = "读取"; break;
		case 1: access = "写入"; break;
		case 8: access = "执行"; break;
		}

		auto [Rel2, Str2] = AnalyzeAddr((DWORD)AccessAddr);
		Log::WriteLine("程序试图%s 0x%08X（%s+%X）[访问权限：%s]。",
			access ? access : ("<未知行为：" + std::to_string(dbgEvent.u.Exception.ExceptionRecord.ExceptionInformation[0]) + ">").c_str(),
			AccessAddr, Str2.c_str(), Rel2,
			GetAccessStr(pInfo.hProcess, (LPCVOID)AccessAddr).c_str());
		if (IsExecutable(pInfo.hProcess, (LPCVOID)AccessAddr))Log::WriteLine("试图访问的地址为可执行的代码。");
		else Log::WriteLine("试图访问的地址不是代码，可能为分配的内存。");


		CONTEXT context;
		context.ContextFlags = CONTEXT_FULL;
		GetThreadContext(currentThread, &context);

		Log::WriteLine();
		Log::WriteLine("寄存器：");
		Log::WriteLine("\tEAX = 0x%08X\tECX = 0x%08X\tEDX = 0x%08X",
			context.Eax, context.Ecx, context.Edx);
		Log::WriteLine("\tEBX = 0x%08X\tESP = 0x%08X\tEBP = 0x%08X",
			context.Ebx, context.Esp, context.Ebp);
		Log::WriteLine("\tESI = 0x%08X\tEDI = 0x%08X\tEIP = 0x%08X",
			context.Esi, context.Edi, context.Eip);
		Log::WriteLine();



		Log::WriteLine("\t堆栈转储信息：（按可能的栈帧分段）");
		auto const esp = reinterpret_cast<DWORD*>(context.Esp);
		auto const eend = LongStackDump ? (DWORD*)0xFFFFFFFF : esp + 0x100;
		bool PrevHook = false;
		for (auto p = esp; p < eend; ++p)
		{
			DWORD dw;
			if (ReadMem(p, &dw, 4)) {
				if (dw >= 0x10000 && dw <= 0xFFFF0000)
				{
					
					auto [Rel1, Str1] = AnalyzeAddr(dw);
					if (IsExecutable(pInfo.hProcess, (LPCVOID)dw))
					{
						if (PrevHook)
						{
							Log::WriteLine("（钩子地址为%X）", dw);
							PrevHook = false;
						}
						else if (!OnlyShowStackFrame)
							Log::WriteLine();
					}
					else if (OnlyShowStackFrame)
					{
						continue;
					}
					if (Database.InHookRange(dw))PrevHook = true;
					Log::WriteLine("\t0x%08X:\t0x%08X （%s+%X）[访问权限：%s]", 
						p, dw, Str1.c_str(), Rel1,
						GetAccessStr(pInfo.hProcess, (LPCVOID)dw).c_str());
				}
				else if(!OnlyShowStackFrame)
				{
					Log::WriteLine("\t0x%08X:\t0x%08X", p, dw);
				}
			}
			else {
				if (LongStackDump)
				{
					break;
				}
				Log::WriteLine("\t0x%08X:\t（无法读取）", p);
			}
		}
		Log::WriteLine();
#if 0
		Log::WriteLine("Making crash dump:\n");
		MINIDUMP_EXCEPTION_INFORMATION expParam;
		expParam.ThreadId = dbgEvent.dwThreadId;
		EXCEPTION_POINTERS ep;
		ep.ExceptionRecord = const_cast<PEXCEPTION_RECORD>(&dbgEvent.u.Exception.ExceptionRecord);
		ep.ContextRecord = &context;
		expParam.ExceptionPointers = &ep;
		expParam.ClientPointers = FALSE;

		wchar_t filename[MAX_PATH];
		wchar_t path[MAX_PATH];
		SYSTEMTIME time;

		GetLocalTime(&time);
		GetCurrentDirectoryW(MAX_PATH, path);

		swprintf(filename, MAX_PATH, L"%s\\syringe.crashed.%04u%02u%02u-%02u%02u%02u.dmp",
			path, time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond);

		HANDLE dumpFile = CreateFileW(filename, GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_WRITE | FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_FLAG_WRITE_THROUGH, nullptr);

		MINIDUMP_TYPE type = (MINIDUMP_TYPE)MiniDumpWithFullMemory;

		MiniDumpWriteDump(pInfo.hProcess, dbgEvent.dwProcessId, dumpFile, type, &expParam, nullptr, nullptr);
		CloseHandle(dumpFile);

		Log::WriteLine("Crash dump generated.\n");
#endif

		bAVLogged = true;
		if (InfiniteWaitForDebug)
		{	
			Log::WriteLine("Syringe正在等待调试……");
			Log::Flush();
			MessageBoxW(NULL, L"Syringe遇到了异常。点击确定以继续运行程序。", VersionLString, MB_OK);
		}
	}
}

void SyringeDebugger::PreloadData()
{
	RemoteMapSuffix = pInfo.dwProcessId;
	SharedMemHeader hd;
	hd.WritingComplete = 0;
	hd.RecordCount = DLLs.size();
	hd.RecordSize = sizeof(SharedMemRecord);
	hd.TotalSize = hd.RecordCount * hd.RecordSize + sizeof(SharedMemHeader);
	hd.ReservedHandle = GetCurrentProcessId();
	Mapper.Create(hd, RemoteMapSuffix, "SYRINGE");
	auto pArr = Mapper.OffsetPtr<SharedMemRecord>(sizeof(SharedMemHeader));
	for (size_t i = 0; i < DLLShort.size(); i++)
	{
		pArr[i].TargetHash = QuickHashCStrUpper(DLLShort[i].c_str());
	}

	if (RunningYR)
	{
		Log::WriteLine(__FUNCTION__ ": 正在写入运行前信息……");
		//Log::WriteLine(__FUNCTION__ ": 假定启动了标准的YR V1.001。");
		Database.CreateData();
		Log::WriteLine(__FUNCTION__ ": 运行前信息创建完毕。");
		Database.WriteToStream();
		for (auto& p : LibExt)Database.CopyAndPush(p.second.GetMemCopy());
		Database.CopyAndPushEnd();
		Log::WriteLine(__FUNCTION__ ": 运行前信息打包完毕。");
		Database.SendData();
		Log::WriteLine(__FUNCTION__ ": 运行前信息写入完毕。");
	}


	if (GenerateINJ)
	{
		Log::WriteLine(__FUNCTION__ ": 正在创建INJ文件……");
		if(Analyzer.GenerateINJ())
			Log::WriteLine(__FUNCTION__ ": INJ文件创建完成。");
		else Log::WriteLine(__FUNCTION__ ": INJ文件创建失败。");
	}
}

DWORD SyringeDebugger::Handle_BreakPoint(DEBUG_EVENT const& dbgEvent)
{
	auto const exceptCode = dbgEvent.u.Exception.ExceptionRecord.ExceptionCode;
	auto const exceptAddr = dbgEvent.u.Exception.ExceptionRecord.ExceptionAddress;
	
	auto& threadInfo = Threads[dbgEvent.dwThreadId];
	HANDLE currentThread = threadInfo.Thread;
	CONTEXT context;

	context.ContextFlags = CONTEXT_CONTROL;
	GetThreadContext(currentThread, &context);

	// entry breakpoint
	if (bEntryBP)
	{
		bEntryBP = false;
		return DBG_CONTINUE;
	}

	// fix single step repetition issues
	if (context.EFlags & 0x100)
	{
		auto const buffer = INT3;
		context.EFlags &= ~0x100;
		PatchMem(threadInfo.lastBP, &buffer, 1);
	}

	// load DLLs and retrieve proc addresses
	if (!bDLLsLoaded)
	{

		// restore
		PatchMem(exceptAddr, &Breakpoints[exceptAddr].original_opcode, 1);
		if (!LoadedCount && DLLs.size())
			PreloadData();
		if (LoadedCount < (int)DLLs.size())
		{
			strcpy(ExLoadingLib, DLLs[LoadedCount].c_str());
			PatchMem(&GetData()->LibName, ExLoadingLib, MaxNameLength);
			PatchMem(&GetData()->ProcName, ExProc, MaxNameLength);

			Log::WriteLine(__FUNCTION__ ": 预加载 （%d/%d）%s", LoadedCount + 1, DLLs.size() + 1, DLLShort[LoadedCount].c_str());
			LoadedCount++;

			context.Eip = reinterpret_cast<DWORD>(&GetData()->LoadLibraryFunc);
			context.EFlags |= 0x100;
			context.ContextFlags = CONTEXT_CONTROL;
			SetThreadContext(currentThread, &context);
			threadInfo.lastBP = exceptAddr;
			return DBG_CONTINUE;
		}

		if (FirstHook)
		{

			PatchMem(&GetData()->LibName, ExLib, MaxNameLength);
			PatchMem(&GetData()->ProcName, ExProc, MaxNameLength);
			Log::WriteLine(__FUNCTION__ ": 预加载 （%d/%d）SyringeEx.dll", DLLs.size() + 1, DLLs.size() + 1);

			context.Eip = reinterpret_cast<DWORD>(&GetData()->LoadLibraryFunc);
			FirstHook = false;
			context.EFlags |= 0x100;
			context.ContextFlags = CONTEXT_CONTROL;
			SetThreadContext(currentThread, &context);
			threadInfo.lastBP = exceptAddr;
			return DBG_CONTINUE;
		}
#pragma warning(push)
#pragma warning(disable:4244)//屏蔽有关toupper的警告
		if (loop_LoadLibrary == v_AllHooks.end())
		{
			SetEnvironmentVariable("HERE_IS_SYRINGE", "1");
			auto hSyringeEx = LoadLibraryA(ExLib);
			if (!hSyringeEx)
			{
				Log::WriteLine("无法注入SyringeEx.dll。Syringe注入代码失败，即将退出……");
				MessageBoxA(NULL, "无法注入SyringeEx.dll。Syringe注入代码失败，即将退出……", VersionString, MB_OK | MB_ICONERROR);
				throw_lasterror((DWORD)-1, "");
			}
			SetEnvironmentVariable("HERE_IS_SYRINGE", NULL);
			
			
			auto pHeader = Mapper.OffsetPtr<SharedMemHeader>(0);
			
			if (Mapper.Available() && hSyringeEx)
			{
				if (DLLs.size())while (!pHeader->WritingComplete);
				NullOutput = pHeader->ReservedPtr;
				auto pArr = Mapper.OffsetPtr<SharedMemRecord>(sizeof(SharedMemHeader));
				for (size_t i = 0; i < DLLShort.size(); i++)
				{
					Log::WriteLine("通过Syringe载入的DLL: %s = 0x%08X", DLLShort[i].c_str(), pArr[i].BaseAddr);
					std::transform(DLLShort[i].begin(), DLLShort[i].end(), DLLShort[i].begin(), ::toupper);
					//LibAddr[DLLShort[i]] = pArr[i].BaseAddr;
				}

				LibBase.resize(Mapper.Header()->DllRecordCount);
				//Log::WriteLine("All DLL: at 0x%08X", Mapper.Header()->DllRecordAddr);
				if (!ReadMem((LPCVOID)Mapper.Header()->DllRecordAddr, (LPVOID)LibBase.data(), Mapper.Header()->DllRecordCount * sizeof(SharedMemRecord)))
					Log::WriteLine(__FUNCTION__ ": 载入DLL读入失败。");
				std::sort(LibBase.begin(), LibBase.end(), [](const auto& lhs, const auto& rhs)->bool
					{
						return lhs.BaseAddr < rhs.BaseAddr;
					});
				int j = 1;
				for (auto p : LibBase)
				{
					auto Str = UnicodetoANSI(p.Name);
					std::transform(Str.begin(), Str.end(), Str.begin(), ::toupper);
					LibAddr[Str] = p.BaseAddr;
					Log::WriteLine("获取模块（%d/%d）：%hs = 0x%08X", j, LibBase.size(), Str.c_str(), p.BaseAddr);
					++j;
				}

				for (auto& it : BreakpointRel)
				{
					for (auto& i : it.second.hooks)
					{
						for (char* p = i.RelativeLib; *p; ++p)
						{
							*p = ::toupper(*p);
						}
						auto ait = LibAddr.find(i.RelativeLib);
						if (ait == LibAddr.end())
						{
							Log::WriteLine(__FUNCTION__ ": 无法载入相对钩子：来自库\"%s\"的函数\"%s\"试图从未通过Syringe载入的\"%s\"寻址。", i.lib, i.proc, i.RelativeLib);
							continue;
						}
						auto& hks = Breakpoints[(LPVOID)((DWORD)it.first + ait->second)].hooks;
						hks.push_back(i);
						v_AllHooks.push_back(&hks.back());
						//Log::WriteLine("载入相对钩子：来自库\"%s\"的函数\"%s\"，位于%s + 0x%X (0x%08X)。", i.lib, i.proc, i.RelativeLib, it.first, ((DWORD)it.first + ait->second));
					}
				}
			}
			//if(hSyringeEx)CloseHandle(hSyringeEx);
			loop_LoadLibrary = v_AllHooks.begin();
#pragma warning(pop)
		}
		else
		{
			auto const& hook = *loop_LoadLibrary;
			ReadMem(&GetData()->ProcAddress, &hook->proc_address, 4);

			if (!hook->proc_address) {
				Log::WriteLine(
					__FUNCTION__ ": 不能在 %s 库中找到函数"
					" %s", hook->lib, hook->proc);
			}

			++loop_LoadLibrary;
		}

		if (loop_LoadLibrary != v_AllHooks.end())
		{
			auto const& hook = *loop_LoadLibrary;
			PatchMem(&GetData()->LibName, hook->lib, MaxNameLength);
			PatchMem(&GetData()->ProcName, hook->proc, MaxNameLength);

			context.Eip = reinterpret_cast<DWORD>(&GetData()->LoadLibraryFunc);
		}
		else
		{
			Log::WriteLine(__FUNCTION__ ": 成功载入所需函数地址.");
			Log::Flush();
			bDLLsLoaded = true;

			context.Eip = reinterpret_cast<DWORD>(pcEntryPoint);
		}

		// single step mode
		context.EFlags |= 0x100;
		context.ContextFlags = CONTEXT_CONTROL;
		SetThreadContext(currentThread, &context);

		threadInfo.lastBP = exceptAddr;

		return DBG_CONTINUE;
	}

	if (exceptAddr == pcEntryPoint)
	{
		if (!bHooksCreated)
			Handle_ApplyHook();

		// restore
		PatchMem(exceptAddr, &Breakpoints[exceptAddr].original_opcode, 1);

		// single step mode
		context.EFlags |= 0x100;
		--context.Eip;

		context.ContextFlags = CONTEXT_CONTROL;
		SetThreadContext(currentThread, &context);

		threadInfo.lastBP = exceptAddr;
		EverythingIsOK = true;

		return DBG_CONTINUE;
	}
	else
	{
		// could be a Debugger class breakpoint to call a patching function!

		context.ContextFlags = CONTEXT_CONTROL;
		SetThreadContext(currentThread, &context);
		EverythingIsOK = true;

		auto [V, S] = AnalyzeAddr(context.Eip);
		Log::WriteLine(__FUNCTION__ ": 意外断点：0x%08X (%s+0x%X)", context.Eip, S.c_str(), V);
		MessageBoxA(NULL, __FUNCTION__ ": 遇到了意外的断点。详见Syringe.log。", VersionString, MB_ICONEXCLAMATION | MB_OK);

		return DBG_EXCEPTION_NOT_HANDLED;
	}
}

DWORD SyringeDebugger::HandleException(DEBUG_EVENT const& dbgEvent)
{
	auto const exceptCode = dbgEvent.u.Exception.ExceptionRecord.ExceptionCode;

	if(exceptCode == EXCEPTION_BREAKPOINT)
		//整个载入流程都在这了。不用管Return，哥们，这里写代码的顺序就是执行的顺序，这个函数会连续执行好几千次，从前到后把每一块执行完毕
	{
		//Log::WriteLine(__FUNCTION__ ": EXCEPTION_BREAKPOINT");
		return Handle_BreakPoint(dbgEvent);
	}
	else if(exceptCode == EXCEPTION_SINGLE_STEP)
	{
		//Log::WriteLine(__FUNCTION__ ": EXCEPTION_SINGLE_STEP");
		auto const buffer = INT3;
		auto const& threadInfo = Threads[dbgEvent.dwThreadId];
		PatchMem(threadInfo.lastBP, &buffer, 1);

		HANDLE hThread = threadInfo.Thread;
		CONTEXT context;

		context.ContextFlags = CONTEXT_CONTROL;
		GetThreadContext(hThread, &context);

		context.EFlags &= ~0x100;

		context.ContextFlags = CONTEXT_CONTROL;
		SetThreadContext(hThread, &context);

		if (EverythingIsOK && DetachAfterInjection)
		{
			PrepareForDetach = true;
		}

		return DBG_CONTINUE;
	}
	//else if (exceptCode == 114514)
	else if (exceptCode == EXCEPTION_UNKNOWN_ERROR_1)//非致命的
	{
		/*
		char Buf[260];
		Log::WriteLine(__FUNCTION__ ": EXCEPTION_UNKNOWN_ERROR_1");
		GetExceptionWhatSafe(
			pInfo.hProcess,
			&dbgEvent.u.Exception.ExceptionRecord,
			Buf, 
			sizeof(Buf)
		);
		Log::WriteLine(__FUNCTION__ ": EXCEPTION_UNKNOWN_ERROR_1: %s", Buf);
		*/

		char Buf[260];
		auto ptr = dbgEvent.u.Exception.ExceptionRecord.ExceptionInformation[1];
		//Log::WriteLine(__FUNCTION__ ": EXCEPTION_UNKNOWN_ERROR_1  ADDR = %08X", ptr);
		//MessageBoxA(NULL, "!!", "!!", MB_OK);
		
		//read ptr+4 as a pointer REMOTELY
		LPVOID pRemotePtr;
		ReadMem(((LPBYTE)ptr) + 4, &pRemotePtr, sizeof(pRemotePtr));
		ReadMem(pRemotePtr, Buf, sizeof(Buf) - 1);
		//Log::WriteLine(__FUNCTION__ ": EXCEPTION_UNKNOWN_ERROR_1: %s", Buf);

		ReadMem(((LPBYTE)ptr), &pRemotePtr, sizeof(pRemotePtr));
		auto [Rel, DllStr]=AnalyzeAddr((DWORD)pRemotePtr);

		//Log::WriteLine(__FUNCTION__ ": EXCEPTION_UNKNOWN_ERROR_1");
		Log::WriteLine("程序触发了一个可能已经捕获的异常。（一般不会影响运行）");
		Log::WriteLine("%s ：%s", DllStr.c_str(), Buf);
		if(CheckInsignificantException)Handle_StackDump(dbgEvent);
		return DBG_EXCEPTION_NOT_HANDLED;
	}
	else
	{
		//Log::WriteLine(__FUNCTION__ ": StackDump");
		Handle_StackDump(dbgEvent);
		return DBG_EXCEPTION_NOT_HANDLED;
	}

	return DBG_CONTINUE;
}



void SyringeDebugger::Run(std::string_view const arguments)
{
	constexpr auto AllocDataSize = sizeof(AllocData);

	Log::WriteLine(
		__FUNCTION__ ": 开始调试。 命令行： \"%s %.*s\"",
		exe.c_str(), printable(arguments));
	DebugProcess(arguments);

	Log::WriteLine(__FUNCTION__ ": 分配了 0x%u 个字节的内存。", AllocDataSize);
	pAlloc = AllocMem(nullptr, AllocDataSize);

	

	Log::WriteLine(__FUNCTION__ ": 该段内存的地址： 0x%08X", pAlloc.get());

	// write DLL loader code
	Log::WriteLine(__FUNCTION__ ": 正在写入DLL的载入、调用代码……");

	static BYTE const cLoadLibrary[] = {
		//0x50, // push eax
		//0x64, 0xA1, 0x30, 0x00, 0x00, 0x00, //mov eax, fs:[0x30]
		//0xA3, INIT, INIT, INIT, INIT, //mov PEBTableEntry, eax
		//0x58, // pop eax
		0x50, // push eax
		0x51, // push ecx
		0x52, // push edx
		0x68, INIT, INIT, INIT, INIT, // push offset pdLibName
		0xFF, 0x15, INIT, INIT, INIT, INIT, // call pImLoadLibrary
		0x85, 0xC0, // test eax, eax
		0x74, 0x0C, // jz
		0x68, INIT, INIT, INIT, INIT, // push offset pdProcName
		0x50, // push eax
		0xFF, 0x15, INIT, INIT, INIT, INIT, // call pdImGetProcAddress
		0xA3, INIT, INIT, INIT, INIT, // mov pdProcAddress, eax
		0x5A, // pop edx
		0x59, // pop ecx
		0x58, // pop eax
		INT3, NOP, //NOP, NOP, NOP // int3 and some padding
	};

	std::array<BYTE, AllocDataSize> data;
	static_assert(AllocData::CodeSize >= sizeof(cLoadLibrary));
	ApplyPatch(data.data(), cLoadLibrary);
	ApplyPatch(data.data() + 0x04, &GetData()->LibName);
	ApplyPatch(data.data() + 0x0A, pImLoadLibrary);
	ApplyPatch(data.data() + 0x13, &GetData()->ProcName);
	ApplyPatch(data.data() + 0x1A, pImGetProcAddress);
	ApplyPatch(data.data() + 0x1F, &GetData()->ProcAddress);
	ApplyPatch(data.data() + 0x2E, Database.GetDblInteractData().FinalAddr);
	PatchMem(pAlloc, data.data(), data.size());

	Log::WriteLine(__FUNCTION__ ": 载入代码位于 0x%08X", &GetData()->LoadLibraryFunc);

	// breakpoints for DLL loading and proc address retrieving
	bDLLsLoaded = false;
	bHooksCreated = false;
	loop_LoadLibrary = v_AllHooks.end();

	// set breakpoint
	Log::WriteLine(__FUNCTION__ ": 设置入口处的断点。");
	SetBP(pcEntryPoint);

	DEBUG_EVENT dbgEvent;
	ResumeThread(pInfo.hThread);

	bAVLogged = false;
	Log::WriteLine(__FUNCTION__ ": 开始调试循环。");
	auto exit_code = static_cast<DWORD>(-1);
	Log::Flush();

	for(;;)
	{
		WaitForDebugEvent(&dbgEvent, INFINITE);

		DWORD continueStatus = DBG_CONTINUE;
		bool wasBP = false;

		switch(dbgEvent.dwDebugEventCode)
		{
		case CREATE_PROCESS_DEBUG_EVENT:
			pInfo.hProcess = dbgEvent.u.CreateProcessInfo.hProcess;
			pInfo.dwThreadId = dbgEvent.dwProcessId;
			pInfo.hThread = dbgEvent.u.CreateProcessInfo.hThread;
			pInfo.dwThreadId = dbgEvent.dwThreadId;
			Threads.emplace(dbgEvent.dwThreadId, dbgEvent.u.CreateProcessInfo.hThread);
			CloseHandle(dbgEvent.u.CreateProcessInfo.hFile);
			break;

		case CREATE_THREAD_DEBUG_EVENT:
			Threads.emplace(dbgEvent.dwThreadId, dbgEvent.u.CreateThread.hThread);
			break;

		case EXIT_THREAD_DEBUG_EVENT:
			if(auto const it = Threads.find(dbgEvent.dwThreadId); it != Threads.end())
			{
				it->second.Thread.release();
				Threads.erase(it);
			}
			break;

		case EXCEPTION_DEBUG_EVENT:
			continueStatus = HandleException(dbgEvent);
			wasBP = (dbgEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT);
			break;

		case LOAD_DLL_DEBUG_EVENT:
			CloseHandle(dbgEvent.u.LoadDll.hFile);
			break;

		case OUTPUT_DEBUG_STRING_EVENT:
			break;
		}

		if(dbgEvent.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
			exit_code = dbgEvent.u.ExitProcess.dwExitCode;
			break;
		} else if(dbgEvent.dwDebugEventCode == RIP_EVENT) {
			break;
		}

		ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, continueStatus);

		if (PrepareForDetach)
		{
			DebugSetProcessKillOnExit(FALSE);
			CloseHandle(pInfo.hProcess);
			Log::WriteLine(__FUNCTION__ ": Syringe将分离并结束运行，已注入的代码将保留。");
			Log::WriteLine();
			return;
		}
	}

	SymCleanup(pInfo.hProcess);
	CloseHandle(pInfo.hProcess);

	Log::WriteLine(
		__FUNCTION__ ": 正常退出，返回码：%X (%u).", exit_code, exit_code);
	Log::WriteLine();	
}

void SyringeDebugger::RemoveBP(LPVOID const address, bool const restoreOpcode)
{
	if(auto const i = Breakpoints.find(address); i != Breakpoints.end()) {
		if(restoreOpcode) {
			PatchMem(address, &i->second.original_opcode, 1);
		}

		Breakpoints.erase(i);
	}
}

void SyringeDebugger::RetrieveInfo()
{
	Database.Init(this);
	
	Log::WriteLine(
		__FUNCTION__ ": 正在从可执行文件 \"%s\" 中读入信息……", exe.c_str());

	try {
		PortableExecutable pe{ exe };
		auto const dwImageBase = pe.GetImageBase();

		ExeImageBase = dwImageBase;

		// creation time stamp
		dwTimeStamp = pe.GetPEHeader().FileHeader.TimeDateStamp;

		// entry point
		pcEntryPoint = reinterpret_cast<void*>(dwImageBase + pe.GetPEHeader().OptionalHeader.AddressOfEntryPoint);

		// get imports
		pImLoadLibrary = nullptr;
		pImGetProcAddress = nullptr;

		for(auto const& import : pe.GetImports()) {
			if(_strcmpi(import.Name.c_str(), "KERNEL32.DLL") == 0) {
				for(auto const& thunk : import.vecThunkData) {
					if(_strcmpi(thunk.Name.c_str(), "GETPROCADDRESS") == 0) {
						pImGetProcAddress = reinterpret_cast<void*>(dwImageBase + thunk.Address);
					} else if(_strcmpi(thunk.Name.c_str(), "LOADLIBRARYA") == 0) {
						pImLoadLibrary = reinterpret_cast<void*>(dwImageBase + thunk.Address);
					}
				}
			}
		}
	} catch(...) {
		Log::WriteLine(__FUNCTION__ ": 无法打开可执行文件 \"%s\"", exe.c_str());

		throw;
	}

	if(!pImGetProcAddress || !pImLoadLibrary) {
		Log::WriteLine(
			__FUNCTION__ ": 错误：无法载入 LoadLibraryA 和 GetProcAddress ！");

		throw_lasterror_or(ERROR_PROC_NOT_FOUND, exe);
	}

	// read meta information: size and checksum
	if(ifstream is{ exe, ifstream::binary }) {
		is.seekg(0, ifstream::end);
		dwExeSize = static_cast<DWORD>(is.tellg());
		is.seekg(0, ifstream::beg);

		CRC32 crc;
		char buffer[0x1000];
		while(auto const read = is.read(buffer, std::size(buffer)).gcount()) {
			crc.compute(buffer, read);
		}
		dwExeCRC = crc.value();
	}

	Log::WriteLine(__FUNCTION__ ": 成功载入可执行文件的信息。");
	Log::WriteLine("\t文件名：%s", exe.c_str());
	Log::WriteLine("\tLoadLibrary位于：0x%08X", pImLoadLibrary);
	Log::WriteLine("\tGetProcAddress位于：0x%08X", pImGetProcAddress);
	Log::WriteLine("\tEntryPoint位于：0x%08X", pcEntryPoint);
	Log::WriteLine("\t文件大小：0x%08X", dwExeSize);
	Log::WriteLine("\t文件CRC值：0x%08X", dwExeCRC);
	Log::WriteLine("\t载入时间戳：0x%08X", dwTimeStamp);
	Log::WriteLine();

	Log::WriteLine(__FUNCTION__ ": 打开 %s 以确定载入所需信息。", exe.c_str());
}

const std::string& ExecutableDirectoryPath()
{
	static std::string ss;
	if (!ss.empty())return ss;
	std::vector<char> full_path_exe(MAX_PATH);

	for (;;)
	{
		const DWORD result = GetModuleFileName(NULL,
			&full_path_exe[0],
			full_path_exe.size());

		if (result == 0)
		{
			// Report failure to caller. 
		}
		else if (full_path_exe.size() == result)
		{
			// Buffer too small: increase size. 
			full_path_exe.resize(full_path_exe.size() * 2);
		}
		else
		{
			// Success. 
			break;
		}
	}

	// Remove executable name. 
	std::string result(full_path_exe.begin(), full_path_exe.end());
	std::string::size_type i = result.find_last_of("\\/");
	if (std::string::npos != i) result.erase(i);

	ss = result;
	return ss;
}

const std::wstring& ExecutableDirectoryPathW()
{
	static std::wstring ss;
	if (!ss.empty())return ss;
	std::vector<wchar_t> full_path_exe(MAX_PATH);

	for (;;)
	{
		const DWORD result = GetModuleFileNameW(NULL,
			&full_path_exe[0],
			full_path_exe.size());

		if (result == 0)
		{
			// Report failure to caller. 
		}
		else if (full_path_exe.size() == result)
		{
			// Buffer too small: increase size. 
			full_path_exe.resize(full_path_exe.size() * 2);
		}
		else
		{
			// Success. 
			break;
		}
	}

	// Remove executable name. 
	std::wstring result(full_path_exe.begin(), full_path_exe.end());
	std::wstring::size_type i = result.find_last_of(L"\\/");
	if (std::string::npos != i) result.erase(i);

	ss = result;
	return ss;
}

std::vector<std::string> SimpleDLLs;


void SyringeDebugger::FindDLLsLoop(const FindFile& file,const std::string& Path, bool AlwaysLoad)
{
	std::string fn = UnicodetoANSI(file->cFileName);
	std::string AbsPath = Path + "\\" + fn;
	std::string cfn = fn;

	bool HasHandshake = true;

	for (auto& c : cfn)c = (char)::toupper(c);
	if (cfn == "SYRINGEEX.DLL")
	{
		Log::WriteLine(
			__FUNCTION__ ": 跳过 DLL ：\"%.*s\"", printable(fn));
		return;
	}

	try {
		PortableExecutable DLL{ AbsPath };
		HookBuffer buffer;

		//Log::WriteLine(__FUNCTION__ ": Opening %s as a dll Handle : %08X", UnicodetoANSI(file->cFileName).c_str(), (uint32_t)(FILE*)DLL.GetHandle());
		//for (auto& [Name, Addr] : DLL.GetExportSymbols())Log::WriteLine(__FUNCTION__ ": %s = %08X", Name.c_str(), Addr);

		auto Export = DLL.GetExportSymbols();
		if (!Export.count("SyringeHandshake"))HasHandshake = false;
		if (Export.count("SyringeForceLoad"))AlwaysLoad = true;

		auto canLoad = false;
		auto const hooks = DLL.FindSection(".syhks00");
		if (hooks || DLL.FindSection(".hphks00")) {
			canLoad = ParseHooksSection(DLL, hooks, buffer);
		}
		else {
			canLoad = ParseInjFileHooks(AbsPath, buffer);
		}

		if (AlwaysLoad)canLoad = true;

		if (canLoad)
		{
			Log::WriteLine(
				__FUNCTION__ ": 已识别到 DLL：\"%.*s\"", printable(fn));
			DLLs.push_back(AbsPath);
			DLLShort.emplace_back(fn);

			auto const jsf = AbsPath + ".json";
			auto& Ext = LibExt[AbsPath];
			Ext.ReadFromFile(jsf, AbsPath);
			if (Ext.Available())
			{
				Ext.PushDiasbleHooks(IdxSet);
			}
			for (auto& h : Ext.GetHooks())
			{
				auto eip = h.proc_address;
				h.proc_address = 0;
				buffer.add(eip, h);
			}

			auto const pdbname = AbsPath.substr(0, AbsPath.size() - 4) + ".pdb";
			std::filesystem::path pdbPath(pdbname);
			if (std::filesystem::exists(pdbPath))Ext.SetPDBPath(pdbPath.wstring(), (size_t)std::filesystem::file_size(pdbPath));
			else Ext.SetPDBPath(L"", 0);

			if (!Ext.PDBExists)
			{
				auto const mapname = AbsPath.substr(0, AbsPath.size() - 4) + ".map";
				std::filesystem::path mapPath(mapname);
				if (std::filesystem::exists(mapPath))Ext.SetMAPPath(mapPath.wstring());
				else Ext.SetMAPPath(L"");
			}

			std::filesystem::path AbsPathW(AbsPath);
			Ext.ModuleName = AbsPathW.wstring();

			Database.CreateLibData(Ext, DLL, fn, AbsPath);
		}

		if (canLoad) {
			auto const res = (EnableHandshakeCheck && HasHandshake) ? Handshake(
				DLL.GetFilename(), static_cast<int>(buffer.count),
				buffer.checksum.value()) : true;
			if (res)
			{
				canLoad = *res;
			}
			else if (auto const hosts = DLL.FindSection(".syexe00")) {
				canLoad = CanHostDLL(DLL, *hosts);
			}
		}


		if (canLoad) {
			for (auto const& it : buffer.hooks) {
				auto const eip = it.first;
				auto& h = Breakpoints[eip];
				h.p_caller_code.clear();
				h.original_opcode = 0x00;
				h.hooks.insert(
					h.hooks.end(), it.second.begin(), it.second.end());
			}
			for (auto const& it : buffer.hookExt) {
				auto const eip = it.first;
				auto& h = BreakpointRel[eip];
				h.p_caller_code.clear();
				h.original_opcode = 0x00;
				h.hooks.insert(
					h.hooks.end(), it.second.begin(), it.second.end());
			}
		}
		else if (!buffer.hooks.empty()) {
			Log::WriteLine(
				__FUNCTION__ ": DLL \"%.*s\" 中无法检测到钩子，停止载入",
				printable(fn));
		}
	}
	catch (...) {
		Log::WriteLine(
			__FUNCTION__ ": DLL \"%.*s\" 载入失败。", printable(fn));
	}
}

void SyringeDebugger::FindDLLs()
{
	
	Breakpoints.clear();
	std::wstring EDPath = ExecutableDirectoryPathW();

	
	Log::WriteLine(__FUNCTION__ ": 在目录 \"%s\" 中搜寻DLL。 ", ExecutableDirectoryPath().c_str());
	for(auto file = FindFile((EDPath + L"\\*.dll").c_str()); file; ++file) {
		Log::WriteLine(__FUNCTION__ ": 正在检测 DLL \"%s\".", UnicodetoANSI(file->cFileName).c_str());
		FindDLLsLoop(file, UnicodetoANSI(EDPath), false);
	}

	bool UseDefaultLoadingPolicy = true;
	if (!DefaultExtPack.empty() && ExtPacks.find(DefaultExtPack) != ExtPacks.end())
			UseDefaultLoadingPolicy = false;
	if (DefaultExtPack == "NONE")
	{
		Log::WriteLine(__FUNCTION__ ": 使用空白扩展配置。");
	}
	else if (UseDefaultLoadingPolicy)
	{
		Log::WriteLine(__FUNCTION__ ": 使用默认扩展配置（\"\\Patches\\*.dll\"）。");
		std::wstring EDPathAlt = EDPath + L"\\Patches";
		Log::WriteLine(__FUNCTION__ ": 在目录 \"%s\\Patches\"中搜寻DLL。", ExecutableDirectoryPath().c_str());
		for (auto file = FindFile((EDPath + L"\\Patches\\*.dll").c_str()); file; ++file) {
			Log::WriteLine(__FUNCTION__ ": 正在检测 DLL \"%s\".", UnicodetoANSI(file->cFileName).c_str());
			FindDLLsLoop(file, UnicodetoANSI(EDPathAlt), false);
		}
	}
	else
	{
		auto& Pack = ExtPacks[DefaultExtPack];
		Log::WriteLine(__FUNCTION__ ": 使用扩展配置 \"%s\"。", UTF8toANSI(DefaultExtPack).c_str());
		for (auto& Dir : Pack.Directories)
		{
			auto wp = UTF8toUnicode(Dir.Path);
			std::wstring EDPathAlt = EDPath + wp;
			Log::WriteLine(__FUNCTION__ ": 在目录 \"%s%s\"中搜寻DLL。", ExecutableDirectoryPath().c_str(), Dir.Path.c_str());
			for (auto file = FindFile((EDPath + wp + L"\\*.*").c_str()); file; ++file) {
				auto U8 = UnicodetoUTF8(file->cFileName);
				if (Dir.MatchName(U8.c_str()))
				{
					Log::WriteLine(__FUNCTION__ ": 正在检测 DLL \"%s\".", U8.c_str());
					FindDLLsLoop(file, UnicodetoANSI(EDPathAlt), Dir.LoadAllMatchedFiles);
				}
			}
		}
	}
	

	for (auto& p : Breakpoints )
	{
		std::sort(p.second.hooks.begin(), p.second.hooks.end(), [](const Hook& lh, Hook& rh) -> bool
			{
				if (lh.Priority != rh.Priority) return lh.Priority > rh.Priority;
				else return strcmp(lh.SubPriority, rh.SubPriority) > 0;
			});
	}
	IdxSet.Disable(GlobalDisableHooks);
	IdxSet.Enable(GlobalEnableHooks);



	// summarize all hooks
	v_AllHooks.clear();
	for(auto& it : Breakpoints) {
		for(auto& i : it.second.hooks) {

			if(IdxSet.Disabled({ i.lib,i.proc }))continue;
			std::string_view filename = i.lib;
			auto sz = filename.find_last_of('\\');
			auto sv = (sz != std::string_view::npos) ? filename.substr(sz + 1, filename.size() - sz - 1) : filename;
			if (ShowHookAnalysis)
			{
				if (InLibList(sv) && InAddrList((int)it.first))
					Analyzer.Add(std::move(HookAnalyzeData{ sv.data(), i.proc, (int)it.first, (int)i.num_overridden, i.Priority, i.SubPriority, i.RelativeLib }));
			}
			Analyzer.AddEx(std::move(HookAnalyzeData{ sv.data(), i.proc, (int)it.first, (int)i.num_overridden, i.Priority, i.SubPriority, i.RelativeLib }));
			v_AllHooks.push_back(&i);
		}
	}

	for (auto& it : BreakpointRel) {
		for (auto& i : it.second.hooks) {

			if (IdxSet.Disabled({ i.lib,i.proc }))continue;
			std::string_view filename = i.lib;
			auto sz = filename.find_last_of('\\');
			auto sv = (sz != std::string_view::npos) ? filename.substr(sz + 1, filename.size() - sz - 1) : filename;
			if (ShowHookAnalysis)
			{
				if (InLibList(sv) && InAddrList((int)it.first))
					Analyzer.Add(std::move(HookAnalyzeData{ sv.data(), i.proc, (int)it.first, (int)i.num_overridden, i.Priority, i.SubPriority, i.RelativeLib }));
			}
			Analyzer.AddEx(std::move(HookAnalyzeData{ sv.data(), i.proc, (int)it.first, (int)i.num_overridden, i.Priority, i.SubPriority, i.RelativeLib }));

		}
	}


	if (ShowHookAnalysis)
	{
		Log::WriteLine(__FUNCTION__ ": 正在输出钩子分析报告……", v_AllHooks.size());
		if (Analyzer.Report())Log::WriteLine(__FUNCTION__ ": 钩子分析报告已完成，详见 HookAnalysis.log 。", v_AllHooks.size());
		else Log::WriteLine(__FUNCTION__ ": 钩子分析报告生成失败。", v_AllHooks.size());
	}


	Log::WriteLine(__FUNCTION__ ": 载入完成，共添加 %d 个钩子。", v_AllHooks.size());
	Log::WriteLine();
}

//临时从老代码借来的XD，没优化
std::string CutSpace(const std::string& ss)//REPLACE ORIG
{
	auto fp = ss.find_first_not_of(" \011\r\n\t"), bp = ss.find_last_not_of(" \011\r\n\t");
	return std::string(ss.begin() + (fp == ss.npos ? 0 : fp),
		ss.begin() + (bp == ss.npos ? 0 : bp + 1));
}
std::vector<std::string> SplitParam(const std::string_view Text)//ORIG
{
	if (Text.empty())return {};
	size_t cur = 0, crl;
	std::vector<std::string> ret;
	while ((crl = Text.find_first_of(',', cur)) != Text.npos)
	{
		ret.push_back(CutSpace(std::string(Text.begin() + cur, Text.begin() + crl)));
		cur = crl + 1;
	}
	ret.push_back(CutSpace(std::string(Text.begin() + cur, Text.end())));
	return ret;
}


bool SyringeDebugger::ParseInjFileHooks(
	std::string_view const lib, HookBuffer& hooks)
{
	auto const inj = std::string(lib) + ".inj";
	static char Buf[10086];

	if(auto const file = FileHandle(_fsopen(inj.c_str(), "r", _SH_DENYWR))) {
		constexpr auto Size = 0x100;
		char line[Size];
		while(fgets(line, Size, file)) {
			if(*line != ';' && *line != '\r' && *line != '\n') {
				void* eip = nullptr;
				size_t n_over = 0u;
				int pr;

				// parse the line (length is optional, defaults to 0)
				if(sscanf_s(
					line, "%p = %[^\t;\r\n]", &eip, Buf, 10000) == 2)
				{
					auto vec = SplitParam(Buf);
					//0:func %s 1:n_over %x 2:priority %d 3: sub_priority %s
					if (vec.size() >= 2)
					{
						sscanf_s(vec[1].c_str(), "%x", &n_over);
						if (vec.size() >= 3)
						{
							sscanf_s(vec[2].c_str(), "%d", &pr);
							if (vec.size() >= 4)
							{
								hooks.add(eip, lib, vec[0].c_str(), n_over, pr, vec[3].c_str(),"");
							}
							else
							{
								hooks.add(eip, lib, vec[0].c_str(), n_over, pr, "", "");
							}
						}
						else
						{
							hooks.add(eip, lib, vec[0].c_str(), n_over, 100000, "", "");
						}
					}
				}
			}
		}

		return true;
	}

	return false;
}

bool SyringeDebugger::CanHostDLL(
	PortableExecutable const& DLL, IMAGE_SECTION_HEADER const& hosts) const
{
	constexpr auto const Size = sizeof(hostdecl);
	auto const base = DLL.GetImageBase();

	auto const begin = hosts.PointerToRawData;
	auto const end = begin + hosts.SizeOfRawData;

	std::string hostName;
	for(auto ptr = begin; ptr < end; ptr += Size) {
		hostdecl h;
		if(DLL.ReadBytes(ptr, Size, &h)) {
			if(h.hostNamePtr) {
				auto const rawNamePtr = DLL.VirtualToRaw(h.hostNamePtr - base);
				if(DLL.ReadCString(rawNamePtr, hostName)) {
					hostName += ".exe";
					if(!_strcmpi(hostName.c_str(), exe.c_str())) {
						return true;
					}
				}
			}
		} else {
			break;
		}
	}
	return false;
}

bool SyringeDebugger::ParseHooksSection(
	PortableExecutable& DLL, IMAGE_SECTION_HEADER const* phooks,
	HookBuffer& buffer)
{
	//Log::WriteLine(__FUNCTION__ ": Executing");

	constexpr auto const Size = sizeof(hookdecl);
	auto const base = DLL.GetImageBase();
	auto const filename = std::string_view(DLL.GetFilename());

	std::string hookName, hookSub;
	if (phooks)
	{
		IMAGE_SECTION_HEADER const& hooks = *phooks;
		auto const begin = hooks.PointerToRawData;
		auto const end = begin + hooks.SizeOfRawData;

		for (auto ptr = begin; ptr < end; ptr += Size) {
			hookdecl h;
			if (DLL.ReadBytes(ptr, Size, &h)) {
				// msvc linker inserts arbitrary padding between variables that come
				// from different translation units

				//Log::WriteLine(__FUNCTION__ ": Hook: Addr %08X Size %d HookNamePtr %08X",h.hookAddr,h.hookSize,h.hookNamePtr);
				if (h.hookNamePtr) {
					auto const rawNamePtr = DLL.VirtualToRaw(h.hookNamePtr - base);
					if (DLL.ReadCString(rawNamePtr, hookName)) {
						//Log::WriteLine(__FUNCTION__ ": \t\tName \"%s\"", hookName.c_str());
						buffer.add(reinterpret_cast<void*>(h.hookAddr), filename, hookName, h.hookSize, 100000, "", "");
					}
				}
			}
			else {
				Log::WriteLine(__FUNCTION__ ": 从 \"%s\" 中插入钩子时发生故障", DLL.GetFilename());
				return false;
			}
		}
	}

	auto const hookalt = DLL.FindSection(".hphks00");
	if (hookalt)
	{
		Log::WriteLine(__FUNCTION__ ": 正在载入扩展格式的钩子……");
		auto const beginalt = hookalt->PointerToRawData;
		auto const endalt = beginalt + hookalt->SizeOfRawData;
		constexpr auto const SizeAlt = sizeof(hookdecl);

		for (auto ptr = beginalt; ptr < endalt; ptr += SizeAlt) {
			hookaltdecl h;
			if (DLL.ReadBytes(ptr, SizeAlt, &h)) {
				//Log::WriteLine(__FUNCTION__ ": Hook: Addr %08X Size %d HookNamePtr %08X Priority %d SubPrioriyPtr %08X", h.hookAddr, h.hookSize, h.hookNamePtr, h.Priority, h.SubPriorityPtr);
				if (h.hookNamePtr && h.hookAddr) {
					auto const rawNamePtr = DLL.VirtualToRaw(h.hookNamePtr - base);
					if (DLL.ReadCString(rawNamePtr, hookName)) {
						//Log::WriteLine(__FUNCTION__ ": \t\tName \"%s\"", hookName.c_str());
						if (h.SubPriorityPtr)
						{
							if (DLL.ReadCString(DLL.VirtualToRaw(h.SubPriorityPtr - base), hookSub))
							{
								buffer.add(reinterpret_cast<void*>(h.hookAddr), filename, hookName, h.hookSize, h.Priority, hookSub, "");
							}
							else buffer.add(reinterpret_cast<void*>(h.hookAddr), filename, hookName, h.hookSize, h.Priority, "", "");
						}
						else buffer.add(reinterpret_cast<void*>(h.hookAddr), filename, hookName, h.hookSize, h.Priority, "", "");
					}
				}
			}
			else {
				Log::WriteLine(__FUNCTION__ ": 从 \"%s\" 中插入钩子时发生故障", DLL.GetFilename());
				return false;
			}
		}
	}

	return true;
}

// check whether the library wants to be included. if it exports a special
// function, we initiate a handshake. if it fails, or the dll opts out,
// the hooks aren't included. if the function is not exported, we have to
// rely on other methods.

struct SyringeSimpleDLLInfo
{
	using PathBuf = char[300];
	size_t cbSize;
	int NPathBuf;
	PathBuf* Bufs;
};

using SYRINGEGETSIMPLEDLLLISTFUNC = HRESULT(__cdecl*)(SyringeSimpleDLLInfo*);

std::optional<bool> SyringeDebugger::Handshake(
	char const* const lib, int const hooks, unsigned int const crc)
{
	std::optional<bool> ret;

	if(auto const hLib = ModuleHandle(LoadLibrary(lib))) {
		if(auto const func = reinterpret_cast<SYRINGEHANDSHAKEFUNC>(
			GetProcAddress(hLib, "SyringeHandshake")))
		{
			Log::WriteLine(__FUNCTION__ ": 在Syringe.exe的进程空间中与DLL通讯： \"%s\" 。", lib);
			constexpr auto Size = 0x100u;
			std::vector<char> buffer(Size + 1); // one more than we tell the dll

			auto const shInfo = std::make_unique<SyringeHandshakeInfo>();
			shInfo->cbSize = sizeof(SyringeHandshakeInfo);
			shInfo->num_hooks = hooks;
			shInfo->checksum = crc;
			shInfo->exeFilesize = dwExeSize;
			shInfo->exeTimestamp = dwTimeStamp;
			shInfo->exeCRC = dwExeCRC;
			shInfo->cchMessage = static_cast<int>(Size);
			shInfo->Message = buffer.data();

			if(auto const res = func(shInfo.get()); SUCCEEDED(res)) {
				buffer.back() = 0;
				Log::WriteLine(
					__FUNCTION__ ": 返回信息： \"%s\" (%X)", buffer.data(), res);
				ret = (res == S_OK);
			} else {
				// don't use any properties of shInfo.
				Log::WriteLine(__FUNCTION__ ": 调取失败。 (%X)", res);
				ret = false;
			}
		} else {
			//Log::WriteLine(__FUNCTION__ ": Not available.");
		}
	}
	return ret;
}
