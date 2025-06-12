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
	int ANSIlen = WideCharToMultiByte(CP_ACP, 0, Unicode.c_str(), -1, 0, 0, 0, 0);// ��ȡUTF-8���볤��
	char* ANSI = new CHAR[ANSIlen + 4]{};
	WideCharToMultiByte(CP_ACP, 0, Unicode.c_str(), -1, ANSI, ANSIlen, 0, 0); //ת����UTF-8����
	std::string ret = ANSI;
	delete[] ANSI;
	return ret;
}

std::string UnicodetoUTF8(const std::wstring& Unicode)
{
	int UTF8len = WideCharToMultiByte(CP_UTF8, 0, Unicode.c_str(), -1, 0, 0, 0, 0);// ��ȡUTF-8���볤��
	char* UTF8 = new CHAR[UTF8len + 4]{};
	WideCharToMultiByte(CP_UTF8, 0, Unicode.c_str(), -1, UTF8, UTF8len, 0, 0); //ת����UTF-8����
	std::string ret = UTF8;
	delete[] UTF8;
	return ret;
}

// UTF-8�ַ���ת����Unicode
std::wstring UTF8toUnicode(const std::string& UTF8)
{
	int nLength = MultiByteToWideChar(CP_UTF8, 0, UTF8.c_str(), -1, NULL, NULL);   // ��ȡ���������ȣ��ٷ����ڴ�
	WCHAR* tch = new WCHAR[nLength + 4]{};
	MultiByteToWideChar(CP_UTF8, 0, UTF8.c_str(), -1, tch, nLength);     // ��UTF-8ת����Unicode
	std::wstring ret = tch;
	delete[] tch;
	return ret;
}

// UTF-8�ַ���ת����ANSI
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
			if (Res.second == L"[δ֪]" || Res.first == 0xFFFFFFFF)return Ret;
			else return std::make_pair(Res.first, UnicodetoANSI(LibBase[i].Name + std::wstring(L"!") + Res.second));
		}
	}
	if (LibBase.back().BaseAddr <= Addr)
	{
		auto Ret = std::make_pair(Addr - LibBase.back().BaseAddr, std::move(UnicodetoANSI(LibBase.back().Name)));
		auto Res = ResolveFunctionSymbol(pInfo.hProcess, Addr);
		if (Res.second == L"[δ֪]" || Res.first == 0xFFFFFFFF)return Ret;
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

	Log::WriteLine(__FUNCTION__ ": ��ʼ����DLL�����������ӡ�");

	std::vector<BYTE> code;

	for (auto& it : Breakpoints)
	{
		auto const p_original_code = static_cast<BYTE*>(it.first);

		//Log::WriteLine("���� 0x%08X �����빳�ӡ�", it.first);

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
			Log::WriteLine(__FUNCTION__ ":���� %X ���Ĺ����޷���ȡ��Ԥ����Ŀռ��ַ��", p_original_code);
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
			//Log::WriteLine("�� 0x%08X �����빳����ڡ�", p_original_code);
		}
		else
		{
			Log::WriteLine("�޷��� 0x%08X �����빳����ڡ�", p_original_code);
		}
		VirtualProtectEx(pInfo.hProcess, p_original_code, code.size(), OldProtect, &OldProtect);
	}
	Log::Flush();
	bHooksCreated = true;
}

const std::unordered_map<int, std::string> TmpMap
{
	{0x10,"��ִ��"},
	{0x20,"��/ִ��"},
	{0x40,"��/д/ִ��"},
	{0x80,"д��ʱ����/ִ��"},
	{0x01,"���ɷ���"},
	{0x02,"ֻ��"},
	{0x04,"��/д"},
	{0x08,"д��ʱ����"},
	{0x00,"δ����/���ͷ�"},
};

const std::unordered_map<int, std::string> ExcMap
{{
EXCEPTION_ACCESS_VIOLATION,"������ͼԽȨ����ĳ����ַ��"}, {
EXCEPTION_ARRAY_BOUNDS_EXCEEDED,"�߽��鷢�����������Խ�硣"}, {
EXCEPTION_BREAKPOINT,"�����ϵ㡣"}, {
EXCEPTION_DATATYPE_MISALIGNMENT,"�����Զ�дδ���������������ݡ�"}, {
EXCEPTION_FLT_DENORMAL_OPERAND,"��������ʱ����ͼ�����޷���ʾΪ��׼����ֵ�Ĺ�С��������"}, {
EXCEPTION_FLT_DIVIDE_BY_ZERO,"���и���������ʱ��ͼ����0��"}, {
EXCEPTION_FLT_INEXACT_RESULT,"��������Ľ����Խ�˿�׼ȷ��ʾ�ķ�Χ��"}, {
EXCEPTION_FLT_INVALID_OPERATION,"δ֪�ĸ����������"}, {
EXCEPTION_FLT_OVERFLOW,"���븡���������ָ������"}, {
EXCEPTION_FLT_STACK_CHECK,"��������ʱ����ջ��������������硣"}, {
EXCEPTION_FLT_UNDERFLOW,"���븡���������ָ����С��"}, {
EXCEPTION_ILLEGAL_INSTRUCTION,"������ִ����Ч��ָ��򲻴��ڵ�ָ�"}, {
EXCEPTION_IN_PAGE_ERROR,"������ͼ����ϵͳ��ʱ�޷����ص��ڴ�ҳ�棬��ͨ���������г���ʱ�������ӶϿ��ȡ�"}, {
EXCEPTION_INT_DIVIDE_BY_ZERO,"������������ʱ��ͼ����0��"}, {
EXCEPTION_INT_OVERFLOW,"��������Ľ����������硣"}, {
EXCEPTION_INVALID_DISPOSITION,"�쳣���������쳣�Ĵ�����Ч��ʹ�ø߼����Եĳ���Ա��Ӧ�������쳣��"}, {
EXCEPTION_NONCONTINUABLE_EXCEPTION,"������ͼ�ڷ��������쳣��������С�"}, {
EXCEPTION_PRIV_INSTRUCTION,"������ִ������Ȩִ�е�ָ�"}, {
EXCEPTION_SINGLE_STEP,"���ڵ��������У���ִ��һ��ָ�"}, {
EXCEPTION_STACK_OVERFLOW,"ջ�ռ䷢�����硣"}, {
STATUS_FAIL_FAST_EXCEPTION ,"����ʧ�ܻ���Ҫ����������˳���"}, {
EXCEPTION_UNKNOWN_ERROR_1 ,"�׳���C++�쳣�������񣬿�������ȱ�ٶ�Ӧ��catch�飬��C++������ʱ���ô����쳣��"}
};
/*
���۵�΢������
const std::unordered_map<int, std::string> ExcMap
{
{EXCEPTION_ACCESS_VIOLATION,"�̳߳��Դ������ַ��ȡ��д����û����Ӧ����Ȩ�޵������ַ��"
}, {
EXCEPTION_ARRAY_BOUNDS_EXCEEDED,"�̳߳��Է��ʳ����߽��һ���Ӳ��֧�ֱ߽��������Ԫ�ء�"
}, {
EXCEPTION_BREAKPOINT,"�����ϵ㡣"
}, {
EXCEPTION_DATATYPE_MISALIGNMENT,"�̳߳��Զ�ȡ��д���ڲ��ṩ�����Ӳ����δ��������ݡ� ���磬16 λֵ������ 2 �ֽڱ߽��϶���; 4 �ֽڱ߽��ϵ� 32 λֵ�ȡ�"
}, {
EXCEPTION_FLT_DENORMAL_OPERAND,"���������е�һ���������Ƿ������㡣 �ǹ淶ֵ̫С���޷���ʾΪ��׼����ֵ��"
}, {
EXCEPTION_FLT_DIVIDE_BY_ZERO,"�̳߳��Խ�����ֵ���� 0 �ĸ��������"
}, {
EXCEPTION_FLT_INEXACT_RESULT,"��������Ľ��������ȫ��ʾΪС���㡣"
}, {
EXCEPTION_FLT_INVALID_OPERATION,"���쳣��ʾ���б���δ�������κθ����쳣��"
}, {
EXCEPTION_FLT_OVERFLOW,"���������ָ��������Ӧ���������������"
}, {
EXCEPTION_FLT_STACK_CHECK,"��ջ�򸡵��������������硣"
}, {
EXCEPTION_FLT_UNDERFLOW,"���������ָ��С����Ӧ���������������"
}, {
EXCEPTION_ILLEGAL_INSTRUCTION,"�̳߳���ִ����Чָ�"
}, {
EXCEPTION_IN_PAGE_ERROR,"�̳߳��Է��ʲ����ڵ�ҳ�棬��ϵͳ�޷����ظ�ҳ�� ���磬�����ͨ���������г���ʱ�������ӶϿ�������ܻᷢ�����쳣��"
}, {
EXCEPTION_INT_DIVIDE_BY_ZERO,"�̳߳��Խ�����ֵ�����������������"
}, {
EXCEPTION_INT_OVERFLOW,"��������Ľ������ִ�н��������Ҫ��λ��"
}, {
EXCEPTION_INVALID_DISPOSITION,"�쳣����������쳣���ȳ��򷵻�����Ч���á� ʹ�ø߼����ԣ��� C���ĳ���Ա��Ӧ�������쳣��"
}, {
EXCEPTION_NONCONTINUABLE_EXCEPTION,"�̳߳����ڷ��������������쳣�����ִ�С�"
}, {
EXCEPTION_PRIV_INSTRUCTION,"�̳߳���ִ���ڵ�ǰ�����ģʽ�²������������ָ�"
}, {
EXCEPTION_SINGLE_STEP,"���������������ָ�����ָʾ��ִ��һ��ָ�"
}, {
EXCEPTION_STACK_OVERFLOW,"�߳�ռ�������ջ��"
}, {
0xC0000409 ,"����δ����Ŀ����쳣��"}//STATUS_FAIL_FAST_EXCEPTION E06D7363
, {
EXCEPTION_UNKNOWN_ERROR_1 ,"ĳ�δ����׳���һ���쳣����û���˲�������Ҳ�ܿ�����C++������ʱ���ô����쳣��"}
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
			return "δ֪Ȩ�ޣ����������ڴ汣�����Գ�������ȷ����ֵ�ĺ��壩��" + std::to_string(BInfo.Protect);
		}
		else
		{
			return it->second;
		}
	}
	else return "��ȡʧ��";
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
		return "δ֪";
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

	// ���÷�������·��
	if (!SymSetSearchPathW(hProcess, pdbPath.c_str())) 
	{
		Log::WriteLine(__FUNCTION__ ": SymSetSearchPath ����ʧ�ܣ������� %d", GetLastError());
	}


	// ����ģ�����
	DWORD64 modBase = SymLoadModuleExW(
		hProcess,
		NULL,
		pdbPath.c_str(),
		dllName.c_str(),
		baseAddr,
		Size,        // �Զ�ȷ����С
		nullptr,   // ����Ҫ��������
		0
	);

	IMAGEHLP_MODULEW64 hlp;
	hlp.SizeOfStruct = sizeof(hlp);
	if (!SymGetModuleInfoW64(hProcess, baseAddr, &hlp))
	{
		Log::WriteLine(__FUNCTION__ ": SymGetModuleInfoW64 ��ȡģ����Ϣʧ�ܣ������� %d", GetLastError());
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
		Log::WriteLine(__FUNCTION__ ": SymLoadModuleEx ʧ��, ������ %d", GetLastError());
		Log::WriteLine(__FUNCTION__ ": ����PDB: \"%s\"", UnicodetoANSI(pdbPath).c_str());
		Log::WriteLine(__FUNCTION__ ": DLL: \"%s\"", UnicodetoANSI(dllName).c_str());
		Log::WriteLine(__FUNCTION__ ": ��ַ: %08X", baseAddr);
		Log::WriteLine(__FUNCTION__ ": �ļ���С: %u", Size);
		// ����ֱ��ͨ��·������
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
			Log::WriteLine(__FUNCTION__ ": SymGetModuleInfoW64 ��ȡģ����Ϣʧ�ܣ������� %d", GetLastError());
			//return false;
		}

		if (modBase == 0) {
			Log::WriteLine(__FUNCTION__ ": DLL �������ʧ��, ������ %d", GetLastError());
			return false;
		}
	}

	Log::WriteLine(__FUNCTION__ ": \"%s\" ���� %08X ������PDB���š�", UnicodetoANSI(dllName).c_str(), modBase);
	return true;
}

std::string GetFileName(const std::string& ss)//�ļ���
{
	using namespace std;
	auto p = ss.find_last_of('\\');
	return p == ss.npos ? ss : string(ss.begin() + min(p + 1, ss.length()), ss.end());
}

std::wstring GetFileName(const std::wstring& ss)//�ļ���
{
	using namespace std;
	auto p = ss.find_last_of('\\');
	return p == ss.npos ? ss : wstring(ss.begin() + min(p + 1, ss.length()), ss.end());
}

std::pair<DWORD, std::wstring>  ResolveFunctionSymbol(HANDLE hProcess, DWORD address) {
	
	
	
// ׼�����Ż�����
	SYMBOL_INFOW* pSymbol = (SYMBOL_INFOW*)malloc(sizeof(SYMBOL_INFOW) + MAX_SYM_NAME * sizeof(wchar_t));
	if (!pSymbol) return { 0, L"" };

	pSymbol->SizeOfStruct = sizeof(SYMBOL_INFOW);
	pSymbol->MaxNameLen = MAX_SYM_NAME;

	DWORD64 displacement = 0;

	// ���Ի�ȡԴ�ļ���Ϣ
	IMAGEHLP_LINEW64 line;
	line.SizeOfStruct = sizeof(IMAGEHLP_LINEW64);
	DWORD lineDisplacement;
	bool HasLine = false;
	if (SymGetLineFromAddrW64(hProcess, address, &lineDisplacement, &line)) {
		HasLine = true;//return { DWORD(displacement), std::wstring(L"[Դ] ") + line.FileName + L":" + std::to_wstring(line.LineNumber) };
	}
	else {
		//Log::WriteLine(__FUNCTION__ ": SymGetLineFromAddrW64 ��ȡԴ�ļ���Ϣʧ�ܣ������� %d", GetLastError());
	}


	if (SymFromAddrW(hProcess, address, &displacement, pSymbol)) {
		std::wstring result(pSymbol->Name);
		free(pSymbol);
		if (HasLine)
		{
			result += L'{';
			result += GetFileName(line.FileName);
			result += L"����";
			result += std::to_wstring(line.LineNumber);
			result += L'}';
		}
		return { DWORD(displacement), result };
	}
	else {
		//Log::WriteLine(__FUNCTION__ ": SymFromAddrW ��ȡ����ʧ�ܣ������� %d", GetLastError());
	}

	free(pSymbol);

	if (HasLine)
	{
		return { DWORD(lineDisplacement), std::wstring(L"[Դ] ") + line.FileName + L":" + std::to_wstring(line.LineNumber) };
	}

	return { address, L"[δ֪]" };
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
		Log::WriteLine(__FUNCTION__ ": �޷���ʼ���������棬�������: %d", GetLastError());
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
	//	Log::WriteLine("�Ѽ��ؿ⣺%s ��ַ��0x%08X", k.c_str(), v);

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
		__FUNCTION__ ": �����쳣������: 0x%08X ", exceptCode);
	Log::WriteLine(
		"(����ԭ��%s)", GetExcStr(exceptCode).c_str());
	Log::WriteLine(
		"��ַ�� 0x%08X��%s+%X��[����Ȩ�ޣ�%s]", 
		exceptAddr, Str.c_str(), Rel, GetAccessStr(pInfo.hProcess, exceptAddr).c_str());
	if (IsExecutable(pInfo.hProcess, (LPCVOID)exceptAddr))Log::WriteLine("�����쳣�ĵ�ַΪ��ִ�еĴ��롣");
	else Log::WriteLine("�����쳣�ĵ�ַ���Ǵ��룬����Ϊ������ڴ档");
	if (ExceptionReportAlwaysFull || !bAVLogged)
	{
		//Log::WriteLine(__FUNCTION__ ": ACCESS VIOLATION at 0x%08X!", exceptAddr);
		auto const& threadInfo = Threads[dbgEvent.dwThreadId];
		HANDLE currentThread = threadInfo.Thread;

		char const* access = nullptr;
		switch (dbgEvent.u.Exception.ExceptionRecord.ExceptionInformation[0])
		{
		case 0: access = "��ȡ"; break;
		case 1: access = "д��"; break;
		case 8: access = "ִ��"; break;
		}

		auto [Rel2, Str2] = AnalyzeAddr((DWORD)AccessAddr);
		Log::WriteLine("������ͼ%s 0x%08X��%s+%X��[����Ȩ�ޣ�%s]��",
			access ? access : ("<δ֪��Ϊ��" + std::to_string(dbgEvent.u.Exception.ExceptionRecord.ExceptionInformation[0]) + ">").c_str(),
			AccessAddr, Str2.c_str(), Rel2,
			GetAccessStr(pInfo.hProcess, (LPCVOID)AccessAddr).c_str());
		if (IsExecutable(pInfo.hProcess, (LPCVOID)AccessAddr))Log::WriteLine("��ͼ���ʵĵ�ַΪ��ִ�еĴ��롣");
		else Log::WriteLine("��ͼ���ʵĵ�ַ���Ǵ��룬����Ϊ������ڴ档");


		CONTEXT context;
		context.ContextFlags = CONTEXT_FULL;
		GetThreadContext(currentThread, &context);

		Log::WriteLine();
		Log::WriteLine("�Ĵ�����");
		Log::WriteLine("\tEAX = 0x%08X\tECX = 0x%08X\tEDX = 0x%08X",
			context.Eax, context.Ecx, context.Edx);
		Log::WriteLine("\tEBX = 0x%08X\tESP = 0x%08X\tEBP = 0x%08X",
			context.Ebx, context.Esp, context.Ebp);
		Log::WriteLine("\tESI = 0x%08X\tEDI = 0x%08X\tEIP = 0x%08X",
			context.Esi, context.Edi, context.Eip);
		Log::WriteLine();



		Log::WriteLine("\t��ջת����Ϣ���������ܵ�ջ֡�ֶΣ�");
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
							Log::WriteLine("�����ӵ�ַΪ%X��", dw);
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
					Log::WriteLine("\t0x%08X:\t0x%08X ��%s+%X��[����Ȩ�ޣ�%s]", 
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
				Log::WriteLine("\t0x%08X:\t���޷���ȡ��", p);
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
			Log::WriteLine("Syringe���ڵȴ����ԡ���");
			Log::Flush();
			MessageBoxW(NULL, L"Syringe�������쳣�����ȷ���Լ������г���", VersionLString, MB_OK);
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
		Log::WriteLine(__FUNCTION__ ": ����д������ǰ��Ϣ����");
		//Log::WriteLine(__FUNCTION__ ": �ٶ������˱�׼��YR V1.001��");
		Database.CreateData();
		Log::WriteLine(__FUNCTION__ ": ����ǰ��Ϣ������ϡ�");
		Database.WriteToStream();
		for (auto& p : LibExt)Database.CopyAndPush(p.second.GetMemCopy());
		Database.CopyAndPushEnd();
		Log::WriteLine(__FUNCTION__ ": ����ǰ��Ϣ�����ϡ�");
		Database.SendData();
		Log::WriteLine(__FUNCTION__ ": ����ǰ��Ϣд����ϡ�");
	}


	if (GenerateINJ)
	{
		Log::WriteLine(__FUNCTION__ ": ���ڴ���INJ�ļ�����");
		if(Analyzer.GenerateINJ())
			Log::WriteLine(__FUNCTION__ ": INJ�ļ�������ɡ�");
		else Log::WriteLine(__FUNCTION__ ": INJ�ļ�����ʧ�ܡ�");
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

			Log::WriteLine(__FUNCTION__ ": Ԥ���� ��%d/%d��%s", LoadedCount + 1, DLLs.size() + 1, DLLShort[LoadedCount].c_str());
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
			Log::WriteLine(__FUNCTION__ ": Ԥ���� ��%d/%d��SyringeEx.dll", DLLs.size() + 1, DLLs.size() + 1);

			context.Eip = reinterpret_cast<DWORD>(&GetData()->LoadLibraryFunc);
			FirstHook = false;
			context.EFlags |= 0x100;
			context.ContextFlags = CONTEXT_CONTROL;
			SetThreadContext(currentThread, &context);
			threadInfo.lastBP = exceptAddr;
			return DBG_CONTINUE;
		}
#pragma warning(push)
#pragma warning(disable:4244)//�����й�toupper�ľ���
		if (loop_LoadLibrary == v_AllHooks.end())
		{
			SetEnvironmentVariable("HERE_IS_SYRINGE", "1");
			auto hSyringeEx = LoadLibraryA(ExLib);
			if (!hSyringeEx)
			{
				Log::WriteLine("�޷�ע��SyringeEx.dll��Syringeע�����ʧ�ܣ������˳�����");
				MessageBoxA(NULL, "�޷�ע��SyringeEx.dll��Syringeע�����ʧ�ܣ������˳�����", VersionString, MB_OK | MB_ICONERROR);
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
					Log::WriteLine("ͨ��Syringe�����DLL: %s = 0x%08X", DLLShort[i].c_str(), pArr[i].BaseAddr);
					std::transform(DLLShort[i].begin(), DLLShort[i].end(), DLLShort[i].begin(), ::toupper);
					//LibAddr[DLLShort[i]] = pArr[i].BaseAddr;
				}

				LibBase.resize(Mapper.Header()->DllRecordCount);
				//Log::WriteLine("All DLL: at 0x%08X", Mapper.Header()->DllRecordAddr);
				if (!ReadMem((LPCVOID)Mapper.Header()->DllRecordAddr, (LPVOID)LibBase.data(), Mapper.Header()->DllRecordCount * sizeof(SharedMemRecord)))
					Log::WriteLine(__FUNCTION__ ": ����DLL����ʧ�ܡ�");
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
					Log::WriteLine("��ȡģ�飨%d/%d����%hs = 0x%08X", j, LibBase.size(), Str.c_str(), p.BaseAddr);
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
							Log::WriteLine(__FUNCTION__ ": �޷�������Թ��ӣ����Կ�\"%s\"�ĺ���\"%s\"��ͼ��δͨ��Syringe�����\"%s\"Ѱַ��", i.lib, i.proc, i.RelativeLib);
							continue;
						}
						auto& hks = Breakpoints[(LPVOID)((DWORD)it.first + ait->second)].hooks;
						hks.push_back(i);
						v_AllHooks.push_back(&hks.back());
						//Log::WriteLine("������Թ��ӣ����Կ�\"%s\"�ĺ���\"%s\"��λ��%s + 0x%X (0x%08X)��", i.lib, i.proc, i.RelativeLib, it.first, ((DWORD)it.first + ait->second));
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
					__FUNCTION__ ": ������ %s �����ҵ�����"
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
			Log::WriteLine(__FUNCTION__ ": �ɹ��������躯����ַ.");
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
		Log::WriteLine(__FUNCTION__ ": ����ϵ㣺0x%08X (%s+0x%X)", context.Eip, S.c_str(), V);
		MessageBoxA(NULL, __FUNCTION__ ": ����������Ķϵ㡣���Syringe.log��", VersionString, MB_ICONEXCLAMATION | MB_OK);

		return DBG_EXCEPTION_NOT_HANDLED;
	}
}

DWORD SyringeDebugger::HandleException(DEBUG_EVENT const& dbgEvent)
{
	auto const exceptCode = dbgEvent.u.Exception.ExceptionRecord.ExceptionCode;

	if(exceptCode == EXCEPTION_BREAKPOINT)
		//�����������̶������ˡ����ù�Return�����ǣ�����д�����˳�����ִ�е�˳���������������ִ�кü�ǧ�Σ���ǰ�����ÿһ��ִ�����
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
	else if (exceptCode == EXCEPTION_UNKNOWN_ERROR_1)//��������
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
		Log::WriteLine("���򴥷���һ�������Ѿ�������쳣����һ�㲻��Ӱ�����У�");
		Log::WriteLine("%s ��%s", DllStr.c_str(), Buf);
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
		__FUNCTION__ ": ��ʼ���ԡ� �����У� \"%s %.*s\"",
		exe.c_str(), printable(arguments));
	DebugProcess(arguments);

	Log::WriteLine(__FUNCTION__ ": ������ 0x%u ���ֽڵ��ڴ档", AllocDataSize);
	pAlloc = AllocMem(nullptr, AllocDataSize);

	

	Log::WriteLine(__FUNCTION__ ": �ö��ڴ�ĵ�ַ�� 0x%08X", pAlloc.get());

	// write DLL loader code
	Log::WriteLine(__FUNCTION__ ": ����д��DLL�����롢���ô��롭��");

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

	Log::WriteLine(__FUNCTION__ ": �������λ�� 0x%08X", &GetData()->LoadLibraryFunc);

	// breakpoints for DLL loading and proc address retrieving
	bDLLsLoaded = false;
	bHooksCreated = false;
	loop_LoadLibrary = v_AllHooks.end();

	// set breakpoint
	Log::WriteLine(__FUNCTION__ ": ������ڴ��Ķϵ㡣");
	SetBP(pcEntryPoint);

	DEBUG_EVENT dbgEvent;
	ResumeThread(pInfo.hThread);

	bAVLogged = false;
	Log::WriteLine(__FUNCTION__ ": ��ʼ����ѭ����");
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
			Log::WriteLine(__FUNCTION__ ": Syringe�����벢�������У���ע��Ĵ��뽫������");
			Log::WriteLine();
			return;
		}
	}

	SymCleanup(pInfo.hProcess);
	CloseHandle(pInfo.hProcess);

	Log::WriteLine(
		__FUNCTION__ ": �����˳��������룺%X (%u).", exit_code, exit_code);
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
		__FUNCTION__ ": ���ڴӿ�ִ���ļ� \"%s\" �ж�����Ϣ����", exe.c_str());

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
		Log::WriteLine(__FUNCTION__ ": �޷��򿪿�ִ���ļ� \"%s\"", exe.c_str());

		throw;
	}

	if(!pImGetProcAddress || !pImLoadLibrary) {
		Log::WriteLine(
			__FUNCTION__ ": �����޷����� LoadLibraryA �� GetProcAddress ��");

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

	Log::WriteLine(__FUNCTION__ ": �ɹ������ִ���ļ�����Ϣ��");
	Log::WriteLine("\t�ļ�����%s", exe.c_str());
	Log::WriteLine("\tLoadLibraryλ�ڣ�0x%08X", pImLoadLibrary);
	Log::WriteLine("\tGetProcAddressλ�ڣ�0x%08X", pImGetProcAddress);
	Log::WriteLine("\tEntryPointλ�ڣ�0x%08X", pcEntryPoint);
	Log::WriteLine("\t�ļ���С��0x%08X", dwExeSize);
	Log::WriteLine("\t�ļ�CRCֵ��0x%08X", dwExeCRC);
	Log::WriteLine("\t����ʱ�����0x%08X", dwTimeStamp);
	Log::WriteLine();

	Log::WriteLine(__FUNCTION__ ": �� %s ��ȷ������������Ϣ��", exe.c_str());
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
			__FUNCTION__ ": ���� DLL ��\"%.*s\"", printable(fn));
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
				__FUNCTION__ ": ��ʶ�� DLL��\"%.*s\"", printable(fn));
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
				__FUNCTION__ ": DLL \"%.*s\" ���޷���⵽���ӣ�ֹͣ����",
				printable(fn));
		}
	}
	catch (...) {
		Log::WriteLine(
			__FUNCTION__ ": DLL \"%.*s\" ����ʧ�ܡ�", printable(fn));
	}
}

void SyringeDebugger::FindDLLs()
{
	
	Breakpoints.clear();
	std::wstring EDPath = ExecutableDirectoryPathW();

	
	Log::WriteLine(__FUNCTION__ ": ��Ŀ¼ \"%s\" ����ѰDLL�� ", ExecutableDirectoryPath().c_str());
	for(auto file = FindFile((EDPath + L"\\*.dll").c_str()); file; ++file) {
		Log::WriteLine(__FUNCTION__ ": ���ڼ�� DLL \"%s\".", UnicodetoANSI(file->cFileName).c_str());
		FindDLLsLoop(file, UnicodetoANSI(EDPath), false);
	}

	bool UseDefaultLoadingPolicy = true;
	if (!DefaultExtPack.empty() && ExtPacks.find(DefaultExtPack) != ExtPacks.end())
			UseDefaultLoadingPolicy = false;
	if (DefaultExtPack == "NONE")
	{
		Log::WriteLine(__FUNCTION__ ": ʹ�ÿհ���չ���á�");
	}
	else if (UseDefaultLoadingPolicy)
	{
		Log::WriteLine(__FUNCTION__ ": ʹ��Ĭ����չ���ã�\"\\Patches\\*.dll\"����");
		std::wstring EDPathAlt = EDPath + L"\\Patches";
		Log::WriteLine(__FUNCTION__ ": ��Ŀ¼ \"%s\\Patches\"����ѰDLL��", ExecutableDirectoryPath().c_str());
		for (auto file = FindFile((EDPath + L"\\Patches\\*.dll").c_str()); file; ++file) {
			Log::WriteLine(__FUNCTION__ ": ���ڼ�� DLL \"%s\".", UnicodetoANSI(file->cFileName).c_str());
			FindDLLsLoop(file, UnicodetoANSI(EDPathAlt), false);
		}
	}
	else
	{
		auto& Pack = ExtPacks[DefaultExtPack];
		Log::WriteLine(__FUNCTION__ ": ʹ����չ���� \"%s\"��", UTF8toANSI(DefaultExtPack).c_str());
		for (auto& Dir : Pack.Directories)
		{
			auto wp = UTF8toUnicode(Dir.Path);
			std::wstring EDPathAlt = EDPath + wp;
			Log::WriteLine(__FUNCTION__ ": ��Ŀ¼ \"%s%s\"����ѰDLL��", ExecutableDirectoryPath().c_str(), Dir.Path.c_str());
			for (auto file = FindFile((EDPath + wp + L"\\*.*").c_str()); file; ++file) {
				auto U8 = UnicodetoUTF8(file->cFileName);
				if (Dir.MatchName(U8.c_str()))
				{
					Log::WriteLine(__FUNCTION__ ": ���ڼ�� DLL \"%s\".", U8.c_str());
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
		Log::WriteLine(__FUNCTION__ ": ����������ӷ������桭��", v_AllHooks.size());
		if (Analyzer.Report())Log::WriteLine(__FUNCTION__ ": ���ӷ�����������ɣ���� HookAnalysis.log ��", v_AllHooks.size());
		else Log::WriteLine(__FUNCTION__ ": ���ӷ�����������ʧ�ܡ�", v_AllHooks.size());
	}


	Log::WriteLine(__FUNCTION__ ": ������ɣ������ %d �����ӡ�", v_AllHooks.size());
	Log::WriteLine();
}

//��ʱ���ϴ��������XD��û�Ż�
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
				Log::WriteLine(__FUNCTION__ ": �� \"%s\" �в��빳��ʱ��������", DLL.GetFilename());
				return false;
			}
		}
	}

	auto const hookalt = DLL.FindSection(".hphks00");
	if (hookalt)
	{
		Log::WriteLine(__FUNCTION__ ": ����������չ��ʽ�Ĺ��ӡ���");
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
				Log::WriteLine(__FUNCTION__ ": �� \"%s\" �в��빳��ʱ��������", DLL.GetFilename());
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
			Log::WriteLine(__FUNCTION__ ": ��Syringe.exe�Ľ��̿ռ�����DLLͨѶ�� \"%s\" ��", lib);
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
					__FUNCTION__ ": ������Ϣ�� \"%s\" (%X)", buffer.data(), res);
				ret = (res == S_OK);
			} else {
				// don't use any properties of shInfo.
				Log::WriteLine(__FUNCTION__ ": ��ȡʧ�ܡ� (%X)", res);
				ret = false;
			}
		} else {
			//Log::WriteLine(__FUNCTION__ ": Not available.");
		}
	}
	return ret;
}
