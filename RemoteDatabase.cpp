#include "RemoteDatabase.h"
#include "SyringeDebugger.h"
#include "PortableExecutable.h"
#include "HookAnalyzer.h"
#include "Setting.h"
#include "Log.h"
#include "ExtJson.h"
#include "ExtFunc.h"
#include <winternl.h>
#include <algorithm>
#include "DbgCmdServer.h"
#include <thread>


extern BYTE hook_code_call[40];
extern BYTE hook_jmp_back[5];
extern BYTE hook_jmp[5];


DWORD QuickHashCStr(const char* str)
{
	DWORD Result = 0;
	DWORD Mod = 19260817;
	for (const char* ps = str; *ps; ++ps)
	{
		Result *= Mod;
		Result += (DWORD)(*ps);
	}
	return Result + strlen(str);
}

DWORD QuickHashCStrUpper(const char* str)
{
	DWORD Result = 0;
	DWORD Mod = 19260817;
	for (const char* ps = str; *ps; ++ps)
	{
		Result *= Mod;
		Result += (DWORD)toupper(*ps);
	}
	return Result + strlen(str);
}

const BYTE* TempByteStream::Data() const
{
	return Buffer.data();
}
BYTE* TempByteStream::Offset(int Ofs) const
{
	return const_cast<BYTE*>(Buffer.data()+Ofs);
}
size_t TempByteStream::Size() const
{
	return Buffer.size();
}

//Base Addr: 0x888808 RulesClass::Instance.align_1628[0]
//DWORD ppHeaderAddr = 0x888808;
//DWORD* ppHeader = (DWORD*)ppHeaderAddr;

void RemoteDatabase::WriteToStream()
{
	RemoteDataHeader Header;
	Header.Size = 0;
	Header.NLib = Lib.size();
	Header.NAddr = Addr.size();
	Header.NHook = Hook.size();
	Header.ExeDataOffset = 0;
	Header.LibDataListOffset = 0;
	Header.AddrDataListOffset = 0;
	Header.HookDataListOffset = 0;
	Header.HookOpCodeSize = sizeof(hook_code_call);
	Header.JmpBackCodeSize = sizeof(hook_jmp_back);

	auto OfsHeader = Push(Header);
	auto OfsExe = Push(*Exe);
	Offset<RemoteDataHeader>(OfsHeader).ExeDataOffset = OfsExe;

	auto OfsLibDataList = PushZero(4 * Lib.size());
	Offset<RemoteDataHeader>(OfsHeader).LibDataListOffset = OfsLibDataList;
	int i = 0;
	for (auto& lib : Lib)
	{
		auto OfsBase = Push(lib.Base);
		StrList[OfsBase] = lib.LibName;
		StrList[OfsBase + 0x4] = lib.AbsPath;
		StrList[OfsBase + 0xC] = lib.Json;
		OfsList[OfsLibDataList + i * 4] = OfsBase;
		++i;
	}

	auto OfsAddrDataList = PushZero(4 * Addr.size());
	Offset<RemoteDataHeader>(OfsHeader).AddrDataListOffset = OfsAddrDataList;
	i = 0;
	for (auto& addr : Addr)
	{
		auto OfsBase = Push(addr.Base);
		PushBytes((const BYTE*)addr.HookID.data(), sizeof(DWORD) * addr.HookID.size());
		OfsList[OfsAddrDataList + i * 4] = OfsBase;
		++i;
	}

	auto OfsHookDataList = PushZero(4 * Hook.size());
	Offset<RemoteDataHeader>(OfsHeader).HookDataListOffset = OfsHookDataList;
	i = 0;
	for (auto& hook : Hook)
	{
		auto OfsBase = Push(hook.Base);
		StrList[OfsBase] = hook.ProcName;
		OfsList[OfsHookDataList + i * 4] = OfsBase;
		++i;
	}

	auto OfsDaemonData = PushZero(sizeof(DaemonData));
	Offset<RemoteDataHeader>(OfsHeader).DaemonDataOffset = OfsDaemonData;
	DaemonDataPtr = OfsDaemonData;

	Interact.FinalOffset = Push(Interact.Transfer);
}

void RemoteDatabase::ResetPointer(DWORD BaseAddr)
{
	Interact.FinalAddr = Interact.FinalOffset + BaseAddr;
	for (auto& ps : OfsList)
	{
		Offset<DWORD>(ps.first) = ps.second + BaseAddr;
		//Log::WriteLine(__FUNCTION__ ": 重定向：[ %d ] : %d -> %d", ps.first, ps.second ,ps.second + BaseAddr);
	}
	for (auto& ps : NegOfsList)
	{
		Offset<DWORD>(ps.first) = ps.second - BaseAddr;
		//Log::WriteLine(__FUNCTION__ ": 重定向：[ %d ] : %d -> %d", ps.first, ps.second ,ps.second + BaseAddr);
	}
	for (auto& ps : CopyRangeList)
	{
		ps.second.Begin += BaseAddr;
		ps.second.End += BaseAddr;
	}
	DaemonDataPtr += BaseAddr;
}

size_t RemoteDatabase::CopyAndPush(DWORD Start, DWORD End)
{
	PushZero(16 - (Stm.Size() % 16));//Align by 16
	DWORD Len = End - Start;
	BYTE* Buf = new BYTE[Len + 4];
	Dbg->ReadMem((const void*)Start, Buf, Len);
	auto sz = PushBytes(Buf, Len);
	delete[]Buf;
	PushZero(16 - (Stm.Size() % 16));//Align by 16
	return sz;
}

void RemoteDatabase::CopyAndPush(const std::vector<MemCopyInfo>& Arr)
{
	CopyAll.insert(CopyAll.end(), Arr.begin(), Arr.end());
	for (const auto& p : Arr)
	{
		auto sz = CopyAndPush(p.Start, p.End);
		CopyRangeList[p.Name] = { sz,sz + p.End - p.Start };
		CopyList[p.Name] = (DWORD)sz;
		for (const auto i : p.OffsetFixes)
		{
			NegOfsList[i - p.Start + sz] = Offset<DWORD>(i - p.Start + sz) + p.Start - sz;
		}
	}
}

void RemoteDatabase::CopyAndPushEnd()
{
	auto OfsCopyList = PushZero(4 * CopyList.size());
	Offset<RemoteDataHeader>(0).CopyMemListOffset = OfsCopyList;
	Offset<RemoteDataHeader>(0).NMem = CopyList.size();
	int i = 0;
	for (auto& p : CopyList)
	{
		auto OfsBase = PushZero(sizeof(MemCopyData));
		StrList[OfsBase] = p.first;
		OfsList[OfsBase + 4] = p.second;
		OfsList[OfsCopyList + i * 4] = OfsBase;
		++i;
	}
}

void RemoteDatabase::PushString()
{
	for (auto& ps : StrList)
	{
		OfsList[ps.first] = PushBytes((const BYTE*)ps.second.data(), ps.second.size());
		PushZero(1);
	}
	PushZero(16 - (Stm.Size() % 16));//Align by 16
	Offset<RemoteDataHeader>(0).Size = Stm.Size();
}

void RemoteDatabase::Dump()
{
	FileHandle hd(fopen("RemoteData.dmp", "wb"));
	if (!hd)
	{
		Log::WriteLine(__FUNCTION__ ": 运行前信息转储失败。", Stm.Size(), Stm.Size());
	}
	else
	{
		fwrite(Stm.Data(), 1, Stm.Size(), hd);
		fflush(hd);
		Log::WriteLine(__FUNCTION__ ": 运行前信息已转储到RemoteData.dmp。", Stm.Size(), Stm.Size());
	}
}

void RemoteDatabase::SendData()
{
	PushString();
	Mem = Dbg->AllocMem(nullptr, Stm.Size());
	RemoteDBStart = (DWORD)Mem.get();
	Log::WriteLine(__FUNCTION__ ": 远程向 0x%08X 处分配了 %d (0x%X) 个字节以存储运行前信息。", (DWORD)Mem.get(), Stm.Size(), Stm.Size());
	RemoteDBEnd = RemoteDBStart + Stm.Size();
	ResetPointer((DWORD)Mem.get());
	Dbg->PatchMem(Mem, Stm.Data(), Stm.Size());
	if (RemoteDatabaseDump)Dump();
	Dbg->Mapper.Header()->DatabaseAddr = RemoteDBStart;
	//DWORD dw = Dbg->RemoteMapSuffix;
	//Dbg->PatchMem(ppHeader, &dw, 4);
	Log::WriteLine(__FUNCTION__ ": 远程载入了运行前信息。", Stm.Size(), Stm.Size());

	//Lib.clear();
	//Addr.clear();
	//Hook.clear();
	//StrList.clear();
	//OfsList.clear();
}

DWORD RemoteDatabase::GetDaemonDataAddr() const
{
	return DaemonDataPtr;
}

void RemoteDatabase::StartDaemonMonitor(bool FromException)
{

	auto DaemonID = GetDaemonThreadID();
	for (auto& [ID, Handle] : Dbg->Threads)
	{
		if (ID != DaemonID)Handle.Thread.suspend();
	}
	InitPipeName();
	std::thread DaemonMonitor(
		[this, DaemonID]()
		{
			IsDaemonMonitorOpen = true;
			EnterDaemonLoop();
			for (auto& [ID, Handle] : Dbg->Threads)
			{
				if (ID != DaemonID)Handle.Thread.resume();
			}
			IsDaemonMonitorOpen = false;
		}
	);
	DaemonMonitor.detach();
}

DWORD RemoteDatabase::InitializeDaemon(bool FromException)
{
	if (EnableDaemon() && !IsDaemonMonitorOpen)
	{
		StartDaemonMonitor(FromException);
		return DBG_CONTINUE;
	}
	else return DBG_EXCEPTION_NOT_HANDLED;
}

bool RemoteDatabase::EnableDaemon()
{
	RemoteBuf<DaemonData> rd(Dbg, (DaemonData*)GetDaemonDataAddr());
	const auto& DaemonData = *rd;
	auto Enabled = DaemonData.EnableDaemon;
	return Enabled;
}

void RemoteDatabase::EnterDaemonLoop()
{
	if (!EnableDaemon())return;

	Log::WriteLine(__FUNCTION__ ": 进入守护线程交互循环。");
	FlushDaemonReport();
	OpenDaemonPipe();
	StartDaemonWork();
	if (WaitForDaemonConnect())
	{
		FinishDaemonLoop = false;
		while (!FinishDaemonLoop)
			DaemonCommLoop();
	}
	FinishDaemonWork();
	CloseDaemonPipe();
	Log::WriteLine(__FUNCTION__ ": 离开守护线程交互循环。");
}

void RemoteDatabase::InitPipeName()
{
	char PipeNameStr[1000];
	sprintf_s(PipeNameStr, "\\\\.\\pipe\\SyringeDaemonPipe_%08X", Dbg->pInfo.dwProcessId);
	RemoteBuf<DaemonData> rd(Dbg, (DaemonData*)GetDaemonDataAddr());

	auto length = (DWORD)strlen(PipeNameStr);
	rd->lpDebugPipeNameLen = length;
	~rd;

	VirtualMemoryHandle PipeNameMem = Dbg->AllocMem(nullptr, length + 1);
	Dbg->PatchMem(PipeNameMem, PipeNameStr, length + 1);
	PipeNameRemote.swap(PipeNameMem);

	rd->lpDebugPipeName = (DWORD)PipeNameRemote.get();
	~rd;
}

void RemoteDatabase::OpenDaemonPipe()
{
	char PipeNameStr[1000];
	sprintf_s(PipeNameStr, "\\\\.\\pipe\\SyringeDaemonPipe_%08X", Dbg->pInfo.dwProcessId);
	DaemonCommBuffer.resize(PipeBufferSize);

	DaemonPipe = CreateNamedPipeA(
		PipeNameStr,                  // 管道名称
		PIPE_ACCESS_DUPLEX |        // 双向访问
		FILE_FLAG_OVERLAPPED,       // 使用重叠I/O
		PIPE_TYPE_MESSAGE |         // 消息类型管道
		PIPE_READMODE_MESSAGE |     // 消息读取模式
		PIPE_WAIT,                  // 阻塞模式
		PIPE_UNLIMITED_INSTANCES,   // 最大实例数
		PipeBufferSize,                // 输出缓冲区大小
		PipeBufferSize,                // 输入缓冲区大小
		0,                          // 默认超时时间
		NULL                        // 默认安全属性
	);

	if (DaemonPipe == INVALID_HANDLE_VALUE)
	{
		Log::WriteLine(__FUNCTION__ ": 创建守护线程管道失败，错误码 %d", GetLastError());
		IsDaemonPipeOpen = false;
		return;
	}
	Log::WriteLine(__FUNCTION__ ": 创建守护线程管道成功，名称为 %s", PipeNameStr);
	IsDaemonPipeOpen = true;
}

bool RemoteDatabase::WaitForDaemonConnect()
{
	if (!IsDaemonPipeOpen)return false;

	OVERLAPPED overlapped = {};
	overlapped.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);

	// 异步等待客户端连接
	if (!ConnectNamedPipe(DaemonPipe, &overlapped)) {
		DWORD error = GetLastError();
		if (error != ERROR_IO_PENDING && error != ERROR_PIPE_CONNECTED) {
			Log::WriteLine(__FUNCTION__ ": 等待连接失败，错误码 %d", error);
			CloseHandle(overlapped.hEvent);
			return false;
		}
	}

	// 等待连接完成
	DWORD result = WaitForSingleObject(overlapped.hEvent, 6000);
	CloseHandle(overlapped.hEvent);

	if (result == WAIT_TIMEOUT)
	{
		Log::WriteLine(__FUNCTION__ ": 等待连接超时，请检查调试接口。");
		return false;
	}
	else if (result != WAIT_OBJECT_0) 
	{
		Log::WriteLine(__FUNCTION__ ": 等待连接失败，错误码 %d", GetLastError());
		return false;
	}

	Log::WriteLine(__FUNCTION__ ": 守护线程管道连接成功。");
	return true;
}


void RemoteDatabase::DaemonCommLoop()
{
	//Wait For Data In
	//Process and Output
	memset(DaemonCommBuffer.data(), 0, DaemonCommBuffer.size());
	DWORD bytesRead;

	if (!ReadFile(DaemonPipe, DaemonCommBuffer.data(), DaemonCommBuffer.size(), &bytesRead, NULL)) 
	{
		DWORD error = GetLastError();
		if (error == ERROR_BROKEN_PIPE) {
			FinishDaemonLoop = true;
			return;
		}
		ProcessReceivedMessage("无法读取指令信息。", error);
		return;
	}
	DaemonCommBuffer[bytesRead] = '\0';
	Log::WriteLine(__FUNCTION__": 接收到守护线程管道数据：%s", DaemonCommBuffer.data());
	ProcessReceivedMessage(DaemonCommBuffer.data(), ERROR_SUCCESS);
}

std::string UTF8toANSI(const std::string& MBCS);

std::string PackErrorMsg(const std::string& Msg, LONG Error)
{
	return "{\"Response\":" + EscapeString(Msg) + ",\"Error\":" + std::to_string(Error) + "}";
}

std::string PackSuccessMsg(const std::string& Msg)
{
	return "{\"Response\": " + EscapeString(Msg) + ",\"Error\": 0 }";
}

void RemoteDatabase::ProcessReceivedMessage(const char* Msg, LONG Error)
{
	std::string Result;
	/*
	Request:
	{
		"Method" : string,
		"Arguments" : Object
	}
	Result:
	{
		"Response" : string,
		"Error" : int
	}
	*/
	DWORD bytesWritten;

	if (Error == ERROR_SUCCESS)
	{
		JsonFile Request;
		auto ErrorStr = Request.ParseChecked(Msg, (const char*)u8"【出错位置】");
		if (!ErrorStr.empty())
		{
			Log::WriteLine(__FUNCTION__ ": 解析请求失败，错误信息：%s", UTF8toANSI(ErrorStr).c_str());
			Error = ERROR_INVALID_DATA;
			Result = PackErrorMsg("请求数据语法错误。", Error);
		}
		else
		{
			auto MethodObj = Request.GetObj().GetObjectItem("Method");
			auto ArgObj = Request.GetObj().GetObjectItem("Arguments");
			if (MethodObj.Available() && ArgObj.Available() && MethodObj.IsTypeString() && ArgObj.IsTypeObject())
			{
				std::string Method = MethodObj.GetString();
				auto Res = ProcessDebugCommand(Dbg, Method, ArgObj);
				std::visit(
					[&](auto&& arg) {
						using T = std::decay_t<decltype(arg)>;
						if constexpr (std::is_same_v<T, JsonFile>)
						{
							Result = PackSuccessMsg(arg.GetObj().GetText());
						}
						else if constexpr (std::is_same_v<T, std::pair<std::string, LONG>>)
						{
							Result = PackErrorMsg(arg.first, arg.second);
						}
					},
					Res
				);
			}
			else
			{
				Log::WriteLine(__FUNCTION__ ": 请求数据缺少合法的 Method 或 Arguments 字段。");
				Error = ERROR_INVALID_DATA;
				Result = PackErrorMsg("请求数据缺少合法的 Method 或 Arguments 字段。", Error);
			}
		}
	}
	else Result = PackErrorMsg(Msg, Error);

	Log::WriteLine(__FUNCTION__": 向管道发送数据：%s", Result.c_str());

	if (!WriteFile(DaemonPipe, Result.c_str(),
		static_cast<DWORD>(Result.size()),
		&bytesWritten, NULL)) 
	{
		Log::WriteLine(__FUNCTION__ ": 无法写入数据。程序试图写入：\n%s", Result.c_str());
	}
}

void RemoteDatabase::CloseDaemonPipe()
{
	if (IsDaemonPipeOpen)
	{
		DisconnectNamedPipe(DaemonPipe);
		CloseHandle(DaemonPipe);
		DaemonPipe = INVALID_HANDLE_VALUE;
	}
}

DWORD RemoteDatabase::GetDaemonThreadID()
{
	RemoteBuf<DaemonData> rd(Dbg, (DaemonData*)GetDaemonDataAddr());
	return rd->ThreadID;
}

void RemoteDatabase::StartDaemonWork()
{
	RemoteBuf<DaemonData> rd(Dbg, (DaemonData*)GetDaemonDataAddr());
	rd->OpenAsDaemon = TRUE;
	~rd;
}

void RemoteDatabase::FinishDaemonWork()
{
	RemoteBuf<DaemonData> rd(Dbg, (DaemonData*)GetDaemonDataAddr());
	rd->OpenAsDaemon = FALSE;
	~rd;
}

void RemoteDatabase::PushReportLineToDaemon(const wchar_t* Line)
{
	DaemonReport += Line;
	DaemonReport += L"\n";
}
void RemoteDatabase::ClearDaemonReport()
{
	DaemonReport.clear();
}
void RemoteDatabase::FlushDaemonReport()
{
	if (DaemonReport.empty())
	{
		RemoteBuf<DaemonData> rd(Dbg, (DaemonData*)GetDaemonDataAddr());
		auto Ptr = rd->lpReportStringW;
		char nul[1]{ 0 };
		Dbg->PatchMem((void*)Ptr, nul, 1); // Clear the previous report string
	}
	else
	{
		VirtualMemoryHandle NewRptString{ Dbg->AllocMem(nullptr, DaemonReport.size() * sizeof(wchar_t)) };
		auto Ptr = NewRptString.get();
		Dbg->PatchMem(Ptr, DaemonReport.c_str(), DaemonReport.size() * sizeof(wchar_t));
		DaemonReportRemote.swap(NewRptString);
		RemoteBuf<DaemonData> rd(Dbg, (DaemonData*)GetDaemonDataAddr());
		rd->lpReportStringW = (DWORD)Ptr;
		~rd;
		rd->lpReportStringWLen = (DWORD)DaemonReport.size();
		~rd;
		ClearDaemonReport();
	}
}

void RemoteDatabase::CreateData()
{
	Exe.reset(new ExeRemoteData);
	strcpy(Exe->SyringeVersionStr, VersionString);
	Exe->VMajor = VMajor;
	Exe->VMinor = VMinor;
	Exe->VRelease = VRelease;
	Exe->VBuild = VBuild;

	Exe->BaseAddress = Dbg->ExeImageBase;
	Exe->EntryPoint = (DWORD)Dbg->pcEntryPoint;
	strcpy(Exe->AbsPath, (ExecutableDirectoryPath()+"\\"+ Dbg->exe).c_str());
	strcpy(Exe->FileName, Dbg->exe.c_str());

	for (auto& pp : Dbg->Analyzer.ByAddressEx)
	{
		Addr.emplace_back();
		auto& ad = Addr.back();
		ad.Base.Addr = pp.first;
		ad.Base.OverriddenCount = sizeof(hook_jmp);
		for (auto& ph : pp.second)
		{
			ad.Base.OverriddenCount = std::max(ad.Base.OverriddenCount, ph.Len);
			ad.HookID.push_back(QuickHashCStrUpper((ph.Lib + AnalyzerDelim + ph.Proc).c_str()));
		}
		ad.Base.HookCount = ad.HookID.size();

		auto const sz = sizeof(AddrHiddenHeader)+pp.second.size() * sizeof(hook_code_call)
			+ sizeof(hook_jmp_back) + ad.Base.OverriddenCount;

		ad.Base.HookDataAddr = HookStm.PushAligned(sz,16);//align by 16
		ad.HookDataSize = sz;

		AddrList[pp.first] = &Addr.back();
	}
	HookMem = std::move(Dbg->AllocMem(nullptr, HookStm.Size()));
	Log::WriteLine(__FUNCTION__ ": 远程向 0x%08X 分配了 %d(0x%X) 个字节以存储钩子信息。", (DWORD)HookMem.get(), HookStm.Size(), HookStm.Size());
	for (auto& ad : Addr)
	{
		ad.Base.HookDataAddr += (DWORD)HookMem.get();
		ad.HookHeaderAddr = ad.Base.HookDataAddr;
		//Log::WriteLine("Alloc %d Bytes At %X", ad.HookDataSize, ad.Base.HookDataAddr);
		ad.Base.HookDataAddr += sizeof(AddrHiddenHeader);
		ad.HookOpAddr = ad.Base.HookDataAddr;
		AddrList[ad.Base.Addr] = &ad;
	}

	for (auto& ph : Dbg->v_AllHooks)
	{
		Hook.emplace_back();
		auto& hk = Hook.back();

		std::string_view filename = ph->lib;
		auto sz = filename.find_last_of('\\');
		auto sv = (sz != std::string_view::npos) ? filename.substr(sz + 1, filename.size() - sz - 1) : filename;

		auto str{ sv.data() + AnalyzerDelim + ph->proc };

		hk.ProcName = ph->proc;
		hk.Base.HookAddress = Dbg->Analyzer.HookMap[str].Addr;
		hk.Base.OverrideLength = ph->num_overridden;
		hk.Base.LibID = QuickHashCStrUpper(ph->lib);
		hk.Base.HookID = QuickHashCStrUpper(str.c_str());
	}
}

void RemoteDatabase::CreateLibData(LibExtData& Ext, const PortableExecutable& DLL, std::string_view cname, std::string_view abs)
{
	Lib.emplace_back();
	auto& lib = Lib.back();

	lib.AbsPath = abs;
	lib.LibName = cname;
	lib.Json = Ext.GetSetting();
	lib.Base.ID = QuickHashCStrUpper(lib.AbsPath.c_str());
	(void)DLL;
}

MemCopyInfo* RemoteDatabase::GetCopyMemName(DWORD RemoteAddr)
{
	if (!InRange(RemoteAddr))return nullptr;
	for (auto& p : CopyAll)
	{
		if (((DWORD)p.Start <= RemoteAddr) && (RemoteAddr < (DWORD)p.End))
		{
			return &p;
		}
	}
	return nullptr;
}

std::pair<DWORD, std::string> RemoteDatabase::AnalyzeDBAddr(DWORD RemoteAddr)
{
	if (!InRange(RemoteAddr))return std::make_pair(RemoteAddr, "UNKNOWN");
	for (auto& p : CopyRangeList)
	{
		if ((p.second.Begin <= RemoteAddr) && (RemoteAddr < p.second.End))
		{
			return std::make_pair(RemoteAddr - p.second.Begin, "RemoteDatabase::" + p.second.ptr->Name);
		}
	}
	return std::make_pair(RemoteAddr - RemoteDBStart, "RemoteDatabase");
}


std::pair<DWORD, std::string> RemoteDatabase::AnalyzeHookAddr(DWORD RemoteAddr)
{
	if(!InHookRange(RemoteAddr))return std::make_pair(RemoteAddr, "UNKNOWN");
	return std::make_pair(RemoteAddr- (DWORD)HookMem.get(), "钩子代码");
}

struct _USTRING
{
	unsigned short Len;
	unsigned short MaxLen;
	wchar_t* Buf;
};


DWORD* _PEB;
DWORD ModuleListHeader()
{
	__asm
	{
		push eax
		mov eax, fs:[0x30]
		mov _PEB, eax
		pop eax
	}
	return *(_PEB + 0x03) + 0x0C;
}



void PrintModuleList(DWORD Header)
{
	static wchar_t ws[1000];
	_LIST_ENTRY* p, * Head;
	p = Head = ((_LIST_ENTRY*)Header)->Flink;
	do
	{
		_USTRING* Name = (_USTRING*)(((int)p) + 0x2C);
		if (Name->Buf)swprintf(ws, 1000, L"%s %d %d : 0x%08X", Name->Buf,Name->Len,Name->MaxLen, *((int*)(((int)p) + 0x18)));
		else swprintf(ws, 1000, L"NULL : 0x%08X", *((int*)(((int)p) + 0x18)));
		MessageBoxW(NULL, ws, L"aleale", MB_OK);
		p = p->Flink;
	} while (p != Head);

}

void PrintModuleList()
{
	PrintModuleList(ModuleListHeader());
}



void RemoteBuf_Load(SyringeDebugger* Dbg, void* Addr, void* Buffer, size_t Size)
{
	Dbg->ReadMem(Addr, Buffer, Size);
}

void RemoteBuf_Save(SyringeDebugger* Dbg, void* Addr, void* Buffer, size_t Size)
{
	Dbg->PatchMem(Addr, Buffer, Size);
}
