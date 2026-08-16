// nametest.exe -- SyringeIH thread-naming (0x406D1388) integration test rig (manual).
//
// Purpose: raise the MSVC thread-name exception to name the main thread
// "CrashWorker", then fault so the crash report shows the name in both
// catalog channels:
//   1. TEXT segment header: "异常线程ID = N（名称：CrashWorker）"
//   2. thread JSON segment: {"name":"CrashWorker", ...}
// plus the one-line naming hint in syringe.log:
//   "SyringeDebugger::HandleException: 线程 N 命名为 \"CrashWorker\"。"
//
// SEH keeps the process alive ~5 s after the fault so Syringe's daemon monitor
// (2 s connect timeout) flushes the TEXT report to syringe.log.
//
// Build (x86 toolchain, e.g. VS2022 vcvars32):
//   cl /nologo /MT /O1 /DYNAMICBASE:NO /EHa nametest.c /link /BASE:0x00500000 /OPT:NOREF /OUT:nametest.exe
//
// Run (in a directory containing Syringe.exe, SyringeEx.dll):
//   Syringe.exe "nametest.exe"

#include <windows.h>

// Referenced so the linker keeps the imports (RetrieveInfo needs them) even
// though the calls are unreachable at runtime.
static void keep_imports(void)
{
    volatile int never = 0;
    if (never)
    {
        LoadLibraryA("x");
        GetProcAddress((HMODULE)0x12345678, "x");
    }
}

typedef struct
{
    DWORD dwType;      // must be 0x1000
    LPCSTR szName;     // pointer to the name (x86)
    DWORD dwThreadID;  // 0 = calling thread
    DWORD dwFlags;     // reserved, must be 0
} THREADNAME_INFO_T;

int main(void)
{
    keep_imports();

    // MSVC SetThreadName style: RaiseException(0x406D1388, ...)
    THREADNAME_INFO_T tni;
    tni.dwType = 0x1000;
    tni.szName = "CrashWorker";
    tni.dwThreadID = GetCurrentThreadId();
    tni.dwFlags = 0;

    ULONG_PTR args[4] = { 0x1000, (ULONG_PTR)&tni, 0, 0 };
    RaiseException(0x406D1388, 0, 4, args);

    __try
    {
        *(volatile int*)0xDEADBEEF = 1; // AV -> crash report carries the thread name
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        // Keep the process alive long enough for the daemon monitor to time
        // out (2 s) and flush the report to syringe.log.
        Sleep(5000);
    }

    return 0;
}
