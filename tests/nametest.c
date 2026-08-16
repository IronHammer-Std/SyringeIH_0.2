// nametest.exe -- SyringeIH thread-naming (0x406D1388) integration test rig.
//
// Purpose: raise the MSVC thread-name exception (hybrid layout: params =
// {0x1000, &THREADNAME_INFO, ...}) to name the main thread "CrashWorker",
// then fault so the crash report shows the name in both catalog channels:
//   1. TEXT segment header: "异常线程ID = N（CrashWorker）"
//   2. thread JSON segment: {"name":"CrashWorker", ...}
// plus the one-line naming hint in syringe.log:
//   "SyringeDebugger::HandleException: 线程 N 命名为 \"CrashWorker\"。"
//
// SEH keeps the process alive ~5 s after the fault so Syringe's daemon monitor
// (2 s connect timeout) flushes the TEXT report to syringe.log.
//
// Automated: Tests.exe (ThreadNameIntegrationTests.cpp) runs the full debug
// session in-process against nametest.exe / nametest_std.exe.
// Build: via tests\NametestTarget.vcxproj (x86, /MT, /O1, /EHa, /DYNAMICBASE:NO).

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
