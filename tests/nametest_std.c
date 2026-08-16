// nametest_std.exe -- canonical MSVC SetThreadName (0x406D1388) test rig.
//
// Uses the canonical THREADNAME_INFO layout:
//   RaiseException(0x406D1388, 0, sizeof(info)/sizeof(DWORD), (DWORD*)&info)
// i.e. ExceptionInformation[0] = &THREADNAME_INFO.
// A worker thread names itself "CrashWorker" then faults, so the exception
// report must carry the worker thread's name (per-thread naming, not main).
//
// Build: tests\NametestStdTarget.vcxproj (x86, /MT, /O1, /EHa, /DYNAMICBASE:NO).

#include <windows.h>

// Kept so the linker retains the imports (Syringe's RetrieveInfo needs them).
static void keep_imports(void)
{
    volatile int never = 0;
    if (never)
    {
        LoadLibraryA("x");
        GetProcAddress((HMODULE)0x12345678, "x");
    }
}

typedef struct tagTHREADNAME_INFO
{
    DWORD dwType;        // must be 0x1000
    LPCSTR szName;       // pointer to name (in user addr space)
    DWORD dwThreadID;    // thread ID (-1=caller thread)
    DWORD dwFlags;       // reserved for future use, must be zero
} THREADNAME_INFO;

void SetThreadName(DWORD dwThreadID, LPCSTR szThreadName)
{
    THREADNAME_INFO info;
    info.dwType = 0x1000;
    info.szName = szThreadName;
    info.dwThreadID = dwThreadID;
    info.dwFlags = 0;

    __try
    {
        RaiseException(0x406D1388, 0, sizeof(info) / sizeof(DWORD), (DWORD*)&info);
    }
    __except(EXCEPTION_CONTINUE_EXECUTION)
    {
        int a = 1;
        (void)a;
    }
}

static DWORD WINAPI CrashWorker(LPVOID param)
{
    (void)param;
    SetThreadName(GetCurrentThreadId(), "CrashWorker");
    Sleep(1000);
    __try
    {
        *(volatile int*)0xDEADBEEF = 1; // AV -> exception report carries the worker's name
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        // Keep the process alive so the report flushes to the log.
        Sleep(5000);
    }
    return 0;
}

int main(void)
{
    keep_imports();
    HANDLE worker = CreateThread(NULL, 0, CrashWorker, NULL, 0, NULL);
    if (worker)
    {
        WaitForSingleObject(worker, INFINITE);
        CloseHandle(worker);
    }
    return 0;
}
