// riptest.exe -- SyringeIH RIP_EVENT exit-code test rig (manual).
//
// Purpose: terminate the process WITHOUT calling ExitProcess (the main thread
// exits via ExitThread), which makes the debugger receive RIP_EVENT instead
// of EXIT_PROCESS_DEBUG_EVENT. RIP_EVENT carries no exit code, so the debugger
// must wait for the process and call GetExitCodeProcess to report the real
// code (42). Before the SyringeEx alignment, SyringeIH reported the stale
// initial value 0xFFFFFFFF.
//
// Build (x86 toolchain, e.g. VS2022 vcvars32):
//   cl /nologo /MT /O1 riptest.c /link /BASE:0x00500000 /OPT:NOREF /OUT:riptest.exe
//
// Run (in a directory containing Syringe.exe, SyringeEx.dll):
//   Syringe.exe "riptest.exe"
// Expect in syringe.log: "正常退出，返回码：2A (42)."
//
// LoadLibraryA/GetProcAddress stay in the import table (RetrieveInfo needs
// them) but are never called, so Syringe's INT3 patches on their IAT slots are
// never triggered.

#include <windows.h>

static void keep_imports(void)
{
    volatile int never = 0;
    if (never)
    {
        LoadLibraryA("x");
        GetProcAddress((HMODULE)0x12345678, "x");
    }
}

int main(void)
{
    keep_imports();

    // The last thread exits without ExitProcess -> the debugger gets RIP_EVENT.
    ExitThread(42);

    return 0;
}
