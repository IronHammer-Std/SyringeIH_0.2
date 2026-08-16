// edbtest.exe -- SyringeIH gamemd.edb integration test rig (manual).
//
// Purpose: produce a deterministic access violation whose ExceptionAddress is
// exactly EDB_FAULT_ADDR (default 0x04000D00), so a gamemd.edb entry
// "0xEDB_FAULT_ADDR,0,0,<description>" hits the exception-address matcher in
// SyringeDebugger::Handle_StackDump. Compile with
// /DEDB_FAULT_ADDR=0x006DE99D to fault at an address present in the real
// Phobos gamemd.edb (e.g. the "Trigger House does not exist" entry).
//
// Flow (SyringeIH debugger side):
//   1. fault at EDB_FAULT_ADDR -> first-chance AV -> Handle_StackDump builds
//      the report (including the EDB hit line) -> daemon monitor started.
//   2. Debugger continues (DBG_CONTINUE) -> instruction refaults -> dedup path
//      returns DBG_EXCEPTION_NOT_HANDLED -> this program's __except catches it
//      and keeps the process alive ~5 s.
//   3. The daemon monitor's connect wait times out after 2 s and
//      FlushRestDumpInfo() writes the whole report (EDB hit line included)
//      to syringe.log.
//
// Why generated code: the faulting instruction must live at EDB_FAULT_ADDR so
// the EDB lookup (exact match on ExceptionAddress) succeeds. The page is
// allocated right below EDB_FAULT_ADDR (page-aligned); the default 0x04000000
// page works because the 0x00400000 region holds the default process heap when
// the image is based at 0x00500000.
//
// LoadLibraryA/GetProcAddress stay in the import table (RetrieveInfo needs
// them) but are never called, so Syringe's INT3 patches on their IAT slots are
// never triggered.
//
// Build (x86 toolchain, e.g. VS2022 vcvars32):
//   cl /nologo /MT /O1 /DYNAMICBASE:NO /EHa edbtest.c /link /BASE:0x00500000 /OPT:NOREF /OUT:edbtest.exe
//
// Run (in a directory containing Syringe.exe, SyringeEx.dll, gamemd.edb):
//   Syringe.exe "edbtest.exe"
// Then check syringe.log for:
//   "...已从 gamemd.edb 载入 N 条已知崩溃记录。"
//   "已知崩溃信息（gamemd.edb）：..."

#include <windows.h>

// Referenced so the linker keeps the imports even though the calls are
// unreachable at runtime (belt and suspenders with /OPT:NOREF).
static void keep_imports(void)
{
    volatile int never = 0;
    if (never)
    {
        LoadLibraryA("x");
        GetProcAddress((HMODULE)0x12345678, "x");
    }
}

#ifndef EDB_FAULT_ADDR
#define EDB_FAULT_ADDR 0x04000D00
#endif

int main(void)
{
    keep_imports();

    // VirtualAlloc rounds lpAddress DOWN to the 64KB allocation granularity,
    // so align the page to 64KB and place the faulting instruction at the
    // low-16-bit offset of EDB_FAULT_ADDR.
    unsigned char* page = (unsigned char*)VirtualAlloc(
        (void*)(EDB_FAULT_ADDR & ~0xFFFFu), 0x10000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!page)
        return 2;

    unsigned char* base = page + (EDB_FAULT_ADDR & 0xFFFFu);

    //  0x00: A1 EF BE AD DE    mov eax, [0xDEADBEEF]   ; AV here, ExceptionAddress = EDB_FAULT_ADDR
    //  0x05: C3                ret
    unsigned char code[] = { 0xA1, 0xEF, 0xBE, 0xAD, 0xDE, 0xC3 };
    for (int i = 0; i < (int)sizeof(code); ++i)
        base[i] = code[i];

    __try
    {
        ((void(*)(void))base)(); // -> AV, ExceptionAddress = EDB_FAULT_ADDR
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        // Keep the process alive long enough for Syringe's daemon monitor to
        // time out (2 s) and flush the crash report to syringe.log.
        Sleep(5000);
    }

    return 0;
}
