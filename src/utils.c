/*
 * Utility implementation — loads all NTAPI function pointers from ntdll.
 *
 * This is the ONLY file that does GetProcAddress on ntdll.
 * Every other module uses the function pointers declared in utils.h.
 *
 * The module handle for ntdll is cached and never freed (it's a system
 * DLL that stays loaded for the lifetime of the process anyway).
 */

#include "utils.h"

/* ── Function pointer definitions ── */
pNtCreateProcessEx          fnNtCreateProcessEx       = NULL;
pNtUnmapViewOfSection       fnNtUnmapViewOfSection    = NULL;
pNtCreateSection            fnNtCreateSection         = NULL;
pNtMapViewOfSection         fnNtMapViewOfSection      = NULL;
pNtClose                    fnNtClose                  = NULL;
pNtCreateThreadEx           fnNtCreateThreadEx         = NULL;
pNtResumeThread             fnNtResumeThread           = NULL;
pNtSuspendProcess           fnNtSuspendProcess         = NULL;
pNtResumeProcess            fnNtResumeProcess          = NULL;
pRtlCreateProcessReflection fnRtlCreateProcessReflection = NULL;

BOOL utils_initialize(void)
{
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll == NULL) {
        return FALSE;
    }

    RESOLVE_NTAPI(hNtdll, "NtCreateProcessEx",       fnNtCreateProcessEx);
    RESOLVE_NTAPI(hNtdll, "NtUnmapViewOfSection",    fnNtUnmapViewOfSection);
    RESOLVE_NTAPI(hNtdll, "NtCreateSection",         fnNtCreateSection);
    RESOLVE_NTAPI(hNtdll, "NtMapViewOfSection",      fnNtMapViewOfSection);
    RESOLVE_NTAPI(hNtdll, "NtClose",                  fnNtClose);
    RESOLVE_NTAPI(hNtdll, "NtCreateThreadEx",        fnNtCreateThreadEx);
    RESOLVE_NTAPI(hNtdll, "NtResumeThread",          fnNtResumeThread);

    /* These are optional — not all Windows versions have them */
    RESOLVE_NTAPI_VOID(hNtdll, "NtSuspendProcess",   fnNtSuspendProcess);
    RESOLVE_NTAPI_VOID(hNtdll, "NtResumeProcess",    fnNtResumeProcess);
    RESOLVE_NTAPI_VOID(hNtdll, "RtlCreateProcessReflection",
                       fnRtlCreateProcessReflection);

    return TRUE;
}
