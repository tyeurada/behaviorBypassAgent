# Remote Process Hollowing (classic)

## Concept
Create a legitimate signed process suspended, **unmap its original image** (`NtUnmapViewOfSection`), allocate memory at the preferred base, write a replacement image in, fix relocations, redirect entry point, resume. The final process runs attacker code while masquerading under a legit image name/path.

## Why it's in the survey
- Canonical T1055 baseline: EDR coverage is *expected* to be strong — a useful yardstick for Elastic's hollowing-family rules.
- Contrasts with self-hollowing/module-stomping: remote version adds cross-process allocation + image-replacement artifacts.

## Steps
1. `CreateProcessW` signed host binary (e.g. `svchost.exe`, `notepad.exe`) with `CREATE_SUSPENDED`.
2. `NtQueryInformationProcess` → PEB → image base.
3. `NtUnmapViewOfSection` on the image base region.
4. `VirtualAllocEx` in child at same/preferred base; write PE headers + sections (`WriteProcessMemory`); apply relocations; fix imports (or run shellcode directly — simpler variant: write shellcode, point entry/thread context at it).
5. `GetThreadContext`/`SetThreadContext` to redirect RIP (or `QueueUserAPC`-style), then `ResumeThread`.

## Pitfalls
- `NtUnmapViewOfSection` on the base image is a *loud* signal — dedicated hollowing rules key on it.
- Suspended start + unmap + rewrite + redirect chain is the classic multi-signal fingerprint; each step adds telemetry.
- If the shellcode isn't a full PE (raw payload), simpler: allocate RX in child, write shellcode, redirect thread — still shows unbacked exec.
- Compare detection profile vs self-module-stomping: remote adds `remote_alloc`/`remote_write`/`parent-child` artifacts.
