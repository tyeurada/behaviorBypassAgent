# Early Bird APC Injection

## Concept
Launch a legitimate host process in **suspended** state and queue an APC (`QueueUserAPC`) targeting its main thread *before* it ever runs. When the thread resumes for initialization, the queued APC executes first — often before EDR userland hooks are fully active inside the child.

## Why it may matter
- Userland hooking installs during process init (LdrInitializeThunk chain). An APC queued while suspended can run code *before* hooks land, depending on engine design.
- Kernel telemetry still sees everything — this mainly tests whether execution-timing beats userland instrumentation.

## Steps
1. `CreateProcessW(NULL, host, ..., CREATE_SUSPENDED, ...)` — pick a signed host (notepad, svchost-adjacent system binaries) in a normal path.
2. Allocate/write shellcode in the child (`VirtualAllocEx`+`WriteProcessMemory` or section mapping).
3. `QueueUserAPC(shellcode_addr, child_main_thread, 0)`.
4. `ResumeThread`.

## Pitfalls
- `VirtualAllocEx` + `WriteProcessMemory` across process boundaries is a heavily watched API pair — expect `remote_alloc`/`remote_write` telemetry.
- Suspended-process creation itself is a common detection signal (`process hollowing` family, T1055).
- APC exec lands on an alertable thread — the entry point must be alertable or the APC may never fire on resume timing. Some payloads need `NtTestAlert`-style forcing.
- Child region is still unbacked unless combined with module-backed staging.
