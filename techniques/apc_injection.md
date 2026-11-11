# APC Injection (self-process)

## Goal
Execute shellcode via an APC on an alertable thread — no `CreateThread`/ `CreateRemoteThread` events at all. Self-process variant only (remote APC injection needs process handles and widens the detection surface).

## Pattern
```c
// Own-thread APC
QueueUserAPC((PAPCFUNC)execAddr, GetCurrentThread(), 0);
SleepEx(INFINITE, TRUE);                 // alertable wait -> APC fires

// or NtQueueApcThread(execAddr, GetCurrentThread(), NULL, NULL, NULL);
```

## Detection surface (Elastic)
- `QueueUserAPC` to own thread has a small footprint; rules target the *cross-process* pattern (`OpenProcess`+`WriteProcessMemory`+`QueueUserAPC` sequence), which self-APC never produces.
- `NtQueueApcThread` appears as an `Nt*` API event — monitored by newer rules; prefer `QueueUserAPC` for stealth, Nt* only if userland hooks on the former are suspected.
- `execAddr` still needs good memory hygiene — stomped module address >> RX private heap > RWX region.

## Pitfalls
- The APC only fires when the target thread enters an alertable wait — forgetting `SleepEx(..., TRUE)`/`WaitForSingleObjectEx(..., TRUE)` means the payload never runs (shows up as `exec_failed` with zero telemetry).
- One-shot semantics: after the APC completes, execution returns to the wait — make the payload exit the process or loop, as needed.
