# Read-Only Memory Execution via Hardware Breakpoints + VEH

## Concept
Keep shellcode in **PAGE_READONLY** (never executable, never RWX) memory and execute it *indirectly*: install a Vectored Exception Handler, set a hardware breakpoint (DR0–DR3) on the shellcode address via `SetThreadContext`, and steer execution inside the handler — the memory is never executable, so memory-permission scanners see only read-only private data.

## Why it may matter
- `PAGE_EXECUTE*` never appears on the region: allocation-based and permission-scan rules see nothing executable.
- The "execution" is exception dispatch — `KiUserExceptionDispatcher` → VEH chain → our handler. The shellcode bytes never run *from* that page directly; instead the handler can emulate/switch context to run them.

## Steps
1. Allocate shellcode buffer as `PAGE_READWRITE`, write payload, flip to `PAGE_READONLY` (a single RW→RO protect — much less suspicious than RW→RX/RWX).
2. `AddVectoredExceptionHandler(1, handler)`.
3. Create a worker thread; `SuspendThread`; `GetThreadContext`; set `Dr0=shellcode_addr`, `Dr7` L0 bit (or execution bp); `SetThreadContext`; `ResumeThread`.
4. When the bp fires, our VEH runs: either (a) single-step payload op-by-op, or (b) copy shellcode into a *different* already-executable region and `ContextRecord->Rip = that region; return EXCEPTION_CONTINUE_EXECUTION`. Variant (b) is essentially "breakpoint-triggered trampoline" — the final exec region still needs to come from somewhere (module stomping works).

## Pitfalls
- Debug-register writes (`Dr*`) are themselves a telemetry point — `hardware breakpoint manipulation` rules may exist.
- The *landing* region still needs executable backing; this technique alone only hides the *storage*. Combine with module-backed exec for the actual run.
- Dr registers are per-thread — every thread that must trigger needs its own `SetThreadContext`.
- Some EDRs mirror/watch Dr register writes via kernel callbacks.
- Exception-heavy execution is slow and noisy — fit for a payload trigger, not for executing the entire payload op-by-op.
