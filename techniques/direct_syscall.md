# Direct / Indirect Syscalls (HellsGate-style)

## Concept
EDR userland hooks sit inside `ntdll` functions. If we invoke the kernel **directly** — emitting `mov eax, <SSN>; syscall` from our own code or jumping to the `syscall` instruction inside ntdll (indirect) — the hooked prologue is never executed, so hook-based telemetry is bypassed.

## Why it may matter
- Same goal as ntdll unhooking but *surgical*: no writes to ntdll, so the `ntdll_memory_unhooking`/`memory_write` rules do not fire.
- Each NT call that EDR watches in userland loses its telemetry path.
- Kernel instrumentation (ETW-Ti, call-stack scan on thread events, memory events) is **untouched** — call-stack/backing rules still see everything.

## Steps
1. Obtain System Service Numbers (SSNs) without calling the hooked function:
   - Read ntdll's `.text` and pattern-match `mov eax, imm; ... syscall; ret` stubs (SSN = the imm operand) — the classic HellsGate approach.
   - Neighboring-N stub math (Tartarus/HalosGate) handles hooked stubs where the first bytes are replaced by `jmp`.
2. Build a syscall trampoline:
   - **Direct**: emit `mov r10, rcx; mov eax, SSN; syscall; ret` in our own code and call it with NT-call signature args.
   - **Indirect**: locate a `syscall; ret` gadget inside a legit DLL, call it after setting registers — the return-address/call-stack looks more legitimate because the `syscall` instruction itself lives in a signed module.
3. Replace hooked-API calls (NtAllocateVirtualMemory, NtCreateSection, NtMapViewOfSection, NtProtectVirtualMemory, ...) with trampoline calls.

## Pitfalls
- **SSN changes per build**: never hardcode across machines; resolve at runtime from loaded ntdll.
- Call-stack authenticity: a `syscall` instruction executed from OUR code (direct) produces an anomalous stack — the return frame is in unbacked or unexpected memory. Indirect (jump to ntdll's own `syscall`) looks cleaner but still differs from normal ntdll call paths — EDRs maintain syscall-instruction whitelists.
- Register ABI: Windows x64 syscall uses `r10=arg1`, args 5+ on stack — get the calling convention wrong and every call returns STATUS_*.
- This only hides *userland API hook* telemetry. Memory backing, process-injection kernel events, and image-load telemetry remain.
