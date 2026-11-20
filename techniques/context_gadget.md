# SetThreadContext + Gadget Chain Entry

## Concept
Instead of pointing a hijacked thread's RIP *directly* at shellcode (which lands the first call-stack frame in unbacked memory), redirect it into a **gadget inside a signed module** — e.g. `jmp rsp`, `call rbx`, `push reg; ret` — so the first userland frame on the call stack is a signed DLL instruction, and only the second frame is the payload.

## Why it may matter
- `call_stack_contains_unbacked` and `call_stack_final_user_module`-based rules examine the *origin* of the call. If the top frame resolves to `kernel32.dll!gadget`, the "execution origin" looks module-backed even though control immediately flows to unbacked memory.
- Tests whether Elastic's unbacked detection keys on the **entry frame only** or walks deeper frames — a genuine research question this technique answers empirically.

## Steps
1. Locate a usable gadget inside a loaded signed module — classic search: `FF E4` (jmp rsp) / `FF D3` (call rbx) / `FF E3` (jmp rbx) byte patterns in `kernel32`/`ntdll`/`kernelbase` `.text`.
2. Create/suspend a victim thread; place the shellcode address on its stack or in the target register (adjust `Rsp`, `Rbx`, etc.).
3. `SetThreadContext` with `Rip = gadget_addr`.
4. `ResumeThread` — thread enters the gadget in the signed module, which immediately transfers to the payload.

## Pitfalls
- The register/stack layout must be right *before* resume: `jmp rsp` needs shellcode addr at the *top* of the stack; wrong offset → crash.
- Only the entry frame is masked — if the rule inspects *all* frames for unbacked regions, the payload frame still shows. Empirical question.
- `SetThreadContext` on a suspended thread is itself telemetry (`remote thread context manipulation` rule exists for cross-process).
- Gadget selection: pick one in a hot, frequently-executed path (a gadget in a rarely-used DLL frame may itself look anomalous).
