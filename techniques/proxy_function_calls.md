# Proxy Function Calls (Gadget-mediated API calls)

## Concept
Never call a hooked/sensitive API from our own code frame. Instead, call it through a **gadget or legitimate helper inside a signed module** — e.g. find `syscall` stubs, `call rax`-style gadgets, or wrapper functions inside `ntdll`/`kernel32`, and arrange registers+stack so the call site appears to be the signed module's code.

## Why it may matter
- `call_stack_summary`-based rules pattern-match on the *frames* of the calling thread: `ntdll|kernelbase|kernel32|Unbacked` means "final frame in unbacked memory". Routing the API call through a signed-module gadget changes the deepest userland frame from `Unbacked` to a named module.
- Complements direct_syscall: syscall resolves the SSN itself; proxy calls additionally launder the *calling context*.

## Steps
1. Pick the sensitive API(s) the loader needs (allocation, protection, write, create-thread).
2. Locate a forwarding gadget in a signed DLL: `jmp rax`/`call rax` (`FF E0`/`FF D0`), or a whole exported wrapper (e.g. `ntdll!LdrGetProcedureAddress` style helpers).
3. Set up the call: push args / set registers per ABI, then transfer control INTO the gadget so the *return address* the callee sees points at our continuation — or better, into a chained sequence.
4. The kernel/stack telemetry sees the call originating from a signed module's address range.

## Pitfalls
- Return-address integrity: the gadget's `ret` must land back on our continuation — forge the stack carefully or the thread crashes after one call.
- `call_stack_final_user_module` vs `call_stack_contains_unbacked` are different checks — a gadget masks the entry frame only if deeper frames don't show unbacked regions; when our *continuation* code is unbacked the mask is partial.
- Combine with module-backed payload storage so post-gadget frames are also clean.
