# Exception-Dispatched Execution (VEH trampoline)

## Concept
Trigger a controlled exception, then inside a Vectored/Exception handler **redirect `ContextRecord->Rip`** to the payload and return `EXCEPTION_CONTINUE_EXECUTION` — the OS restores the *modified* context and resumes at shellcode. Execution transfer is performed by the kernel's exception dispatcher (`KiUserExceptionDispatcher`), not a thread-creation or jump API in our code.

## Why it may matter
- No `CreateThread`/APC/`SetThreadContext`: the control-flow change happens inside the OS exception path.
- The return-address chain seen during `KiUserExceptionDispatcher` is the legitimate ntdll exception frame — the payload runs "post-exception" which may dodge call-stack-origin checks.

## Steps
1. `AddVectoredExceptionHandler(1, handler)` (first-chance).
2. Trigger exception: `int 3`, invalid access, divide-by-zero, or `NtRaiseException`.
3. In handler: `ContextRecord->Rip = shellcode_addr; return EXCEPTION_CONTINUE_EXECUTION`.
4. Payload runs on the same thread, but the pre-shellcode frame is the exception dispatcher's.

## Pitfalls
- VEH registration + self-triggered exception is an anomalous pair; `RtlAddVectoredExceptionHandler` is monitored.
- If the payload expects arguments/entry convention, it inherits the post-exception register state — most calc shellcode doesn't care.
- The payload region still needs executable backing — combine with module-stomping/RWX-reuse for the memory side.
- `read_only_trick` adds hardware breakpoints on top of this pattern; this is the simpler no-DR variant.
