# Thread Call Stack Spoofing

## Goal
Make the call stack that EDRs walk (during API calls, sleeps, syscalls) look like it originates from legitimate modules, hiding the unbacked/shellcode frame that `call_stack_*` fields would otherwise expose.

## Approaches
- **Return-address overwrite**: place a gadget inside a legit DLL (`jmp rbx`/`ret`-style) and patch the current frame's return address while calling the sensitive API, restoring it afterwards.
- **Synthetic frames**: build a fake `CONTEXT`/stack so stack-walking APIs (`RtlVirtualUnwind`, `StackWalk64`) resolve frames to legit modules.
- **Sleep disguise**: while sleeping (`WaitForSingleObject` on self / `NtDelayExecution`), overwrite our own stack so timer-based stack scans see a benign origin — the classic "Foliage/Ekko/Nightmare" family.

## Hard constraint for this project
A robust implementation needs **assembly** (separate `.asm` assembled by `ml64`/`nasm`) for frame control — pure C cannot reliably manufacture stack frames. Current compiler pipeline builds a *single* `.c` -> `.exe`, so:

- Feasible in pure C: partial masking — call the sensitive API from a pointer inside a legit/stomped module (module stomping already covers most of the benefit), or `VirtualProtect`-proxy a legit `syscall; ret` gadget.
- Not feasible without pipeline changes: full Ekko-style frame replacement. If asm support is added, revisit with an `.asm` side file + ml64.

## Detection surface (Elastic)
- `process.thread.Ext.call_stack_*` fields on `OpenProcess`, `VirtualAlloc`, `VirtualProtect`, `CreateThread` API events.
- `call_stack_final_user_module` — the last non-OS module in the stack; making that resolve to a legit DLL path (stomping) is usually enough; full frame spoofing is only needed for stricter rules.
