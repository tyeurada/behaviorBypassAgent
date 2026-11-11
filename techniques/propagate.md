# PROPagate (Subclass Callback Injection)

## Concept
Abuse the **window subclass/property callback** mechanism: every window can carry property lists and subclass procs (`SetProp`, `SetWindowSubclass`, `UxSubclassInfo`). Payload is stored as a window property in a target process's window; a forged subclass header + `SetWindowSubclass`-equivalent APC triggers execution inside the target — the "function pointer" mechanism is the windowing subsystem itself, not a thread/APC API.

## Why it may matter
- No `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread` — the primitives are `SetProp`, `SetWindowSubclass`, SendMessage.
- Executed on a UI thread processing window messages — different telemetry surface than process/thread APIs.

## Steps
1. Find target process with a visible window (`EnumWindows`).
2. `SetPropW(hwnd, "UxSubclassInfo", fake_subclass_header)` — the header contains our callback pointer.
3. Trigger subclass invocation via window message (`PostMessage`/event).
4. Payload location: either embed code pointer to pre-staged executable region in target, or encode shellcode as window property content.

## Pitfalls
- Requires GUI subsystem + target windows — headless targets unusable.
- The `UxSubclassInfo` property is a known structure — dedicated detection rules exist for malformed/forged subclass headers.
- Payload still needs executable memory in the target — PROPagate provides the *trigger*, not the storage.
- 2017-era technique; modern EDRs fingerprint the SetProp+subclass pattern.
