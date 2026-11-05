# Threadless Injection (function hooking / callback hijack)

## Goal
Execute shellcode without creating any thread at all — patch a function body or a callback slot that gets invoked on a normal call path.

## Local-process variants (single-exe feasible)
- **Callback slot overwrite**: replace a function pointer our own process already calls — e.g. a window proc (`SetWindowLongPtr(GWLP_WNDPROC)`), a registered `atexit` handler, or a message hook invoked via the message loop.
- **IAT patch**: overwrite an imported-function entry in our own module's IAT (e.g. patch `GetSystemTime`'s slot) then call it — the call goes to the payload.
- **Enum/callback execution**: APIs that invoke a callback synchronously (`EnumWindows`, `EnumDesktopWindows`, `EnumSystemLocalesEx`, `EnumDateFormatsExEx`, `CertEnumSystemStore`) with the payload address as the callback — simplest "threadless" execution of all.

## Remote variant (documented, not recommended for this pipeline)
Patching a function inside a *victim* process requires `OpenProcess` + `VirtualProtectEx` + `WriteProcessMemory` + trigger — every one of those is instrumented. Only useful with strong call-stack hygiene already in place.

## Detection surface (Elastic)
- `VirtualProtect` on a module's `.text`/IAT region and writes into image sections are watched — combine with stomping discipline.
- Exotic callback APIs are rule-catalogued one by one; common `Enum*` calls with a callback pointer into a file-backed (stomped) region are the lowest-noise option.

## Pitfalls
- Payload signature must match the patched callback's calling convention — mismatched prototypes crash after execution.
- Overwriting WNDPROC/IAT needs the write to happen while no other thread uses the slot; for own-process loaders, do it before starting the message loop.
