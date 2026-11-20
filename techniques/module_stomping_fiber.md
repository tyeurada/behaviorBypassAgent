# Module Stomping + Fiber (recommended combination)

## Goal
Combine a file-backed stomped module (address hygiene) with fiber-based execution (no thread telemetry). Workshop-verified: this combination produced no Elastic alerts for a calc-spawning payload.

## Pattern
```c
// A. Stomp via image-section mapping (see module_stomping_section_mapping.md)
//    -> execAddr = base + offset inside the mapped DLL's .text

// B. Execute through a fiber
ConvertThreadToFiber(NULL);
LPVOID fiber = CreateFiber(0, (LPFIBER_START_ROUTINE)execAddr, NULL);
SwitchToFiber(fiber);          // payload runs inside the stomped module
```

## Why the combination matters
- **Stomping alone**: solves the "unbacked/private memory" call-stack problem but `CreateThread execAddr`-style launches still emit thread-start events pointing at weird offsets inside a module.
- **Fiber alone**: kills thread telemetry, but a fiber start address in private memory is itself suspicious.
- **Together**: the fiber's start address resolves to a *file-backed, signed module path* AND no thread-start event is emitted. Both detection surfaces go quiet simultaneously.

## Detection surface (Elastic)
- Residual risk: `VirtualProtect`/`NtProtectVirtualMemory` events during the RW->RX flip — keep them targeted at the image region, not private memory.
- `NtMapViewOfSection` with `SEC_IMAGE` shows the DLL path — choose a DLL whose path is covered by the rule's allowlist when one exists.

## Pitfalls
- The fiber shares the caller's thread; an unhandled exception inside the payload kills the loader process — the `exec_failed` branch then fires with no EDR alert, which is fine (fix code, not stealth).
- Fiber start routine signature is `void WINAPI (PVOID)` — payload entry must not expect C argc/argv.
