# Fiber Execution

## Goal
Run shellcode inside a Windows fiber instead of a thread, avoiding thread-creation telemetry (`CreateThread`/`CreateRemoteThread`, ETW ThreadStart, kernel thread-create callbacks).

## Pattern
```c
ConvertThreadToFiber(NULL);                    // main thread -> fiber
LPVOID fiber = CreateFiber(0, (LPFIBER_START_ROUTINE)codeAddr, NULL);
SwitchToFiber(fiber);                          // executes codeAddr
// afterwards: SwitchToFiber(mainFiber), DeleteFiber(fiber)
```

## Why it helps (Elastic)
- Elastic Defend rules heavily weight `thread` events. A fiber's start address is NOT delivered as a thread-start event, so rules matching `process.Ext.api.name : "CreateThread*"` or thread-start call stacks never fire.
- The workshop demonstrated `Module Stomping + Fiber` executing calc.exe with zero Elastic alerts — fibers provide the execution primitive, stomping provides a file-backed module address.

## Requirements
- `codeAddr` must point at executable memory — pair with Module Stomping or an RW->RX allocation; a fiber cannot fix the memory-permission detection surface.
- Stack unwinding still happens inside the fiber; if shellcode calls hooked APIs (VirtualProtect etc.) the call stack is still visible — keep the sensitive calls outside the fiber or inside the stomped module.

## Pitfalls
- `CreateFiber` itself is a benign API and rarely gated, but an executable pointer as its argument can appear in `process.Ext.api.parameters` style fields — prefer passing the stomped-module address, not private memory.
- Fibers share the thread's stack unless created with a custom size; exceptions inside the fiber kill the thread — wrap payload entry carefully.
