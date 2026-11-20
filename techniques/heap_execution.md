# Heap Execution

## Goal
Execute shellcode from private heap memory instead of `VirtualAlloc`-allocated memory. `VirtualAlloc`/`VirtualAllocEx` are heavily instrumented; heap allocations produce far less EDR telemetry.

## Pattern
```c
HANDLE heap = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, size, 0);
PVOID mem = HeapAlloc(heap, 0, size);
memcpy(mem, shellcode, size);
// execute via fiber, callback, or direct call — see fiber_execution.md
```

## Detection surface (Elastic)
- `HEAP_CREATE_ENABLE_EXECUTE` may be flagged by rules keying on `process.Ext.api.parameters` of `RtlCreateHeap`/`HeapCreate`. If flagged, allocate a *non-executable* heap, then `VirtualProtect` the payload region (returns to the RW->RX surface — see rw_to_rx.md).
- Executable private heap still shows as `unbacked`/`private` memory in call-stack fields — pairing with Module Stomping beats it on that axis; use heap_execution when stomping is unavailable or as a fallback variant.

## Pitfalls
- DEP/NX: on strict systems a non-executable heap will fault — always set `HEAP_CREATE_ENABLE_EXECUTE` or protect explicitly.
- `HeapAlloc` has no `PAGE_*` flags; the flag lives on the heap, not the block.
