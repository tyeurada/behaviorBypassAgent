# RW -> RX Memory Transition (safe_memory_transition)

## Goal
Avoid `PAGE_EXECUTE_READWRITE` (RWX) entirely: allocate writable memory, copy the payload, then flip to read-execute. RWX allocations are one of the most reliable Elastic telemetry triggers (`allocate_rwx_shellcode` behavior).

## Pattern
```c
PVOID mem = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
memcpy(mem, shellcode, size);
DWORD old;
VirtualProtect(mem, size, PAGE_EXECUTE_READ, &old);
FlushInstructionCache(GetCurrentProcess(), mem, size);  // required on some CPUs
```

## Detection surface (Elastic)
- The `VirtualProtect` RW->RX transition is itself an API event — rules may match on `process.Ext.api.name : "VirtualProtect"` with target protection `PAGE_EXECUTE_READ*`. Mitigations:
  - Do the protect call from a **stomped module address** (call stack hygiene).
  - Use `NtProtectVirtualMemory` directly (fewer userland hooks, but the Nt* name is still visible in API telemetry — trade-off).
  - Prefer **HeapCreate + HeapAlloc(HEAP_CREATE_ENABLE_EXECUTE)** when RX-on- private-heap is acceptable — no protect event at all.
- Combine with `module_stomping` for strongest effect: RW transition inside a file-backed image mapping.

## Pitfalls
- Never leave the region RWX even briefly — a race against the scanner is a bad habit; allocate RW, write, flip.
- `VirtualAlloc` alone (RW) is benign; the *combination* alloc->write-> protect->jump is what rules chain on. Stagger or interleave with benign work if a sequence-based rule persists.
