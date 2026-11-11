# RWX Allocation (baseline — expected to be detected)

## Goal
Simplest possible loader: allocate RWX, copy shellcode, execute. Useful only as the iteration-1 baseline — virtually every memory rule catches it.

## Pattern
```c
PVOID mem = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE,
                         PAGE_EXECUTE_READWRITE);
memcpy(mem, shellcode, size);
((void(*)())mem)();
```

## Why it gets caught
- `PAGE_EXECUTE_READWRITE` at allocation time triggers Elastic's `allocate_rwx_shellcode` behavior tag.
- The region is `MEM_PRIVATE` + unbacked → `call_stack_*` fields show no module.
- Write-then-execute into RWX is the textbook injection signature.

## Use it for
- Baseline comparison only. If it survives, the lab's EDR is probably not reporting — fix the lab, not the loader.
- Always upgrade immediately: `RW_to_RX`, `heap_execution`, or `module_stomping` are the real candidates.
