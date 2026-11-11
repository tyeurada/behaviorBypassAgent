# Atom Bombing

## Concept
Use the Windows **global atom table** (normally a string-sharing facility for windowing) as a cross-process data channel: `GlobalAddAtom` stores our shellcode, then `NtQueueApcThread` forces a thread in the target process to call `GlobalGetAtomNameW` — which copies the atom's content into a buffer in the *target's* address space. A second APC triggers execution. No `VirtualAllocEx`/`WriteProcessMemory` pair — the data transfer API is a windowing primitive.

## Why it may matter
- Classic remote-injection telemetry keys on `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` chains; atom bombing replaces the write primitive with atom-table reads.
- Historic (2016) technique — treat as a coverage yardstick like remote hollowing.

## Steps
1. `GlobalAddAtomW(encoded_payload)` — atom content is size-limited (~32KB string); split shellcode across multiple atoms if needed.
2. Open target process/thread; `NtQueueApcThread` an APC that calls `GlobalGetAtomNameW(atom, rw_buffer, size)` — performs the write inside the target.
3. Ensure a writable buffer exists in the target (`VirtualAllocEx` or reuse `.data` of a module); a second APC flips protection and transfers control (`NtProtectVirtualMemory` + APC to exec address).

## Pitfalls
- Atom name strings are unicode — payload must be encoded (e.g. as hex/UTF16 units) unless using undocumented integer-atom tricks.
- Requires an alertable thread in target or forcing alertability — same APC caveat as early-bird.
- The exec region still needs executable memory in the target — atoms only move the bytes; combine with a staging strategy.
- `NtQueueApcThread` cross-process on a protected/signed target is itself telemetry-rich.
