# Module Overloading (Double Mapping)

## Concept
Map the **same DLL twice**: once normally (as the visible, clean cover module that appears in PEB loader lists) and once as a private/modified copy that hosts the payload. Scanners enumerating modules see the clean mapping; the payload actually executes from the second mapping — or the technique is used to keep a module *listed* that actually serves different code than its file.

## Variants
1. **Dual-map stomping**: `CreateFileMapping`/`NtMapViewOfSection` twice on the same DLL path — write payload into mapping B, keep mapping A pristine. Module lists show path X (clean in list view), execution happens in B.
2. **Classic module overloading**: allocate `SizeOfImage` for DLL X at our own address, copy X's headers+sections, then write payload *into* that private copy — the private region isn't a normal module entry but carries X's legitimate headers/imports.
3. **PEB-list lying**: add/remove InMemoryOrderModuleList entries so the loaded module enumeration reports a different story than VAD/private memory shows.

## Why it may matter
- Module-integrity checks that compare `module on disk` vs `module in memory` get confused about *which* mapping is authoritative.
- Unlike plain stomping, the "cover" mapping stays byte-identical to disk — integrity re-scan passes while code runs elsewhere.

## Steps (dual-map)
1. `CreateFileW`/`NtCreateFile` on chosen DLL → `CreateFileMappingW` (or `NtCreateSection SEC_IMAGE`) → `NtMapViewOfSection` twice.
2. Keep view A untouched (cover); write payload into view B's `.text` (or tail slack space) and execute from B.
3. Optional: unlink B from loader list or rewrite its name entry.

## Pitfalls
- Two VAD entries for the same file is itself anomalous — VAD-scanners can flag "same file mapped twice with differing content."
- Executing from view B still needs B mapped RX — `SEC_IMAGE` maps come in already RX; a second *file* mapping (`PAGE_READWRITE`) is NOT executable — prefer two SEC_IMAGE views and stomp only one.
- Region size must cover the payload; pick a DLL with slack.
