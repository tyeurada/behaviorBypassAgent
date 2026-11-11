# Phantom DLL Hollowing

## Goal
Map a DLL as `SEC_IMAGE_NO_EXECUTE` (or manipulate its section mapping) so the module exists as a file-backed image region, then write payload code into it and remap/re-protect — the module appears loaded and signed while carrying our code.

## Pattern sketch
```c
// Map a benign DLL as SEC_IMAGE_NO_EXECUTE — image region, not executable
NtCreateFile(&hFile, ... dll path ..., FILE_READ_DATA | SYNCHRONIZE, ...);
NtCreateSection(&hSec, ..., PAGE_READONLY, SEC_IMAGE_NO_EXECUTE, hFile);
NtMapViewOfSection(hSec, ..., &base, ...);

// Overwrite a code cave / target section in the private copy,
// then transition the region to RX (or create a second SEC_EXECUTE mapping
// of the same object — "phantom" remapping).
```

## Detection surface (Elastic)
- `SEC_IMAGE_NO_EXECUTE` mappings are unusual — some rules specifically watch `NtCreateSection` parameters for the `IMAGE_NO_EXECUTE` flag. Weigh against plain `SEC_IMAGE` stomping (`module_stomping_section_mapping`), which looks more like a normal image map.
- Same call-stack hygiene benefit as section-mapping stomping: execution address resolves to a real DLL path.

## Pitfalls
- `SEC_IMAGE_NO_EXECUTE` was introduced in newer Windows builds — check target OS version; on older builds the flag is ignored or rejected.
- Double-mapping the same file object (one NX image + one exec) is what makes it "phantom"; keep both views' lifetimes managed or the unload tears down running code.
