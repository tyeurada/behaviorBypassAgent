# Module Stomping (Module Overloading)

## Goal
Execute shellcode from memory backed by a legitimate, signed DLL image, so memory scanners see a "trusted" module instead of unbacked private memory.

## Two variants

### A. Classic stomping (LoadLibrary)
1. `LoadLibrary` a large, benign DLL rarely scanned at runtime (e.g. `mshtml.dll`, `edgehtml.dll`, `Chakra.dll` — avoid `kernel32`/`ntdll`, avoid DLLs that are already loaded and in use).
2. Locate its `.text` (or another executable) section via PE header parsing.
3. `VirtualProtect` -> RW, overwrite entry/section with shellcode, restore RX.
4. Jump to the stomped code (call it, or use a fiber/callback/APC).

### B. Stomping via section mapping (preferred against Elastic)
Map the DLL manually as an image section instead of `LoadLibrary`, which avoids a `library_load` event and keeps the module *unregistered* in the loader list:

```c
NtCreateFile(&hFile, ... sacrificial dll path ...);
NtCreateSection(&hSection, ..., PAGE_READONLY, SEC_IMAGE, hFile);
NtMapViewOfSection(hSection, ..., &base, ...);   // mapped RX, image-backed
NtCreateSection(&hSec2, ..., PAGE_READWRITE, SEC_COMMIT, NULL, size); // private
// write shellcode into hSec2 view, then VirtualProtect RX,
// or write directly over the image mapping after VirtualProtect
```

Notes:
- `SEC_IMAGE` mapping shows up in the alert's call stack as a *file-backed* module path (the sacrificial DLL), which satisfies rules checking for `unbacked` / `private` memory in call stacks.
- Overwriting the `.text` section of a freshly mapped image does NOT dirty the on-disk file and does not trigger image-integrity checks at runtime.

## Detection surface (Elastic)
- `call_stack_final_user_module` — last module in the call stack of the API call. With stomping this resolves to the sacrificial DLL name/path. Rules often allowlist specific paths (e.g. `c:\windows\assembly\nativeimages_*.dll`, `c:\program files\*`) — pick or place a sacrificial DLL accordingly.
- Hash-based allowlists on `call_stack_final_user_module.hash.sha256`: the sacrificial DLL keeps its *original* hash only for the on-disk image; the stomped in-memory content is not hashed the same way, but scanners may hash the file on disk — so a signed, unmodified system DLL passes.
- `process.Ext.api.behaviors`: watch for `allocate_shellcode` / `allocate_rwx_shellcode` triggers — combine stomping with RW->RX transition rather than direct RWX writes.

## Pitfalls
- The DLL must be large enough: shellcode must fit inside the overwritten section (check `SizeOfRawData`/`Misc.VirtualSize`).
- Entry-point execution (runnning `DllMain`/`entry`) vs `.text` overwrite: overwriting `.text` mid-image corrupts real code — acceptable for loaders since we never call the DLL's real exports.
- Some EDRs compare `Image` section content vs disk on `write`/`protect` events — prefer writing before flipping to RX, or use the section-remap variant.
