# Mockingjay (RWX Section Reuse)

## Concept
Instead of allocating executable memory or modifying a loaded module, find a legitimate signed DLL that already ships with a **PAGE_EXECUTE_READWRITE (RWX) section**, load it, and write shellcode directly into that section. No `VirtualAlloc`/`VirtualProtect`/`NtCreateSection` calls are needed at all — the memory is already executable AND image-backed by a signed file.

## Why it matters
- VirtualProtect-class "hollow_image" behavioral rules never fire: the API is never called on image memory.
- The executed region is backed by a signed DLL on disk, so call-stack "unbacked memory" rules see a trusted module frame.
- No new section mapping telemetry either.

## Steps
1. Enumerate candidate DLLs known to contain RWX sections. Classic example: `msys-2.0.dll` (Git/MSYS2), some `python312.dll` builds, certain signed toolchains. On a clean Windows install, none may exist — the loader should first scan `C:\Windows\System32` and `PATH` locations for a DLL whose PE section headers carry `IMAGE_SCN_MEM_EXECUTE|IMAGE_SCN_MEM_WRITE`. An alternative is dropping a benign signed-binary-adjacent DLL we control (e.g. a DLL we build with an RWX section) — but note unsigned drops may trip file-reputation detections.
2. LoadLibrary it (a normal, signed DLL load — low telemetry).
3. Locate the RWX section's in-memory address: parse the loaded image's section headers via `IMAGE_NT_HEADERS`/`IMAGE_FIRST_SECTION`, find the section with `0xC0000000`-ish characteristics (EXECUTE|WRITE|READ), compute `module_base + section.VirtualAddress`.
4. `memcpy` shellcode into the RWX section (respect `SizeOfRawData`/VirtualSize bounds; pick a DLL whose section is large enough).
5. Call/jump to the section base. No protection flip needed — it was already RWX.

## Pitfalls
- Most stock DLLs have **no** RWX section. If enumeration finds nothing, document it — do not silently fall back to VirtualProtect.
- Section size: calc-style shellcode is small (hundreds of bytes) but pick a DLL with ample slack to avoid overwriting live data.
- The DLL stays "clean" on disk; detection pressure moves to `suspicious module write` telemetry — expect rules watching writes into image sections if any exist.
- If the section is shared-mapped elsewhere, writes may be visible to other processes — prefer freshly loaded DLLs in our own process.
