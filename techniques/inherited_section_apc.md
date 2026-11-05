# Inherited-Handle Section APC (no remote write/map)

## Concept
Project-original composition: carry the payload across the process boundary inside a **section object the child inherits at birth**, not via `VirtualAllocEx`/`WriteProcessMemory`/`NtMapViewOfSection(remote)`. `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` lets the parent hand specific handles to a suspended child — the kernel duplicates them into the child's handle table during `CreateProcess`, so the data transfer happens as a handle-table copy, not a memory operation. The child then maps the section **itself** — a local operation on an object it legitimately owns.

## Why it may matter
- `95c534ee` (Remote Process Injection via Mapping) keys on *remote* `NtMapViewOfSection`; `remote_alloc`/`remote_write` rules key on `VirtualAllocEx`+`WriteProcessMemory`. Here neither primitive exists — the payload never crosses a live process boundary through a watched API.
- The child's `NtMapViewOfSection` targets `GetCurrentProcess()` — a benign-looking local map.
- Remaining surface collapses to the spawn (`CREATE_SUSPENDED`, parent attribution) + whatever trigger launches the mapper stub — same class as early_bird, minus the staging artifacts.

## Steps
1. `NtCreateSection` a page-file-backed section large enough for the final shellcode; map it locally, write the payload (+ optional mapper stub), unmap. Create/duplicate the handle with `OBJ_INHERIT`/`SetHandleInformation(HANDLE_FLAG_INHERIT)`.
2. Build a `STARTUPINFOEX` with `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` = the section handle; `CreateProcessW(host, CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT, bInheritHandles=TRUE)`. The child now owns the same numeric handle value.
3. Trigger the child to map the handle. Options, ordered by stealth/complexity:
   a) **Tiny WPM stub (pragmatic)**: write ~40-60 bytes of stub (not the payload — it carries no signature) that calls `ZwMapViewOfSection(hSection, NtCurrentProcess(), &view...)` then jumps in. Trigger stub via early-bird APC or context redirect.
   b) **Gadget/ROP entry (pure)**: `SetThreadContext` the suspended thread's RIP into a gadget chain inside ntdll that arranges the `ZwMapViewOfSection` call — combines with `context_gadget`; no remote write at all, but fragile to construct.
4. Mapper stub calls `ZwMapViewOfSection` locally with the inherited handle value (passed via `QueueUserAPC` dwData or embedded in the stub), then transfers into the mapped payload.

## Pitfalls
- The **bootstrap problem is intrinsic**: the inherited handle is data, not code — something in the child must run first. Without a remote-write stub the only zero-write trigger is a context/gadget redirect; pick the tradeoff explicitly.
- `CREATE_SUSPENDED` + parent attribution (`5eb295bd`-class unsigned-parent rules) still fire — pair with `ppid_spoof`-style parent selection if those rules prove relevant.
- `OBJ_INHERIT` handles are duplicated only when `bInheritHandles=TRUE`; `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` additionally restricts *which* handles inherit — forgetting either silently loses the handle in the child.
- Section created as `SEC_COMMIT` page-file-backed is still unnamed/private provenance — combining with an image section of a crafted file moves toward `transacted_hollowing` territory.
