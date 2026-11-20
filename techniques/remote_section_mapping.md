# Remote Section Mapping Injection

## Concept
Instead of `VirtualAllocEx`+`WriteProcessMemory`, create a section object in **our** process (`NtCreateSection`), write the payload into our own mapped view, then `NtMapViewOfSection` the **same section into a remote process** — the remote view is image/file-backed from the kernel's perspective rather than private anonymous memory.

## Why it may matter
- Remote-private-memory and remote-write rules key on `VirtualAllocEx`/`WriteProcessMemory` calls; mapping an existing section uses neither.
- The remote view's VAD entry references a section (potentially `SEC_IMAGE`-flagged) — a different provenance class than private alloc.
- Classic obscure primitive, used by real implants; dedicated rules likely exist (`remote thread via mapped section` family).

## Steps
1. `NtCreateSection` a page-file-backed section of payload size (RW).
2. Map it in *our* process (`NtMapViewOfSection` local), write shellcode, unmap our view.
3. Open target process; `NtMapViewOfSection` with `SECTION_ALL_ACCESS` into it — a second view appears in the target's address space, already containing the payload (shared physical pages).
4. Flip remote view to RX if needed (`NtProtectVirtualMemory` remote) or map it RX from the start; trigger execution via context/APC/thread-start.

## Pitfalls
- Remote `NtMapViewOfSection` is a niche API — signature-able on its own.
- A page-file-backed section is still *unnamed/private* — the remote view is file-less; unbacked-style rules may still classify it.
- Using `SEC_IMAGE` + a real file makes it image-backed but drags in file telemetry — tradeoff.
- The trigger step (new thread or hijack in target) is the remaining detection surface — pair with a quiet trigger.
