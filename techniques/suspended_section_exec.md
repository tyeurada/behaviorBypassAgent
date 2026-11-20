# Suspended-Process Section Write (hollow without unmap)

## Concept
A midpoint between module-stomping and process hollowing: spawn a **signed
host process suspended**, `NtMapViewOfSection` a payload-carrying section
directly into its address space (no unmap of the original image — keep the
host binary intact), then redirect the main thread's RIP (or queue an APC)
into the mapped payload and resume.

## Why it may matter
- Classic hollowing needs `NtUnmapViewOfSection` on the image base — a loud,
  dedicated signal. Keeping the original image mapped removes that call.
- The payload region in the child is section-backed (file/image provenance),
  potentially dodging remote-private-write rules that expect
  `VirtualAllocEx`-style allocations.
- `process hollowing` rules keying on unmap+rewrite patterns see only a
  suspended start + a section map + a thread redirect.

## Steps
1. `CreateProcessW` a signed host (`svchost.exe`, `notepad.exe`,
   `RuntimeBroker.exe`) with `CREATE_SUSPENDED`.
2. In OUR process: `NtCreateSection` + map view + write payload (or map a
   crafted file/SEC_IMAGE).
3. `NtMapViewOfSection` the section into the child via its process handle —
   RX or copy-on-write view.
4. `GetThreadContext`/`SetThreadContext` child main thread → Rip = remote
   view base (or `NtQueueApcThread`).
5. `NtResumeThread`/`ResumeThread`.

## Pitfalls
- Cross-process `NtMapViewOfSection` is covered: `95c534ee` (Remote Process
  Injection via Mapping) fires on it — observed in survey.
- Thread-context manipulation adds `c456266f`-class alerts; try APC variant.
- The child's mapped payload is still an *extra* region vs the original
  image layout — image-region-diff style detections may still see it.
- `d7bc9652`/`e6b77636`-class module-tamper rules if you also touch ntdll.
