# Process Doppelgänging (TxF)

## Concept
Abuse NTFS **transactions** (TxF): create a transacted file, overwrite it with a malicious payload, then *roll back* the transaction — the file on disk reverts, but a `SEC_IMAGE` section created from the transacted handle keeps the payload content. Launch a process from that section: a running process whose backing file "doesn't exist" on disk.

## Why it may matter
- The executed image never exists as a normal file — file-scan/AV hooks see only the rolled-back (clean) file.
- Process image is a *mapped section*, not a file-backed path — file-based reputation checks have nothing to scan.

## Steps
1. `CreateFileTransacted` a legit-looking path (temp dir).
2. Inside the transaction, overwrite with payload PE (or shellcode-loaded stub PE).
3. `NtCreateSection(..., SEC_IMAGE, transacted_handle)` — section captures the *transacted* (malicious) content.
4. `RollbackTransaction` — on-disk file is pristine/empty.
5. `NtCreateProcessEx`/`RtlCreateProcessParameters` → build remote process params (push params via NtWriteVirtualMemory), create thread with `NtCreateThreadEx` pointing at image entry.

## Pitfalls
- Heavy NT plumbing: `NtCreateProcessEx` isn't a normal API call — requires correct `PS_CREATE_INFO`/`AttributeList` handling; parameter mistakes crash at process creation, not at compile time.
- TxF is deprecated on Win10+ but still functional; some builds have quirks.
- EDR may watch transacted-file ops (`CreateFileTransacted` is rare in legit software) and `NtCreateSection SEC_IMAGE` from non-standard sources.
- The resulting process has no normal on-disk image — `unbacked image` / `ghost image` style rules target exactly this.
- This is a classic (2017) technique — assume full coverage; its value is as a coverage yardstick, not a stealth bet.
