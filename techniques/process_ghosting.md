# Process Ghosting (Delete-Pending Image)

## Concept
Create a file, immediately put it in **delete-pending** state (`NtSetInformationFile FileDispositionInformation` / `FILE_DELETE_ON_CLOSE`), write a payload PE into it, create a `SEC_IMAGE` section from the delete-pending handle, then close the file — the file vanishes but the section retains the image. `NtCreateProcessEx` from that section yields a process with **no on-disk backing file at all**.

## Why it may matter
- Extreme version of "image with no clean file": the backing file is *gone*, so file scanners, hash lookups, and path-based reputation have nothing.
- Related rules: any `ghost image`/`delete-pending`/`unbacked image` signatures, plus process-from-section telemetry.

## Steps
1. `CreateFileW`/`NtCreateFile` a temp file → write crafted PE (or a PE stub carrying shellcode).
2. Set delete-pending on the handle.
3. `NtCreateSection(SEC_IMAGE, file_handle)` — must happen *while* the file is delete-pending (section holds the last reference).
4. `CloseHandle` — file is deleted; section survives.
5. `NtCreateProcessEx` + build process params (`RtlCreateProcessParametersEx` pushed via remote write) + `NtCreateThreadEx` at entry.

## Pitfalls
- Same heavy NT plumbing as doppelgänging — `NtCreateProcessEx` parameter correctness dominates failures.
- Modern EDRs fingerprint `image section from delete-pending file` — treat as coverage yardstick.
- Section-from-file is the only window; after close, creation fails.
- Defender/EDR may resurrect-scan the file content at write time — the payload PE itself may be flagged before ghosting completes.
