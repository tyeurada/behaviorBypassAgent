# Signed Host Execution (rundll32 / regsvr32 / LOLBins)

## Concept
Don't run the payload inside our unsigned loader at all — build it as a **DLL with an export entry** and launch it via a signed Windows binary: `rundll32 payload.dll,Run` / `regsvr32 /s /i:"..." payload.dll` / `mshta`/`wscript` variants. The process that hosts payload execution is `rundll32.exe` — signed, normal-looking parent.

## Why it may matter
- Rules like `5eb295bd` (unbacked via unsigned parent) require the *parent* to be unsigned AND freshly created (relative_file_creation_time≤500) — `rundll32.exe` is signed, old, in System32 → the sequence's first event cannot match.
- `relative_file_name_modify_time` also fails — the executable is a system binary.

## Steps (two-artifact constraint)
1. Loader exe embeds a DLL as byte data (or compiles a second artifact — but our toolchain produces one exe, so embed it).
2. `WriteFile`/`CreateFile` the DLL to a plausible path (`%TEMP%\...\svc.dll` or a name mimicking a system component). File-write may trip drop rules — pick a quiet directory.
3. `CreateProcess`/`WinExec`/`ShellExecute`: `rundll32 <dll>,<Export>` — the export function body runs the payload staging+exec.
4. The payload then executes *inside rundll32.exe* — a signed system process.

## Pitfalls
- The dropped DLL is unsigned: `unsigned module load`/`file drop` rules can still flag the DLL itself; signing isn't available, so prefer unremarkable names/paths.
- rundll32 calls the export with `(hwnd, hinst, cmdline, show)` — the export signature must tolerate the args.
- A command line `rundll32 <random-name>.dll` is heavily fingerprinted — rules like `rundll32 execution with unusual dll path` exist.
- This changes who *hosts* the payload, not the memory backing — inside rundll32 the payload region is still private alloc unless combined with module-backed staging (which then runs in the rundll32 context).
