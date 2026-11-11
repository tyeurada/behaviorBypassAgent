# DLL Side Loading (not yet pipeline-compatible)

## Goal
Ship a legitimate signed application plus a malicious proxy DLL with the name the app imports; the app's loader picks up our DLL and runs the payload inside a trusted, signed process.

## Why it is strong against behavior rules
- The executing process is a *signed* binary — `code_signature`-based exclusions and `Malware Detection Alert` entropy/ML heuristics improve a lot.
- Load order, call stacks, and modules are all "normal" for the application.

## Hard constraint for this project
- Requires **two build artifacts**: the loader exe AND a payload DLL with matching exported function names the host app imports. The compiler module currently builds a single source -> single exe.
- Requires a known-vulnerable host executable on the target (or bundled in a directory we control). "Drop a vulnerable DLL next to it" is a deployment concern, not a code-generation concern.

## When pipeline support lands
- `lib/compiler.py` needs multi-target builds (exe + dll).
- `lib/executor.py` needs to lay down both artifacts and invoke the exe.
- Prompt templates need `artifact` awareness so the LLM emits two sources.
- Candidate host apps: older installers, `TeamViewer`-family, or any binary importing a non-`KnownDLLs` name — pick per-environment, never system DLLs in `KnownDLLs` (they bypass search order).
