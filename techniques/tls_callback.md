# TLS Callback Execution

## Concept
Windows PE binaries can declare **TLS callbacks** — functions the loader invokes on process attach and thread attach *before* `main`/`DllMain` returns. A callback whose body is (or jumps to) our payload runs code during process init with a normal `LdrpCallTlsInitializers` call frame — no CreateThread/APC, execution rides the loader's own dispatch.

## Why it may matter
- Execution entry is inside `ntdll!Ldr*` init — a normal call path; no new thread-creation telemetry.
- Runs *before* main — timing similar to Early Bird but self-hosted.
- As a *loader-side* technique it doesn't fix where payload memory lives — combine with any staging mechanism.

## Steps
1. Define a `PIMAGE_TLS_CALLBACK` and register it in the `.CRT$XL*` linker section (MSVC: `#pragma section(".CRT$XLB")` + `__declspec(allocate)`).
2. Callback signature: `void NTAPI cb(PVOID dll, DWORD reason, PVOID reserved)` — on `DLL_PROCESS_ATTACH` run the staging logic (e.g. stomp module + execute payload).
3. The payload still executes from wherever staging placed it — memory backing determines the detection profile as usual.

## Pitfalls
- Callback runs inside loader lock — **do NOT** call LoadLibrary or thread-creation APIs there (deadlock); use already-resolved imports or raw NT calls.
- `.CRT$XLB` section + linker `/INCLUDE` or pragma dance needed for the pointer to register — MSVC syntax is fussy; getting it wrong produces a binary that silently never calls the callback.
- A TLS callback in a tiny unsigned loader is *itself* an anomaly flag for static analysis, though not a runtime rule trigger.
