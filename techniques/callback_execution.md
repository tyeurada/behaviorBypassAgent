# Callback Function Execution

## Concept
Execute shellcode by passing its address as a **callback parameter** to a legitimate Windows API that invokes user-supplied function pointers. The API itself becomes the trampoline — no `CreateThread`, no APC, no `jmp` to raw shellcode from our own code path.

## Callback-bearing APIs (examples)
- `EnumWindows`, `EnumDesktopWindows`, `EnumChildWindows` (WNDENUMPROC)
- `EnumFontsW`/`EnumFontFamiliesExW` (FONTENUMPROC)
- `EnumResourceTypesW`/`EnumResourceNamesW` (ENUMRESTYPEPROC)
- `EnumDateFormatsEx`/`EnumTimeFormats`/`EnumSystemLocales` (locale callbacks)
- `SetTimer`/`SetWaitableTimer` (TIMERPROC — fires asynchronously)
- `CertEnumSystemStore`, `LineTranslalteDialog`-family, `CertCreateContext` cert helpers, `ImageGetDigestStream`-adjacent APIs

## Steps
1. Get shellcode into executable memory by whatever staging method the run selects (allocation, stomping, section mapping — that choice determines which memory-related rules still apply).
2. Call the enumeration API with the shellcode address as the callback.
3. The API invokes the "callback" — control transfers to shellcode inside a legitimate API call frame.

## Pitfalls
- **Dedicated Elastic rule exists**: `shellcode_execution_via_a_callback_function` — callback-based execution is a known pattern and may be fingerprinted by the API choice itself.
- Callback signature mismatch: the payload runs with whatever arguments the API pushes. Most calc-style shellcode ignores arguments, but a prototype mismatch can corrupt the stack on return — pick callbacks whose prototype returns BOOL/int and takes pointer-sized args.
- The call-stack on entry will show the legit API → unbacked/module region. Memory backing still matters independently of the trampoline.
- Some callbacks are invoked on a worker/APC thread — thread context may surprise payload assumptions.
