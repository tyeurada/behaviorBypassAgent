# NTDLL Unhooking

## Concept
EDR products commonly install inline hooks (jmp patches) in `ntdll.dll`'s `.text` section to intercept NT API calls from userland. Unhooking restores the original bytes — either from a clean copy on disk or from the `KnownDlls` section mapping — disabling userland telemetry for subsequent calls.

## Why it may matter
- If Elastic's userland hooks feed detection rules, restoring clean ntdll bytes may blind hook-derived telemetry for *later* calls.
- Combined with other techniques: unhook first, then run the injection — telemetry from the injection itself is partially suppressed.
- **Does not** affect kernel-level telemetry (call-stack inspection, memory events) — unbacked-execution rules may still fire.

## Sources of clean ntdll
1. **KnownDlls section**: `NtOpenSection("\\KnownDlls\\ntdll.dll")` + map — the kernel keeps a pristine copy there.
2. **Disk file**: open `%SystemRoot%\System32\ntdll.dll`, read, map the sections manually (account for ASLR-relative addresses).
3. **Debug/embedded copy**: embed known-good bytes (fragile across builds).

## Steps
1. Resolve our loaded ntdll base; locate its `.text`.
2. Obtain clean copy via one of the sources above.
3. `VirtualProtect` .text → RW, `memcpy` clean bytes, restore protection. Alternatively `NtProtectVirtualMemory`. Some engines specifically watch writes into `ntdll` — expect `potential_ntdll_memory_unhooking` / `suspicious_ntdll_memory_write` rule hits.
4. Selective patching: restore only the few stub functions needed (NtCreate Section etc.) instead of the whole section — smaller write footprint, less diff to flag.

## Pitfalls
- **Dedicated rules exist** watching ntdll writes/unhooking — this is a known offensive move; do NOT assume it's silent.
- Version drift: clean copy MUST match the loaded build byte-for-byte (hotpatch bytes, version mismatches crash downstream calls).
- Writing to `.text` needs RX→RW flip — the flip itself is a signal.
- Hooks may live in kernel callbacks too; unhooking only removes userland visibility. Empirically test which rules still fire.
