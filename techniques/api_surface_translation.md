# API Surface Translation (meta-transform, applies to all techniques)

## Concept
Not a standalone technique — a systematic transform applicable to every other KB entry: replace each classic, heavily-fingerprinted Win32/NT API with its modern or exotic twin that performs the identical kernel operation under a different telemetry name. Elastic rules frequently match on `process.Ext.api.name` strings enumerated from the classic API set; whether the newer names produce distinct telemetry is a cheap, directly testable hypothesis.

## Substitution table
| Classic call | Modern/exotic twin |
|---|---|
| `VirtualAlloc`/`VirtualAllocEx` | `VirtualAlloc2`/`VirtualAllocExNuma` (+`MEM_RESERVE_PLACEHOLDER`) |
| `MapViewOfFile`/`NtMapViewOfSection` | `MapViewOfFile3`/`NtMapViewOfSectionEx` (+`MEM_REPLACE_PLACEHOLDER`) |
| `UnmapViewOfFile` | `UnmapViewOfFile2`/`UnmapViewOfFileEx` |
| `VirtualProtect`/`VirtualProtectEx` | `VirtualProtectFromApp`, direct `NtProtectVirtualMemory` |
| `CreateFile`/`CreateFileTransacted` | `CreateFile2` (+`FILE_FLAG_*` variants), `NtCreateFile` |
| `CreateThread`/`CreateRemoteThread` | `NtCreateThreadEx` flags, `EtwpCreateEtwThread` (see etw notes) |
| `GetThreadContext`/`SetThreadContext` | `NtGetContextThread`/`NtSetContextThread` direct |

## Placeholder subclass (storage-axis twist)
`VirtualAlloc2(MEM_RESERVE|MEM_RESERVE_PLACEHOLDER, PAGE_NOACCESS)` creates a reserved "empty slot" VAD long before any content arrives; `MapViewOfFile3(..., MEM_REPLACE_PLACEHOLDER)` later replaces it atomically with a section view at the exact same range. The *allocation* event and the *content-arrival* event decouple in time and in API identity — sequences that rules chain on (`alloc→write→protect→exec`) break apart.

## Steps
1. Pick any existing technique KB; rewrite each memory/handle call using the table (keep semantics identical — the twins are documented equivalents, not different operations).
2. Test against Elastic with a one-iteration run: if the rule set is name-matching, telemetry shows the substituted names; if it hooks the shared syscall stub underneath, zero gain — measure, don't assume.
3. Whatever substitutions evade, propagate back into the affected KB entries' `Steps`.

## Pitfalls
- Kernel-level telemetry (VAD events, object callbacks, call-stack capture) is **unchanged** — this transform only moves the API-name/import dimension. It cannot fix unbacked-memory or remote-map detections by itself.
- Several twins resolve to the identical `Nt*` syscall stub — if the sensor hooks the syscall rather than matching API names, the transform is a no-op. Verify empirically per rule family.
- `VirtualAlloc2`/`MapViewOfFile3` live in `kernel32.dll`/`api-ms-win-core-memory` sets and need Win10+; unavailable exports on older builds.
- `VirtualProtectFromApp` only manages a restricted protection subset; semantics differ from full `VirtualProtect` — read the docs per call before substituting.
