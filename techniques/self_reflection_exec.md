# Self-Reflection Execution (fork-and-run, zero cross-process ops)

## Concept
Use Windows' process **reflection/fork** primitive on *ourselves*: `RtlCreateProcessReflection` (or `RtlCloneUserProcess`) asks the kernel to clone our own process into a new child — all committed memory, including an already-staged payload, is copied copy-on-write at fork time. The payload in the child is therefore "inherited at birth": no remote allocation, write, or map call ever exists, and the child even inherits our handle table.

## Why it may matter
- The entire staging surface disappears: there is no `VirtualAllocEx`/`WriteProcessMemory`/remote-map event *into the executing process* — the payload arrives via a single process-create syscall.
- Deep Instinct's "Dirty Vanity" (BH EU 2022) published the mechanism as fork-the-victim; the self-directed variant (fork after local staging, run in our own clone) is a simpler, unlabeled composition that also removes the target-write step entirely.
- `RtlCreateProcessReflection(ProcessHandle, Flags, StartRoutine, StartContext, EventHandle, ReflInfo)` can start the clone's new thread at `StartRoutine` — pointing it at the staged payload address (identical in the clone, since the layout is preserved) executes the payload inside the child without a `CreateThread`-named API.

## Steps
1. Stage the payload locally — plain RW/RX private memory works, or a stomped module if unbacked provenance must be fixed (composition point: see module_stomping_*). Record its absolute address; the clone shares the same layout.
2. Call `RtlCreateProcessReflection(GetCurrentProcess(), RTL_PROCESS_REFLECTION_FLAGS_INHERIT_HANDLES, payload_addr, param, NULL, NULL)` — or `RtlCloneUserProcess` for the raw fork form (returns in both processes; branch on the child path).
3. The child process — a clone of the unsigned loader image — starts a thread at `payload_addr` and runs the shellcode inside its inherited (COW) memory.

## Pitfalls
- Reflection/clone APIs (`RtlCreateProcessReflection`, `RtlCloneUserProcess`, `NtCreateProcessEx`-with-parent) are niche — expect the *call itself* to be signature-able even though no write/map events exist.
- Child image = our own unsigned loader binary: `5eb295bd`-class "unsigned fresh parent/child" attribution rules see a familiar picture — this technique only removes the *staging* events, not provenance.
- The cloned payload region keeps `MEM_PRIVATE`/unbacked provenance in the child — pair with module-backed staging first if call-stack rules are the target.
- Kernel thread-creation callbacks (`PsSetCreateThreadNotifyRoutine`) still observe the reflection thread; only userland `CreateThread*`-name matching is avoided.
- The clone inherits the handle table — close sensitive handles or use non-inheritable flags before forking.
