# Scattered / Fragmented Allocation

## Concept
Split the shellcode into many small chunks spread across separate allocations (heap slots, mapped views, atom strings). At execution time a stub reassembles them — or the chunks are threaded via relative jumps (`jmp next_chunk`) so the payload never exists contiguously in one page.

## Why it may matter
- Signature/content scanners (incl. Elastic's memory-threat engine `5b88772f`) match contiguous byte patterns — fragmentation defeats window-size-limited matching.
- `relative_file_creation_time`/size-based heuristics that key on "one suspicious large alloc" see only small allocations.

## Steps
1. Split shellcode at N-byte boundaries (e.g. 64–256B chunks).
2. Allocate K small RW regions (heap or VirtualAlloc); write each chunk.
3. Reassembly strategy:
   a) One RX staging buffer + memcpy chunks in order (simplest — the staging buffer re-introduces a contiguous payload, but only exists briefly).
   b) Jump-chain: append `E9 <rel32>` to each chunk so execution flows chunk→chunk without reassembly (all chunks must be executable — unbacked-exec rules still apply).
   c) Reassemble into a stomped/RWX-reused module region (best: pairs with module-backed execution).

## Pitfalls
- Option (a/b) keep chunks in unbacked memory — behavioral rules still fire unless the final exec region is module/image-backed.
- Chunk boundaries must not split multi-byte instructions mid-way unless jump-chaining accounts for it — corrupting the payload silently fails at exec.
- Dozens of tiny allocs are themselves an unusual allocation fingerprint.
- Memory scanner may scan at exec time on the reassembled region — fragment at rest ≠ fragmented at exec. Prefer reassembly into module-backed space.
