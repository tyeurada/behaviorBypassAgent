# Windows Hook (SetWindowsHookEx) Injection

## Concept
`SetWindowsHookEx(WH_*)` registers a hook whose callback lives in a DLL; Windows loads that DLL into **every process** matching the hook scope (GUI processes for WH_GETMESSAGE etc.) — the OS itself performs the "injection", so no VirtualAllocEx/WriteProcessMemory/CreateRemoteThread exists.

## Why it may matter
- Classic legit-API-as-loader: module load happens through `user32.dll`'s hook machinery inside the *target* process, attributed to a system path.
- Well-known detection: `SetWindowsHookEx` with an unusual DLL path/name, unsigned module load into many processes.

## Steps
1. Build a DLL exporting the hook proc (e.g. `GetMsgProc`) whose body runs the payload (or stages it in the host on first call).
2. `hMod = LoadLibrary(dll)` in our process; `SetWindowsHookEx(WH_GETMESSAGE, proc, hMod, target_thread_id)` — targeting one GUI thread (e.g. a window of notepad) limits blast radius vs a global (0) hook.
3. When the target next pulls a message, Windows maps our DLL in and calls the hook → payload runs inside the target.
4. `UnhookWindowsHookEx` after trigger.

## Pitfalls
- Only works against GUI threads; services/console procs unaffected.
- The hook DLL must match target bitness; our compiled payload needs a DLL build path (MSVC `/LD`) — check compiler config supports it.
- An unsigned DLL mapped into a signed host triggers `unsigned module load` and `hook injection` style rules — storage inside the target is still module-file-backed (our DLL on disk), which helps vs unbacked rules but hurts on reputation rules.
- Global hooks (`thread id 0`) are maximally noisy.
