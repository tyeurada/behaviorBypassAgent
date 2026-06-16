using System;
using System.IO;
using System.Runtime.InteropServices;

public class Program
{
    // Allocates memory with specific protection constants
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr VirtualAlloc(
        IntPtr lpAddress,
        uint dwSize,
        uint flAllocationType,
        uint flProtect);

    // Frees previously allocated memory
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern bool VirtualFree(
        IntPtr lpAddress,
        uint dwSize,
        uint dwFreeType);

    // Memory allocation type constants
    private const uint MEM_COMMIT = 0x1000;
    private const uint MEM_RESERVE = 0x2000;

    // Memory protection constants
    private const uint PAGE_EXECUTE_READWRITE = 0x40;

    // Memory deallocation type constant
    private const uint MEM_RELEASE = 0x8000;

    // Delegate type for the shellcode entry point
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate void RunShellcode();

    public static void Main(string[] args)
    {
        if (args.Length == 0)
        {
            Console.WriteLine("Usage: Program.exe <path_to_shellcode_bin>");
            return;
        }

        string filePath = args[0];
        if (!File.Exists(filePath))
        {
            Console.WriteLine(string.Format("Error: File not found at '{0}'", filePath));
            return;
        }

        byte[] payload;
        try
        {
            payload = File.ReadAllBytes(filePath);
        }
        catch (Exception e)
        {
            Console.WriteLine(string.Format("Error reading file: {0}", e.Message));
            return;
        }

        if (payload.Length == 0)
        {
            Console.WriteLine("Error: Shellcode file is empty.");
            return;
        }

        IntPtr execMem = IntPtr.Zero;
        try
        {
            // 1. Allocate a memory buffer with Read/Write/Execute permissions
            execMem = VirtualAlloc(
                IntPtr.Zero,
                (uint)payload.Length,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE);

            if (execMem == IntPtr.Zero)
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            }

            // 2. Copy the shellcode from the byte array to the allocated memory
            Marshal.Copy(payload, 0, execMem, payload.Length);

            // 3. Create a delegate to the shellcode function
            RunShellcode func = (RunShellcode)Marshal.GetDelegateForFunctionPointer(
                execMem,
                typeof(RunShellcode));

            // 4. Execute the shellcode
            Console.WriteLine(string.Format("Executing shellcode of size {0} bytes...", payload.Length));
            func();
            Console.WriteLine("Shellcode execution finished.");
        }
        catch (Exception e)
        {
            Console.WriteLine(string.Format("An exception occurred: {0}", e.ToString()));
        }
        finally
        {
            // 5. Free the allocated memory
            if (execMem != IntPtr.Zero)
            {
                VirtualFree(execMem, 0, MEM_RELEASE);
            }
        }
    }
}