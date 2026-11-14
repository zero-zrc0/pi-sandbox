param([Parameter(Mandatory=$true)][string]$Executable)
$ErrorActionPreference = 'Stop'
Add-Type @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
public class RuntimeIntegrity {
    [StructLayout(LayoutKind.Sequential)] struct Attributes { public int size; public IntPtr descriptor; public int inherit; }
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode)] static extern uint GetNamedSecurityInfo(string path, int type, uint info, out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool ConvertSecurityDescriptorToStringSecurityDescriptor(IntPtr descriptor, uint revision, uint info, out IntPtr text, out uint size);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string text, uint revision, out IntPtr descriptor, out uint size);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr CreateFile(string path, uint access, uint sharing, ref Attributes attributes, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr pointer);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool MoveFileEx(string source, string destination, uint flags);
    public static void Commit(string source, string destination) {
        if (!MoveFileEx(source, destination, 9)) throw new Win32Exception();
    }
    public static bool NeedsRepair(string path) {
        IntPtr owner, group, dacl, sacl, descriptor, text;
        uint error = GetNamedSecurityInfo(path, 1, 0x10, out owner, out group, out dacl, out sacl, out descriptor);
        if (error != 0) throw new Win32Exception((int)error);
        try {
            uint size;
            if (!ConvertSecurityDescriptorToStringSecurityDescriptor(descriptor, 1, 0x10, out text, out size)) throw new Win32Exception();
            try {
                string label = Marshal.PtrToStringUni(text);
                return label.Contains(";;;LW)") || label.Contains(";;;UN)");
            } finally { LocalFree(text); }
        } finally { LocalFree(descriptor); }
    }
    public static void CopyAtMedium(string source, string destination) {
        IntPtr descriptor; uint size;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptor("S:(ML;;NW;;;ME)", 1, out descriptor, out size)) throw new Win32Exception();
        try {
            var attributes = new Attributes { size = Marshal.SizeOf(typeof(Attributes)), descriptor = descriptor };
            var handle = CreateFile(destination, 0x40000000, 0, ref attributes, 1, 0x80, IntPtr.Zero);
            if (handle == new IntPtr(-1)) throw new Win32Exception();
            CloseHandle(handle);
            using (var input = File.OpenRead(source))
            using (var output = new FileStream(destination, FileMode.Open, FileAccess.Write, FileShare.None)) input.CopyTo(output);
            File.SetAccessControl(destination, File.GetAccessControl(source, System.Security.AccessControl.AccessControlSections.Access));
        } finally { LocalFree(descriptor); }
    }
}
'@
if ([RuntimeIntegrity]::NeedsRepair($Executable)) {
    $replacement = Join-Path ([IO.Path]::GetDirectoryName($Executable)) ('.integrity-' + [Guid]::NewGuid().ToString('N'))
    try {
        # A new file can declare Medium at creation without relabeling an inherited Low file.
        [RuntimeIntegrity]::CopyAtMedium($Executable, $replacement)
        [RuntimeIntegrity]::Commit($replacement, $Executable)
        if ([RuntimeIntegrity]::NeedsRepair($Executable)) { throw 'Runtime executable retained Low integrity after replacement.' }
    } finally {
        if ([IO.File]::Exists($replacement)) { [IO.File]::Delete($replacement) }
    }
}
