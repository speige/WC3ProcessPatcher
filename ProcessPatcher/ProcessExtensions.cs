using System.Diagnostics;
using System.Runtime.InteropServices;

public static class ProcessExtensions
{
    public static bool IsTargetProcess64Bit(this Process process)
    {
        if (Environment.Is64BitOperatingSystem)
        {
            // On a 64-bit OS, check if the process is running under WOW64
            if (!Win32Api.IsWow64Process(process.Handle, out bool isWow64))
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            }
            return !isWow64;
        }

        // On a 32-bit OS, all processes are 32-bit
        return false;
    }
}
