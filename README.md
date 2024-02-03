# Certified Defense Evader

Learning about defense evasion from articles read, courses taken and malware reversed.
All efforts are to learn about EDRs and encourage the continued development of EDRs.
For ethical use only.
I comment very throughly and obsessively. It helps me learn. You've been warned.


## ETWTI_Stack_Trace_Evader:
### Defenses Evaded: EDR API Userland Hooking, Sysmon
### Defenses Triggered: Windows Defender (Unknown Reason, likely Static Component Related. Runs but deletes upon being scanned.)
Accepts a malicious DLL while evading EDRs. Current release does piss Windows Defender off, so I have more work to do. The stack cleaning technique does work, however. Thanks to Paranoid Ninja for the dope technique. He has several other articles, so I'll have to dig through those to see if I can improve this.

Here is the article.
https://0xdarkvortex.dev/proxying-dll-loads-for-hiding-etwti-stack-tracing/

My version accepts a DLL filename as an argument.

Usage [Create your own DLL file in msfvenom or however you prefer]:

```ETWTIStackTraceEvader.exe [DLL FILENAME].dll```

I highly advise making your DLL send a reverse shell back to your attacking machine as opposed to just making it open notepad.exe or some bullshit. Ultimately, we want to encrypt the DLL, allocate space for the DLL, then decrypt the DLL per Reflective DLL Injection.

Next Step: Test on Elastic Endpoint.

## ldump_rot13: 
Mimikatz but in C# and all run-time signatures stripped. Does not evade scanning of binary at rest at this time.

## Vanilla Process Injection:
Will get caught by Windows Defender, Sysmon, EDRs and probably Granny too. Its not completely useless, tho. If you want to hide Command Line arguments from Sysmon, this is the way. Since the Command Line argument only applies to the spawning of a process, you can inject away and no Command Line arguments in Sysmon will appear. This code just serves as a baseline on which we can improve. Credit to cr0w. This is basically his, but I removed the hungarian notation. I hate that shit. I replaced the variable names to more sensible sounding names so that the reader knows whats going on. If you choose to compile and run this, here is the syntax.

Usage [Create your own shellcode in msfvenom. You must disable Windows Defender]

```VanillaProcessInjection.exe [Victim Process ID]```
