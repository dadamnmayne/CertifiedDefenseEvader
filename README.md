# Certified Defense Evader

Learning about defense evasion from articles read, courses taken and malware reversed.
All efforts are to learn about EDRs and encourage the continued development of EDRs.
For ethical use only.
I comment very throughly and obsessively. It helps me learn. You've been warned.


## ETWTI_Stack_Trace_Evader: When complete, this will accept and execute a malicious DLL while hopefully evading the best EDRs.

Usage [Create your own DLL file in msfvenom or however you prefer]:

```ETWTIStackTraceEvader.exe [DLL FILENAME].dll```

I highly advise making your DLL send a reverse shell back to your attacking machine as opposed to just making it open notepad.exe or some bullshit.

ldump_rot13: Mimikatz but in C# and all run-time signatures stripped. Does not evade scanning of binary at rest at this time.

