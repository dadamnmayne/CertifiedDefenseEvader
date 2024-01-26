#include <windows.h>
#include <stdio.h>

/* https://0xdarkvortex.dev/proxying-dll-loads-for-hiding-etwti-stack-tracing/ */

/*INTENT: To build a function pointer type named TPALLOCWORK.

TPALLOCWORK takes the following parameters:
   PTP_WORK* ptpWrk: A pointer to a pointer to a TP_WORK structure.
   PTP_WORK_CALLBACK pfnwkCallback: A pointer to a callback function.
   PVOID OptionalArg: An optional argument that can be passed to the callback function.
   PTP_CALLBACK_ENVIRON CallbackEnvironment: A pointer to a callback environment structure.
   The function returns an NTSTATUS status code (typedef NTSTATUS).

TPALLOCWORK is intended to pass LoadLibraryA, the function we need for 
our DLL load, as a callback. Callback functions are pointers (addresses) to a 
function which can be passed on to other functions to be executed 
inside them.

WHY: To forward all of the functions of LoadLibraryA properly. We need
LoadLibraryA to load our special DLL.*/
typedef NTSTATUS (NTAPI* TPALLOCWORK)(PTP_WORK* ptpWrk, PTP_WORK_CALLBACK pfnwkCallback, PVOID OptionalArg, PTP_CALLBACK_ENVIRON CallbackEnvironment);







typedef VOID (NTAPI* TPPOSTWORK)(PTP_WORK);
typedef VOID (NTAPI* TPRELEASEWORK)(PTP_WORK);
