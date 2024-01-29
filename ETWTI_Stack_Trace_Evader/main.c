#include <windows.h>
#include <stdio.h>

/* https://0xdarkvortex.dev/proxying-dll-loads-for-hiding-etwti-stack-tracing/ */

/*INTENT: To build a function pointer type named TPALLOCWORK.

TPALLOCWORK takes the following parameters:
o PTP_WORK* ptpWrk: A pointer to a pointer to a TP_WORK structure.
o PTP_WORK_CALLBACK pfnwkCallback: A pointer to a callback function.
o PVOID OptionalArg: An optional argument that can be passed to the callback function.
o PTP_CALLBACK_ENVIRON CallbackEnvironment: A pointer to a callback environment structure.

The function returns an NTSTATUS status code (typedef NTSTATUS).

TPALLOCWORK is intended to pass LoadLibraryA, the function we need for 
our DLL load, as a callback. Callback functions are pointers (addresses) to a 
function which can be passed on to other functions to be executed 
inside them.

WHY: To forward all of the functions of LoadLibraryA properly. We need
LoadLibraryA to load our special DLL.*/
typedef NTSTATUS (NTAPI* TPALLOCWORK)(PTP_WORK* ptpWrk, PTP_WORK_CALLBACK pfnwkCallback, PVOID OptionalArg, PTP_CALLBACK_ENVIRON CallbackEnvironment);

/*
INTENT: To define a function pointer type named 'TPPOSTWORK'
This object posts a thread pool work object. But we're going to
set this to null. 
*/
typedef VOID (NTAPI* TPPOSTWORK)(PTP_WORK);

/*
INTENT: To define a function pointer type named 'TPRELEASEWORK.
This object releases a thread pool work object. But we're going
to set this to null.
*/
typedef VOID (NTAPI* TPRELEASEWORK)(PTP_WORK);

/*
In C and C++, a function pointer is a variable that can hold the
address of a function. It allows you to use a function as an argument
to another function, return a function from a function, and store functions
in data structures. A function pointer type is a typedef or a type alias 
that makes it easier to declare and use function pointers.

Function pointers are particularly useful in scenarios where you want to
pass functions as arguments or return functions from other functions, 
such as in callback mechanisms or implementing function tables.
*/

/* 
So, FARPROC pLoadLibraryA; declares a function pointer variable
named pLoadLibraryA, which is expected to point to a function with the
same signature as LoadLibraryA. Later in the code, you might assign the
address of LoadLibraryA to this function pointer to dynamically load a DLL
and use its functions.

FARPROC: This is a typedef used in Windows programming to declare a function 
pointer type. It stands for "Far Procedure," where "far" refers to memory 
addressing in the segmented memory model used in older versions of Windows. 
In modern Windows programming, with the flat memory model, the distinction 
between near and far pointers is no longer relevant, but the typedefs are 
still used for compatibility.

pLoadLibraryA: This is the name of the variable being declared. 
It suggests that this function pointer may be used to hold the address of 
the LoadLibraryA function. LoadLibraryA is a function from the Windows API 
used to load a dynamic-link library (DLL).
*/

FARPROC pLoadLibraryA;

/*
The function getLoadLibraryA appears to be returning the address of the function
pointed to by the pLoadLibraryA functionpointer as a UINT_PTR (unsigned integer
type designed to hold a pointer). Here's a breakdown of the code:

    UINT_PTR: This is an unsigned integer type that is 
    designed to be large enough to hold a pointer. It's commonly 
    used for storing addresses and is part of Windows programming,
    often used in the WinAPI.

    getLoadLibraryA(): This is the function declaration. 
    It returns a value of type UINT_PTR.

    { return (UINT_PTR)pLoadLibraryA; }: This is the body of the 
    function. It casts the function pointer pLoadLibraryA to UINT_PTR 
    and returns that value.

This function is likely used in a scenario where you need to obtain 
the address of the LoadLibraryA function through the pLoadLibraryA 
function pointer. The UINT_PTR type is used to ensure that the address 
is properly represented in an unsigned integer type. The cast is necessary 
because pLoadLibraryA is declared as a function pointer, and you want to 
obtain the raw address of the function it's pointing to.
*/

UINT_PTR getLoadLibraryA() {
    return (UINT_PTR)pLoadLibraryA;
}

/* INTENT: To create a function that activates our reroutingWorkCallback.asm file.*/
extern VOID CALLBACK WorkCallback(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("nah\n");
        return 1;
    }
    /* INTENT: To find the address of, and eventually retrieve, getLoadLibraryA 
    so we can move some stuff around.*/
    pLoadLibraryA = GetProcAddress(GetModuleHandleA("kernel32"), "LoadLibraryA");

    /* INTENT: To find the address of, and eventually retrieve, TPALLOCWORK.
    TPALLOCWORK will pass LoadLibraryA, our DLL loader, as a pointer to a function
    that can be manipulated or passed to other functions. The pointer will be 
    known as a Callback function.*/
    FARPROC pTpAllocWork = GetProcAddress(GetModuleHandleA("ntdll"), "TpAllocWork");

    /*INTENT: To retrieve the object that allows us to post a work item to the thread
    pool.*/
    FARPROC pTpPostWork = GetProcAddress(GetModuleHandleA("ntdll"), "TpPostWork");
    
    /* INTENT: To retrieve the object that allows us to release a work item from the 
    thread pool. This is required to avoid resource leaks.*/
    FARPROC pTpReleaseWork = GetProcAddress(GetModuleHandleA("ntdll"), "TpReleaseWork");

    /*INTENT: Creates the string wininet.dll so that we can load the file wininet.dll*/
    //CHAR* libName = "wininet2.dll";
    
    char* libName = argv[1];

    /* INTENT: To set the Thread Pool Work Object "WorkReturn" to null. */
    PTP_WORK WorkReturn = NULL;

    /* INTENT: To pass wininet.dll to LoadLibraryA in the stealthiest way possible.
    Here, we can now work with LoadLibraryA and wininet.dll. We're allocating space
    in the thread for LoadLibraryA. */
    ((TPALLOCWORK)pTpAllocWork)(&WorkReturn, (PTP_WORK_CALLBACK)WorkCallback, libName, NULL);

    /* INTENT: To set the Thread Pool Post work and thread pool release work to null.
    Seems dangerous.*/
    ((TPPOSTWORK)pTpPostWork)(WorkReturn);
    ((TPRELEASEWORK)pTpReleaseWork)(WorkReturn);

    /* INTENT: To wait until the specified object is in the signaled
    state or the time-out interval elapses. */
    WaitForSingleObject((HANDLE)-1, 0x1000);

    /* INTENT: Proof that it works.*/
    printf("%s: %p\n", libName, GetModuleHandleA(libName));

    return 0;
}
