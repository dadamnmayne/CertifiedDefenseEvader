section .text

extern getLoadLibraryA

global WorkCallback

WorkCallback:
	; INTENT: To move to rcx (first argument) from rdx (second argument)
	; Needed if you have to move arguments around for a function.
    mov rcx, rdx
	; INTENT: To set rdx (second argument of getLoadLibraryA) to zero.
    xor rdx, rdx
	; INTENT: Calls getLoadLibraryA.
    call getLoadLibraryA
	; INTENT: Jump to the return value of getLoadLibraryA.
    jmp rax
