bits 64
default rel                     ;Fixed Relocation issues related to truncation.

section .bss
    global wSyscallID
    global qSyscallAddress

section .data
    wSyscallID dq 0
    qSyscallAddress qword 0

section .text
    global IndirectDirectSysCallUpdate
    global IndirectDirectSysCall

DirectSysCallUpdate:
    mov qword [wSyscallID], 0   ; Reset the value in wSyscallID to 0
    mov word [wSyscallID], cx   ; Move the 16-bit value from CX to the lower 2 bytes of wSyscallID
    ret
    
DirectSysCall:
    mov r10, rcx
    mov eax, dword [wSyscallID]     ; Load syscall SSN into eax
    jmp qword ptr [qSyscallAddress] ; Invoke the system call through jump -> qSyscallAddress (Syscall)
    ret
