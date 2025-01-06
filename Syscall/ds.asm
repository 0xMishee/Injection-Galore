bits 64
default rel                      ;Fixed Relocation issues related to truncation.

section .bss
    global wSyscallID

section .data
    wSyscallID dq 0

section .text
    global DirectSysCallUpdate
    global DirectSysCall

DirectSysCallUpdate:
    mov qword [wSyscallID], 0   ; Reset the value in wSyscallID to 0
    mov word [wSyscallID], cx   ; Move the 16-bit value from CX to the lower 2 bytes of wSyscallID
    ret
    
DirectSysCall:
    mov r10, rcx
    mov eax, dword [wSyscallID]     ; Load syscall SSN into eax
    syscall                 ; Invoke the system call
    ret
