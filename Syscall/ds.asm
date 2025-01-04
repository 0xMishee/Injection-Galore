section .data
    wSyscall dd 0x000  ; 

section .text
    global DirectSysCallUpdate
    global DirectSysCall

DirectSysCallUpdate:
    mov dword [wSyscall], 0x000  
    mov dword [wSyscall], ecx     ; Update SSN number
    ret

DirectSysCall:
    mov r10, rcx
    mov eax, dword [wSyscall]     ; Load syscall SSN into eax
    syscall                       ; Invoke the system call
    ret
