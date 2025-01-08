#ifndef INDIRECT_SYSCALL_H
#define INDIRECT_SYSCALL_H

#include <stdio.h>
#include <windows.h>

enum IndirectSyscallSwitch {
    On, 
    Off
};

typedef struct NtDLLConfig
{

    PDWORD pdwArrayOfAddresses; 
    PDWORD pdwArrayOfNames;    
    PWORD pwArrayOfOrdinals;   
    DWORD dwNumberOfNames;     
    ULONG_PTR uModule;        

}NtDLLConfig, * PNtDLLConfig;




#endif // INDIRECT_SYSCALL_H
