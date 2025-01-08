#ifndef DIRECT_SYSCALL_H
#define DIRECT_SYSCALL_H

#include <stdio.h>
#include <Windows.h>

#include "structs.h"

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

// Current implamentation is based on Hell's Gate technique.
// https://github.com/am0nsec/HellsGate/blob/master/HellsGate/main.c#L8

enum DirectSyscallSwitch {
    On, 
    Off
};

typedef struct NtTableEntry {
    PVOID pAddress; 
    DWORD64 dwHash;
    WORD wSyscall;
} NtTableEntry, *pNtTableEntry;

typedef struct NtTable {
    NtTableEntry NtAllocateVirtualMemory;
    NtTableEntry NtProtectVitualMemory;
    NtTableEntry NtWriteVirtualMemory;
    NtTableEntry NtCreateThreadEx;
} NtTable, *pNtTable;

enum DirectSyscallLibrary {
    SysNtAllocateVirtualMemory,
    SysNtProtectVirtualMemory,
    SysNtWriteVirtualMemory,
    SysNtCreateThreadEx,
    SysNtWaitForSingleObject
};

PTEB RtlGetThreadEnvironmentBlock(VOID);
BOOL GetPebImageExportDirectory(IN PVOID pModuleBase, OUT PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory);
BOOL GetNtTableEntry(IN PVOID pModuleBase, IN PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, IN pNtTableEntry pVxTableEntry);
BOOL initiateDirectSyscallTable(IN NtTable *NtTable);
BOOL runDirectSyscall(IN pNtTable *pNtTable, IN enum DirectSyscallLibrary DirectSyscallLibrary, ...);
DWORD64 fnv1(PBYTE data);











#endif // DIRECT_SYSCALL_H
