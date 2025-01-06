#ifndef NT_STRUCTS_H
#define NT_STRUCTS_H

#include <stdio.h>
#include <Windows.h>

EXTERN_C NTSTATUS NtAllocateVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID *BaseAddress,
    IN ULONG ZeroBits,
    IN OUT PSIZE_T RegionSize,
    IN ULONG AllocationType,
    IN ULONG Protect
);


#endif // NT_STRUCTS_H
