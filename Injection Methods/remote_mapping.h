#ifndef REMOTE_MAPPING_H
#define REMOTE_MAPPING_H

#include <stdio.h>

typedef PVOID (WINAPI *PFN_MapViewOfFile2)(
    HANDLE, 
    HANDLE, 
    ULONG64, 
    ULONG64, 
    SIZE_T, 
    ULONG, 
    ULONG);

BOOL findTargetProcessRemoteMapping(IN char* szProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess);
BOOL runRemoteMappingInjection(IN HANDLE hProcess, IN PBYTE pShellCodeBuffer, IN DWORD dwShellcodeBufferSize);

#endif // REMOTE_MAPPING_H
