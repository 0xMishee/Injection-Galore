#ifndef REMOTE_SHELLCODE_H
#define REMOTE_SHELLCODE_H
#include <stdio.h>
#include <Windows.h>

BOOL findTargetProcessRemoteShellCode(IN char* szProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess);
BOOL runShellcodeInjection(IN char* TARGET_PROCESS, IN PBYTE pShellcodeBuffer, IN DWORD dwShellcodeBufferSize);

#endif // REMOTE_SHELLCODE_H
