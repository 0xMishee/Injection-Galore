#ifndef DLL_INJECTION_H
#define DLL_INJECTION_H

#include <stdio.h>
#include <windows.h>

BOOL findTargetProcessRemoteDLL(IN char* szProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess);
BOOL injectDLL(IN HANDLE hProcess, IN LPWSTR DllPath, IN HMODULE hKernel32Module);
BOOL runDLLInjection(IN char* szProcessName, IN HMODULE hKernel32Module, IN LPWSTR DllPath);

#endif // DLL_INJECTION_H
