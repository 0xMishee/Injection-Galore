#ifndef REFLECTIVE_DLL_INJECTION_H
#define REFLECTIVE_DLL_INJECTION_H

#include <stdio.h>
#include <Windows.h>

typedef struct _BASE_RELOCATION_BLOCK {
    DWORD PageAddress;
    DWORD BlockSize;
} BASE_RELOCATION_BLOCK, *PBASE_RELOCATION_BLOCK;

static UINT32 CRC32B(LPCSTR str);
static HMODULE ModuleHandle(IN UINT32 uModuleHash);
static FARPROC GetProcAddressEx(IN HMODULE hModule, IN UINT32 uFunctionHash);
static BOOL importAddressTable(IN PIMAGE_DATA_DIRECTORY pEntryImportDataDir, IN PBYTE pPEBaseAddress);
static BOOL Reloc(IN PIMAGE_DATA_DIRECTORY pEntryRelocDataDir, IN ULONG_PTR pPEBaseAddress, IN ULONG_PTR pPreferredBaseAddress);
static BOOL MemPermissions(IN ULONG_PTR pPEBaseAddress, IN PIMAGE_NT_HEADERS pImgNtHeaders, IN PIMAGE_SECTION_HEADER pImgSectionHeaders);
BOOL runReflectiveDLLInjection(IN HANDLE hProcess, IN DWORD dwRflFuncOffset, IN PBYTE pRflDllBuffer, IN DWORD dwRflDllSize);





#endif // REFLECTIVE_DLL_INJECTION_H