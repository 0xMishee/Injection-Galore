#include <stdio.h>
#include <Windows.h>
#include "direct_syscall.h"
#include "structs.h"



BOOL GetNtTableEntryIndirectVersion(IN PVOID pModuleBase, IN PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, IN pNtTableEntry pNtTableEntry){

    // Fetch Func, Name, Ordinal from PEB Export Table.
    PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfFunctions);
    PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNames);
	PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNameOrdinals);

    for (WORD i = 0; i < pImageExportDirectory->NumberOfNames; i++) {
		PCHAR pFunctionName = (PCHAR)((PBYTE)pModuleBase + pdwAddressOfNames[i]);
		PVOID pFunctionAddress = (PBYTE)pModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[i]];
        
        // Debugging 😘
        //printf("Function: %s : %s\n", pFunctionName, fnv1((PBYTE)pFunctionName) == pNtTableEntry->dwHash ? "True" : "False");

		if (fnv1((PBYTE)pFunctionName) == pNtTableEntry->dwHash) {
			pNtTableEntry->pAddress = pFunctionAddress;
            WORD j = 0;
			while (TRUE) {
                // Check for ret
				if (*((PBYTE)pFunctionAddress + j) == 0x0f && *((PBYTE)pFunctionAddress + j + 1) == 0x05)
					return FALSE;
				if (*((PBYTE)pFunctionAddress + j) == 0xc3)
					return FALSE;

                /* Debugging 😘
                printf("%x ", *((PBYTE)pFunctionAddress + j));
                printf("%x ", *((PBYTE)pFunctionAddress + 1 + j));
                printf("%x ", *((PBYTE)pFunctionAddress + 2 + j));
                printf("%x ", *((PBYTE)pFunctionAddress + 3 + j));
                printf("%x ", *((PBYTE)pFunctionAddress + 4 + j));
                printf("%x\n", *((PBYTE)pFunctionAddress + 5 + j));
                */

				// First opcodes should be : incrament if hooked.
				//    MOV R10, Ri
				//    MOV Ri, <syscall>
				if (*((PBYTE)pFunctionAddress + j) == 0x4c
					&& *((PBYTE)pFunctionAddress + 1 + j) == 0x8b
					&& *((PBYTE)pFunctionAddress + 2 + j) == 0xd1
					&& *((PBYTE)pFunctionAddress + 3 + j) == 0xb8
					&& *((PBYTE)pFunctionAddress + 5 + j) == 0x00) {
					BYTE high = *((PBYTE)pFunctionAddress + 5 + j);
					BYTE low = *((PBYTE)pFunctionAddress + 4 + j);
                    // Multiply by 256 and add the low byte.
                    pNtTableEntry->wSyscall = (high * 256) + low;
					break;
				}

				j++;
			};
		}
	}


    return TRUE;
}