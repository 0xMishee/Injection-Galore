// Standard Libraries
#include <stdio.h>
#include <windows.h>

// Custom Libraries
#include "../Headers/info.h"
#include "../Headers/config.h"
#include "../Headers/hashtable.h"
#include "../Headers/enumeration.h"
#include "../Headers/error.h"

/*
The idea of this program is to be able to choose injection methods to test with various payloads. 
*/

typedef struct {
    char *injectionMethod;
    char *payload;
    char *encryption;
    char *enumeration;
} config, *pConfig;



int main(int argc, char *argv[]) {
    
    // Early failure checks
    if (argc < 2) {
        informationUsageHelp();
        return 1;
    } else {
        // Validate the flags.
        for (size_t i = 1; i < argc; i+=2) {
            //printf("Flag %s, value %s\n", argv[i], argv[i+1]);
        }
    }

    HMODULE hNTDLLMoudle = GetModuleHandleW(L"ntdll.dll");
    if (!hNTDLLMoudle) {
        handleError(ERROR_INVALID_MODULE, "Failed to get module handle ntdll.dll");
        goto Cleanup;
        return 1;
    }
    HMODULE hKernel32Module = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32Module) {
        handleError(ERROR_INVALID_MODULE, "Failed to get module handle kernel32.dll");
        goto Cleanup;
        return 1;
    }

    if (!enumerateAll(hNTDLLMoudle, hKernel32Module)) {
        handleError(ERROR_INVALID_ENUMERATION, "Failed to enumerate all");
        goto Cleanup;
        return 1;
    }

    
    Cleanup:
    if (hNTDLLMoudle) {FreeLibrary(hNTDLLMoudle);}
    if (hKernel32Module) {FreeLibrary(hKernel32Module);}



    return 0;
}