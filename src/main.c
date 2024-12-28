// Standard Libraries
#include <stdio.h>
#include <windows.h>

// Custom Libraries
#include "../Headers/info.h"
#include "../Headers/config.h"
#include "../Headers/hashtable.h"
#include "../Headers/enumeration.h"
#include "../Headers/error.h"
#include "../Injection Methods/dll_injection.h"

#define TARGET_PROCESS "Notepad.exe"
#define TARGET_DLL L"E:\\dev\\Injection Galore\\dll\\injectDll.dll"

/*
The idea of this program is to be able to choose injection methods to test with various payloads. 
The payloads will be encrypted using different encryption methods.
The program will also enumerate the system to gather information about the OS, processes, services, and registry keys.
*/

typedef struct {
    char *injectionMethod;
    char *payload;
    char *encryption;
    char *enumeration;
} config, *pConfig;

// Initate the configuration, all values are set to set option or remains NULL.
void parseArguments(int argc, char *argv[], pConfig config) {
    for (size_t i = 1; i < argc; i+=2) {
        if (strcmp(argv[i], "--injection") == 0) {
            config->injectionMethod = argv[i+1];
        } else if (strcmp(argv[i], "--payload") == 0) {
            config->payload = argv[i+1];
        } else if (strcmp(argv[i], "--encryption") == 0) {
            config->encryption = argv[i+1];
        } else if (strcmp(argv[i], "--enumeration") == 0) {
            config->enumeration = argv[i+1];
        } else {
            handleError(ERROR_INVALID_FLAG, "Invalid flag");
        }
    }
}

void printConfig(const config *config) {
    printf("Injection Method: %s\n", config->injectionMethod);
    printf("Payload: %s\n", config->payload);
    printf("Encryption: %s\n", config->encryption);
    printf("Enumeration: %s\n", config->enumeration);
}

BOOL runConfig(const config *config) {

    if (strcmp(config->injectionMethod, "CreateRemoteThread") == 0) {
        printf("CreateRemoteThread\n");
    } else if (strcmp(config->injectionMethod, "dll") == 0) {
        printf("Dll Injection\n");
    } else {
        handleError(ERROR_INVALID_INJECTION, "Invalid injection method");
        return FALSE;
    }

    Cleanup:
    return TRUE;
}


int main(int argc, char *argv[]) {
    
    // Early failure checks && help
    if (argc < 2) {
        defaultHelp(&argv[0]);
        return 1;
    } else if (strcmp(argv[1], "--help") == 0 && argc == 2) {
        defaultHelp(&argv[0]);
        return 0;
    } else if (strcmp(argv[1], "--help") == 0 && argc > 2) {
        if (strcmp(argv[2], "injection") == 0) {
            injectionMethodsHelp();
        } else if (strcmp(argv[2], "payload") == 0) {
            payloadsHelp();
        } else if (strcmp(argv[2], "encrypt") == 0) {
            encryptionDecryptionMethodsHelp();
        } else if (strcmp(argv[2], "enum") == 0) {
            enumerationMethodsHelp();
        } else {
            defaultHelp(&argv[0]);
        }
        return 0;
    }

    // Parse the arguments
    config config;
    ZeroMemory(&config, sizeof(config));
    parseArguments(argc, argv, &config);

    // Print the configuration. For debugging purposes.
    printConfig(&config);


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

    if (!runDLLInjection(TARGET_PROCESS, hKernel32Module, TARGET_DLL)) {
        handleError(ERROR_INVALID_INJECTION, "Failed to run DLL injection");
        goto Cleanup;
        return 1;
    }




    
    Cleanup:
        if (hNTDLLMoudle) {FreeLibrary(hNTDLLMoudle);}
        if (hKernel32Module) {FreeLibrary(hKernel32Module);}
        return 0;
}