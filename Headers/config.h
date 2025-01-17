#ifndef CONFIG_H
#define CONFIG_H

#include <stdio.h>
#include "error.h"
#include "payloads.h"

typedef struct {
    char *injectionMethod;
    char *payload;
    int directSyscallSwitch;
} config, *pConfig;

typedef struct {
    const char *payloadName;
    const unsigned char *payload;
    const size_t payloadSize;
} configMap, *pConfigMap;

// Injection methods
// Not currently used.
static const char *injectionMethodsValue[] = {
    "rdll",     // Remote DLL
    "ldll",     // Local DLL
    "rsc",      // Remote Shellcode
    "lsc",      // Local Shellcode
    "apc",      // Asynchronous Procedure Call
    "ebapc",    // Early Bird Asynchronous Procedure Call
    "lm",       // Local Mapping
    "rm",       // Remote Mapping
    "lfs",      // Local Function Stomping
    "rfs",      // Remote Function Stomping
    "lpe",      // Local PE
    "redll",    // Reflective DLL
    "tl",       // Threadless
    "gp",       // Ghost Process
    "gh",       // Ghost Hollowing
    "hrp",      // Herpaderping
    "hrph",     // Herpaderping Hollowing
    "ph",       // Process Hypnosis
    "kcp",      // Known Cache Poisoning
    "ca",       // Cross Architecture
    "ab",       // Atom Bombing
};

static configMap payloads[] = {
    {"calc", payloadCalc, PAYLOAD_CALC_SIZE},
    {"bind_shell", payloadBindShell, PAYLOAD_BIND_SHELL_SIZE},
};

// Initate the configuration, all values are set to set option or remains NULL.
void parseArguments(int argc, char *argv[], pConfig config) {
    for (int i = 1; i < argc; i+=2) {
        if (strcmp(argv[i], "--injection") == 0) {
            config->injectionMethod = argv[i+1];
        } else if (strcmp(argv[i], "--payload") == 0) {
            config->payload = argv[i+1];
        } else if (strcmp(argv[i], "--directsyscall") == 0) {
            char *endptr;
            config->directSyscallSwitch = strtol(argv[i+1], &endptr, 10);
            if (*endptr != '\0') {
                handleError(ERROR_INVALID_FLAG, "Invalid number for DirectSysCall");
            }
        } else {
            handleError(ERROR_INVALID_FLAG, "Invalid flag");
        }
    }
}

void printConfig(const config *config) {
    printf("Injection Method: %s\n", config->injectionMethod);
    printf("Payload: %s\n", config->payload);
    printf("DirectSysCall: %u\n", config->directSyscallSwitch);
}

configMap* getPayload(const char *payloadName) {
    for (size_t i = 0; i < sizeof(payloads) / sizeof(payloads[0]); i++) {
        if (strcmp(payloads[i].payloadName, payloadName) == 0) {
            return &payloads[i];
        }
    }
    return NULL;
}


#endif // CONFIG_H
