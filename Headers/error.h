#ifndef ERROR_H
#define ERROR_H

#include <stdio.h>
#include <stdlib.h>

typedef enum {
    ERROR_NONE = 0,
    ERROR_INVALID_ARGUMENTS,
    ERROR_INVALID_FLAG,
    ERROR_INVALID_MODULE,
    ERROR_INVALID_PROCESS,
    ERROR_INVALID_SERVICE,
    ERROR_INVALID_REGISTRY,
    ERROR_INVALID_OS,
    ERROR_INVALID_PAYLOAD,
    ERROR_INVALID_ENCRYPTION,
    ERROR_INVALID_ENUMERATION,
    ERROR_INVALID_INJECTION,
    ERROR_INVALID_CONFIG,
    ERROR_INVALID_HASHTABLE,
    ERROR_INVALID_INFO,
    ERROR_UNKNOWN,
    ERROR_FUNCTION_NOT_FOUND, 
    ERROR_FAILED_TO_GET_PROCESS_ADDRESS,
    ERROR_FAILED_TO_ALLOCATE_MEMORY
} errorCode;

static const char* getErrorMessage(errorCode code){
    switch (code)
    {
        case ERROR_NONE: return "No error";
        case ERROR_INVALID_ARGUMENTS: return "Invalid arguments";
        case ERROR_INVALID_FLAG: return "Invalid flag";
        case ERROR_INVALID_MODULE: return "Invalid module";
        case ERROR_INVALID_PROCESS: return "Invalid process";
        case ERROR_INVALID_SERVICE: return "Invalid service";
        case ERROR_INVALID_REGISTRY: return "Invalid registry";
        case ERROR_INVALID_OS: return "Invalid OS";
        case ERROR_INVALID_PAYLOAD: return "Invalid payload";
        case ERROR_INVALID_ENCRYPTION: return "Invalid encryption";
        case ERROR_INVALID_ENUMERATION: return "Invalid enumeration";
        case ERROR_INVALID_INJECTION: return "Invalid injection";
        case ERROR_INVALID_CONFIG: return "Invalid config";
        case ERROR_INVALID_HASHTABLE: return "Invalid hashtable";
        case ERROR_INVALID_INFO: return "Invalid info";
        case ERROR_UNKNOWN: return "Unknown error";
        case ERROR_FUNCTION_NOT_FOUND: return "Function not found";
        case ERROR_FAILED_TO_GET_PROCESS_ADDRESS: return "Failed to get process address";
        case ERROR_FAILED_TO_ALLOCATE_MEMORY: return "Failed to allocate memory";
        default: return "Unknown error";
    }
}

static void handleError(errorCode code, const char* message){
    fprintf(stderr, "[!] %s: %s\n", getErrorMessage(code), message);
    if (code != ERROR_NONE){
        exit(EXIT_FAILURE);
    }
}




#endif // ERROR_H