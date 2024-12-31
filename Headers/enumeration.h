#ifndef ENUMERATION_H
#define ENUMERATION_H

#include <windows.h>
#include <stdio.h>
#include <string.h> 
#include "../enumeration/processes.h"

typedef LONG (WINAPI *RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);

typedef struct {
    DWORD majorVersion;
    DWORD minorVersion;
    DWORD buildNumber;
} osInfo, *pOSInfo;

BOOL enumerateAll(HMODULE hNTDLLModule);
BOOL enumerateProcesses(void);
BOOL enumerateServices(void);
BOOL enumerateRegistry(void);
BOOL enumerateOS(HMODULE hNTDLLModule, osInfo *os);

#endif // ENUMERATION_H
