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

BOOL enumerateAll(HMODULE hNTDLLModule, HMODULE hKernel32Module);
static BOOL enumerateProcesses();
static BOOL enumerateServices();
static BOOL enumerateRegistry();
static BOOL enumerateOS(HMODULE hNTDLLModule, osInfo *os);

#endif // ENUMERATION_H