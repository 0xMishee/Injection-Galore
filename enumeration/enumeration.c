#include <windows.h>
#include <stdio.h>


#include "os.h"
#include "process.h"
#include "registry.h"
#include "services.h"
#include "enumeration.h"

typedef LONG (WINAPI *RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);

BOOL enumerateAll() {
    return TRUE;
}

BOOL enumerateProcesses() {
    return TRUE;
}

BOOL enumerateServices() {
    return TRUE;
}

BOOL enumerateRegistry() {
    return TRUE;
}

// Add module handle as input later on.
BOOL enumerateOS() {
    SYSTEM_INFO siSysInfo;
    GetSystemInfo(&siSysInfo);
    printf("Hardware information: \n");
    printf("OEM ID: %lu\n", siSysInfo.dwOemId);
    printf("Number of processors: %lu\n", siSysInfo.dwNumberOfProcessors);
    printf("Page size: %lu\n", siSysInfo.dwPageSize);
    printf("Processor type: %lu\n", siSysInfo.dwProcessorType);
    printf("Minimum application address: %p\n", siSysInfo.lpMinimumApplicationAddress);
    printf("Maximum application address: %p\n", siSysInfo.lpMaximumApplicationAddress);
    printf("Active processor mask: %llu\n", siSysInfo.dwActiveProcessorMask);

    HMODULE hModule = GetModuleHandleW(L"ntdll.dll");
    if (hModule == NULL) {
        printf("Failed to get module handle\n");
        return FALSE;
    } else {
        RtlGetVersionPtr RtlGetVersion = (RtlGetVersionPtr)GetProcAddress(hModule, "RtlGetVersion");
        if (RtlGetVersion == NULL) {
            printf("Failed to get process address\n");
            return FALSE;
        } else {
            RTL_OSVERSIONINFOW info;
            info.dwOSVersionInfoSize = sizeof(info);
            RtlGetVersion(&info);
            printf("OS Version: %lu.%lu.%lu\n", info.dwMajorVersion, info.dwMinorVersion, info.dwBuildNumber);
        }
    }


    return TRUE;
}

