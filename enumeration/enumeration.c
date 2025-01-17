#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <string.h>
#include <winsvc.h>

#include "process.h"
#include "registry.h"
#include "services.h"
#include "../Headers/enumeration.h"
#include "../Headers/error.h"

#define MAX_PATH 260
#define MAX_PROCESS_COUNT 1024

/**
 * @brief Enumerates processes and checks against a list of anti-analysis processes.
 *
 * This function creates a snapshot of the currently running processes and iterates through them.
 * It compares each process name against a predefined list of anti-analysis processes. If a match
 * is found, the process information is stored in an array.
 *
 * @return BOOL - Returns TRUE if any anti-analysis processes are found, otherwise FALSE.
 *
 * @note The function allocates memory for storing process information, which is freed before the function returns.
 *       Ensure that MAX_PROCESS_COUNT is defined and that antiAnalysisProcesses is an array of process names to check against.
 */
BOOL enumerateProcesses(void) {

    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;
    size_t processCount = 0;

    processInfo *processes = (processInfo*)malloc(MAX_PROCESS_COUNT * sizeof(processInfo));
    if (!processes) {
        handleError(ERROR_FAILED_TO_ALLOCATE_MEMORY, "Failed to allocate memory for processes");
        return FALSE;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        handleError(ERROR_INVALID_PROCESS, "Failed to create process snapshot");
        goto Cleanup;
    }

    if (!Process32First(hProcessSnap, &pe32)) {
        handleError(ERROR_INVALID_PROCESS, "Failed to get first process");
        goto Cleanup;
    }

    do {
        for (size_t i = 0; i < sizeof(antiAnalysisProcesses) / sizeof(antiAnalysisProcesses[0]); i++) {
            if (strcmp(pe32.szExeFile, antiAnalysisProcesses[i]) == 0) {
                if (processCount >= MAX_PROCESS_COUNT) {
                    goto Cleanup;
                }
                processes[processCount].processID = pe32.th32ProcessID;
                strncpy_s(processes[processCount].processName, sizeof(processes[processCount].processName), pe32.szExeFile, _TRUNCATE);
                processCount++;
                break;
            }
        }
    } while (Process32Next(hProcessSnap, &pe32));

    Cleanup:
        if (hProcessSnap != INVALID_HANDLE_VALUE) {
            CloseHandle(hProcessSnap);
        }
        free(processes);
    return processCount > 0 ? TRUE : FALSE;
}

/**
 * Enumerates all services on the system and prints their names and statuses.
 * 
 * This function opens the Service Control Manager, retrieves the list of services,
 * and prints the name and status (running or stopped) of each service.
 * 
 * @return TRUE if the services were successfully enumerated, FALSE otherwise.
 */
BOOL enumerateServices(void) {

    DWORD dwBytesNeeded = 0;
    DWORD dwServicesReturned = 0;
    DWORD dwResumeHandle = 0;

    LPENUM_SERVICE_STATUS_PROCESSA services = NULL;

    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCManager) {
        handleError(ERROR_INVALID_SERVICE, "Failed to open service control manager");
        goto Cleanup;
    } else {
        // Do nothing
    }

    EnumServicesStatusEx(
                        hSCManager,
                        SC_ENUM_PROCESS_INFO,
                        SERVICE_WIN32,
                        SERVICE_STATE_ALL, // Active | Inactive <.<
                        NULL,
                        0,
                        &dwBytesNeeded,
                        &dwServicesReturned,
                        &dwResumeHandle,
                        NULL); 
    
    services = (LPENUM_SERVICE_STATUS_PROCESSA)malloc(dwBytesNeeded);
    if (!services) {
        handleError(ERROR_FAILED_TO_ALLOCATE_MEMORY, "Failed to allocate memory for services");
        goto Cleanup;
    } else {
        ZeroMemory(services, dwBytesNeeded);
    }

    if (!EnumServicesStatusEx(
                        hSCManager,
                        SC_ENUM_PROCESS_INFO,
                        SERVICE_WIN32,
                        SERVICE_STATE_ALL,
                        (LPBYTE)services,
                        dwBytesNeeded,
                        &dwBytesNeeded,
                        &dwServicesReturned,
                        &dwResumeHandle,
                        NULL)) {
        handleError(ERROR_INVALID_SERVICE, "Failed to enumerate services");
        goto Cleanup;
    } else {
        printf("Services found: %lu\n", dwServicesReturned);
    }

    /*    
    for (size_t i = 0; i < dwServicesReturned; i++) {
        printf("Service name: %s Status: %s\n", services[i].lpServiceName, services[i].ServiceStatusProcess.dwCurrentState == SERVICE_RUNNING ? "Running" : "Stopped");
    }  
    */

    Cleanup:
        if (hSCManager) {
            CloseServiceHandle(hSCManager);
        }
        if (services) {
            free(services);
        }
    return dwServicesReturned > 0 ? TRUE : FALSE;
}

BOOL enumerateRegistry(void) {

    DWORD dwKeysFound = 0;
    registryInfo *registryKeys = NULL;

    registryKeys = (registryInfo*)malloc(sizeof(registryInfo));
    if (!registryKeys) {
        handleError(ERROR_FAILED_TO_ALLOCATE_MEMORY, "Failed to allocate memory for registry keys");
        goto Cleanup;
    } else {
        ZeroMemory(registryKeys, sizeof(registryInfo));
    }

    for (size_t i = 0; i < sizeof(antiAnalysisRegistryKeys) / sizeof(antiAnalysisRegistryKeys[0]); i++) {
        HKEY hKey;
        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, antiAnalysisRegistryKeys[i], 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            strncpy_s(registryKeys->registryKey, sizeof(registryKeys->registryKey), antiAnalysisRegistryKeys[i], _TRUNCATE);
            RegCloseKey(hKey);
            dwKeysFound++;
        }
    } 

    Cleanup:
        free(registryKeys);

    return dwKeysFound > 0 ? TRUE : FALSE;
}

/**
 * @brief Enumerates the operating system version information.
 *
 * This function retrieves the OS version information using the RtlGetVersion function
 * from the NTDLL module and populates the provided osInfo structure with the major version,
 * minor version, and build number of the OS.
 * @return TRUE if the operation is successful, FALSE otherwise.
 */
BOOL enumerateOS(IN HMODULE hNTDLLModule, IN osInfo *os) {

    RtlGetVersionPtr RtlGetVersion = (RtlGetVersionPtr)(void *)GetProcAddress(hNTDLLModule, "RtlGetVersion");
    if (!RtlGetVersion) {
        handleError(ERROR_FAILED_TO_GET_PROCESS_ADDRESS, "Failed to get function address RtlGetVersion");
        return FALSE;
    } else {
        RTL_OSVERSIONINFOW info = {0};
        info.dwOSVersionInfoSize = sizeof(info);
        RtlGetVersion(&info);

        // Populate the osInfo struct.
        os->majorVersion = info.dwMajorVersion;
        os->minorVersion = info.dwMinorVersion;
        os->buildNumber = info.dwBuildNumber;
    }

    return TRUE;
}

BOOL enumerateAll(IN HMODULE hNTDLLModule) {
    
    /*
    These will return the arrays with all the found information.
    Used to help identity potential issues when triggering injections.
    */
    osInfo os;
    if (!enumerateOS(hNTDLLModule, &os)) {return FALSE;}

    if (!enumerateProcesses()) {return FALSE;}

    if (!enumerateServices()) {return FALSE;}

    if (!enumerateRegistry()) {return FALSE;}

    printf("Done enumerating all\n");
    return TRUE;
}
