#ifndef REGISTRY_H
#define REGISTRY_H

#include <stdio.h>

typedef struct {
    char registryKey[MAX_PATH];
} registryInfo, *pRegistryInfo;

static const char* antiAnalysisRegistryKeys[] = {
    "SOFTWARE\\Bitdefender",
    "SOFTWARE\\Classes\\Applications\\VMwareHostOpen.exe",
    "SOFTWARE\\Classes\\Applications\\vmware-tray.exe",
    "SOFTWARE\\Classes\\Applications\\vmware.exe",
    "SOFTWARE\\Classes\\VMwareHostOpen.AssocFile",
    "SOFTWARE\\Classes\\VMwareHostOpen.AssocURL",
    "SOFTWARE\\Classes\\VMware.Document",
    "SOFTWARE\\Classes\\VMware.Snapshot",
    "SOFTWARE\\Classes\\vm",
};

#endif // REGISTRY_H
